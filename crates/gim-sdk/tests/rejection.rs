//! Definite rejections (4xx) are never resent; unknown outcomes (5xx,
//! network errors) are resent unchanged.

mod common;

use std::time::Duration;

use gim_base::model::{Membership, MessageKind, SendState};
use gim_base::StateReader;
use gim_common::{ClientId, GroupId};
use gim_sdk::transport::TransportError;
use gim_sdk::ClientError;

use common::{lowest, quick_proposals, server_handshakes, Device, FlakyTransport};

/// Longer than the quick proposal delay.
const AFTER_DELAY: Duration = Duration::from_millis(1200);

fn rejected(status: u16, code: &str) -> TransportError {
    TransportError::Rejected {
        status,
        code: code.into(),
        message: "injected".into(),
    }
}

fn inject(transport: &FlakyTransport, kind: MessageKind, err: TransportError) {
    transport
        .faults
        .peer_failures
        .lock()
        .unwrap()
        .push_back((kind, err));
}

fn commit_posts(transport: &FlakyTransport) -> Vec<(ClientId, Vec<u8>)> {
    transport.faults.commit_posts.lock().unwrap().clone()
}

fn message_posts(transport: &FlakyTransport) -> Vec<ClientId> {
    transport.faults.message_posts.lock().unwrap().clone()
}

fn is_rejected<T: std::fmt::Debug>(result: &Result<T, ClientError>, status: u16) -> bool {
    matches!(result, Err(ClientError::Transport(TransportError::Rejected { status: s, .. })) if *s == status)
}

async fn direct_chat(transport: &FlakyTransport) -> (Device, Device, GroupId) {
    let alice = Device::register(transport, "alice").await;
    let bob = Device::register(transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    (alice, bob, g)
}

#[test]
fn only_unknown_outcomes_are_retryable() {
    for err in [
        TransportError::Network("timeout".into()),
        TransportError::Server("500: internal".into()),
        TransportError::Server("429 Too Many Requests: rate_limited".into()),
        TransportError::PeerRefused("peer_refused".into()),
        TransportError::PeerUnavailable {
            retry_after_secs: None,
            reason: "peer_unavailable".into(),
        },
        TransportError::RetryLater {
            status: 429,
            retry_after_secs: 1,
            reason: "rate_limited".into(),
        },
    ] {
        assert!(err.outcome_unknown(), "{err:?}");
    }
    for err in [
        rejected(400, "validation_failed"),
        rejected(403, "forbidden"),
        rejected(422, "unprocessable"),
        TransportError::NotFound("not_found".into()),
        TransportError::Conflict("conflict".into()),
        TransportError::TooLarge("payload_too_large".into()),
        TransportError::HostingRecordRequired("hosting_record_required".into()),
        TransportError::Unauthorized,
    ] {
        assert!(!err.outcome_unknown(), "{err:?}");
    }
}

#[tokio::test]
async fn rejected_message_fails_without_retries() {
    let transport = FlakyTransport::new();
    let (alice, _bob, g) = direct_chat(&transport).await;
    let posts = message_posts(&transport).len();

    inject(
        &transport,
        MessageKind::Application,
        rejected(400, "validation_failed"),
    );
    let id = alice.client.send_text(&g, "bad", None).await.unwrap();
    assert_eq!(alice.message(&id).send_state, Some(SendState::Failed));
    assert_eq!(alice.store.outbox_entry(&id).unwrap().unwrap().attempts, 1);
    for _ in 0..3 {
        alice.client.network_reachable();
        alice.client.flush_outbox().await.unwrap();
    }
    assert_eq!(message_posts(&transport).len(), posts + 1);
    assert_eq!(alice.message(&id).send_state, Some(SendState::Failed));
}

#[tokio::test]
async fn message_of_unknown_outcome_is_resent_with_the_same_client_id() {
    let transport = FlakyTransport::new();
    let (alice, bob, g) = direct_chat(&transport).await;
    let posts = message_posts(&transport).len();

    inject(
        &transport,
        MessageKind::Application,
        TransportError::Server("500: internal".into()),
    );
    let id = alice.client.send_text(&g, "again", None).await.unwrap();
    assert_eq!(alice.message(&id).send_state, Some(SendState::Pending));
    alice.client.network_reachable();
    alice.client.flush_outbox().await.unwrap();
    assert_eq!(alice.message(&id).send_state, Some(SendState::Sent));
    let posted = message_posts(&transport).split_off(posts);
    assert_eq!(posted.len(), 2);
    assert_eq!(posted[0], posted[1]);
    assert_eq!(posted[0].as_str(), id.as_str());
    bob.sync().await;
    assert_eq!(bob.messages(&g).len(), 1);
}

#[tokio::test]
async fn rejected_commit_is_dropped_and_rebuilt_not_resubmitted() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    let service = transport.inner.service();
    let before = commit_posts(&transport).len();

    // E.g. a KeyPackage not claimed through this hub (kp_not_claimed).
    inject(
        &transport,
        MessageKind::Commit,
        rejected(400, "validation_failed"),
    );
    let added = alice.client.add_members(&g, &[carol.user_id()]).await;
    assert!(is_rejected(&added, 400), "{added:?}");
    assert_eq!(service.epoch(&g), Ok(1));
    assert_eq!(alice.store.pending_commit(&g).unwrap(), None);
    let posts = commit_posts(&transport).split_off(before);
    assert_eq!(posts.len(), 1);
    let rejected_commit = posts[0].clone();

    // Nothing is resubmitted by the next sync.
    alice.sync().await;
    assert_eq!(commit_posts(&transport).len(), before + 1);

    // Trying again builds a new Commit.
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    assert_eq!(service.epoch(&g), Ok(2));
    let posts = commit_posts(&transport).split_off(before + 1);
    assert!(!posts.is_empty());
    assert!(posts.iter().all(|p| p.1 != rejected_commit.1));
    alice.client.send_text(&g, "hi carol", None).await.unwrap();
    carol.sync().await;
    assert_eq!(carol.messages(&g).len(), 1);
}

#[tokio::test]
async fn commit_of_unknown_outcome_is_resubmitted_unchanged() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    let before = commit_posts(&transport).len();

    inject(
        &transport,
        MessageKind::Commit,
        TransportError::Server("503: unavailable".into()),
    );
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    assert_eq!(transport.inner.service().epoch(&g), Ok(2));
    let posts = commit_posts(&transport).split_off(before);
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
}

/// Alice's group with Bob and Carol, everybody synced (epoch 1).
async fn trio(transport: &FlakyTransport) -> (Device, Device, Device, GroupId) {
    let alice = Device::register_with(transport, "alice", quick_proposals()).await;
    let bob = Device::register_with(transport, "bob", quick_proposals()).await;
    let carol = Device::register_with(transport, "carol", quick_proposals()).await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id(), carol.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    carol.sync().await;
    (alice, bob, carol, g)
}

/// A rejected leave Proposal is abandoned: the chat is back to `Joined`
/// (a `ChatUpserted` change) and the caller gets the rejection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_leave_proposal_keeps_the_chat_joined() {
    let transport = FlakyTransport::new();
    let (alice, _bob, carol, g) = trio(&transport).await;
    let before = commit_posts(&transport).len();
    let handshakes = server_handshakes(&transport, &g);

    inject(&transport, MessageKind::Commit, rejected(403, "forbidden"));
    let left = carol.client.leave(&g).await;
    assert!(is_rejected(&left, 403), "{left:?}");
    let chat = carol.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.membership, Membership::Joined);
    assert_eq!(carol.store.pending_leave(&g).unwrap(), None);

    // Not proposed again; the chat works as before.
    carol.sync().await;
    assert_eq!(commit_posts(&transport).len(), before + 1);
    assert_eq!(server_handshakes(&transport, &g), handshakes);
    carol
        .client
        .send_text(&g, "still here", None)
        .await
        .unwrap();
    alice.sync().await;
    assert_eq!(alice.messages(&g).len(), 1);
}

#[tokio::test]
async fn leave_proposal_of_unknown_outcome_is_resent_unchanged() {
    let transport = FlakyTransport::new();
    let (_alice, _bob, carol, g) = trio(&transport).await;
    let before = commit_posts(&transport).len();

    inject(
        &transport,
        MessageKind::Commit,
        TransportError::Network("timeout".into()),
    );
    carol.client.leave(&g).await.unwrap();
    let chat = carol.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.membership, Membership::Leaving);
    let posts = commit_posts(&transport).split_off(before);
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
}

/// The hub refuses a Commit of the pending Proposals (e.g. a reference to
/// a Proposal it no longer holds): they are dropped, not committed again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_proposal_commit_drops_the_proposals() {
    let transport = FlakyTransport::new();
    let (alice, bob, carol, g) = trio(&transport).await;
    let service = transport.inner.service();
    carol.client.leave(&g).await.unwrap();
    let (chosen, _other) = lowest([&alice, &bob]);
    let before = commit_posts(&transport).len();

    inject(
        &transport,
        MessageKind::Commit,
        rejected(400, "validation_failed"),
    );
    chosen.sync().await;
    assert_eq!(commit_posts(&transport).len(), before + 1);
    assert_eq!(service.epoch(&g), Ok(1));

    // Dropped: neither the next sync nor the delayed commit retries it.
    chosen.sync().await;
    tokio::time::sleep(AFTER_DELAY).await;
    assert_eq!(commit_posts(&transport).len(), before + 1);
    assert_eq!(service.epoch(&g), Ok(1));
    // The group still works for the committer.
    chosen.client.send_text(&g, "hello", None).await.unwrap();
}
