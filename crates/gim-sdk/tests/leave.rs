//! Leaving a group by a Proposal that another member commits by reference.

mod common;

use std::time::Duration;

use gim_base::model::{Membership, MembershipChangeKind, MessageKind, SendState};
use gim_base::{BaseError, StateReader};
use gim_common::GroupId;
use gim_proto::envelope::Content;
use gim_sdk::ClientError;

use common::{lowest, quick_proposals, server_handshakes, Device, FlakyTransport};

/// Longer than the quick proposal delay.
const AFTER_DELAY: Duration = Duration::from_millis(1200);

struct Trio {
    transport: FlakyTransport,
    alice: Device,
    bob: Device,
    carol: Device,
    g: GroupId,
}

/// Alice's group with Bob and Carol, everybody synced (epoch 1).
async fn trio() -> Trio {
    let transport = FlakyTransport::new();
    let alice = Device::register_with(&transport, "alice", quick_proposals()).await;
    let bob = Device::register_with(&transport, "bob", quick_proposals()).await;
    let carol = Device::register_with(&transport, "carol", quick_proposals()).await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id(), carol.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    carol.sync().await;
    assert_eq!(transport.inner.service().epoch(&g), Ok(1));
    Trio {
        transport,
        alice,
        bob,
        carol,
        g,
    }
}

fn membership(device: &Device, g: &GroupId) -> Membership {
    device.store.chat(g).unwrap().unwrap().membership
}

fn has_member(device: &Device, g: &GroupId, member: &Device) -> bool {
    device
        .store
        .chat(g)
        .unwrap()
        .unwrap()
        .members
        .iter()
        .any(|m| m.device == member.device())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lowest_device_commits_the_leave_and_the_other_does_nothing() {
    let Trio {
        transport,
        alice,
        bob,
        carol,
        g,
    } = trio().await;
    let service = transport.inner.service();
    carol.client.leave(&g).await.unwrap();
    assert_eq!(membership(&carol, &g), Membership::Leaving);
    let handshakes = server_handshakes(&transport, &g);

    // The other member stores the proposal and waits.
    let (chosen, other) = lowest([&alice, &bob]);
    other.sync().await;
    assert_eq!(service.epoch(&g), Ok(1));
    // The lowest device id commits it at once.
    chosen.sync().await;
    assert_eq!(service.epoch(&g), Ok(2));
    assert!(!has_member(chosen, &g, &carol));
    // After its delay the other finds the proposal committed: no commit.
    tokio::time::sleep(AFTER_DELAY).await;
    assert_eq!(service.epoch(&g), Ok(2));
    assert_eq!(server_handshakes(&transport, &g), handshakes + 1);
    other.sync().await;
    assert!(!has_member(other, &g, &carol));
    for device in [&alice, &bob] {
        let event = device.store.membership_events(&g).unwrap().pop().unwrap();
        assert_eq!(
            (event.user_id, event.actor, event.kind),
            (
                carol.user_id(),
                chosen.user_id(),
                MembershipChangeKind::Left
            )
        );
    }

    // Carol applies the commit: Left, MLS group dropped, nothing later
    // reaches her.
    carol.sync().await;
    assert_eq!(membership(&carol, &g), Membership::Left);
    assert_eq!(carol.store.pending_leave(&g).unwrap(), None);
    let event = carol.store.membership_events(&g).unwrap().pop().unwrap();
    assert_eq!(
        (event.user_id, event.actor, event.kind),
        (carol.user_id(), carol.user_id(), MembershipChangeKind::Left)
    );
    alice
        .client
        .send_text(&g, "after carol", None)
        .await
        .unwrap();
    bob.sync().await;
    carol.sync().await;
    assert_eq!(bob.messages(&g).len(), 1);
    assert!(carol.messages(&g).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_member_commits_when_the_lowest_is_offline() {
    let Trio {
        transport,
        alice,
        bob,
        carol,
        g,
    } = trio().await;
    let service = transport.inner.service();
    carol.client.leave(&g).await.unwrap();
    let (_offline, other) = lowest([&alice, &bob]);
    other.sync().await;
    assert_eq!(service.epoch(&g), Ok(1));
    tokio::time::sleep(AFTER_DELAY).await;
    assert_eq!(service.epoch(&g), Ok(2));
    assert!(!has_member(other, &g, &carol));
    carol.sync().await;
    assert_eq!(membership(&carol, &g), Membership::Left);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_sending_commits_the_pending_proposal_first() {
    let Trio {
        transport,
        alice,
        bob,
        carol,
        g,
    } = trio().await;
    let service = transport.inner.service();
    carol.client.leave(&g).await.unwrap();
    // MLS refuses to encrypt while a proposal is pending: the sender
    // commits it, whoever is chosen.
    let (chosen, other) = lowest([&alice, &bob]);
    other.sync().await;
    other.client.send_text(&g, "bye carol", None).await.unwrap();
    assert_eq!(service.epoch(&g), Ok(2));
    chosen.sync().await;
    assert_eq!(service.epoch(&g), Ok(2));
    assert_eq!(chosen.messages(&g).len(), 1);
    assert!(!has_member(chosen, &g, &carol));
    carol.sync().await;
    assert_eq!(membership(&carol, &g), Membership::Left);
    assert!(carol.messages(&g).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_leave_proposal_is_resent_for_the_new_epoch() {
    let transport = FlakyTransport::new();
    let alice = Device::register_with(&transport, "alice", quick_proposals()).await;
    let carol = Device::register_with(&transport, "carol", quick_proposals()).await;
    let dave = Device::register_with(&transport, "dave", quick_proposals()).await;
    let g = alice
        .client
        .create_group_chat(None, &[carol.user_id()])
        .await
        .unwrap();
    carol.sync().await;
    let service = transport.inner.service();

    carol.client.leave(&g).await.unwrap();
    let first = carol.store.pending_leave(&g).unwrap().unwrap();
    assert_eq!((first.epoch, first.attempts), (1, 1));
    // Alice adds Dave without having seen the proposal: the epoch ends and
    // the hub drops the proposal.
    alice
        .client
        .add_members(&g, &[dave.user_id()])
        .await
        .unwrap();
    assert_eq!(service.epoch(&g), Ok(2));
    // Carol is still a member and proposes again for epoch 2.
    carol.sync().await;
    assert_eq!(membership(&carol, &g), Membership::Leaving);
    let renewed = carol.store.pending_leave(&g).unwrap().unwrap();
    assert_eq!((renewed.epoch, renewed.attempts), (2, 2));
    assert!(renewed.accepted);
    assert_ne!(renewed.client_id, first.client_id);

    // The stale one is ignored; the new one is committed.
    let (chosen, _) = lowest([&alice, &dave]);
    dave.sync().await;
    chosen.sync().await;
    assert_eq!(service.epoch(&g), Ok(3));
    carol.sync().await;
    assert_eq!(membership(&carol, &g), Membership::Left);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_rejects_sends_and_fails_queued_messages() {
    let Trio {
        transport,
        carol,
        g,
        ..
    } = trio().await;
    // Queued for a retry when the user leaves.
    transport
        .faults
        .fail_posts(MessageKind::Application, false, 1);
    let queued = carol.client.send_text(&g, "queued", None).await.unwrap();
    assert_eq!(carol.message(&queued).send_state, Some(SendState::Pending));
    carol.client.leave(&g).await.unwrap();

    assert!(matches!(
        carol
            .client
            .send(&g, Content::Text { body: "x".into() })
            .await,
        Err(ClientError::Base(BaseError::InvalidState(_)))
    ));
    carol.client.network_reachable();
    carol.client.flush_outbox().await.unwrap();
    assert_eq!(carol.message(&queued).send_state, Some(SendState::Failed));
    // Leaving again is a no-op while the proposal is accepted.
    let handshakes = server_handshakes(&transport, &g);
    carol.client.leave(&g).await.unwrap();
    assert_eq!(server_handshakes(&transport, &g), handshakes);
}
