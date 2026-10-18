//! The hub user policy (allow/deny list) against an in-process mock hub:
//! a hub that does not admit the user (`user_not_admitted`), an owning hub
//! that refuses the user's posts (`not_admitted_by_peer`) and claims of
//! users whose hub does not admit this user (`not_admitted`).

mod mock_server;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use gim_base::model::{Membership, SendFailure, SendState};
use gim_base::{MemoryStore, StateReader};
use gim_common::{GroupId, MessageId};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::{
    ClientBuilder, ClientError, ConnectionState, HttpTransport, SecretStorage,
    DEVICE_KEY_SECRET_KEY, ROOT_KEY_SECRET_KEY, SESSION_SECRET_KEY,
};
use mock_server::{fast_settings, reach_state, MockServer, Peer};

struct Setup {
    transport: FakeTransport,
    server: MockServer,
    alice: Peer,
    bob: Peer,
}

/// Alice on the fake transport, Bob over HTTP against the mock hub.
async fn setup() -> Setup {
    let transport = FakeTransport::new();
    let server = MockServer::start(transport.clone()).await;
    let alice = Peer::fake(&transport, "alice").await;
    let bob = Peer::http(&server, "bob", fast_settings()).await;
    Setup {
        transport,
        server,
        alice,
        bob,
    }
}

/// A group chat of alice with bob, joined by bob.
async fn group_with_bob(alice: &Peer, bob: &Peer) -> GroupId {
    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    bob.client.sync_once().await.unwrap();
    assert!(bob.has_chat(&g));
    g
}

fn requests(server: &MockServer) -> usize {
    server.controls.requests.load(Ordering::SeqCst)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_admitted_user_gets_user_not_admitted_after_one_sign_in() {
    let Setup {
        transport,
        server,
        bob,
        ..
    } = setup().await;
    bob.client.sync_once().await.unwrap();
    let hub_id = transport.service().hub_id().to_string();
    let challenges = || server.controls.challenges.load(Ordering::SeqCst);
    let before = challenges();

    // The policy change deletes the session: the call gets 401, the
    // sign-in 403 `user_not_admitted`, which the caller gets.
    server.controls.not_admitted.store(true, Ordering::SeqCst);
    let result = bob.client.sync_once().await;
    assert!(
        matches!(&result, Err(ClientError::UserNotAdmitted { hub_id: h }) if *h == hub_id),
        "{result:?}"
    );
    assert_eq!(challenges(), before + 1);
    // The session is kept, and the next calls do not sign in again.
    assert!(bob.client.session().is_some());
    let served = requests(&server);
    for _ in 0..3 {
        let result = bob.client.sync_once().await;
        assert!(
            matches!(result, Err(ClientError::UserNotAdmitted { .. })),
            "{result:?}"
        );
    }
    assert_eq!(challenges(), before + 1);
    assert_eq!(requests(&server), served);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_loop_of_a_not_admitted_user_settles_without_reconnecting() {
    let Setup { server, bob, .. } = setup().await;
    let mut states = bob.client.subscribe_connection_state();
    bob.client.start_sync().unwrap();
    reach_state(&mut states, ConnectionState::Connected).await;
    server.streams_served(1).await;
    let before = server.controls.challenges.load(Ordering::SeqCst);

    server.controls.not_admitted.store(true, Ordering::SeqCst);
    reach_state(&mut states, ConnectionState::Offline).await;
    let served = requests(&server);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        server.controls.challenges.load(Ordering::SeqCst),
        before + 1
    );
    let during = requests(&server) - served;
    assert!(during <= 2, "{during} requests while not admitted");
    assert!(bob.client.is_sync_running());
    assert!(bob.client.session().is_some());
    bob.client.stop_sync().unwrap();
}

#[tokio::test]
async fn refused_registration_leaves_nothing_and_can_be_retried() {
    let transport = FakeTransport::new();
    let server = MockServer::start(transport.clone()).await;
    let secrets = Arc::new(MemorySecretStorage::new());
    let data_dir = tempfile::tempdir().unwrap();
    let client = ClientBuilder::new(
        Arc::new(MemoryStore::new()),
        Arc::new(HttpTransport::new(server.url.parse().unwrap()).unwrap()),
        secrets.clone() as Arc<dyn SecretStorage>,
    )
    .data_dir(data_dir.path())
    .build()
    .unwrap();

    server.controls.not_admitted.store(true, Ordering::SeqCst);
    let result = client.create_identity("Carol").await;
    assert!(
        matches!(result, Err(ClientError::UserNotAdmitted { .. })),
        "{result:?}"
    );
    // The enrollment was discarded: no session, no keys, no sign-in.
    assert!(client.session().is_none());
    for key in [
        ROOT_KEY_SECRET_KEY,
        DEVICE_KEY_SECRET_KEY,
        SESSION_SECRET_KEY,
    ] {
        assert!(secrets.get(key).unwrap().is_none(), "{key} is left");
    }
    assert_eq!(server.controls.challenges.load(Ordering::SeqCst), 0);

    // Once the hub admits the user, onboarding works.
    server.controls.not_admitted.store(false, Ordering::SeqCst);
    client.create_identity("Carol").await.unwrap();
    assert!(client.session().is_some());
}

/// Bob's message `id` failed with `cause`.
fn assert_failed(bob: &Peer, id: &MessageId, cause: SendFailure) {
    assert_eq!(
        bob.store.message(id).unwrap().unwrap().send_state,
        Some(SendState::Failed)
    );
    assert_eq!(
        bob.store.outbox_entry(id).unwrap().unwrap().failure,
        Some(cause)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn posts_refused_by_the_owning_hub_fail_for_good_and_other_chats_still_send() {
    let Setup {
        transport,
        server,
        alice,
        bob,
    } = setup().await;
    let refused = group_with_bob(&alice, &bob).await;
    let open = group_with_bob(&alice, &bob).await;
    let hub_id = transport.service().hub_id().to_string();
    server
        .controls
        .refused_groups
        .lock()
        .unwrap()
        .insert(refused.clone());

    // A message: `Failed` with the cause at once, not retried.
    let id = bob.send_text(&refused, "hello?").await;
    assert_failed(&bob, &id, SendFailure::NotAdmittedByPeer);
    let served = requests(&server);
    for _ in 0..3 {
        assert_eq!(bob.client.flush_outbox().await.unwrap(), None);
    }
    assert_eq!(requests(&server), served);

    // A commit: the error, and the pending commit is dropped.
    let result = bob
        .client
        .remove_members(&refused, &[alice.user_id()])
        .await;
    assert!(
        matches!(&result, Err(ClientError::NotAdmittedByPeer { hub_id: h, group_id })
            if *h == hub_id && *group_id == refused.to_string()),
        "{result:?}"
    );
    assert!(bob.store.pending_commit(&refused).unwrap().is_none());
    // A leave proposal: the error, and the chat stays joined.
    let result = bob.client.leave(&refused).await;
    assert!(
        matches!(result, Err(ClientError::NotAdmittedByPeer { .. })),
        "{result:?}"
    );
    assert_eq!(
        bob.store.chat(&refused).unwrap().unwrap().membership,
        Membership::Joined
    );

    // The hub is not blocked: another chat sends through it.
    let sent = bob.send_text(&open, "still here").await;
    assert_eq!(
        bob.store.message(&sent).unwrap().unwrap().send_state,
        Some(SendState::Sent)
    );
    alice.client.sync_once().await.unwrap();
    assert_eq!(alice.texts(&open), ["still here"]);
    // Nor is the sync loop.
    bob.client.sync_once().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contacts_whose_hub_does_not_admit_the_user_are_reported() {
    let Setup {
        transport,
        server,
        alice,
        bob,
    } = setup().await;
    let carol = Peer::fake(&transport, "carol").await;
    server
        .controls
        .claim_not_admitted
        .lock()
        .unwrap()
        .insert(alice.user_id());

    // Every requested user refused: `ContactNotAdmitted`, nothing created.
    let chats = bob.store.chats().unwrap().len();
    let result = bob.client.create_direct_chat(&alice.user_id()).await;
    assert!(
        matches!(&result, Err(ClientError::ContactNotAdmitted { user_ids }) if *user_ids == [alice.user_id()]),
        "{result:?}"
    );
    let result = bob.client.create_group_chat(None, &[alice.user_id()]).await;
    assert!(
        matches!(result, Err(ClientError::ContactNotAdmitted { .. })),
        "{result:?}"
    );
    assert_eq!(bob.store.chats().unwrap().len(), chats);

    // Partly refused: the admitted users are added, the refused ones
    // skipped.
    let g = bob
        .client
        .create_group_chat(None, &[alice.user_id(), carol.user_id()])
        .await
        .unwrap();
    carol.client.sync_once().await.unwrap();
    alice.client.sync_once().await.unwrap();
    assert!(carol.has_chat(&g));
    assert!(!alice.has_chat(&g));
    assert!(bob.client.pending_invites(&g).is_empty());

    // Adding only refused users fails the same way.
    let result = bob.client.add_members(&g, &[alice.user_id()]).await;
    assert!(
        matches!(result, Err(ClientError::ContactNotAdmitted { .. })),
        "{result:?}"
    );
}
