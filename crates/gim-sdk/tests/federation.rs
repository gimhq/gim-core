//! Federated behaviour (hub contract v2 `federation.md` §6.7, §9.2):
//! unavailable KeyPackage claims become pending invites, peer hub failures
//! (502/503) on posts are retried unchanged, replica history starts at the
//! member hub's join point, and remote users may have no handle.

mod common;
mod mock_server;

use std::sync::Arc;
use std::time::{Duration, Instant};

use gim_base::model::{
    GroupMessage, IncomingEvent, MembershipChangeKind, MessageContent, MessageKind, StateChange,
};
use gim_base::{MemoryStore, StateReader, StateStore, StoreTxn};
use gim_common::{now_ms, GroupId};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{HubEvent, TransportError};
use gim_sdk::{ClientBuilder, ClientError, SecretStorage, SyncSettings};

use common::{server_messages, Device, FlakyTransport};
use mock_server::{fast_settings, wait_until, MockServer, Peer};

/// Registers a device with fast invite retries.
async fn device(transport: &FlakyTransport, handle: &str, settings: SyncSettings) -> Device {
    let store = Arc::new(MemoryStore::new());
    let data_dir = tempfile::tempdir().unwrap();
    let client = ClientBuilder::new(
        store.clone(),
        Arc::new(transport.clone()),
        Arc::new(MemorySecretStorage::new()) as Arc<dyn SecretStorage>,
    )
    .data_dir(data_dir.path())
    .sync_settings(settings)
    .build()
    .unwrap();
    client.register(handle, handle).await.unwrap();
    Device {
        client,
        store,
        data_dir,
    }
}

fn invite_settings(invite_ttl: Duration) -> SyncSettings {
    SyncSettings {
        invite_retry: Duration::from_millis(20),
        invite_ttl,
        ..fast_settings()
    }
}

fn hub_members(transport: &FlakyTransport, group_id: &GroupId) -> Vec<gim_common::UserId> {
    let info = transport.inner.service().group(group_id).unwrap();
    info.members.into_iter().map(|d| d.user_id).collect()
}

fn texts(device: &Device, group_id: &GroupId) -> Vec<String> {
    device
        .messages(group_id)
        .into_iter()
        .filter_map(|m| match m.content {
            MessageContent::Text { body } => Some(body),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn unavailable_invitee_is_added_by_the_sync_loop() {
    let transport = FlakyTransport::new();
    let settings = invite_settings(Duration::from_secs(3600));
    let alice = device(&transport, "alice", settings).await;
    let bob = device(&transport, "bob", settings).await;
    let carol = device(&transport, "carol", settings).await;
    transport
        .faults
        .unreachable
        .lock()
        .unwrap()
        .insert(bob.user_id());

    // Carol is reachable and added now; Bob waits.
    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[bob.user_id(), carol.user_id()])
        .await
        .unwrap();
    assert_eq!(alice.client.pending_invites(&g), vec![bob.user_id()]);
    let members = hub_members(&transport, &g);
    assert!(members.contains(&carol.user_id()));
    assert!(!members.contains(&bob.user_id()));

    // Still unreachable: retried, kept.
    alice.client.start_sync().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(alice.client.pending_invites(&g), vec![bob.user_id()]);

    transport.faults.unreachable.lock().unwrap().clear();
    let (hub, gid, bob_id) = (transport.clone(), g.clone(), bob.user_id());
    wait_until("bob added", move || {
        hub_members(&hub, &gid).contains(&bob_id)
    })
    .await;
    assert!(alice.client.pending_invites(&g).is_empty());
    // The group name follows the commit.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        bob.sync().await;
        let chat = bob.store.chat(&g).unwrap();
        if chat.and_then(|c| c.name).as_deref() == Some("crew") {
            break;
        }
        assert!(Instant::now() < deadline, "bob never got the group name");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    alice.client.stop_sync().unwrap();
}

#[tokio::test]
async fn direct_chat_with_an_unreachable_user_is_created_with_the_invite_pending() {
    let transport = FlakyTransport::new();
    let settings = invite_settings(Duration::from_secs(3600));
    let alice = device(&transport, "alice", settings).await;
    let bob = device(&transport, "bob", settings).await;
    transport
        .faults
        .unreachable
        .lock()
        .unwrap()
        .insert(bob.user_id());

    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    assert!(alice.store.chat(&g).unwrap().is_some());
    assert_eq!(hub_members(&transport, &g), vec![alice.user_id()]);
    assert_eq!(alice.client.pending_invites(&g), vec![bob.user_id()]);

    // Adding an unreachable user to an existing chat is not an error either.
    let carol = device(&transport, "carol", settings).await;
    transport
        .faults
        .unreachable
        .lock()
        .unwrap()
        .insert(carol.user_id());
    let h = alice.client.create_group_chat(None, &[]).await.unwrap();
    alice
        .client
        .add_members(&h, &[carol.user_id()])
        .await
        .unwrap();
    assert_eq!(alice.client.pending_invites(&h), vec![carol.user_id()]);

    transport.faults.unreachable.lock().unwrap().clear();
    tokio::time::sleep(Duration::from_millis(30)).await;
    alice.client.retry_pending_invites().await.unwrap();
    assert!(alice.client.pending_invites(&g).is_empty());
    assert!(alice.client.pending_invites(&h).is_empty());
    bob.sync().await;
    assert_eq!(
        bob.store.chat(&g).unwrap().unwrap().kind,
        gim_base::model::ChatKind::Direct
    );
    assert!(hub_members(&transport, &h).contains(&carol.user_id()));
}

#[tokio::test]
async fn pending_invite_expires_as_a_removal() {
    let transport = FlakyTransport::new();
    let settings = invite_settings(Duration::from_millis(200));
    let alice = device(&transport, "alice", settings).await;
    let bob = device(&transport, "bob", settings).await;
    transport
        .faults
        .unreachable
        .lock()
        .unwrap()
        .insert(bob.user_id());
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    let mut changes = alice.client.subscribe_changes();

    // Retried while it lasts.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let due = alice.client.retry_pending_invites().await.unwrap();
    assert!(due.is_some());
    assert_eq!(alice.client.pending_invites(&g), vec![bob.user_id()]);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(alice.client.retry_pending_invites().await.unwrap(), None);
    assert!(alice.client.pending_invites(&g).is_empty());
    let failed: Vec<_> = std::iter::from_fn(|| changes.try_recv().ok())
        .filter_map(|c| match c {
            StateChange::MembershipChanged(e) => Some(e),
            _ => None,
        })
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].group_id, g);
    assert_eq!(failed[0].user_id, bob.user_id());
    assert_eq!(failed[0].actor, alice.user_id());
    assert_eq!(failed[0].kind, MembershipChangeKind::Removed);
    assert_eq!(hub_members(&transport, &g), vec![alice.user_id()]);
}

#[tokio::test]
async fn peer_unavailable_message_is_resent_after_retry_after() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    transport.faults.message_posts.lock().unwrap().clear();
    transport.faults.peer_failures.lock().unwrap().push_back((
        MessageKind::Application,
        TransportError::PeerUnavailable {
            retry_after_secs: Some(1),
            reason: "peer_unavailable".into(),
        },
    ));

    let sent_at = now_ms();
    let id = alice.client.send_text(&g, "hello", None).await.unwrap();
    let entry = alice.store.outbox_entry(&id).unwrap().unwrap();
    let delay = entry.next_attempt_at_ms - sent_at;
    assert!((900..=1500).contains(&delay), "delay {delay} ms");

    // Not before the delay.
    let due = alice.client.flush_outbox().await.unwrap();
    assert_eq!(due, Some(entry.next_attempt_at_ms));
    assert_eq!(transport.faults.message_posts.lock().unwrap().len(), 1);

    tokio::time::sleep(Duration::from_millis(
        entry.next_attempt_at_ms.saturating_sub(now_ms()) + 20,
    ))
    .await;
    alice.client.flush_outbox().await.unwrap();
    assert!(alice.store.outbox_entry(&id).unwrap().is_none());
    let posts = transport.faults.message_posts.lock().unwrap().clone();
    assert_eq!(posts.len(), 2);
    assert!(posts.iter().all(|c| c.as_str() == id.as_str()));
    let stored = server_messages(&transport, &g, &alice.device());
    assert_eq!(
        stored
            .iter()
            .filter(|m| m.client_id.as_str() == id.as_str())
            .count(),
        1
    );
}

/// The commit posts since `from`, as `(client_id, bytes)`.
fn commit_posts(transport: &FlakyTransport, from: usize) -> Vec<(String, Vec<u8>)> {
    transport.faults.commit_posts.lock().unwrap()[from..]
        .iter()
        .map(|(c, b)| (c.to_string(), b.clone()))
        .collect()
}

#[tokio::test]
async fn peer_failures_resubmit_the_identical_commit() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let dave = Device::register(&transport, "dave").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;

    // 502 without Retry-After: resubmitted within the call.
    let from = transport.faults.commit_posts.lock().unwrap().len();
    transport.faults.peer_failures.lock().unwrap().push_back((
        MessageKind::Commit,
        TransportError::PeerRefused("peer_refused".into()),
    ));
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    let posts = commit_posts(&transport, from);
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
    assert!(hub_members(&transport, &g).contains(&carol.user_id()));

    // 503 with a short Retry-After: waited for, then resubmitted.
    let from = transport.faults.commit_posts.lock().unwrap().len();
    transport.faults.peer_failures.lock().unwrap().push_back((
        MessageKind::Commit,
        TransportError::PeerUnavailable {
            retry_after_secs: Some(1),
            reason: "peer_unavailable".into(),
        },
    ));
    let started = Instant::now();
    alice
        .client
        .remove_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(1));
    let posts = commit_posts(&transport, from);
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
    assert!(!hub_members(&transport, &g).contains(&carol.user_id()));

    // A long Retry-After: the commit stays pending, sync goes on, and the
    // same commit is resubmitted before the next send.
    let from = transport.faults.commit_posts.lock().unwrap().len();
    transport.faults.peer_failures.lock().unwrap().push_back((
        MessageKind::Commit,
        TransportError::PeerUnavailable {
            retry_after_secs: Some(60),
            reason: "peer_unavailable".into(),
        },
    ));
    let err = alice
        .client
        .add_members(&g, &[dave.user_id()])
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ClientError::Transport(e) if e.is_peer_failure()),
        "{err}"
    );
    assert!(alice.store.pending_commit(&g).unwrap().is_some());
    bob.client.send_text(&g, "meanwhile", None).await.unwrap();
    alice.sync().await;
    // Held back until the own commit is settled.
    assert!(texts(&alice, &g).is_empty());
    assert_eq!(commit_posts(&transport, from).len(), 1);

    alice.client.send_text(&g, "after", None).await.unwrap();
    let posts = commit_posts(&transport, from);
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
    assert!(alice.store.pending_commit(&g).unwrap().is_none());
    assert!(hub_members(&transport, &g).contains(&dave.user_id()));
    // Bob's message was at the old epoch: applied once the commit merged.
    assert_eq!(texts(&alice, &g), vec!["meanwhile", "after"]);
    dave.sync().await;
    assert_eq!(texts(&dave, &g), vec!["after"]);
}

#[tokio::test]
async fn replica_history_starting_at_the_join_point() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    bob.sync().await;
    alice.sync().await;
    for text in ["m1", "m2", "m3", "m4"] {
        bob.client.send_text(&g, text, None).await.unwrap();
    }
    let sent = server_messages(&transport, &g, &bob.device());
    let m3 = &sent[sent.len() - 2];
    let m4 = sent.last().unwrap();

    // Alice misses the events; her hub's history starts at m3.
    let head = transport
        .inner
        .service()
        .events(&alice.device(), 0, usize::MAX)
        .1;
    alice
        .store
        .transaction(|txn| Ok(txn.set_global_cursor(head)?))
        .unwrap();
    transport
        .faults
        .history_from
        .lock()
        .unwrap()
        .insert(g.clone(), m3.seq);
    transport
        .faults
        .injected_events
        .lock()
        .unwrap()
        .push(HubEvent::Group(IncomingEvent::Message(GroupMessage {
            group_id: g.clone(),
            seq: m4.seq,
            sender: m4.sender.clone(),
            kind: MessageKind::Application,
            payload: m4.payload.clone(),
            client_id: Some(m4.client_id.clone()),
        })));

    alice.sync().await;
    assert_eq!(texts(&alice, &g), vec!["m3", "m4"]);
    let cursor = alice.store.group_cursor(&g).unwrap();
    assert_eq!(cursor.contiguous_seq, m4.seq);
    assert!(cursor.ahead.is_empty());
    // Nothing left to fill.
    alice.sync().await;
    assert_eq!(texts(&alice, &g), vec!["m3", "m4"]);
}

#[tokio::test]
async fn remote_user_without_handle_is_named_by_short_user_id() {
    let transport = FakeTransport::new();
    let server = MockServer::start(transport.clone()).await;
    let alice = Peer::http(&server, "alice", fast_settings()).await;
    let bob = Peer::fake(&transport, "bob").await;
    // The hub has no profile, and Bob has no handle (as a remote user).
    bob.client.release_handle("bob").await.unwrap();
    assert_eq!(
        transport.service().user(&bob.user_id()).unwrap().handle,
        None
    );

    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let short: String = bob.user_id().as_str().chars().take(12).collect();
    let user = alice.store.user(&bob.user_id()).unwrap().unwrap();
    assert_eq!(user.handle, "");
    assert_eq!(user.display_name, short);
    let chat = alice.store.chat(&g).unwrap().unwrap();
    let member = chat
        .members
        .iter()
        .find(|m| m.device.user_id == bob.user_id())
        .unwrap();
    assert_eq!(member.display_name.as_deref(), Some(short.as_str()));
}
