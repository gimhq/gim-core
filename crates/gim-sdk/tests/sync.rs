//! Sync against an in-process mock gim-server: per-group seq gap backfill,
//! holes the server confirms as empty, and expired-cursor (410 / close
//! 4410) recovery.

mod mock_server;

use std::sync::atomic::Ordering;

use gim_base::StateReader;
use gim_common::GroupId;
use gim_sdk::testing::FakeTransport;
use gim_sdk::ConnectionState;
use mock_server::{fast_settings, reach_state, upserted_texts, wait_until, MockServer, Peer};

struct Setup {
    transport: FakeTransport,
    server: MockServer,
    alice: Peer,
    bob: Peer,
    group_id: GroupId,
}

/// Alice (fake transport) and Bob (HTTP against the mock server) in a
/// group chat Bob has joined.
async fn setup() -> Setup {
    let transport = FakeTransport::new();
    let server = MockServer::start(transport.clone()).await;
    let alice = Peer::fake(&transport, "alice").await;
    let bob = Peer::http(&server, "bob", fast_settings()).await;
    let group_id = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.client.sync_once().await.unwrap();
    assert!(bob.has_chat(&group_id));
    Setup {
        transport,
        server,
        alice,
        bob,
        group_id,
    }
}

impl Setup {
    /// Seq the group's next message gets.
    fn next_seq(&self) -> u64 {
        let history = self
            .transport
            .service()
            .messages(&self.group_id, 0, usize::MAX)
            .unwrap();
        history.len() as u64 + 1
    }

    fn hide(&self, seq: u64) {
        self.server
            .controls
            .hidden
            .lock()
            .unwrap()
            .insert((self.group_id.clone(), seq));
    }

    fn history_requests(&self) -> Vec<Option<u64>> {
        self.server
            .controls
            .history
            .lock()
            .unwrap()
            .iter()
            .filter(|(g, _)| *g == self.group_id)
            .map(|(_, after)| *after)
            .collect()
    }

    /// Bob's head cursor on the server.
    fn bob_head(&self) -> u64 {
        self.transport
            .service()
            .events(&self.bob.device(), 0, usize::MAX)
            .1
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seq_gap_is_backfilled_before_later_events() {
    let s = setup().await;
    let mut changes = s.bob.client.subscribe_changes();
    let first = s.next_seq();
    s.hide(first + 1);
    for text in ["m1", "m2", "m3"] {
        s.alice.send_text(&s.group_id, text).await;
    }
    s.bob.client.sync_once().await.unwrap();
    assert_eq!(s.bob.texts(&s.group_id), ["m1", "m2", "m3"]);
    assert_eq!(
        upserted_texts(&mut changes),
        ["m1", "m2", "m3"],
        "applied in seq order"
    );
    assert_eq!(s.history_requests(), [Some(first)]);

    // Nothing is missing any more.
    s.alice.send_text(&s.group_id, "m4").await;
    s.bob.client.sync_once().await.unwrap();
    assert_eq!(s.bob.texts(&s.group_id), ["m1", "m2", "m3", "m4"]);
    assert_eq!(s.history_requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hole_of_a_welcome_to_another_device_is_confirmed_once() {
    let s = setup().await;
    let carol = Peer::fake(&s.transport, "carol").await;
    s.alice
        .client
        .add_members(&s.group_id, &[carol.user_id()])
        .await
        .unwrap();
    // The Welcome to Carol takes a seq Bob never gets.
    s.alice.send_text(&s.group_id, "m1").await;
    s.bob.client.sync_once().await.unwrap();
    assert_eq!(s.bob.texts(&s.group_id), ["m1"]);
    assert_eq!(s.history_requests().len(), 1);
    let cursor = s.bob.store.group_cursor(&s.group_id).unwrap();
    assert!(cursor.ahead.is_empty(), "{cursor:?}");

    s.alice.send_text(&s.group_id, "m2").await;
    s.bob.client.sync_once().await.unwrap();
    assert_eq!(s.bob.texts(&s.group_id), ["m1", "m2"]);
    assert_eq!(
        s.history_requests().len(),
        1,
        "the hole is not looked up again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_cursor_backfills_joined_chats_and_continues_from_head() {
    let s = setup().await;
    let after = s
        .bob
        .store
        .group_cursor(&s.group_id)
        .unwrap()
        .contiguous_seq;
    s.alice.send_text(&s.group_id, "m1").await;
    s.alice.send_text(&s.group_id, "m2").await;
    s.server
        .controls
        .events_expired_below
        .store(u64::MAX, Ordering::SeqCst);
    s.bob.client.sync_once().await.unwrap();
    assert_eq!(s.bob.texts(&s.group_id), ["m1", "m2"]);
    assert_eq!(s.history_requests().first(), Some(&Some(after)));
    assert_eq!(s.bob.store.global_cursor().unwrap(), Some(s.bob_head()));

    s.server
        .controls
        .events_expired_below
        .store(0, Ordering::SeqCst);
    s.alice.send_text(&s.group_id, "m3").await;
    s.bob.client.sync_once().await.unwrap();
    assert_eq!(s.bob.texts(&s.group_id), ["m1", "m2", "m3"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_close_4410_recovers_and_reconnects() {
    let s = setup().await;
    let mut states = s.bob.client.subscribe_connection_state();
    s.bob.client.start_sync().unwrap();
    reach_state(&mut states, ConnectionState::Connected).await;

    // Pruned: these events never reach Bob; only the history has them.
    let first = s.next_seq();
    s.hide(first);
    s.hide(first + 1);
    s.alice.send_text(&s.group_id, "m1").await;
    s.alice.send_text(&s.group_id, "m2").await;
    s.server
        .controls
        .stream_expired_below
        .store(u64::MAX, Ordering::SeqCst);
    s.server.controls.kick.store(true, Ordering::SeqCst);

    reach_state(&mut states, ConnectionState::Connected).await;
    reach_state(&mut states, ConnectionState::Syncing).await;
    reach_state(&mut states, ConnectionState::Connected).await;
    wait_until("recovered messages", || s.bob.texts(&s.group_id).len() == 2).await;
    assert_eq!(s.bob.texts(&s.group_id), ["m1", "m2"]);

    s.alice.send_text(&s.group_id, "m3").await;
    wait_until("live message", || s.bob.texts(&s.group_id).len() == 3).await;
    assert_eq!(s.bob.texts(&s.group_id), ["m1", "m2", "m3"]);
    s.bob.client.stop_sync().unwrap();
}
