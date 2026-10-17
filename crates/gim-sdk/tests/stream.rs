//! The sync loop over the `/v2/stream` WebSocket and the long-poll
//! fallback, against an in-process mock hub: reconnects, connection
//! states, token rejection, suspended users and reachability.

mod mock_server;

use std::sync::atomic::Ordering;
use std::time::Duration;

use gim_sdk::testing::FakeTransport;
use gim_sdk::{ClientError, ConnectionState, SyncSettings};
use mock_server::{
    fast_settings, next_state, reach_state, recv_texts, upserted_texts, wait_until, MockServer,
    Peer,
};

use ConnectionState::{Connected, Connecting, Offline, Syncing};

struct Setup {
    transport: FakeTransport,
    server: MockServer,
    alice: Peer,
    bob: Peer,
    group_id: gim_common::GroupId,
}

/// Alice (fake transport) has a direct chat with Bob (HTTP against the
/// mock server), which Bob has not synced yet.
async fn setup(settings: SyncSettings) -> Setup {
    let transport = FakeTransport::new();
    let server = MockServer::start(transport.clone()).await;
    let alice = Peer::fake(&transport, "alice").await;
    let bob = Peer::http(&server, "bob", settings).await;
    let group_id = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    Setup {
        transport,
        server,
        alice,
        bob,
        group_id,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_after_drop_resumes_from_cursor_without_duplicates() {
    let Setup {
        server,
        alice,
        bob,
        group_id,
        ..
    } = setup(fast_settings()).await;
    let mut changes = bob.client.subscribe_changes();
    let mut states = bob.client.subscribe_connection_state();
    bob.client.start_sync().unwrap();
    reach_state(&mut states, Connected).await;
    assert!(
        bob.has_chat(&group_id),
        "the Welcome is applied while catching up"
    );

    // The stream drops mid-way; the rest comes after the reconnect. Arm the
    // drop for the second connection only once the first is served.
    server.streams_served(1).await;
    *server.controls.drop_stream_after.lock().unwrap() = Some(3);
    server.controls.kick.store(true, Ordering::SeqCst);
    reach_state(&mut states, Connected).await;
    server.streams_served(2).await;
    let expected: Vec<String> = (1..=6).map(|i| format!("m{i}")).collect();
    for text in &expected {
        alice.send_text(&group_id, text).await;
    }
    wait_until("all messages", || {
        bob.texts(&group_id).len() == expected.len()
    })
    .await;
    assert_eq!(bob.texts(&group_id), expected);
    // Changes are broadcast after the store commit: wait for them.
    assert_eq!(
        recv_texts(&mut changes, expected.len()).await,
        expected,
        "messages applied in order"
    );

    // The catch-up after the drop may deliver the rest before the third
    // connection opens.
    server.streams_served(3).await;
    let cursors = server.controls.stream_cursors.lock().unwrap().clone();
    assert!(cursors.len() >= 3, "{cursors:?}");
    assert!(cursors.iter().all(Option::is_some), "{cursors:?}");
    assert!(cursors.windows(2).all(|w| w[0] <= w[1]), "{cursors:?}");
    assert!(
        cursors[2] > cursors[1],
        "resumed after the delivered events"
    );
    bob.client.stop_sync().unwrap();
    assert_eq!(bob.client.connection_state(), Offline);
    assert_eq!(
        upserted_texts(&mut changes),
        Vec::<String>::new(),
        "each message applied once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_token_is_sent_only_in_the_authorization_header() {
    let Setup { server, bob, .. } = setup(fast_settings()).await;
    let mut states = bob.client.subscribe_connection_state();
    bob.client.start_sync().unwrap();
    reach_state(&mut states, Connected).await;
    // Reconnect, so the upgrade request carries a cursor.
    server.streams_served(1).await;
    server.controls.kick.store(true, Ordering::SeqCst);
    server.streams_served(2).await;

    let token = bob.client.session().unwrap().token;
    let requests = server.controls.stream_requests.lock().unwrap().clone();
    assert!(requests.len() >= 2, "{requests:?}");
    for (query, authorization) in &requests {
        assert_eq!(
            authorization.as_deref(),
            Some(format!("Bearer {}", token.as_str()).as_str())
        );
        let query = query.as_deref().unwrap_or_default();
        assert!(!query.contains("token"), "{query}");
        assert!(!query.contains(token.as_str()), "{query}");
    }
    assert!(requests
        .iter()
        .any(|(query, _)| query.as_deref().is_some_and(|q| q.starts_with("cursor="))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn falls_back_to_long_poll_without_stream() {
    let Setup {
        server,
        alice,
        bob,
        group_id,
        ..
    } = setup(fast_settings()).await;
    server
        .controls
        .stream_disabled
        .store(true, Ordering::SeqCst);
    let mut states = bob.client.subscribe_connection_state();
    bob.client.start_sync().unwrap();
    reach_state(&mut states, Connected).await;
    alice.send_text(&group_id, "hello").await;
    alice.send_text(&group_id, "again").await;
    wait_until("long-polled messages", || bob.texts(&group_id).len() == 2).await;
    assert_eq!(bob.texts(&group_id), ["hello", "again"]);
    let polls = server.controls.polls.lock().unwrap().clone();
    assert!(polls.iter().any(|(_, wait)| *wait == Some(1)), "{polls:?}");
    assert!(server.controls.stream_cursors.lock().unwrap().is_empty());
    bob.client.stop_sync().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_states_and_token_rejection() {
    let Setup { server, bob, .. } = setup(fast_settings()).await;
    let mut states = bob.client.subscribe_connection_state();
    assert_eq!(bob.client.connection_state(), Offline);
    bob.client.start_sync().unwrap();
    for expected in [Connecting, Syncing, Connected] {
        assert_eq!(next_state(&mut states).await, expected);
    }

    server.streams_served(1).await;
    server.controls.kick.store(true, Ordering::SeqCst);
    for expected in [Offline, Connecting, Syncing, Connected] {
        assert_eq!(next_state(&mut states).await, expected);
    }

    // Close code 4401, and the hub refuses the sign-in (device_not_active):
    // the loop stops and the client is signed out.
    server.streams_served(2).await;
    server.controls.reject.store(true, Ordering::SeqCst);
    assert_eq!(next_state(&mut states).await, Offline);
    wait_until("sync loop ended", || !bob.client.is_sync_running()).await;
    assert!(matches!(
        bob.client.stop_sync(),
        Err(ClientError::DeviceNotActive(_))
    ));
    assert_eq!(bob.client.connection_state(), Offline);
    assert_eq!(bob.client.session(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspended_user_gets_user_suspended_after_one_sign_in() {
    let Setup {
        transport,
        server,
        bob,
        ..
    } = setup(fast_settings()).await;
    bob.client.sync_once().await.unwrap();
    let hub_id = transport.service().hub_id().to_string();
    let challenges = || server.controls.challenges.load(Ordering::SeqCst);
    let before = challenges();

    // The suspension deletes the session: the call gets 401, the sign-in
    // 403 `user_suspended`, which the caller gets.
    server.controls.suspended.store(true, Ordering::SeqCst);
    let result = bob.client.sync_once().await;
    assert!(
        matches!(&result, Err(ClientError::UserSuspended { hub_id: h }) if *h == hub_id),
        "{result:?}"
    );
    assert_eq!(challenges(), before + 1);
    // The session is kept, and the next calls do not sign in again.
    assert!(bob.client.session().is_some());
    let requests = server.controls.requests.load(Ordering::SeqCst);
    for _ in 0..3 {
        let result = bob.client.sync_once().await;
        assert!(
            matches!(result, Err(ClientError::UserSuspended { .. })),
            "{result:?}"
        );
    }
    assert_eq!(challenges(), before + 1);
    assert_eq!(server.controls.requests.load(Ordering::SeqCst), requests);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_loop_of_a_suspended_user_settles_without_reconnecting() {
    let Setup { server, bob, .. } = setup(fast_settings()).await;
    let mut states = bob.client.subscribe_connection_state();
    bob.client.start_sync().unwrap();
    reach_state(&mut states, Connected).await;
    server.streams_served(1).await;
    let before = server.controls.challenges.load(Ordering::SeqCst);

    // Close 4401, then the sign-in answers `user_suspended`: the loop goes
    // offline and stays there, without signing in again.
    server.controls.suspended.store(true, Ordering::SeqCst);
    reach_state(&mut states, Offline).await;
    let requests = server.controls.requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        server.controls.challenges.load(Ordering::SeqCst),
        before + 1
    );
    let during = server.controls.requests.load(Ordering::SeqCst) - requests;
    assert!(during <= 2, "{during} requests while suspended");
    assert_eq!(bob.client.connection_state(), Offline);
    // Not stopped: it tries again after the suspension wait.
    assert!(bob.client.is_sync_running());
    assert!(bob.client.session().is_some());
    bob.client.stop_sync().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_stream_session_signs_in_again_and_reconnects() {
    let Setup {
        transport,
        server,
        alice,
        bob,
        group_id,
    } = setup(fast_settings()).await;
    let mut states = bob.client.subscribe_connection_state();
    bob.client.start_sync().unwrap();
    reach_state(&mut states, Connected).await;
    server.streams_served(1).await;
    let before = bob.client.session().unwrap();

    // The hub drops the session: the stream closes with 4401, the client
    // signs in again and reconnects.
    transport.service().expire_sessions(&before.device);
    reach_state(&mut states, Connected).await;
    server.streams_served(2).await;
    let after = bob.client.session().unwrap();
    assert_ne!(after.token, before.token);
    assert!(bob.client.is_sync_running());

    alice.send_text(&group_id, "after re-sign-in").await;
    wait_until("live message", || {
        bob.texts(&group_id) == ["after re-sign-in"]
    })
    .await;
    bob.client.stop_sync().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reachability_cuts_the_reconnect_backoff_short() {
    let settings = SyncSettings {
        backoff_min: Duration::from_secs(30),
        backoff_max: Duration::from_secs(60),
        ..fast_settings()
    };
    let Setup { server, bob, .. } = setup(settings).await;
    let mut states = bob.client.subscribe_connection_state();
    bob.client.start_sync().unwrap();
    reach_state(&mut states, Connected).await;
    server.streams_served(1).await;
    server.controls.kick.store(true, Ordering::SeqCst);
    reach_state(&mut states, Offline).await;
    bob.client.network_reachable();
    tokio::time::timeout(Duration::from_secs(5), reach_state(&mut states, Connected))
        .await
        .expect("reconnected without waiting for the backoff");
    bob.client.stop_sync().unwrap();
}
