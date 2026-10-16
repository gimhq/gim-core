//! Push (contract `push.md`): the registration goes to every listed hub
//! (also hubs added later, and again after a 401 renewal) and is removed
//! from all of them; `process_push` turns every payload shape of §3 into
//! notification content through the sync apply path, so the stream does
//! not apply a pushed message again. Inline MLS bytes from the (untrusted)
//! push relay are never applied: the message is fetched from the hub.

mod mock_server;

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use gim_base::model::{MembershipChangeKind, StateChange};
use gim_base::{MemoryStore, StateReader};
use gim_common::GroupId;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{Transport, TransportError};
use gim_sdk::{
    Client, ClientBuilder, ClientError, HubConnector, NotificationKind, PushRegistration,
    SecretStorage, GENERIC_BODY,
};
use gim_test::{Delivered, MessageKind};
use mock_server::{fast_settings, wait_until, MockServer, Peer};
use serde_json::json;

const SEED_B: [u8; 32] = [0x62; 32];
const A_URL: &str = "https://hub-a.example.eu";
const B_URL: &str = "https://hub-b.example.eu";

fn registration(token: &str) -> PushRegistration {
    PushRegistration {
        provider: "apns".into(),
        token: token.into(),
        app_id: Some("im.g.apps".into()),
        sandbox: Some(false),
        p256dh: None,
        auth: None,
    }
}

/// A connector over fake hubs by URL.
fn connector(hubs: &[(&str, &FakeTransport)]) -> HubConnector {
    let hubs: HashMap<String, FakeTransport> = hubs
        .iter()
        .map(|(url, hub)| ((*url).to_string(), (*hub).clone()))
        .collect();
    Arc::new(move |url: &str| {
        hubs.get(url)
            .map(|hub| Arc::new(hub.clone()) as Arc<dyn Transport>)
            .ok_or_else(|| TransportError::Network(format!("no hub at {url}")))
    })
}

/// Alice on hub A, which may connect to hub B.
fn alice_client(
    hub_a: &FakeTransport,
    hub_b: &FakeTransport,
) -> (Client<MemoryStore>, tempfile::TempDir) {
    let data_dir = tempfile::tempdir().unwrap();
    let client = ClientBuilder::new(
        Arc::new(MemoryStore::new()),
        Arc::new(hub_a.clone()),
        Arc::new(MemorySecretStorage::new()) as Arc<dyn SecretStorage>,
    )
    .hub_connector(connector(&[(A_URL, hub_a), (B_URL, hub_b)]))
    .data_dir(data_dir.path())
    .sync_settings(fast_settings())
    .build()
    .unwrap();
    (client, data_dir)
}

fn puts(hub: &FakeTransport) -> usize {
    hub.push_requests()
        .iter()
        .filter(|(_, r)| r.is_some())
        .count()
}

/// The message payload of `push.md` §3 for `delivered`, with or without
/// the inline MLS message.
fn message_payload(delivered: &Delivered, inline: bool) -> String {
    let message_id = format!("{:032x}", delivered.seq);
    let mut payload = json!({
        "v": 1,
        "type": "message",
        "gid": delivered.group_id.as_str(),
        "seq": delivered.seq,
        "message_id": message_id,
        "collapse_id": message_id,
    });
    if inline {
        payload["mls_message"] = STANDARD.encode(&delivered.payload).into();
    }
    payload.to_string()
}

fn target_payload(kind: &str, group_id: &GroupId, seq: u64) -> String {
    let message_id = format!("{seq:032x}");
    json!({
        "v": 1,
        "type": kind,
        "gid": group_id.as_str(),
        "seq": seq,
        "message_id": message_id,
        "collapse_id": message_id,
    })
    .to_string()
}

/// The group's latest message of `kind` on the hub.
fn latest(hub: &FakeTransport, group_id: &GroupId, kind: MessageKind) -> Delivered {
    hub.service()
        .messages(group_id, 0, usize::MAX)
        .unwrap()
        .into_iter()
        .rfind(|m| m.kind == kind)
        .expect("a message of that kind")
}

/// Alice and Bob on one fake hub in a direct chat Alice joined.
async fn direct_chat(hub: &FakeTransport) -> (Peer, Peer, GroupId) {
    let alice = Peer::fake(hub, "alice").await;
    let bob = Peer::fake(hub, "bob").await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.client.sync_once().await.unwrap();
    assert!(alice.has_chat(&group_id));
    (alice, bob, group_id)
}

fn upserted_texts(changes: &[StateChange]) -> Vec<String> {
    changes
        .iter()
        .filter_map(|change| match change {
            StateChange::MessageUpserted(m) => match &m.content {
                gim_base::model::MessageContent::Text { body } => Some(body.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_reaches_every_hub_and_is_renewed_and_removed() {
    let hub_a = FakeTransport::new().with_public_url(A_URL);
    let hub_b = FakeTransport::with_hub_seed(SEED_B).with_public_url(B_URL);
    let (alice, _dir) = alice_client(&hub_a, &hub_b);
    alice.register("alice", "Alice").await.unwrap();
    let device = alice.session().unwrap().device;

    // Malformed: refused before anything is stored or sent.
    let bad = PushRegistration {
        provider: "APNs".into(),
        ..registration("t")
    };
    assert!(matches!(
        alice.register_push(bad).await,
        Err(ClientError::InvalidInput(_))
    ));
    assert_eq!(alice.push_registration().unwrap(), None);
    assert!(hub_a.push_requests().is_empty());

    alice.register_push(registration("token-1")).await.unwrap();
    assert_eq!(
        hub_a.push_registration(&device),
        Some(registration("token-1"))
    );
    assert_eq!(
        alice.push_registration().unwrap(),
        Some(registration("token-1"))
    );

    // A hub added later gets it from the sync loop.
    alice.start_sync().unwrap();
    alice.add_hub(B_URL).await.unwrap();
    wait_until("registration on the added hub", || {
        hub_b.push_registration(&device) == Some(registration("token-1"))
    })
    .await;
    // A new token goes to both hubs at once.
    alice.register_push(registration("token-2")).await.unwrap();
    assert_eq!(
        hub_a.push_registration(&device),
        Some(registration("token-2"))
    );
    assert_eq!(
        hub_b.push_registration(&device),
        Some(registration("token-2"))
    );

    // The hubs reject the sessions: the sync loops sign in again (401
    // renewal) and put the registration again.
    for hub in [&hub_a, &hub_b] {
        let before = puts(hub);
        hub.service().expire_sessions(&device);
        wait_until("registration after the renewal", || puts(hub) > before).await;
        assert_eq!(
            hub.push_registration(&device),
            Some(registration("token-2"))
        );
    }

    alice.unregister_push().await.unwrap();
    for hub in [&hub_a, &hub_b] {
        assert_eq!(hub.push_registration(&device), None);
        assert_eq!(hub.push_requests().last(), Some(&(device.clone(), None)));
    }
    assert_eq!(alice.push_registration().unwrap(), None);
    alice.stop_sync().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_stored_before_onboarding_reaches_the_hub_after_it() {
    let hub_a = FakeTransport::new().with_public_url(A_URL);
    let hub_b = FakeTransport::with_hub_seed(SEED_B).with_public_url(B_URL);
    let (alice, _dir) = alice_client(&hub_a, &hub_b);
    alice.register_push(registration("early")).await.unwrap();
    assert!(hub_a.push_requests().is_empty());

    alice.register("alice", "Alice").await.unwrap();
    alice.start_sync().unwrap();
    let device = alice.session().unwrap().device;
    wait_until("registration after onboarding", || {
        hub_a.push_registration(&device) == Some(registration("early"))
    })
    .await;
    alice.stop_sync().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushed_message_is_applied_once_whoever_delivers_it_first() {
    let hub = FakeTransport::new();
    let (alice, bob, group_id) = direct_chat(&hub).await;

    let id = bob.send_text(&group_id, "Fair winds from Split").await;
    let delivered = latest(&hub, &group_id, MessageKind::Application);
    let payload = message_payload(&delivered, true);
    let content = alice.client.process_push(&payload).await.unwrap();
    assert_eq!(content.kind, NotificationKind::Message);
    assert_eq!(content.body, "Fair winds from Split");
    assert!(content.should_display);
    assert_eq!(content.chat_id.as_ref(), Some(&group_id));
    assert_eq!(content.chat_title.as_deref(), Some("bob"));
    assert_eq!(content.sender_user_id, Some(bob.user_id()));
    assert_eq!(content.sender_display_name.as_deref(), Some("bob"));
    assert_eq!(content.message_id.as_ref(), Some(&id));
    assert_eq!(content.collapse_id, Some(format!("{:032x}", delivered.seq)));
    assert_eq!(alice.texts(&group_id), ["Fair winds from Split"]);

    // The stream delivers it later: not applied again.
    let changes = alice.client.sync_once().await.unwrap();
    assert!(upserted_texts(&changes).is_empty(), "{changes:?}");
    assert_eq!(alice.texts(&group_id), ["Fair winds from Split"]);
    // The same push from another hub: the same content, nothing applied.
    let again = alice.client.process_push(&payload).await.unwrap();
    assert_eq!(again.message_id, content.message_id);
    assert_eq!(again.body, content.body);
    assert_eq!(alice.texts(&group_id), ["Fair winds from Split"]);

    // The stream first: the push describes the stored message.
    bob.send_text(&group_id, "Anchored off Hvar").await;
    alice.client.sync_once().await.unwrap();
    let delivered = latest(&hub, &group_id, MessageKind::Application);
    let content = alice
        .client
        .process_push(&message_payload(&delivered, true))
        .await
        .unwrap();
    assert_eq!(content.body, "Anchored off Hvar");
    assert!(content.should_display);
    assert_eq!(alice.texts(&group_id).len(), 2);
    // Read meanwhile: nothing to show.
    alice.client.mark_read(&group_id).await.unwrap();
    let content = alice
        .client
        .process_push(&message_payload(&delivered, true))
        .await
        .unwrap();
    assert!(!content.should_display);

    // A reaction shows as one; an edit is silent.
    bob.client.react(&group_id, &id, "⛵").await.unwrap();
    let delivered = latest(&hub, &group_id, MessageKind::Application);
    let content = alice
        .client
        .process_push(&message_payload(&delivered, true))
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Reaction);
    assert_eq!(content.body, "reacted ⛵");
    assert_eq!(content.sender_user_id, Some(bob.user_id()));
    assert!(content.should_display);
    let reply = bob.send_text(&group_id, "typo").await;
    alice.client.sync_once().await.unwrap();
    bob.client.edit(&group_id, &reply, "fixed").await.unwrap();
    let delivered = latest(&hub, &group_id, MessageKind::Application);
    let content = alice
        .client
        .process_push(&message_payload(&delivered, true))
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Message);
    assert!(!content.should_display);
    assert!(alice.texts(&group_id).contains(&"fixed".to_string()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn message_without_inline_bytes_is_fetched_by_seq_over_http() {
    let hub = FakeTransport::new();
    let server = MockServer::start(hub.clone()).await;
    let alice = Peer::http(&server, "alice", fast_settings()).await;
    let bob = Peer::fake(&hub, "bob").await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.client.sync_once().await.unwrap();

    // Registration over HTTP.
    alice
        .client
        .register_push(registration("http-token"))
        .await
        .unwrap();
    assert_eq!(
        hub.push_registration(&alice.device()),
        Some(registration("http-token"))
    );

    bob.send_text(&group_id, "Meet at Korčula").await;
    let delivered = latest(&hub, &group_id, MessageKind::Application);
    server.controls.history.lock().unwrap().clear();
    let content = alice
        .client
        .process_push(&message_payload(&delivered, false))
        .await
        .unwrap();
    assert_eq!(content.body, "Meet at Korčula");
    assert!(content.should_display);
    let history = server.controls.history.lock().unwrap().clone();
    assert_eq!(history, [(group_id.clone(), Some(delivered.seq - 1))]);
    assert_eq!(alice.texts(&group_id), ["Meet at Korčula"]);
    let changes = alice.client.sync_once().await.unwrap();
    assert!(upserted_texts(&changes).is_empty(), "{changes:?}");

    alice.client.unregister_push().await.unwrap();
    assert_eq!(hub.push_registration(&alice.device()), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn welcome_push_joins_through_the_pending_welcomes() {
    let hub = FakeTransport::new();
    let alice = Peer::fake(&hub, "alice").await;
    let bob = Peer::fake(&hub, "bob").await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    let welcome = hub
        .service()
        .pending_welcomes(&alice.device(), 10)
        .pop()
        .unwrap();

    let payload = target_payload("welcome", &group_id, welcome.seq);
    let content = alice.client.process_push(&payload).await.unwrap();
    assert_eq!(content.kind, NotificationKind::Invite);
    assert!(content.should_display);
    assert_eq!(content.chat_id.as_ref(), Some(&group_id));
    assert_eq!(content.sender_user_id, Some(bob.user_id()));
    assert_eq!(content.sender_display_name.as_deref(), Some("bob"));
    assert!(alice.has_chat(&group_id));
    assert!(hub
        .service()
        .pending_welcomes(&alice.device(), 10)
        .is_empty());

    // The stream's Welcome event is not joined again.
    let changes = alice.client.sync_once().await.unwrap();
    let joined = changes.iter().any(|change| {
        matches!(change, StateChange::MembershipChanged(e)
            if e.user_id == alice.user_id() && e.kind == MembershipChangeKind::Added)
    });
    assert!(!joined, "{changes:?}");
    bob.send_text(&group_id, "Welcome aboard").await;
    alice.client.sync_once().await.unwrap();
    assert!(alice
        .texts(&group_id)
        .contains(&"Welcome aboard".to_string()));
}

/// The hub keeps one pending push per device: the Welcome and the
/// creator's display name announcement right after it reach Alice as one
/// push for the announcement, in a chat she has not joined. The push joins
/// through the pending Welcomes and shows the invite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coalesced_welcome_push_joins_and_shows_the_invite() {
    let hub = FakeTransport::new();
    let alice = Peer::fake(&hub, "alice").await;
    let bob = Peer::fake(&hub, "bob").await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    let announcement = latest(&hub, &group_id, MessageKind::Application);
    assert!(!alice.has_chat(&group_id));

    let payload = message_payload(&announcement, false);
    let content = alice.client.process_push(&payload).await.unwrap();
    assert_eq!(content.kind, NotificationKind::Invite, "{content:?}");
    assert!(content.should_display);
    assert_eq!(content.chat_id.as_ref(), Some(&group_id));
    assert_eq!(content.sender_user_id, Some(bob.user_id()));
    assert!(alice.has_chat(&group_id));
    assert!(hub
        .service()
        .pending_welcomes(&alice.device(), 10)
        .is_empty());

    // The same push again describes the stored announcement: silent.
    let again = alice.client.process_push(&payload).await.unwrap();
    assert!(!again.should_display, "{again:?}");
    alice.client.sync_once().await.unwrap();
    bob.send_text(&group_id, "Welcome aboard").await;
    alice.client.sync_once().await.unwrap();
    assert_eq!(alice.texts(&group_id), ["Welcome aboard"]);
}

/// A text pushed in a chat not joined yet (its Welcome push coalesced into
/// it) joins the chat and shows the text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_push_in_a_chat_not_joined_yet_joins_and_shows_it() {
    let hub = FakeTransport::new();
    let alice = Peer::fake(&hub, "alice").await;
    let bob = Peer::fake(&hub, "bob").await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    bob.send_text(&group_id, "Anchored off Hvar").await;
    let text = latest(&hub, &group_id, MessageKind::Application);

    let content = alice
        .client
        .process_push(&message_payload(&text, false))
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Message, "{content:?}");
    assert!(content.should_display);
    assert_eq!(content.body, "Anchored off Hvar");
    assert_eq!(content.sender_user_id, Some(bob.user_id()));
    assert!(alice.has_chat(&group_id));
    alice.client.sync_once().await.unwrap();
    assert_eq!(alice.texts(&group_id), ["Anchored off Hvar"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_up_reads_the_events_without_moving_the_cursor() {
    let hub = FakeTransport::new();
    let (alice, bob, group_id) = direct_chat(&hub).await;
    bob.send_text(&group_id, "Wind picking up").await;

    // Minimal mode (`push.md` §3).
    let wake = r#"{"v": 1, "type": "wake", "collapse_id": "0f1e2d3c4b5a69788796a5b4c3d2e1f0"}"#;
    let content = alice.client.process_push(wake).await.unwrap();
    assert_eq!(content.kind, NotificationKind::Message);
    assert_eq!(content.body, "Wind picking up");
    assert!(content.should_display);
    assert_eq!(
        content.collapse_id.as_deref(),
        Some("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    );
    assert_eq!(alice.texts(&group_id), ["Wind picking up"]);

    // Nothing new: silent. Unknown types and versions wake up the same way.
    alice.client.mark_read(&group_id).await.unwrap();
    for payload in [
        wake,
        r#"{"v":2,"type":"message"}"#,
        r#"{"v":1,"type":"future"}"#,
    ] {
        let content = alice.client.process_push(payload).await.unwrap();
        assert_eq!(content.kind, NotificationKind::Generic, "{payload}");
        assert!(!content.should_display, "{payload}");
    }
    // The stream reads the events again; nothing is applied twice.
    let changes = alice.client.sync_once().await.unwrap();
    assert!(upserted_texts(&changes).is_empty(), "{changes:?}");
    assert_eq!(alice.texts(&group_id), ["Wind picking up"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_is_invalid_and_undecryptable_gives_generic_content() {
    let hub = FakeTransport::new();
    let (alice, bob, group_id) = direct_chat(&hub).await;
    for garbage in ["", "not json", "[1, 2]", "\"message\""] {
        assert!(
            matches!(
                alice.client.process_push(garbage).await,
                Err(ClientError::InvalidInput(_))
            ),
            "{garbage:?}"
        );
    }

    bob.send_text(&group_id, "Real one").await;
    alice.client.sync_once().await.unwrap();
    let real = latest(&hub, &group_id, MessageKind::Application);
    // Corrupted inline bytes at the next seq, not on the hub yet: generic
    // content, and the seq is not taken.
    let mut corrupted = real.clone();
    corrupted.seq += 1;
    let last = corrupted.payload.len() - 1;
    corrupted.payload[last] ^= 0xff;
    let content = alice
        .client
        .process_push(&message_payload(&corrupted, true))
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Generic);
    assert_eq!(content.body, GENERIC_BODY);
    assert!(content.should_display);
    assert_eq!(content.chat_id.as_ref(), Some(&group_id));
    assert_eq!(content.sender_user_id, None);
    assert_eq!(alice.texts(&group_id), ["Real one"]);

    // The real message lands at that seq: the same corrupted push now
    // shows it (fetched from the hub) ...
    bob.send_text(&group_id, "Second").await;
    assert_eq!(
        latest(&hub, &group_id, MessageKind::Application).seq,
        corrupted.seq
    );
    let content = alice
        .client
        .process_push(&message_payload(&corrupted, true))
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Message);
    assert_eq!(content.body, "Second");
    assert_eq!(alice.texts(&group_id), ["Real one", "Second"]);
    // ... and a third one, pushed corrupted, still reaches the stream.
    bob.send_text(&group_id, "Third").await;
    let mut third = latest(&hub, &group_id, MessageKind::Application);
    third.payload = vec![0, 1, 0, 2, 0xde, 0xad];
    let _ = alice
        .client
        .process_push(&message_payload(&third, true))
        .await
        .unwrap();
    alice.client.sync_once().await.unwrap();
    assert_eq!(alice.texts(&group_id), ["Real one", "Second", "Third"]);

    // A message the hub does not have.
    let missing = target_payload("message", &group_id, third.seq + 1);
    let content = alice.client.process_push(&missing).await.unwrap();
    assert_eq!(content.kind, NotificationKind::Generic);
    assert!(content.should_display);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replayed_ciphertext_under_a_new_seq_is_not_applied() {
    let hub = FakeTransport::new();
    let (alice, bob, group_id) = direct_chat(&hub).await;
    bob.send_text(&group_id, "Departing Valletta").await;
    let old = latest(&hub, &group_id, MessageKind::Application);
    alice.client.sync_once().await.unwrap();

    // The relay replays the old ciphertext under seqs the hub has not
    // assigned yet: nothing is applied and the seqs stay free.
    let mut replay = old.clone();
    replay.seq = old.seq + 1;
    let content = alice
        .client
        .process_push(&message_payload(&replay, true))
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Generic);
    assert_eq!(alice.texts(&group_id), ["Departing Valletta"]);

    // The hub assigns that seq to a new message: the replayed push shows
    // and applies the hub's message, not the old ciphertext.
    bob.send_text(&group_id, "Arrived in Syracuse").await;
    assert_eq!(
        latest(&hub, &group_id, MessageKind::Application).seq,
        replay.seq
    );
    let content = alice
        .client
        .process_push(&message_payload(&replay, true))
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Message);
    assert_eq!(content.body, "Arrived in Syracuse");
    alice.client.sync_once().await.unwrap();
    assert_eq!(
        alice.texts(&group_id),
        ["Departing Valletta", "Arrived in Syracuse"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn membership_push_catches_the_group_up_silently() {
    let hub = FakeTransport::new();
    let alice = Peer::fake(&hub, "alice").await;
    let bob = Peer::fake(&hub, "bob").await;
    let carol = Peer::fake(&hub, "carol").await;
    let group_id = bob
        .client
        .create_group_chat(Some("Regatta".into()), &[alice.user_id()])
        .await
        .unwrap();
    alice.client.sync_once().await.unwrap();
    bob.client
        .add_members(&group_id, &[carol.user_id()])
        .await
        .unwrap();
    let commit = latest(&hub, &group_id, MessageKind::Commit);

    let payload = target_payload("group.member_added", &group_id, commit.seq);
    let content = alice.client.process_push(&payload).await.unwrap();
    assert_eq!(content.kind, NotificationKind::Membership);
    assert!(!content.should_display);
    assert_eq!(content.chat_title.as_deref(), Some("Regatta"));
    let chat = alice.store.chat(&group_id).unwrap().unwrap();
    assert!(
        chat.members.iter().any(|m| m.device == carol.device()),
        "{chat:?}"
    );
}
