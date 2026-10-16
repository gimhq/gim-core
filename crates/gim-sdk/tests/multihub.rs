//! The multi-hub receive path (contract `multihoming.md` §2.2, §4.4, §6.3):
//! a multi-homed device follows every listed hub with its own cursor, the
//! same message delivered by several hubs is applied once, a Welcome is
//! joined once and acknowledged on every hub, and a 410 is recovered per
//! hub. Hub A (home) owns the groups; hub B is a replica of A over HTTP.

mod mock_server;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use gim_base::model::{MembershipChangeKind, MessageContent, StateChange};
use gim_base::{MemoryStore, StateReader};
use gim_common::{now_ms, DeviceRef, GroupId, UserId};
use gim_identity::{HostingEntry, RootKey, UserHostingRecord};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::Transport;
use gim_sdk::{
    Client, ClientBuilder, HttpTransport, SecretStorage, HOSTING_RECORD_LIFETIME,
    ROOT_KEY_SECRET_KEY,
};
use mock_server::{fast_settings, wait_until, MockServer, Peer};
use tempfile::TempDir;

const SEED_B: [u8; 32] = [0x62; 32];

/// Alice, over HTTP, with her home hub A and the listed hub B.
struct Alice {
    client: Client<MemoryStore>,
    store: Arc<MemoryStore>,
    secrets: Arc<MemorySecretStorage>,
    url: String,
    data_dir: TempDir,
}

impl Alice {
    fn build(&self) -> Client<MemoryStore> {
        build(&self.store, &self.secrets, &self.url, &self.data_dir)
    }

    /// A new client over the same store and secrets.
    async fn restart(&mut self) {
        self.client.stop_sync().unwrap();
        self.client = self.build();
        assert!(self.client.restore_session().await.unwrap());
    }

    fn device(&self) -> DeviceRef {
        self.client.session().unwrap().device
    }

    fn user_id(&self) -> UserId {
        self.device().user_id
    }

    fn root(&self) -> RootKey {
        let seed = self.secrets.get(ROOT_KEY_SECRET_KEY).unwrap().unwrap();
        RootKey::from_seed(&seed.try_into().unwrap())
    }

    fn texts(&self, group_id: &GroupId) -> Vec<String> {
        self.store
            .messages(group_id, None, usize::MAX)
            .unwrap()
            .into_iter()
            .filter_map(|m| match m.content {
                MessageContent::Text { body } => Some(body),
                _ => None,
            })
            .collect()
    }
}

fn build(
    store: &Arc<MemoryStore>,
    secrets: &Arc<MemorySecretStorage>,
    url: &str,
    data_dir: &TempDir,
) -> Client<MemoryStore> {
    let transport = HttpTransport::new(url.parse().unwrap()).unwrap();
    ClientBuilder::new(
        store.clone(),
        Arc::new(transport),
        secrets.clone() as Arc<dyn SecretStorage>,
    )
    .data_dir(data_dir.path())
    .sync_settings(fast_settings())
    .build()
    .unwrap()
}

struct Setup {
    hub_a: FakeTransport,
    hub_b: FakeTransport,
    server_a: MockServer,
    server_b: MockServer,
    alice: Alice,
    bob: Peer,
}

/// Alice is multi-homed on A (home, priority 0) and B (priority 1), signed
/// in on both; Bob is on A.
async fn setup() -> Setup {
    let hub_a = FakeTransport::new();
    let hub_b = FakeTransport::with_hub_seed(SEED_B);
    let server_a = MockServer::start(hub_a.clone()).await;
    let server_b = MockServer::replica(hub_b.clone(), hub_a.clone()).await;
    let store = Arc::new(MemoryStore::new());
    let secrets = Arc::new(MemorySecretStorage::new());
    let data_dir = tempfile::tempdir().unwrap();
    let client = build(&store, &secrets, &server_a.url, &data_dir);
    client.register("alice", "Alice").await.unwrap();
    let alice = Alice {
        client,
        store,
        secrets,
        url: server_a.url.clone(),
        data_dir,
    };

    // The add-hub procedure: the DeviceList on B, a record listing both.
    let user_id = alice.user_id();
    let list = hub_a.service().device_list(&user_id).unwrap();
    hub_b.put_device_list(&user_id, list).await.unwrap();
    let root = alice.root();
    let entries = [(&hub_a, 0), (&hub_b, 1)]
        .iter()
        .map(|(hub, priority)| HostingEntry::sign(hub.hub_root_key(), &user_id, *priority))
        .collect();
    let expires_at = now_ms() + HOSTING_RECORD_LIFETIME.as_millis() as u64;
    let record = UserHostingRecord::new(root.public(), 2, expires_at, entries)
        .and_then(|record| record.sign(&root))
        .unwrap()
        .to_bytes();
    hub_a.set_hosting_record(&user_id, Some(record));
    alice.client.refresh_hubs().await.unwrap();
    alice
        .client
        .set_hub_url(&hub_id(&hub_b), &server_b.url)
        .await
        .unwrap();
    let hubs = alice.client.hubs().await.unwrap();
    assert!(hubs.iter().all(|h| h.signed_in), "{hubs:?}");

    let bob = Peer::fake(&hub_a, "bob").await;
    Setup {
        hub_a,
        hub_b,
        server_a,
        server_b,
        alice,
        bob,
    }
}

fn hub_id(hub: &FakeTransport) -> String {
    hub.service().hub_id().to_string()
}

fn texts(changes: &[StateChange]) -> Vec<String> {
    changes
        .iter()
        .filter_map(|change| match change {
            StateChange::MessageUpserted(m) => match &m.content {
                MessageContent::Text { body } => Some(body.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn joins(changes: &[StateChange], user_id: &UserId) -> usize {
    changes
        .iter()
        .filter(|change| {
            matches!(change, StateChange::MembershipChanged(event)
                if &event.user_id == user_id && event.kind == MembershipChangeKind::Added)
        })
        .count()
}

fn polls(server: &MockServer) -> Vec<Option<u64>> {
    let polls = server.controls.polls.lock().unwrap();
    polls.iter().map(|(cursor, _)| *cursor).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn welcome_pending_on_both_hubs_is_joined_once_and_acked_on_both() {
    let Setup {
        hub_a,
        hub_b,
        server_a,
        server_b,
        alice,
        bob,
    } = setup().await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();

    let changes = alice.client.sync_once().await.unwrap();
    assert_eq!(joins(&changes, &alice.user_id()), 1, "{changes:?}");
    assert_eq!(alice.store.chats().unwrap().len(), 1);
    let device = alice.device();
    assert!(server_a.controls.acked(&device, &group_id));
    assert!(server_b.controls.acked(&device, &group_id));
    assert!(hub_a.service().pending_welcomes(&device, 10).is_empty());
    // Both hubs were read, each from its own cursor.
    assert!(alice.store.global_cursor().unwrap().is_some());
    assert!(alice.store.hub_cursor(&hub_id(&hub_b)).unwrap().is_some());
    assert!(alice.store.hub_cursor(&hub_id(&hub_a)).unwrap().is_none());

    // Nothing is joined again.
    let changes = alice.client.sync_once().await.unwrap();
    assert_eq!(joins(&changes, &alice.user_id()), 0, "{changes:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_message_from_both_hubs_is_applied_once() {
    let Setup {
        server_a,
        server_b,
        alice,
        bob,
        ..
    } = setup().await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.client.sync_once().await.unwrap();
    let mut broadcast = alice.client.subscribe_changes();

    bob.send_text(&group_id, "hello").await;
    let changes = alice.client.sync_once().await.unwrap();
    assert_eq!(texts(&changes), ["hello"]);
    assert_eq!(alice.texts(&group_id), ["hello"]);
    let mut upserted = Vec::new();
    while let Ok(change) = broadcast.try_recv() {
        upserted.push(change);
    }
    assert_eq!(texts(&upserted), ["hello"], "broadcast once");
    // Both hubs delivered it.
    assert!(polls(&server_a).len() >= 2);
    assert!(polls(&server_b).len() >= 2);

    // The background loops agree.
    alice.client.start_sync().unwrap();
    bob.send_text(&group_id, "again").await;
    wait_until("the second message", || alice.texts(&group_id).len() == 2).await;
    server_b.streams_served(1).await;
    bob.send_text(&group_id, "third").await;
    wait_until("the third message", || alice.texts(&group_id).len() == 3).await;
    alice.client.stop_sync().unwrap();
    assert_eq!(alice.texts(&group_id), ["hello", "again", "third"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn message_only_on_hub_b_is_delivered_while_home_is_down() {
    let Setup {
        server_a,
        server_b: _server_b,
        alice,
        bob,
        ..
    } = setup().await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.client.start_sync().unwrap();
    wait_until("the chat", || {
        alice.store.chat(&group_id).unwrap().is_some()
    })
    .await;

    server_a.controls.down.store(true, Ordering::SeqCst);
    bob.send_text(&group_id, "via B").await;
    wait_until("the message from B", || alice.texts(&group_id) == ["via B"]).await;
    assert!(alice.client.is_sync_running());

    // Home comes back: nothing is applied twice.
    server_a.controls.down.store(false, Ordering::SeqCst);
    bob.send_text(&group_id, "both up").await;
    wait_until("the next message", || alice.texts(&group_id).len() == 2).await;
    alice.client.stop_sync().unwrap();
    assert_eq!(alice.texts(&group_id), ["via B", "both up"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_cursor_on_one_hub_recovers_while_the_other_keeps_flowing() {
    let Setup {
        hub_b,
        server_a,
        server_b,
        alice,
        bob,
        ..
    } = setup().await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.client.start_sync().unwrap();
    server_a.streams_served(1).await;
    server_b.streams_served(1).await;
    let b = hub_id(&hub_b);
    wait_until("B caught up", || {
        alice.store.hub_cursor(&b).unwrap().is_some()
            && alice.store.chat(&group_id).unwrap().is_some()
    })
    .await;

    // B's cursor expires; B's stream drops and its catch-up gets a 410.
    let cursor = alice.store.hub_cursor(&b).unwrap().unwrap();
    server_b
        .controls
        .events_expired_below
        .store(cursor + 1, Ordering::SeqCst);
    bob.send_text(&group_id, "during recovery").await;
    server_b.controls.kick.store(true, Ordering::SeqCst);
    wait_until("the message", || {
        alice.texts(&group_id) == ["during recovery"]
    })
    .await;
    wait_until("B recovered", || {
        server_b.controls.expired_served.load(Ordering::SeqCst) == 1
            && alice.store.hub_cursor(&b).unwrap().unwrap() > cursor
    })
    .await;
    server_b.streams_served(2).await;

    // A was not disturbed and both keep flowing.
    assert_eq!(server_a.controls.streams_served.load(Ordering::SeqCst), 1);
    assert_eq!(server_a.controls.expired_served.load(Ordering::SeqCst), 0);
    bob.send_text(&group_id, "after recovery").await;
    wait_until("the next message", || alice.texts(&group_id).len() == 2).await;
    alice.client.stop_sync().unwrap();
    assert_eq!(
        alice.texts(&group_id),
        ["during recovery", "after recovery"]
    );
    assert_eq!(server_b.controls.expired_served.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_resumes_both_cursors() {
    let Setup {
        hub_b,
        server_a,
        server_b,
        mut alice,
        bob,
        ..
    } = setup().await;
    let group_id = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.client.sync_once().await.unwrap();
    bob.send_text(&group_id, "before").await;
    alice.client.sync_once().await.unwrap();
    let b = hub_id(&hub_b);
    let cursor_a = alice.store.global_cursor().unwrap();
    let cursor_b = alice.store.hub_cursor(&b).unwrap();
    assert!(cursor_a.is_some() && cursor_b.is_some());

    alice.restart().await;
    let (seen_a, seen_b) = (polls(&server_a).len(), polls(&server_b).len());
    alice.client.start_sync().unwrap();
    wait_until("both hubs polled", || {
        polls(&server_a).len() > seen_a && polls(&server_b).len() > seen_b
    })
    .await;
    assert_eq!(polls(&server_a)[seen_a], cursor_a, "A resumed");
    assert_eq!(polls(&server_b)[seen_b], cursor_b, "B resumed");

    bob.send_text(&group_id, "after").await;
    wait_until("the next message", || alice.texts(&group_id).len() == 2).await;
    alice.client.stop_sync().unwrap();
    assert_eq!(alice.texts(&group_id), ["before", "after"]);
}
