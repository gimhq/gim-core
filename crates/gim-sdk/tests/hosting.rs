//! Hosting records: published at onboarding, renewed when due (sync loop
//! start, `hosting_record.expiring`), rebuilt after a concurrent upload
//! (409), published again on 403 `hosting_record_required`, and never
//! built from a hub entry that does not verify.

mod common;
mod mock_server;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::{server_messages, EntryTamper, FlakyTransport};
use gim_base::MemoryStore;
use gim_common::{now_ms, UserId};
use gim_identity::{HostingEntry, RootKey, SignedHostingRecord, UserHostingRecord};
use gim_proto::envelope::Content;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{HubEvent, TransportError};
use gim_sdk::{
    Client, ClientBuilder, ClientError, SecretStorage, HOSTING_RECORD_LIFETIME, ROOT_KEY_SECRET_KEY,
};
use mock_server::{fast_settings, wait_until, MockServer, Peer};
use tempfile::TempDir;

const DAY_MS: u64 = 24 * 3_600_000;

struct Account {
    client: Client<MemoryStore>,
    secrets: Arc<MemorySecretStorage>,
    _data_dir: TempDir,
}

impl Account {
    fn new(transport: &FlakyTransport) -> Self {
        let secrets = Arc::new(MemorySecretStorage::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = ClientBuilder::new(
            Arc::new(MemoryStore::new()),
            Arc::new(transport.clone()),
            secrets.clone() as Arc<dyn SecretStorage>,
        )
        .data_dir(data_dir.path())
        .sync_settings(fast_settings())
        .build()
        .unwrap();
        Self {
            client,
            secrets,
            _data_dir: data_dir,
        }
    }

    async fn register(transport: &FlakyTransport, handle: &str) -> Self {
        let account = Self::new(transport);
        account.client.register(handle, handle).await.unwrap();
        account
    }

    fn user_id(&self) -> UserId {
        self.client.session().unwrap().device.user_id
    }

    fn root(&self) -> RootKey {
        let seed = self.secrets.get(ROOT_KEY_SECRET_KEY).unwrap().unwrap();
        RootKey::from_seed(&seed.try_into().unwrap())
    }

    /// A record of this user listing the fake hub, valid for `lifetime_ms`.
    fn record(&self, transport: &FlakyTransport, seq: u64, lifetime_ms: u64) -> Vec<u8> {
        let root = self.root();
        let entry = HostingEntry::sign(transport.inner.hub_root_key(), &self.user_id(), 0);
        UserHostingRecord::new(root.public(), seq, now_ms() + lifetime_ms, vec![entry])
            .and_then(|record| record.sign(&root))
            .unwrap()
            .to_bytes()
    }
}

/// The user's record on the hub, verified now.
fn hub_record(transport: &FakeTransport, user_id: &UserId) -> Option<UserHostingRecord> {
    let bytes = transport.stored_hosting_record(user_id)?;
    let record = SignedHostingRecord::from_bytes(&bytes)
        .and_then(|signed| signed.verify(now_ms()))
        .unwrap();
    assert_eq!(record.user_id(), user_id);
    Some(record)
}

fn hub_seq(transport: &FakeTransport, user_id: &UserId) -> Option<u64> {
    hub_record(transport, user_id).map(|r| r.seq())
}

/// Checks a record the client built just now (between `before` and the
/// call): it lists exactly the fake hub, at priority 0, for seven days.
fn assert_published(transport: &FakeTransport, user_id: &UserId, seq: u64, before: u64) {
    let record = hub_record(transport, user_id).expect("a published record");
    assert_eq!(record.seq(), seq);
    let lifetime = HOSTING_RECORD_LIFETIME.as_millis() as u64;
    assert!(record.expires_at() >= before + lifetime);
    assert!(record.expires_at() <= now_ms() + lifetime);
    assert_eq!(record.hubs().len(), 1);
    let entry = &record.hubs()[0];
    assert_eq!(
        *entry.hub_root_public_key(),
        transport.hub_root_key().public()
    );
    assert_eq!(entry.priority(), 0);
}

#[tokio::test]
async fn onboarding_over_http_publishes_a_valid_record() {
    let transport = FakeTransport::new();
    let server = MockServer::start(transport.clone()).await;
    let before = now_ms();
    let alice = Peer::http(&server, "alice", fast_settings()).await;
    assert_published(&transport, &alice.user_id(), 1, before);
}

#[tokio::test]
async fn restore_publishes_the_next_record_and_a_link_keeps_a_valid_one() {
    let transport = FlakyTransport::new();
    let alice = Account::new(&transport);
    let code = alice.client.create_identity("Alice").await.unwrap();
    let user_id = alice.user_id();
    assert_eq!(hub_seq(&transport.inner, &user_id), Some(1));

    let before = now_ms();
    let restored = Account::new(&transport);
    restored
        .client
        .restore_from_recovery(&user_id, &code, false)
        .await
        .unwrap();
    assert_published(&transport.inner, &user_id, 2, before);

    let puts = transport.faults.hosting_puts.load(Ordering::SeqCst);
    let linked = Account::new(&transport);
    let session = linked
        .client
        .start_link(vec!["hub.example".into()])
        .unwrap();
    let approval = restored
        .client
        .approve_link(&session.qr_string)
        .await
        .unwrap();
    linked.client.wait_link(&session).await.unwrap();
    linked.client.confirm_link(true).await.unwrap();
    restored
        .client
        .confirm_approval(&approval, true)
        .await
        .unwrap();
    assert_eq!(transport.faults.hosting_puts.load(Ordering::SeqCst), puts);
    assert_eq!(hub_seq(&transport.inner, &user_id), Some(2));
}

#[tokio::test]
async fn a_linked_device_publishes_when_the_record_is_missing() {
    let transport = FlakyTransport::new();
    let alice = Account::register(&transport, "alice").await;
    let user_id = alice.user_id();
    transport.inner.set_hosting_record(&user_id, None);

    let before = now_ms();
    let linked = Account::new(&transport);
    let session = linked
        .client
        .start_link(vec!["hub.example".into()])
        .unwrap();
    alice.client.approve_link(&session.qr_string).await.unwrap();
    linked.client.wait_link(&session).await.unwrap();
    assert_published(&transport.inner, &user_id, 1, before);
}

#[tokio::test]
async fn the_sync_loop_renews_only_when_less_than_three_days_remain() {
    let transport = FlakyTransport::new();
    let alice = Account::register(&transport, "alice").await;
    let user_id = alice.user_id();

    // Four days left: kept.
    let kept = alice.record(&transport, 5, 4 * DAY_MS);
    transport
        .inner
        .set_hosting_record(&user_id, Some(kept.clone()));
    let (reads, puts) = (
        transport.inner.hosting_record_reads(),
        transport.faults.hosting_puts.load(Ordering::SeqCst),
    );
    alice.client.start_sync().unwrap();
    let inner = transport.inner.clone();
    wait_until("the renewal check", move || {
        inner.hosting_record_reads() > reads
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    alice.client.stop_sync().unwrap();
    assert_eq!(transport.faults.hosting_puts.load(Ordering::SeqCst), puts);
    assert_eq!(transport.inner.stored_hosting_record(&user_id), Some(kept));

    // Two days left: renewed with the next seq, the same entries and seven
    // more days.
    let due = alice.record(&transport, 6, 2 * DAY_MS);
    transport.inner.set_hosting_record(&user_id, Some(due));
    let before = now_ms();
    alice.client.start_sync().unwrap();
    let inner = transport.inner.clone();
    let uid = user_id.clone();
    wait_until("the renewal", move || hub_seq(&inner, &uid) == Some(7)).await;
    alice.client.stop_sync().unwrap();
    assert_published(&transport.inner, &user_id, 7, before);
}

#[tokio::test]
async fn a_concurrent_upload_is_read_and_the_record_rebuilt() {
    let transport = FlakyTransport::new();
    let alice = Account::register(&transport, "alice").await;
    let user_id = alice.user_id();

    // Another device uploads seq 4, also due, right before this one's
    // seq 4: the 409 makes it read seq 4 and publish seq 5.
    let due = alice.record(&transport, 3, 2 * DAY_MS);
    transport.inner.set_hosting_record(&user_id, Some(due));
    let concurrent = alice.record(&transport, 4, 2 * DAY_MS);
    transport
        .faults
        .concurrent_hosting
        .lock()
        .unwrap()
        .push_back((user_id.clone(), concurrent));
    let puts = transport.faults.hosting_puts.load(Ordering::SeqCst);
    let before = now_ms();
    alice.client.start_sync().unwrap();
    let inner = transport.inner.clone();
    let uid = user_id.clone();
    wait_until("the rebuilt record", move || {
        hub_seq(&inner, &uid) == Some(5)
    })
    .await;
    alice.client.stop_sync().unwrap();
    assert_published(&transport.inner, &user_id, 5, before);
    assert_eq!(
        transport.faults.hosting_puts.load(Ordering::SeqCst),
        puts + 2
    );
}

#[tokio::test]
async fn a_concurrent_renewal_by_another_device_counts_as_renewed() {
    let transport = FlakyTransport::new();
    let alice = Account::register(&transport, "alice").await;
    let user_id = alice.user_id();

    let due = alice.record(&transport, 3, 2 * DAY_MS);
    transport.inner.set_hosting_record(&user_id, Some(due));
    let renewed = alice.record(&transport, 4, 7 * DAY_MS);
    transport
        .faults
        .concurrent_hosting
        .lock()
        .unwrap()
        .push_back((user_id.clone(), renewed.clone()));
    let puts = transport.faults.hosting_puts.load(Ordering::SeqCst);
    alice.client.start_sync().unwrap();
    let faults = transport.faults.clone();
    wait_until("the conflicting upload", move || {
        faults.hosting_puts.load(Ordering::SeqCst) > puts
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    alice.client.stop_sync().unwrap();
    assert_eq!(
        transport.faults.hosting_puts.load(Ordering::SeqCst),
        puts + 1
    );
    assert_eq!(
        transport.inner.stored_hosting_record(&user_id),
        Some(renewed)
    );
}

#[tokio::test]
async fn the_expiring_event_triggers_a_renewal() {
    let transport = FlakyTransport::new();
    let alice = Account::register(&transport, "alice").await;
    let user_id = alice.user_id();
    let reads = transport.inner.hosting_record_reads();
    alice.client.start_sync().unwrap();
    let inner = transport.inner.clone();
    wait_until("the first renewal check", move || {
        inner.hosting_record_reads() > reads
    })
    .await;
    assert_eq!(hub_seq(&transport.inner, &user_id), Some(1));

    // The next daily check is a day away: only the event renews now.
    let expiring = alice.record(&transport, 9, DAY_MS);
    transport.inner.set_hosting_record(&user_id, Some(expiring));
    let before = now_ms();
    transport
        .faults
        .injected_events
        .lock()
        .unwrap()
        .push(HubEvent::HostingRecordExpiring {
            user_id: user_id.clone(),
            expires_at_ms: now_ms() + DAY_MS,
            seq: 9,
        });
    let inner = transport.inner.clone();
    let uid = user_id.clone();
    wait_until("the renewal", move || hub_seq(&inner, &uid) == Some(10)).await;
    alice.client.stop_sync().unwrap();
    assert_published(&transport.inner, &user_id, 10, before);
}

#[tokio::test]
async fn hosting_record_required_publishes_and_retries_the_same_request() {
    let transport = FlakyTransport::new();
    transport.inner.require_hosting_records(true);
    let alice = Account::register(&transport, "alice").await;
    let bob = Account::register(&transport, "bob").await;
    let (alice_id, bob_id) = (alice.user_id(), bob.user_id());

    // A commit: the group is created after the record is published again.
    transport.inner.set_hosting_record(&alice_id, None);
    let group_id = alice
        .client
        .create_group_chat(None, std::slice::from_ref(&bob_id))
        .await
        .unwrap();
    assert_eq!(hub_seq(&transport.inner, &alice_id), Some(1));

    // A message: posted once, with the client id of the first attempt.
    transport.inner.set_hosting_record(&alice_id, None);
    let id = alice
        .client
        .send(&group_id, Content::Text { body: "hi".into() })
        .await
        .unwrap();
    let device = alice.client.session().unwrap().device;
    let posted = server_messages(&transport, &group_id, &device);
    let sent = posted
        .iter()
        .filter(|m| m.client_id.as_str() == id.as_str())
        .count();
    assert_eq!(sent, 1);
    assert_eq!(hub_seq(&transport.inner, &alice_id), Some(1));
}

#[tokio::test]
async fn hosting_record_required_is_returned_when_publishing_fails() {
    let transport = FlakyTransport::new();
    transport.inner.require_hosting_records(true);
    let alice = Account::register(&transport, "alice").await;
    let bob = Account::register(&transport, "bob").await;
    let alice_id = alice.user_id();

    transport.inner.set_hosting_record(&alice_id, None);
    *transport.faults.tamper_entries.lock().unwrap() = Some(EntryTamper::WrongKey);
    let created = alice.client.create_group_chat(None, &[bob.user_id()]).await;
    assert!(
        matches!(
            created,
            Err(ClientError::Transport(
                TransportError::HostingRecordRequired(_)
            ))
        ),
        "{created:?}"
    );
    assert_eq!(transport.inner.stored_hosting_record(&alice_id), None);
}

#[tokio::test]
async fn entries_that_do_not_verify_are_never_published() {
    for tamper in [
        EntryTamper::ForeignUser,
        EntryTamper::WrongHubId,
        EntryTamper::WrongKey,
    ] {
        let transport = FlakyTransport::new();
        *transport.faults.tamper_entries.lock().unwrap() = Some(tamper);
        // Onboarding still succeeds: local operation does not wait for the
        // record.
        let alice = Account::register(&transport, "alice").await;
        let user_id = alice.user_id();
        assert_eq!(
            transport.faults.hosting_puts.load(Ordering::SeqCst),
            0,
            "{tamper:?}"
        );
        assert_eq!(
            transport.inner.stored_hosting_record(&user_id),
            None,
            "{tamper:?}"
        );

        // The sync loop retries once the hub behaves.
        *transport.faults.tamper_entries.lock().unwrap() = None;
        let before = now_ms();
        alice.client.start_sync().unwrap();
        let inner = transport.inner.clone();
        let uid = user_id.clone();
        wait_until("the retried publication", move || {
            hub_seq(&inner, &uid) == Some(1)
        })
        .await;
        alice.client.stop_sync().unwrap();
        assert_published(&transport.inner, &user_id, 1, before);
    }
}
