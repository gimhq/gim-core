//! The app and an app extension (iOS NSE) on one data directory: two
//! clients with their own in-memory state over the same SQLite files, and a
//! second process holding the store lock.

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gim_base::model::{Membership, MessageContent, MessageKind, OutboxState, StateChange};
use gim_base::{BaseError, StateReader};
use gim_common::GroupId;
use gim_sdk::testing::MemorySecretStorage;
use gim_sdk::{
    Client, ClientBuilder, ClientError, ClientMode, SecretStorage, StoreLock, LOCK_FILE_NAME,
};
use gim_sqlite::{DbKey, SqliteStore};
use tempfile::TempDir;

use common::{Device, FlakyTransport};

type Builder = ClientBuilder<SqliteStore>;

/// Set in the child process of [`StoreHolder`]: the data directory whose
/// store lock it holds.
const HOLD_ENV: &str = "GIM_TEST_HOLD_STORE_LOCK";

/// One device whose data directory the app and the extension share.
struct SharedDevice {
    transport: FlakyTransport,
    secrets: Arc<MemorySecretStorage>,
    dir: TempDir,
}

impl SharedDevice {
    async fn register(transport: &FlakyTransport, handle: &str) -> (Self, Client<SqliteStore>) {
        let device = Self {
            transport: transport.clone(),
            secrets: Arc::new(MemorySecretStorage::new()),
            dir: tempfile::tempdir().unwrap(),
        };
        let app = device.app(Duration::from_secs(5));
        app.register(handle, handle).await.unwrap();
        (device, app)
    }

    fn app(&self, lock_timeout: Duration) -> Client<SqliteStore> {
        Builder::open(
            Arc::new(self.transport.clone()),
            self.secrets.clone(),
            |key, new_key| {
                SqliteStore::open_or_reset(self.dir.path(), &DbKey::new(*key), new_key)
                    .map_err(BaseError::from)
            },
        )
        .unwrap()
        .data_dir(self.dir.path())
        .store_lock_timeout(lock_timeout)
        .build()
        .unwrap()
    }

    fn open_extension(&self) -> Result<Client<SqliteStore>, ClientError> {
        Builder::open_extension(
            Arc::new(self.transport.clone()),
            self.secrets.clone(),
            |key| {
                SqliteStore::open_for_extension(self.dir.path(), &DbKey::new(*key))
                    .map_err(BaseError::from)
            },
        )?
        .data_dir(self.dir.path())
        .build()
    }

    async fn extension(&self) -> Client<SqliteStore> {
        let extension = self.open_extension().unwrap();
        assert!(extension.restore_session().await.unwrap());
        extension
    }
}

fn texts(store: &impl StateReader, group_id: &GroupId) -> Vec<String> {
    store
        .messages(group_id, None, usize::MAX)
        .unwrap()
        .into_iter()
        .filter_map(|m| match m.content {
            MessageContent::Text { body } => Some(body),
            _ => None,
        })
        .collect()
}

/// Asserts that `texts` holds each of `expected` exactly once.
fn once_each(texts: &[String], expected: &BTreeSet<String>) {
    let found: BTreeSet<String> = texts.iter().cloned().collect();
    assert_eq!(found.len(), texts.len(), "duplicates in {texts:?}");
    assert_eq!(&found, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_and_extension_apply_and_send_concurrently() {
    let transport = FlakyTransport::new();
    let (alice, app) = SharedDevice::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = app.create_group_chat(None, &[bob.user_id()]).await.unwrap();
    bob.sync().await;
    let extension = alice.extension().await;
    assert_eq!(extension.mode(), ClientMode::Extension);

    let rounds = 8;
    let mut expected = BTreeSet::new();
    for round in 0..rounds {
        for i in 0..2 {
            let text = format!("bob {round}.{i}");
            bob.client.send_text(&g, text.clone(), None).await.unwrap();
            expected.insert(text);
        }
        let (a, b, c, d) = tokio::join!(
            app.sync_once(),
            extension.sync_once(),
            app.send_text(&g, format!("app {round}"), None),
            extension.send_text(&g, format!("nse {round}"), None),
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        d.unwrap();
        expected.insert(format!("app {round}"));
        expected.insert(format!("nse {round}"));
    }
    app.sync_once().await.unwrap();
    extension.flush_outbox().await.unwrap();
    app.flush_outbox().await.unwrap();
    bob.sync().await;

    // Everyone has every message once, decrypted.
    once_each(&texts(&**app.store(), &g), &expected);
    once_each(&texts(&**extension.store(), &g), &expected);
    once_each(&texts(&*bob.store, &g), &expected);
    for message in app.store().messages(&g, None, usize::MAX).unwrap() {
        assert!(message.seq.is_some(), "{message:?}");
    }
    // The group state is intact on both sides: a further exchange works.
    app.send_text(&g, "still fine", None).await.unwrap();
    bob.client.send_text(&g, "and back", None).await.unwrap();
    bob.sync().await;
    extension.sync_once().await.unwrap();
    app.sync_once().await.unwrap();
    assert!(texts(&*bob.store, &g).contains(&"still fine".to_string()));
    assert!(texts(&**app.store(), &g).contains(&"and back".to_string()));
}

#[tokio::test]
async fn app_with_a_cached_group_sends_after_the_extension_applied_a_commit() {
    let transport = FlakyTransport::new();
    let (alice, app) = SharedDevice::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = app.create_group_chat(None, &[bob.user_id()]).await.unwrap();
    bob.sync().await;
    app.send_text(&g, "before", None).await.unwrap();
    let epoch = transport.inner.service().epoch(&g).unwrap();

    // The NSE applies Bob's commit adding Carol while the app is suspended.
    bob.client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    let mut changes = app.subscribe_changes();
    let extension = alice.extension().await;
    extension.sync_once().await.unwrap();
    assert_eq!(transport.inner.service().epoch(&g), Ok(epoch + 1));
    assert_eq!(
        extension.store().chat(&g).unwrap().unwrap().members.len(),
        3
    );
    drop(extension);

    // The app sends at the new epoch.
    let id = app.send_text(&g, "after", None).await.unwrap();
    assert!(app.store().message(&id).unwrap().unwrap().seq.is_some());
    for device in [&bob, &carol] {
        device.sync().await;
        assert!(texts(&*device.store, &g).contains(&"after".to_string()));
    }
    // ... and showed what the extension applied.
    let mut seen = false;
    while let Ok(change) = changes.try_recv() {
        if let StateChange::ChatUpserted(chat) = change {
            seen |= chat.group_id == g && chat.members.len() == 3;
        }
    }
    assert!(seen, "the app did not broadcast the extension's changes");
}

/// A child process (this test binary, running [`store_lock_holder`]) that
/// holds the store lock of a data directory until dropped.
struct StoreHolder {
    child: Child,
    release: std::path::PathBuf,
}

impl StoreHolder {
    fn start(data_dir: &Path) -> Self {
        let held = data_dir.join("held");
        let release = data_dir.join("release");
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store_lock_holder",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HOLD_ENV, data_dir)
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !held.exists() {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "holder did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        Self { child, release }
    }

    fn release(mut self) {
        std::fs::write(&self.release, b"").unwrap();
        assert!(self.child.wait().unwrap().success());
    }
}

/// Only runs as the child process of [`StoreHolder`]: takes the store lock,
/// records a write, signals `held` and waits for `release`.
#[test]
fn store_lock_holder() {
    let Some(dir) = std::env::var_os(HOLD_ENV) else {
        return;
    };
    let dir = Path::new(&dir);
    let lock = StoreLock::open(dir, Duration::from_secs(10)).unwrap();
    let mut guard = lock.acquire().unwrap();
    guard.mark_written().unwrap();
    std::fs::write(dir.join("held"), b"").unwrap();
    while !dir.join("release").exists() {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mutation_waiting_for_another_process_is_deferred_not_lost() {
    let transport = FlakyTransport::new();
    let (alice, app) = SharedDevice::register(&transport, "alice").await;
    drop(app);
    let app = alice.app(Duration::from_millis(200));
    assert!(app.restore_session().await.unwrap());
    let bob = Device::register(&transport, "bob").await;
    let g = app.create_group_chat(None, &[bob.user_id()]).await.unwrap();
    bob.sync().await;
    bob.client.send_text(&g, "incoming", None).await.unwrap();
    assert!(alice.dir.path().join(LOCK_FILE_NAME).is_file());

    let holder = StoreHolder::start(alice.dir.path());
    let started = Instant::now();
    assert!(matches!(
        app.sync_once().await,
        Err(ClientError::StoreBusy(_))
    ));
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(matches!(
        app.send_text(&g, "while locked", None).await,
        Err(ClientError::StoreBusy(_))
    ));
    holder.release();

    // Nothing was applied or dropped meanwhile; now it is, once.
    assert!(!texts(&**app.store(), &g).contains(&"incoming".to_string()));
    app.sync_once().await.unwrap();
    app.sync_once().await.unwrap();
    let texts = texts(&**app.store(), &g);
    assert_eq!(texts.iter().filter(|t| *t == "incoming").count(), 1);
    assert!(!texts.contains(&"while locked".to_string()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outbox_pass_waiting_for_another_process_keeps_the_entry() {
    let transport = FlakyTransport::new();
    let (alice, app) = SharedDevice::register(&transport, "alice").await;
    drop(app);
    let app = alice.app(Duration::from_millis(100));
    assert!(app.restore_session().await.unwrap());
    let bob = Device::register(&transport, "bob").await;
    let g = app.create_group_chat(None, &[bob.user_id()]).await.unwrap();
    bob.sync().await;
    // The post never reaches the hub: the entry waits for a retry.
    transport
        .faults
        .fail_posts(MessageKind::Application, false, 1);
    let id = app.send_text(&g, "queued", None).await.unwrap();
    let entry = app.store().outbox_entry(&id).unwrap().unwrap();
    assert_eq!(entry.state, OutboxState::Pending);

    let holder = StoreHolder::start(alice.dir.path());
    app.network_reachable();
    assert!(matches!(
        app.flush_outbox().await,
        Err(ClientError::StoreBusy(_))
    ));
    let entry = app.store().outbox_entry(&id).unwrap().unwrap();
    assert_eq!(entry.state, OutboxState::Pending);
    holder.release();

    app.network_reachable();
    app.flush_outbox().await.unwrap();
    assert_eq!(app.store().outbox_entry(&id).unwrap(), None);
    bob.sync().await;
    assert_eq!(texts(&*bob.store, &g), vec!["queued".to_string()]);
}

#[tokio::test]
async fn extension_mode_starts_nothing_and_never_resets() {
    let transport = FlakyTransport::new();
    // No database key: the extension fails and creates none.
    let fresh = SharedDevice {
        transport: transport.clone(),
        secrets: Arc::new(MemorySecretStorage::new()),
        dir: tempfile::tempdir().unwrap(),
    };
    assert!(matches!(
        fresh.open_extension(),
        Err(ClientError::InvalidInput(_))
    ));
    assert_eq!(fresh.secrets.get(Builder::DB_KEY_SECRET_KEY).unwrap(), None);

    let (alice, app) = SharedDevice::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = app.create_group_chat(None, &[bob.user_id()]).await.unwrap();
    drop(app);

    let extension = alice.extension().await;
    assert!(matches!(
        extension.start_sync(),
        Err(ClientError::InvalidInput(_))
    ));
    assert!(!extension.is_sync_running());
    let key_packages = extension.store().key_package_records().unwrap().len();
    extension.replenish_key_packages().await.unwrap();
    assert_eq!(
        extension.store().key_package_records().unwrap().len(),
        key_packages
    );
    drop(extension);

    // A key that cannot decrypt the database: the extension fails, the
    // database stays.
    let key = alice
        .secrets
        .get(Builder::DB_KEY_SECRET_KEY)
        .unwrap()
        .unwrap();
    alice
        .secrets
        .set(Builder::DB_KEY_SECRET_KEY, &[9u8; 32])
        .unwrap();
    assert!(alice.open_extension().is_err());
    alice.secrets.set(Builder::DB_KEY_SECRET_KEY, &key).unwrap();
    let app = alice.app(Duration::from_secs(5));
    assert!(app.restore_session().await.unwrap());
    assert_eq!(
        app.store().chat(&g).unwrap().unwrap().membership,
        Membership::Joined
    );
}
