//! Onboarding that fails part-way (identity creation, recovery restore,
//! device link) leaves nothing behind that blocks a retry, also across a
//! restart; a completed identity still cannot be replaced.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use gim_base::{BaseError, StateStore};
use gim_common::{DeviceId, UserId};
use gim_crypto::CryptoStore;
use gim_identity::recovery::RecoveryCode;
use gim_identity::{DeviceList, SignedDeviceList};
use gim_sdk::testing::MemorySecretStorage;
use gim_sdk::transport::{SessionError, TransportError};
use gim_sdk::{
    Client, ClientBuilder, ClientError, SecretStorage, DEVICE_KEY_SECRET_KEY, ROOT_KEY_SECRET_KEY,
    SESSION_SECRET_KEY,
};
use gim_sqlite::{DbKey, SqliteStore};
use tempfile::TempDir;

use common::{FlakyTransport, Step};

/// Where an onboarding call is made to fail.
#[derive(Debug, Clone, Copy)]
enum Fault {
    Step(Step),
    SignIn,
}

/// A device on SQLite whose client can be restarted.
struct Persistent {
    transport: FlakyTransport,
    secrets: Arc<MemorySecretStorage>,
    dir: TempDir,
}

impl Persistent {
    fn new(transport: &FlakyTransport) -> Self {
        Self {
            transport: transport.clone(),
            secrets: Arc::new(MemorySecretStorage::new()),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn open(&self) -> Client<SqliteStore> {
        ClientBuilder::open(
            Arc::new(self.transport.clone()),
            self.secrets.clone() as Arc<dyn SecretStorage>,
            |key, new_key| {
                SqliteStore::open_or_reset(self.dir.path(), &DbKey::new(*key), new_key)
                    .map_err(BaseError::from)
            },
        )
        .unwrap()
        .data_dir(self.dir.path())
        .build()
        .unwrap()
    }

    /// Drops `client` and opens a new one over the same database and
    /// secrets, as after a restart.
    async fn restart(&self, client: Client<SqliteStore>) -> Client<SqliteStore> {
        drop(client);
        self.open()
    }

    fn secret(&self, key: &str) -> Option<Vec<u8>> {
        self.secrets.get(key).unwrap()
    }

    /// Nothing of an enrollment is left: no keys, no session, no identity.
    fn assert_clean(&self, client: &Client<SqliteStore>) {
        assert!(client.session().is_none());
        for key in [
            ROOT_KEY_SECRET_KEY,
            DEVICE_KEY_SECRET_KEY,
            SESSION_SECRET_KEY,
        ] {
            assert!(self.secret(key).is_none(), "{key} is left");
        }
        let identity = client
            .store()
            .transaction(|txn| Ok(txn.load_identity()?))
            .unwrap();
        assert!(identity.is_none());
    }
}

fn inject(transport: &FlakyTransport, fault: Fault) {
    match fault {
        Fault::Step(step) => transport.faults.fail_step(step),
        Fault::SignIn => {
            transport
                .faults
                .sessions
                .lock()
                .unwrap()
                .push_back(SessionError::Transport(TransportError::Network(
                    "injected".into(),
                )))
        }
    }
}

/// The user's DeviceList on the hub.
fn hub_list(transport: &FlakyTransport, user_id: &UserId) -> DeviceList {
    let bytes = transport.inner.service().device_list(user_id).unwrap();
    SignedDeviceList::from_bytes(&bytes)
        .and_then(|signed| signed.verify(user_id))
        .unwrap()
}

fn certified(list: &DeviceList) -> BTreeSet<DeviceId> {
    list.certs().map(|c| c.device_id.clone()).collect()
}

/// The device signed in on `client` is the one its store holds.
fn assert_enrolled(client: &Client<SqliteStore>) {
    let session = client.session().unwrap();
    let identity = client
        .store()
        .transaction(|txn| Ok(txn.load_identity()?))
        .unwrap()
        .unwrap();
    assert_eq!(identity.device, session.device);
}

const CREATE_FAULTS: [Fault; 6] = [
    Fault::Step(Step::PutDeviceList),
    Fault::SignIn,
    Fault::Step(Step::PutRecoveryBackup),
    Fault::Step(Step::UploadKeyPackages),
    Fault::Step(Step::UploadLastResort),
    Fault::Step(Step::CreateGroup),
];

#[tokio::test]
async fn create_identity_succeeds_on_retry_after_any_failed_step() {
    for fault in CREATE_FAULTS {
        let transport = FlakyTransport::new();
        let device = Persistent::new(&transport);
        let client = device.open();
        inject(&transport, fault);
        assert!(
            client.create_identity("Alice").await.is_err(),
            "{fault:?} did not fail"
        );
        device.assert_clean(&client);

        client.create_identity("Alice").await.unwrap();
        assert_enrolled(&client);
        assert!(matches!(
            client.create_identity("Alice").await,
            Err(ClientError::AlreadyLoggedIn)
        ));
        let client = device.restart(client).await;
        assert!(client.restore_session().await.unwrap(), "{fault:?}");
        assert_enrolled(&client);
    }
}

#[tokio::test]
async fn create_identity_succeeds_after_a_restart_mid_enrollment() {
    for step in [
        Step::PutDeviceList,
        Step::UploadKeyPackages,
        Step::CreateGroup,
    ] {
        let transport = FlakyTransport::new();
        let device = Persistent::new(&transport);
        let client = device.open();
        *transport.faults.hang.lock().unwrap() = Some(step);
        let task = {
            let client = client.clone();
            tokio::spawn(async move { client.create_identity("Alice").await })
        };
        transport.faults.hung.notified().await;
        // Killed at the hung step: nothing is rolled back.
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(device.secret(ROOT_KEY_SECRET_KEY).is_some());
        *transport.faults.hang.lock().unwrap() = None;

        let client = device.restart(client).await;
        assert!(!client.restore_session().await.unwrap(), "{step:?}");
        device.assert_clean(&client);
        client.create_identity("Alice").await.unwrap();
        assert_enrolled(&client);
    }
}

#[tokio::test]
async fn create_identity_discards_an_unfinished_enrollment_without_restore_session() {
    let transport = FlakyTransport::new();
    let device = Persistent::new(&transport);
    let client = device.open();
    *transport.faults.hang.lock().unwrap() = Some(Step::UploadLastResort);
    let task = {
        let client = client.clone();
        tokio::spawn(async move { client.create_identity("Alice").await })
    };
    transport.faults.hung.notified().await;
    task.abort();
    let _ = task.await;
    *transport.faults.hang.lock().unwrap() = None;
    let old_root = device.secret(ROOT_KEY_SECRET_KEY).unwrap();

    let client = device.restart(client).await;
    client.create_identity("Alice").await.unwrap();
    assert_enrolled(&client);
    assert_ne!(device.secret(ROOT_KEY_SECRET_KEY).unwrap(), old_root);
}

#[tokio::test]
async fn register_succeeds_on_retry_after_the_handle_claim_failed() {
    let transport = FlakyTransport::new();
    let device = Persistent::new(&transport);
    let client = device.open();
    transport.faults.fail_step(Step::ClaimHandle);
    assert!(client.register("alice", "Alice").await.is_err());
    device.assert_clean(&client);
    client.register("alice", "Alice").await.unwrap();
    assert_enrolled(&client);
}

#[tokio::test]
async fn completed_identity_cannot_be_created_again_after_a_restart() {
    let transport = FlakyTransport::new();
    let device = Persistent::new(&transport);
    let client = device.open();
    client.create_identity("Alice").await.unwrap();
    let session = client.session().unwrap();

    let client = device.restart(client).await;
    assert!(client.restore_session().await.unwrap());
    assert!(matches!(
        client.create_identity("Alice").await,
        Err(ClientError::AlreadyLoggedIn)
    ));
    // Without a restored session the stored identity still blocks it.
    let client = device.restart(client).await;
    assert!(matches!(
        client.create_identity("Alice").await,
        Err(ClientError::AlreadyLoggedIn)
    ));
    assert!(client.restore_session().await.unwrap());
    assert_eq!(client.session().unwrap(), session);

    // Keys gone (e.g. a SAS mismatch wiped them), the store's identity is
    // still never discarded.
    let client = device.restart(client).await;
    for key in [
        ROOT_KEY_SECRET_KEY,
        DEVICE_KEY_SECRET_KEY,
        SESSION_SECRET_KEY,
    ] {
        device.secrets.delete(key).unwrap();
    }
    assert!(matches!(
        client.create_identity("Alice").await,
        Err(ClientError::AlreadyLoggedIn)
    ));
    let identity = client
        .store()
        .transaction(|txn| Ok(txn.load_identity()?))
        .unwrap()
        .unwrap();
    assert_eq!(identity.device, session.device);
}

/// Alice registered on another device; returns her user id and recovery
/// code.
async fn alice(transport: &FlakyTransport) -> (Persistent, UserId, RecoveryCode) {
    let device = Persistent::new(transport);
    let client = device.open();
    let code = client.create_identity("Alice").await.unwrap();
    let user_id = client.session().unwrap().device.user_id;
    (device, user_id, code)
}

#[tokio::test]
async fn restore_succeeds_on_retry_after_any_failed_step() {
    let faults = [
        Fault::Step(Step::PutDeviceList),
        Fault::SignIn,
        Fault::Step(Step::UploadKeyPackages),
        Fault::Step(Step::UploadLastResort),
        Fault::Step(Step::CreateGroup),
    ];
    for fault in faults {
        let transport = FlakyTransport::new();
        let (_alice, user_id, code) = alice(&transport).await;
        let before = certified(&hub_list(&transport, &user_id));
        let device = Persistent::new(&transport);
        let client = device.open();
        inject(&transport, fault);
        assert!(
            client
                .restore_from_recovery(&user_id, &code, false)
                .await
                .is_err(),
            "{fault:?} did not fail"
        );
        device.assert_clean(&client);

        client
            .restore_from_recovery(&user_id, &code, false)
            .await
            .unwrap();
        assert_enrolled(&client);
        let restored = client.session().unwrap().device.device_id;
        // The device of the failed attempt is not left certified.
        let after = certified(&hub_list(&transport, &user_id));
        let mut expected = before.clone();
        expected.insert(restored);
        assert_eq!(after, expected, "{fault:?}");
        assert!(matches!(
            client.restore_from_recovery(&user_id, &code, false).await,
            Err(ClientError::AlreadyLoggedIn)
        ));
    }
}

#[tokio::test]
async fn restore_succeeds_after_a_restart_mid_enrollment() {
    let transport = FlakyTransport::new();
    let (_alice, user_id, code) = alice(&transport).await;
    let before = certified(&hub_list(&transport, &user_id));
    let device = Persistent::new(&transport);
    let client = device.open();
    *transport.faults.hang.lock().unwrap() = Some(Step::UploadKeyPackages);
    let task = {
        let (client, user_id, code) = (client.clone(), user_id.clone(), code.clone());
        tokio::spawn(async move { client.restore_from_recovery(&user_id, &code, false).await })
    };
    transport.faults.hung.notified().await;
    task.abort();
    let _ = task.await;
    *transport.faults.hang.lock().unwrap() = None;
    let discarded: BTreeSet<_> = certified(&hub_list(&transport, &user_id))
        .difference(&before)
        .cloned()
        .collect();
    assert_eq!(discarded.len(), 1);

    let client = device.restart(client).await;
    assert!(!client.restore_session().await.unwrap());
    device.assert_clean(&client);
    client
        .restore_from_recovery(&user_id, &code, false)
        .await
        .unwrap();
    assert_enrolled(&client);
    let list = hub_list(&transport, &user_id);
    let mut expected = before;
    expected.insert(client.session().unwrap().device.device_id);
    assert_eq!(certified(&list), expected);
    assert_eq!(
        list.revoked().iter().cloned().collect::<BTreeSet<_>>(),
        discarded
    );
}

#[tokio::test]
async fn link_succeeds_with_a_new_offer_after_a_failed_enrollment() {
    let transport = FlakyTransport::new();
    let (alice, user_id, _) = alice(&transport).await;
    let old = alice.open();
    assert!(old.restore_session().await.unwrap());
    let device = Persistent::new(&transport);
    let new = device.open();

    // No bundle yet: the same session can wait again.
    let link = new.start_link(vec!["hub.example".into()]).unwrap();
    transport.faults.fail_step(Step::FetchLinkBundle);
    assert!(new.wait_link(&link).await.is_err());
    let first = old.approve_link(&link.qr_string).await.unwrap();
    transport.faults.fail_step(Step::UploadKeyPackages);
    assert!(new.wait_link(&link).await.is_err());
    device.assert_clean(&new);
    // The session is used up: the old device approves a new offer and
    // revokes the device of the failed attempt.
    assert!(matches!(
        new.wait_link(&link).await,
        Err(ClientError::InvalidInput(_))
    ));
    let link = new.start_link(vec!["hub.example".into()]).unwrap();
    let second = old.approve_link(&link.qr_string).await.unwrap();
    let linked = new.wait_link(&link).await.unwrap();
    assert_eq!(linked.sas, second.sas);
    new.confirm_link(true).await.unwrap();
    old.confirm_approval(&first, false).await.unwrap();
    old.confirm_approval(&second, true).await.unwrap();
    assert_enrolled(&new);

    let list = hub_list(&transport, &user_id);
    assert!(list.contains(&second.device.device_id));
    assert!(list.is_revoked(&first.device.device_id));
    let new = device.restart(new).await;
    assert!(new.restore_session().await.unwrap());
}
