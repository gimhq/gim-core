//! Restore from the recovery code: the DeviceList is read from the hub
//! without a session and the next one keeps or revokes the old devices.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use common::FlakyTransport;
use gim_base::MemoryStore;
use gim_common::{DeviceId, UserId};
use gim_identity::recovery::RecoveryCode;
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert, SignedDeviceList};
use gim_sdk::testing::MemorySecretStorage;
use gim_sdk::transport::TransportError;
use gim_sdk::{Client, ClientBuilder, ClientError, SecretStorage, Transport, ROOT_KEY_SECRET_KEY};
use tempfile::TempDir;

struct Device {
    client: Client<MemoryStore>,
    secrets: Arc<MemorySecretStorage>,
    _data_dir: TempDir,
}

impl Device {
    fn new(transport: &FlakyTransport) -> Self {
        let secrets = Arc::new(MemorySecretStorage::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = ClientBuilder::new(
            Arc::new(MemoryStore::new()),
            Arc::new(transport.clone()),
            secrets.clone() as Arc<dyn SecretStorage>,
        )
        .data_dir(data_dir.path())
        .build()
        .unwrap();
        Self {
            client,
            secrets,
            _data_dir: data_dir,
        }
    }

    fn device_id(&self) -> DeviceId {
        self.client.session().unwrap().device.device_id
    }

    fn root(&self) -> RootKey {
        let seed = self.secrets.get(ROOT_KEY_SECRET_KEY).unwrap().unwrap();
        RootKey::from_seed(&seed.try_into().unwrap())
    }
}

/// Alice with two devices: the registered one and a second one listed in a
/// later DeviceList. Returns the first device and the recovery code.
async fn alice(transport: &FlakyTransport) -> (Device, RecoveryCode, DeviceId) {
    let alice = Device::new(transport);
    let code = alice.client.register("alice", "Alice").await.unwrap();
    let user_id = alice.client.session().unwrap().device.user_id;
    let (second, _, list) = extend(&alice, &hub_list(transport, &user_id));
    transport
        .inner
        .put_device_list(&user_id, list)
        .await
        .unwrap();
    (alice, code, second)
}

/// The user's DeviceList on the hub.
fn hub_list(transport: &FlakyTransport, user_id: &UserId) -> DeviceList {
    let bytes = transport.inner.service().device_list(user_id).unwrap();
    SignedDeviceList::from_bytes(&bytes)
        .and_then(|signed| signed.verify(user_id))
        .unwrap()
}

/// `current` with one more device (seq + 1), signed by `owner`'s root key.
fn extend(owner: &Device, current: &DeviceList) -> (DeviceId, DeviceList, Vec<u8>) {
    let root = owner.root();
    let device = DeviceSigningKey::generate().unwrap().public();
    let cert = SignedDeviceCert::issue(&root, &device, 0, current.seq() + 1);
    let list = current.add_cert(cert).unwrap();
    let bytes = list.sign(&root).unwrap().to_bytes();
    (device.device_id(), list, bytes)
}

/// Queues `list` to land on the hub right before the next upload.
fn land_concurrently(transport: &FlakyTransport, user_id: &UserId, list: Vec<u8>) {
    transport
        .faults
        .concurrent_lists
        .lock()
        .unwrap()
        .push_back((user_id.clone(), list));
}

fn certified(list: &DeviceList) -> BTreeSet<DeviceId> {
    list.certs().map(|c| c.device_id.clone()).collect()
}

fn revoked(list: &DeviceList) -> BTreeSet<DeviceId> {
    list.revoked().iter().cloned().collect()
}

#[tokio::test]
async fn revoking_others_publishes_the_next_list_with_every_old_device_revoked() {
    let transport = FlakyTransport::new();
    let (alice, code, second) = alice(&transport).await;
    let user_id = alice.client.session().unwrap().device.user_id;
    let before = hub_list(&transport, &user_id);

    let restored = Device::new(&transport);
    restored
        .client
        .restore_from_recovery(&user_id, &code, true)
        .await
        .unwrap();
    let after = hub_list(&transport, &user_id);
    assert_eq!(after.seq(), before.seq() + 1);
    assert_eq!(certified(&after), BTreeSet::from([restored.device_id()]));
    assert_eq!(revoked(&after), BTreeSet::from([alice.device_id(), second]));
}

#[tokio::test]
async fn keeping_others_on_a_fresh_install_keeps_every_old_device() {
    let transport = FlakyTransport::new();
    let (alice, code, second) = alice(&transport).await;
    let user_id = alice.client.session().unwrap().device.user_id;
    let before = hub_list(&transport, &user_id);

    let restored = Device::new(&transport);
    restored
        .client
        .restore_from_recovery(&user_id, &code, false)
        .await
        .unwrap();
    let after = hub_list(&transport, &user_id);
    assert_eq!(after.seq(), before.seq() + 1);
    assert_eq!(
        certified(&after),
        BTreeSet::from([alice.device_id(), second, restored.device_id()])
    );
    assert!(after.revoked().is_empty());
    // The old device stays signed in.
    alice.client.sync_once().await.unwrap();
}

#[tokio::test]
async fn a_concurrent_list_is_read_again_and_rebuilt_once() {
    let transport = FlakyTransport::new();
    let (alice, code, second) = alice(&transport).await;
    let user_id = alice.client.session().unwrap().device.user_id;
    let before = hub_list(&transport, &user_id);
    let (third, _, concurrent) = extend(&alice, &before);
    land_concurrently(&transport, &user_id, concurrent);

    let restored = Device::new(&transport);
    restored
        .client
        .restore_from_recovery(&user_id, &code, true)
        .await
        .unwrap();
    let after = hub_list(&transport, &user_id);
    assert_eq!(after.seq(), before.seq() + 2);
    assert_eq!(certified(&after), BTreeSet::from([restored.device_id()]));
    assert_eq!(
        revoked(&after),
        BTreeSet::from([alice.device_id(), second, third])
    );
    let reads = transport.faults.list_requests.lock().unwrap().clone();
    assert_eq!(reads, [user_id.clone(), user_id]);
}

#[tokio::test]
async fn a_second_concurrent_list_fails_the_restore() {
    let transport = FlakyTransport::new();
    let (alice, code, _) = alice(&transport).await;
    let user_id = alice.client.session().unwrap().device.user_id;
    let (_, first, first_bytes) = extend(&alice, &hub_list(&transport, &user_id));
    let (_, _, second_bytes) = extend(&alice, &first);
    land_concurrently(&transport, &user_id, first_bytes);
    land_concurrently(&transport, &user_id, second_bytes);
    let restored = Device::new(&transport);
    let result = restored
        .client
        .restore_from_recovery(&user_id, &code, true)
        .await;
    assert!(
        matches!(
            result,
            Err(ClientError::Transport(TransportError::Conflict(_)))
        ),
        "{result:?}"
    );
    assert!(restored.client.session().is_none());
}

#[tokio::test]
async fn a_missing_list_fails_the_restore() {
    let transport = FlakyTransport::new();
    let (alice, code, _) = alice(&transport).await;
    let user_id = alice.client.session().unwrap().device.user_id;
    transport
        .faults
        .hidden_lists
        .lock()
        .unwrap()
        .insert(user_id.clone(), 1);

    let restored = Device::new(&transport);
    let result = restored
        .client
        .restore_from_recovery(&user_id, &code, true)
        .await;
    assert!(
        matches!(
            result,
            Err(ClientError::Transport(TransportError::NotFound(_)))
        ),
        "{result:?}"
    );
    assert!(restored.client.session().is_none());
}
