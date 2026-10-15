//! Groups of devices with gim credentials: lifecycle, and rejection of
//! forged, mismatched, revoked and basic credentials.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use gim_common::{DeviceRef, GroupId, UserId};
use gim_crypto::{
    CryptoError, CryptoStore, DeviceListLookup, GimCredential, MemoryCryptoStore, MlsEngine,
    ProcessedMessage, StoredIdentity,
};
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert};

/// Device lists known to one device, keyed by user.
#[derive(Default)]
struct Lists(RwLock<HashMap<UserId, DeviceList>>);

impl DeviceListLookup for Lists {
    fn device_list(&self, user_id: &UserId) -> Option<DeviceList> {
        self.0.read().unwrap().get(user_id).cloned()
    }
}

struct Device {
    me: DeviceRef,
    root: RootKey,
    key: DeviceSigningKey,
    lists: Arc<Lists>,
    engine: MlsEngine,
    store: MemoryCryptoStore,
}

impl Device {
    fn new(seed: u8) -> Self {
        let root = RootKey::from_seed(&[seed; 32]);
        let key = DeviceSigningKey::from_seed(&[seed.wrapping_add(100); 32]);
        let cert = SignedDeviceCert::issue(&root, &key.public(), 1_700_000_000_000, 1);
        let device = Self::empty(root, key);
        device
            .engine
            .create_identity_v2(&device.store, &device.key, device.root.public(), cert)
            .unwrap();
        device
    }

    /// A device whose store holds `identity` as written, bypassing the
    /// checks of `create_identity_v2`.
    fn crafted(
        seed: u8,
        identity: impl FnOnce(&RootKey, &DeviceSigningKey) -> StoredIdentity,
    ) -> Self {
        let root = RootKey::from_seed(&[seed; 32]);
        let key = DeviceSigningKey::from_seed(&[seed.wrapping_add(100); 32]);
        let device = Self::empty(root, key);
        device
            .store
            .save_identity(&identity(&device.root, &device.key))
            .unwrap();
        device
    }

    fn empty(root: RootKey, key: DeviceSigningKey) -> Self {
        let lists = Arc::new(Lists::default());
        Self {
            me: DeviceRef::new(root.public().user_id(), key.public().device_id()),
            root,
            key,
            engine: MlsEngine::with_device_list_lookup(lists.clone()),
            lists,
            store: MemoryCryptoStore::new(),
        }
    }

    /// Makes this device learn a device list of `other`'s user revoking it.
    fn learn_revocation(&self, other: &Device) {
        let list = DeviceList::new(
            other.root.public(),
            2,
            vec![],
            vec![other.key.public().device_id()],
        )
        .unwrap();
        self.lists
            .0
            .write()
            .unwrap()
            .insert(other.me.user_id.clone(), list);
    }

    fn key_package(&self) -> Vec<u8> {
        self.engine
            .generate_key_packages(&self.store, 1)
            .unwrap()
            .remove(0)
    }

    fn epoch(&self, g: &GroupId) -> u64 {
        self.engine.group_epoch(&self.store, g).unwrap()
    }

    fn members(&self, g: &GroupId) -> Vec<DeviceRef> {
        let mut members = self.engine.group_members(&self.store, g).unwrap();
        members.sort();
        members
    }

    /// Adds `others` and merges; returns the commit and the Welcome.
    fn add(&self, g: &GroupId, others: &[&Device]) -> (Vec<u8>, Vec<u8>) {
        let kps: Vec<_> = others.iter().map(|d| d.key_package()).collect();
        let out = self.engine.add_members(&self.store, g, &kps).unwrap();
        self.engine.merge_pending_commit(&self.store, g).unwrap();
        (out.commit, out.welcome.unwrap())
    }

    fn join(&self, welcome: &[u8]) -> Result<GroupId, CryptoError> {
        Ok(self
            .engine
            .join_from_welcome(&self.store, welcome)?
            .group_id)
    }

    fn process(&self, g: &GroupId, message: &[u8]) -> Result<ProcessedMessage, CryptoError> {
        self.engine.process_message(&self.store, g, message)
    }
}

fn group() -> GroupId {
    GroupId::new("g-credential").unwrap()
}

fn sorted(devices: &[&Device]) -> Vec<DeviceRef> {
    let mut refs: Vec<_> = devices.iter().map(|d| d.me.clone()).collect();
    refs.sort();
    refs
}

fn assert_invalid_credential<T: std::fmt::Debug>(result: Result<T, CryptoError>) {
    assert!(
        matches!(result, Err(CryptoError::InvalidCredential { .. })),
        "{result:?}"
    );
}

#[test]
fn three_devices_create_join_add_remove_message() {
    let g = group();
    let (alice, bob, carol) = (Device::new(1), Device::new(2), Device::new(3));
    assert_eq!(alice.engine.identity(&alice.store).unwrap(), alice.me);
    assert_eq!(
        alice.engine.signature_public_key(&alice.store).unwrap(),
        alice.key.public().as_bytes().to_vec()
    );

    alice.engine.create_group(&alice.store, &g).unwrap();
    let (_, welcome) = alice.add(&g, &[&bob]);
    assert_eq!(bob.join(&welcome).unwrap(), g);

    let (commit, welcome) = alice.add(&g, &[&carol]);
    match bob.process(&g, &commit).unwrap() {
        ProcessedMessage::Commit { sender, added, .. } => {
            assert_eq!(sender, alice.me);
            assert_eq!(added, vec![carol.me.clone()]);
        }
        other => panic!("{other:?}"),
    }
    carol.join(&welcome).unwrap();
    for device in [&alice, &bob, &carol] {
        assert_eq!(device.members(&g), sorted(&[&alice, &bob, &carol]));
    }

    let ct = carol.engine.encrypt(&carol.store, &g, b"hi").unwrap();
    for device in [&alice, &bob] {
        match device.process(&g, &ct).unwrap() {
            ProcessedMessage::Application {
                sender, plaintext, ..
            } => {
                assert_eq!(sender, carol.me);
                assert_eq!(plaintext, b"hi");
            }
            other => panic!("{other:?}"),
        }
    }

    let out = alice
        .engine
        .remove_members(&alice.store, &g, std::slice::from_ref(&bob.me))
        .unwrap();
    alice.engine.merge_pending_commit(&alice.store, &g).unwrap();
    match carol.process(&g, &out.commit).unwrap() {
        ProcessedMessage::Commit { removed, .. } => assert_eq!(removed, vec![bob.me.clone()]),
        other => panic!("{other:?}"),
    }
    match bob.process(&g, &out.commit).unwrap() {
        ProcessedMessage::Commit { self_removed, .. } => assert!(self_removed),
        other => panic!("{other:?}"),
    }
    assert!(!bob.engine.has_group(&bob.store, &g).unwrap());
    assert_eq!(alice.members(&g), sorted(&[&alice, &carol]));
    assert_eq!(carol.members(&g), sorted(&[&alice, &carol]));

    // The credential survives a store export/import.
    let restored = MemoryCryptoStore::import(&alice.store.export().unwrap()).unwrap();
    assert_eq!(
        restored.load_identity().unwrap(),
        alice.store.load_identity().unwrap()
    );
    let ct = alice
        .engine
        .encrypt(&restored, &g, b"after restart")
        .unwrap();
    assert!(matches!(
        carol.process(&g, &ct).unwrap(),
        ProcessedMessage::Application { .. }
    ));
}

#[test]
fn create_identity_v2_checks_chain_and_key() {
    let root = RootKey::from_seed(&[1; 32]);
    let other_root = RootKey::from_seed(&[2; 32]);
    let key = DeviceSigningKey::from_seed(&[3; 32]);
    let other_key = DeviceSigningKey::from_seed(&[4; 32]);
    let engine = MlsEngine::new();

    let forged = SignedDeviceCert::issue(&other_root, &key.public(), 0, 1);
    let store = MemoryCryptoStore::new();
    assert_invalid_credential(engine.create_identity_v2(&store, &key, root.public(), forged));
    let cert = SignedDeviceCert::issue(&root, &key.public(), 0, 1);
    assert_invalid_credential(engine.create_identity_v2(
        &store,
        &other_key,
        root.public(),
        cert.clone(),
    ));
    assert!(store.load_identity().unwrap().is_none());

    engine
        .create_identity_v2(&store, &key, root.public(), cert.clone())
        .unwrap();
    let identity = store.load_identity().unwrap().unwrap();
    assert_eq!(
        identity.credential,
        Some(GimCredential::new(root.public(), cert.clone()).encode())
    );
    assert!(engine
        .create_identity_v2(&store, &key, root.public(), cert)
        .is_err());
}

/// A device whose credential claims its own root but whose cert was signed
/// by another root.
fn forged_device(seed: u8) -> Device {
    Device::crafted(seed, |root, key| {
        let other_root = RootKey::from_seed(&[seed.wrapping_add(50); 32]);
        let cert = SignedDeviceCert::issue(&other_root, &key.public(), 0, 1);
        StoredIdentity {
            device: DeviceRef::new(root.public().user_id(), key.public().device_id()),
            signature_private_key: key.to_seed().to_vec(),
            signature_public_key: key.public().as_bytes().to_vec(),
            credential: Some(GimCredential::new(root.public(), cert).encode()),
        }
    })
}

#[test]
fn forged_cert_rejected_on_add() {
    let g = group();
    let alice = Device::new(1);
    let mallory = forged_device(9);
    alice.engine.create_group(&alice.store, &g).unwrap();
    assert_invalid_credential(
        alice
            .engine
            .add_members(&alice.store, &g, &[mallory.key_package()]),
    );
    assert_eq!(alice.epoch(&g), 0);
    assert!(matches!(
        alice.engine.merge_pending_commit(&alice.store, &g),
        Err(CryptoError::NoPendingCommit)
    ));
}

#[test]
fn forged_cert_rejected_on_welcome() {
    let g = group();
    let bob = Device::new(2);
    let mallory = forged_device(9);
    mallory.engine.create_group(&mallory.store, &g).unwrap();
    let (_, welcome) = mallory.add(&g, &[&bob]);
    assert_invalid_credential(bob.join(&welcome));
    assert!(!bob.engine.has_group(&bob.store, &g).unwrap());
}

#[test]
fn leaf_key_mismatch_rejected() {
    let g = group();
    let alice = Device::new(1);
    // Certifies one key but signs with another.
    let eve = Device::crafted(7, |root, key| {
        let certified = DeviceSigningKey::from_seed(&[77; 32]).public();
        let cert = SignedDeviceCert::issue(root, &certified, 0, 1);
        StoredIdentity {
            device: DeviceRef::new(root.public().user_id(), certified.device_id()),
            signature_private_key: key.to_seed().to_vec(),
            signature_public_key: key.public().as_bytes().to_vec(),
            credential: Some(GimCredential::new(root.public(), cert).encode()),
        }
    });
    alice.engine.create_group(&alice.store, &g).unwrap();
    assert_invalid_credential(
        alice
            .engine
            .add_members(&alice.store, &g, &[eve.key_package()]),
    );

    let bob = Device::new(2);
    eve.engine.create_group(&eve.store, &g).unwrap();
    let (_, welcome) = eve.add(&g, &[&bob]);
    assert_invalid_credential(bob.join(&welcome));
}

#[test]
fn revoked_device_rejected_on_add() {
    let g = group();
    let (alice, dave) = (Device::new(1), Device::new(4));
    alice.engine.create_group(&alice.store, &g).unwrap();
    alice.learn_revocation(&dave);
    assert_invalid_credential(
        alice
            .engine
            .add_members(&alice.store, &g, &[dave.key_package()]),
    );
    assert_eq!(alice.epoch(&g), 0);
}

#[test]
fn revoked_device_rejected_on_incoming_commit() {
    let g = group();
    let (alice, bob, carol, dave) = (
        Device::new(1),
        Device::new(2),
        Device::new(3),
        Device::new(4),
    );
    alice.engine.create_group(&alice.store, &g).unwrap();
    let (_, welcome) = alice.add(&g, &[&bob, &carol]);
    bob.join(&welcome).unwrap();
    carol.join(&welcome).unwrap();

    // A commit adding a device the receiver knows to be revoked.
    bob.learn_revocation(&dave);
    let (commit, _) = alice.add(&g, &[&dave]);
    assert_invalid_credential(bob.process(&g, &commit));
    assert_eq!(bob.epoch(&g), 1);
    assert_eq!(bob.members(&g), sorted(&[&alice, &bob, &carol]));
    // Carol does not know the revocation and accepts it.
    assert!(carol.process(&g, &commit).is_ok());

    // A commit sent by a device the receiver knows to be revoked.
    alice.learn_revocation(&carol);
    let erin = Device::new(5);
    let out = carol
        .engine
        .add_members(&carol.store, &g, &[erin.key_package()])
        .unwrap();
    assert_invalid_credential(alice.process(&g, &out.commit));
    assert_eq!(alice.epoch(&g), 2);
    assert_eq!(alice.members(&g), sorted(&[&alice, &bob, &carol, &dave]));
}

#[test]
fn welcome_from_revoked_device_rejected() {
    let g = group();
    let (alice, bob) = (Device::new(1), Device::new(2));
    alice.engine.create_group(&alice.store, &g).unwrap();
    bob.learn_revocation(&alice);
    let (_, welcome) = alice.add(&g, &[&bob]);
    assert_invalid_credential(bob.join(&welcome));
    assert!(!bob.engine.has_group(&bob.store, &g).unwrap());
}

#[test]
fn basic_key_package_rejected_by_v2_group() {
    let g = group();
    let alice = Device::new(1);
    let legacy = MlsEngine::new();
    let legacy_store = MemoryCryptoStore::new();
    legacy
        .create_identity(&legacy_store, DeviceRef::parse("bob", "phone").unwrap())
        .unwrap();
    let kp = legacy
        .generate_key_packages(&legacy_store, 1)
        .unwrap()
        .remove(0);
    alice.engine.create_group(&alice.store, &g).unwrap();
    assert_invalid_credential(alice.engine.add_members(&alice.store, &g, &[kp]));
    assert_eq!(alice.epoch(&g), 0);
}
