//! Wire-format policy (handshake as PublicMessage, application as
//! PrivateMessage) and membership extraction, with gim credentials.

use std::sync::Arc;

use gim_common::{DeviceRef, GroupId};
use gim_crypto::{
    inspect_handshake, message_epoch, CryptoError, CryptoStore, DeviceListCache, HandshakeKind,
    MemoryCryptoStore, MlsEngine, ProcessedMessage,
};
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{
    GroupId as MlsGroupId, MlsGroup, MlsGroupJoinConfig, MlsMessageIn, WireFormat,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
};

struct Device {
    me: DeviceRef,
    root: RootKey,
    key: DeviceSigningKey,
    lists: Arc<DeviceListCache>,
    engine: MlsEngine,
    store: MemoryCryptoStore,
}

impl Device {
    fn new(seed: u8) -> Self {
        let root = RootKey::from_seed(&[seed; 32]);
        let key = DeviceSigningKey::from_seed(&[seed.wrapping_add(100); 32]);
        let cert = SignedDeviceCert::issue(&root, &key.public(), 1_700_000_000_000, 1);
        let lists = Arc::new(DeviceListCache::new());
        let device = Self {
            me: DeviceRef::new(root.public().user_id(), key.public().device_id()),
            engine: MlsEngine::with_device_list_lookup(lists.clone()),
            lists,
            store: MemoryCryptoStore::new(),
            root,
            key,
        };
        device
            .engine
            .create_identity_v2(&device.store, &device.key, device.root.public(), cert)
            .unwrap();
        device
    }

    fn key_package(&self) -> Vec<u8> {
        self.engine
            .generate_key_packages(&self.store, 1)
            .unwrap()
            .remove(0)
    }

    fn process(&self, message: &[u8]) -> Result<ProcessedMessage, CryptoError> {
        self.engine.process_message(&self.store, &group(), message)
    }
}

fn group() -> GroupId {
    GroupId::new("g-wire").unwrap()
}

fn wire_format(bytes: &[u8]) -> WireFormat {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .wire_format()
}

fn sorted(mut refs: Vec<DeviceRef>) -> Vec<DeviceRef> {
    refs.sort();
    refs
}

/// Alice creates the group and adds Bob and Carol in one commit.
fn trio() -> (Device, Device, Device) {
    let (alice, bob, carol) = (Device::new(1), Device::new(2), Device::new(3));
    alice.engine.create_group(&alice.store, &group()).unwrap();
    let out = alice
        .engine
        .add_members(
            &alice.store,
            &group(),
            &[bob.key_package(), carol.key_package()],
        )
        .unwrap();
    assert_eq!(out.added, vec![bob.me.clone(), carol.me.clone()]);
    assert!(out.removed.is_empty());
    assert_eq!(wire_format(&out.commit), WireFormat::PublicMessage);
    alice
        .engine
        .merge_pending_commit(&alice.store, &group())
        .unwrap();
    let welcome = out.welcome.unwrap();
    for device in [&bob, &carol] {
        let joined = device
            .engine
            .join_from_welcome(&device.store, &welcome)
            .unwrap();
        assert_eq!(
            sorted(joined.members),
            sorted(vec![alice.me.clone(), bob.me.clone(), carol.me.clone()])
        );
    }
    (alice, bob, carol)
}

#[test]
fn handshake_is_public_and_application_is_private() {
    let (alice, bob, carol) = trio();
    let ct = alice.engine.encrypt(&alice.store, &group(), b"hi").unwrap();
    assert_eq!(wire_format(&ct), WireFormat::PrivateMessage);
    assert!(matches!(
        bob.process(&ct).unwrap(),
        ProcessedMessage::Application { .. }
    ));

    let out = alice
        .engine
        .remove_members(&alice.store, &group(), std::slice::from_ref(&carol.me))
        .unwrap();
    assert_eq!(wire_format(&out.commit), WireFormat::PublicMessage);
    // The removed member still processes the PublicMessage commit.
    match carol.process(&out.commit).unwrap() {
        ProcessedMessage::Commit { self_removed, .. } => assert!(self_removed),
        other => panic!("{other:?}"),
    }
}

#[test]
fn private_message_handshake_is_rejected() {
    let (alice, bob, _carol) = trio();
    // Make Alice frame handshake messages as PrivateMessage.
    let mut mls_group = MlsGroup::load(
        alice.store.mls_storage(),
        &MlsGroupId::from_slice(group().as_str().as_bytes()),
    )
    .unwrap()
    .unwrap();
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    mls_group
        .set_configuration(alice.store.mls_storage(), &config)
        .unwrap();

    let out = alice
        .engine
        .add_members(&alice.store, &group(), &[Device::new(4).key_package()])
        .unwrap();
    assert_eq!(wire_format(&out.commit), WireFormat::PrivateMessage);
    assert!(matches!(
        bob.process(&out.commit),
        Err(CryptoError::InvalidInput { .. })
    ));
    assert_eq!(bob.engine.group_epoch(&bob.store, &group()).unwrap(), 1);
}

#[test]
fn commits_expose_added_and_removed_devices() {
    let (alice, bob, carol) = trio();
    let dave = Device::new(4);
    let out = alice
        .engine
        .add_members(&alice.store, &group(), &[dave.key_package()])
        .unwrap();
    alice
        .engine
        .merge_pending_commit(&alice.store, &group())
        .unwrap();
    match bob.process(&out.commit).unwrap() {
        ProcessedMessage::Commit {
            sender,
            added,
            removed,
            ..
        } => {
            assert_eq!(sender, alice.me);
            assert_eq!(added, out.added);
            assert_eq!(added, vec![dave.me.clone()]);
            assert!(removed.is_empty());
        }
        other => panic!("{other:?}"),
    }
    carol.process(&out.commit).unwrap();

    // Duplicates in the request are removed once.
    let out = bob
        .engine
        .remove_members(
            &bob.store,
            &group(),
            &[carol.me.clone(), dave.me.clone(), carol.me.clone()],
        )
        .unwrap();
    assert_eq!(out.removed, vec![carol.me.clone(), dave.me.clone()]);
    assert!(out.added.is_empty());
    bob.engine
        .merge_pending_commit(&bob.store, &group())
        .unwrap();
    match alice.process(&out.commit).unwrap() {
        ProcessedMessage::Commit { added, removed, .. } => {
            assert!(added.is_empty());
            assert_eq!(sorted(removed), sorted(out.removed.clone()));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        sorted(alice.engine.group_members(&alice.store, &group()).unwrap()),
        sorted(vec![alice.me.clone(), bob.me.clone()])
    );
}

#[test]
fn revoked_device_from_cache_is_removed_and_rejected() {
    let (alice, bob, carol) = trio();
    let list = DeviceList::new(
        carol.root.public(),
        1,
        vec![SignedDeviceCert::issue(
            &carol.root,
            &carol.key.public(),
            1_700_000_000_000,
            1,
        )],
        vec![],
    )
    .unwrap();
    let revoked = list.revoke(&carol.me.device_id).unwrap();
    for device in [&alice, &bob] {
        assert!(device
            .lists
            .insert(&carol.me.user_id, &list.sign(&carol.root).unwrap())
            .unwrap());
        assert!(device
            .lists
            .insert(&carol.me.user_id, &revoked.sign(&carol.root).unwrap())
            .unwrap());
    }

    // Bob no longer accepts application messages or commits from the
    // revoked device.
    let message = carol
        .engine
        .encrypt(&carol.store, &group(), b"still here")
        .unwrap();
    assert!(matches!(
        bob.process(&message),
        Err(CryptoError::InvalidCredential { .. })
    ));
    assert!(alice.engine.is_revoked(&carol.me));
    assert!(!alice.engine.is_revoked(&bob.me));

    let from_carol = carol
        .engine
        .remove_members(&carol.store, &group(), std::slice::from_ref(&alice.me))
        .unwrap();
    assert!(matches!(
        bob.process(&from_carol.commit),
        Err(CryptoError::InvalidCredential { .. })
    ));

    let out = alice
        .engine
        .remove_members(&alice.store, &group(), std::slice::from_ref(&carol.me))
        .unwrap();
    assert_eq!(out.removed, vec![carol.me.clone()]);
    alice
        .engine
        .merge_pending_commit(&alice.store, &group())
        .unwrap();
    match bob.process(&out.commit).unwrap() {
        ProcessedMessage::Commit { removed, .. } => assert_eq!(removed, vec![carol.me.clone()]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn hub_reads_epoch_and_membership_from_handshakes() {
    let (alice, bob, carol) = trio();
    let app = bob.engine.encrypt(&bob.store, &group(), b"hi").unwrap();
    assert_eq!(message_epoch(&app).unwrap(), 1);
    assert!(inspect_handshake(&app).is_err());

    let dave = Device::new(4);
    let out = alice
        .engine
        .add_members(&alice.store, &group(), &[dave.key_package()])
        .unwrap();
    let info = inspect_handshake(&out.commit).unwrap();
    assert_eq!(info.group_id, group().as_str().as_bytes());
    assert_eq!(
        (info.kind, info.epoch, info.sender_leaf),
        (HandshakeKind::Commit, 1, Some(0))
    );
    assert_eq!(info.added, vec![dave.me.clone()]);
    assert!(info.removed_leaves.is_empty());
    assert_eq!(info.referenced, 0);
    alice
        .engine
        .clear_pending_commit(&alice.store, &group())
        .unwrap();

    let out = alice
        .engine
        .remove_members(&alice.store, &group(), std::slice::from_ref(&carol.me))
        .unwrap();
    let info = inspect_handshake(&out.commit).unwrap();
    assert_eq!(info.removed_leaves, vec![2]);
    assert!(info.added.is_empty());
}

#[test]
fn leaving_sends_a_self_remove_proposal_that_another_member_commits() {
    let (alice, bob, carol) = trio();
    let proposal = carol.engine.leave_group(&carol.store, &group()).unwrap();
    assert_eq!(wire_format(&proposal), WireFormat::PublicMessage);
    let info = inspect_handshake(&proposal).unwrap();
    assert_eq!(info.kind, HandshakeKind::Proposal);
    assert_eq!((info.epoch, info.removed_leaves), (1, vec![2]));
    for device in [&alice, &bob] {
        match device.process(&proposal).unwrap() {
            ProcessedMessage::Proposal { sender, removed } => {
                assert_eq!(sender, carol.me);
                assert_eq!(removed, Some(carol.me.clone()));
            }
            other => panic!("{other:?}"),
        }
    }
    // The committer drops the stored proposal and removes Carol inline.
    let out = alice
        .engine
        .remove_members(&alice.store, &group(), std::slice::from_ref(&carol.me))
        .unwrap();
    assert_eq!(inspect_handshake(&out.commit).unwrap().referenced, 0);
    alice
        .engine
        .merge_pending_commit(&alice.store, &group())
        .unwrap();
    match bob.process(&out.commit).unwrap() {
        ProcessedMessage::Commit { removed, .. } => assert_eq!(removed, vec![carol.me.clone()]),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        sorted(alice.engine.group_members(&alice.store, &group()).unwrap()),
        sorted(vec![alice.me.clone(), bob.me.clone()])
    );
}
