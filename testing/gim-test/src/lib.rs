//! Test fixtures and helpers: [`FakeDeliveryService`], an in-memory
//! stand-in for gim-hub (API v2), and deterministic gim identities
//! ([`TestIdentity`]).

#![forbid(unsafe_code)]

mod delivery;

use std::collections::BTreeMap;
use std::sync::Mutex;

use gim_common::{DeviceId, DeviceRef, UserId};
use gim_identity::{
    DeviceList, DeviceSigningKey, HubRootKey, RootKey, RootPublicKey, SignedDeviceCert,
    SignedDeviceList,
};

pub use delivery::{
    Claimed, CommitResult, Delivered, DeliveryError, Event, FakeDeliveryService, GroupInfo,
    GroupKind, MembershipChange, MessageKind, StreamEvent, SubmitCommit, User, Welcome,
    KEY_PACKAGES_LOW_THRESHOLD,
};

/// `hub_id` of [`FakeDeliveryService::new`].
pub fn fake_hub_id() -> String {
    HubRootKey::from_seed(&[0x68; 32]).public().hub_id()
}

/// A user's root key and one device key, derived from a name: the same
/// name always gives the same ids.
pub struct TestIdentity {
    pub root: RootKey,
    pub device_key: DeviceSigningKey,
    pub cert: SignedDeviceCert,
    pub device: DeviceRef,
}

impl TestIdentity {
    /// Device 0 of the user `name`.
    pub fn new(name: &str) -> Self {
        Self::device(name, 0)
    }

    /// Device `index` of the user `name`.
    pub fn device(name: &str, index: u8) -> Self {
        let root = RootKey::from_seed(&seed(name, 0xff));
        let device_key = DeviceSigningKey::from_seed(&seed(name, index));
        let public = device_key.public();
        let cert = SignedDeviceCert::issue(&root, &public, 0, 1);
        let device = DeviceRef::new(root.public().user_id(), public.device_id());
        DIRECTORY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(device.user_id.clone())
            .or_insert_with(|| (root.public(), BTreeMap::new()))
            .1
            .insert(device.device_id.clone(), cert.clone());
        Self {
            root,
            device_key,
            cert,
            device,
        }
    }

    /// The signed DeviceList (seq 1) certifying this device only.
    pub fn device_list(&self) -> SignedDeviceList {
        DeviceList::new(self.root.public(), 1, vec![self.cert.clone()], vec![])
            .and_then(|list| list.sign(&self.root))
            .expect("valid device list")
    }
}

type Certs = BTreeMap<DeviceId, SignedDeviceCert>;

/// Certs of the [`TestIdentity`] devices made in this process, by user.
static DIRECTORY: Mutex<BTreeMap<UserId, (RootPublicKey, Certs)>> = Mutex::new(BTreeMap::new());

/// A DeviceList certifying every device of the user made through
/// [`TestIdentity`] in this process: the DeviceList lookup of test MLS
/// engines (credential checks are fail-closed).
pub fn test_device_list(user_id: &UserId) -> Option<DeviceList> {
    let directory = DIRECTORY.lock().unwrap_or_else(|e| e.into_inner());
    let (root, certs) = directory.get(user_id)?;
    let seq = certs.len() as u64;
    DeviceList::new(*root, seq, certs.values().cloned().collect(), vec![]).ok()
}

fn seed(name: &str, index: u8) -> [u8; 32] {
    let mut seed = [index; 32];
    for (i, byte) in name.bytes().enumerate() {
        let slot = &mut seed[i % 32];
        *slot = slot.wrapping_mul(31).wrapping_add(byte);
    }
    seed
}
