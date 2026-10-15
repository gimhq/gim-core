//! gim identity: Ed25519 root and device keys, `user_id` / `device_id`
//! derivation, root-signed device certificates and device lists. Pure
//! encoding and verification; no I/O. The normative wire format is
//! `docs/identity.md`.

#![forbid(unsafe_code)]

mod cbor;
mod cert;
mod error;
mod ids;
mod keys;
mod list;

pub mod link;
pub mod recovery;

pub use cert::{DeviceCert, SignedDeviceCert, DEVICE_CERT_CONTEXT};
pub use error::IdentityError;
pub use ids::{parse_device_id, parse_user_id};
pub use keys::{DevicePublicKey, DeviceSigningKey, RootKey, RootPublicKey};
pub use list::{DeviceList, SignedDeviceList, DEVICE_LIST_CONTEXT};

/// Version number carried as the first element of every signed body.
pub const FORMAT_VERSION: u64 = 1;
