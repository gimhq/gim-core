//! gim identity: Ed25519 root and device keys, `user_id` / `device_id`
//! derivation, root-signed device certificates and device lists, hub
//! identity and proof of possession, hosting records, hub URLs and device
//! authentication. Pure encoding and verification; no I/O. The normative wire format is
//! `docs/identity.md`.

#![forbid(unsafe_code)]

mod auth;
mod cbor;
mod cert;
mod error;
mod hosting;
mod ids;
mod keys;
mod list;
mod url;

pub mod link;
pub mod recovery;

pub use auth::{
    AuthChallenge, AuthResponse, AUTH_CHALLENGE_MAX_LIFETIME_MS, AUTH_CHALLENGE_V2,
    AUTH_RESPONSE_CONTEXT,
};
pub use cert::{DeviceCert, SignedDeviceCert, DEVICE_CERT_CONTEXT};
pub use error::IdentityError;
pub use hosting::{
    libp2p_peer_id_bytes, HostingEntry, HubRootKey, HubRootPublicKey, HubRuntimeCert,
    HubRuntimePublicKey, SignedHostingRecord, SignedHubRuntimeCert, UserHostingRecord,
    HOSTING_ENTRY_CONTEXT, HOSTING_RECORD_CONTEXT, HUB_PROOF_CONTEXT, HUB_RUNTIME_CERT_CONTEXT,
    MAX_HUBS,
};
pub use ids::{parse_device_id, parse_user_id};
pub use keys::{DevicePublicKey, DeviceSigningKey, RootKey, RootPublicKey};
pub use list::{DeviceList, SignedDeviceList, DEVICE_LIST_CONTEXT};
pub use url::{normalize_hub_url, MAX_HUB_URL_LEN};

/// Version number carried as the first element of every signed body.
pub const FORMAT_VERSION: u64 = 1;
