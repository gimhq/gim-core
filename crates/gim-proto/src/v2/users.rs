use serde::{Deserialize, Serialize};

/// `Me`: `GET /v2/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Me {
    pub user_id: String,
    pub device_id: String,
    /// Handle claimed in this hub's directory, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// `User`: `GET /v2/users/{user_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    /// Signed gim-core DeviceList CBOR.
    #[serde(with = "super::base64::bytes")]
    pub device_list: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// `DeviceList`: `GET`/`PUT /v2/users/{user_id}/device-list` response and
/// data of the `device_list.updated` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceList {
    pub user_id: String,
    /// Signed gim-core DeviceList CBOR.
    #[serde(with = "super::base64::bytes")]
    pub device_list: Vec<u8>,
}

/// `PutDeviceListRequest`: `PUT /v2/users/{user_id}/device-list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutDeviceListRequest {
    /// Signed gim-core DeviceList CBOR.
    #[serde(with = "super::base64::bytes")]
    pub device_list: Vec<u8>,
}

/// `Handle`: `GET`/`PUT /v2/handles/{handle}` (`PUT` has no body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handle {
    /// 3-32 chars of `a-z`, `0-9`, `_`.
    pub handle: String,
    pub user_id: String,
}

/// `PutRecoveryBackupRequest`: `PUT /v2/users/{user_id}/recovery-backup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutRecoveryBackupRequest {
    /// Encrypted gim-core recovery backup, at most 65536 bytes.
    #[serde(with = "super::base64::bytes")]
    pub backup: Vec<u8>,
}

/// `RecoveryBackup`: `GET`/`PUT /v2/users/{user_id}/recovery-backup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBackup {
    pub user_id: String,
    /// Encrypted gim-core recovery backup.
    #[serde(with = "super::base64::bytes")]
    pub backup: Vec<u8>,
    /// Unix milliseconds.
    pub updated_at: i64,
}

/// `CreateLinkBundleRequest`: `POST /v2/link-bundles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateLinkBundleRequest {
    /// Shown by the new device (QR code).
    pub link_id: String,
    /// Sealed gim-core link bundle.
    #[serde(with = "super::base64::bytes")]
    pub sealed_bundle: Vec<u8>,
    /// Lifetime in seconds.
    pub expires_in: u32,
}

/// `LinkBundleCreated`: 201 of `POST /v2/link-bundles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkBundleCreated {
    pub link_id: String,
    /// Unix milliseconds.
    pub expires_at: i64,
}

/// `LinkBundle`: `GET /v2/link-bundles/{link_id}`; deleted on first fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkBundle {
    pub link_id: String,
    #[serde(with = "super::base64::bytes")]
    pub sealed_bundle: Vec<u8>,
}

/// Query of `GET /v2/link-bundles/{link_id}`; absent `wait` means 0.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkBundleQuery {
    /// Long-poll timeout in seconds (0-30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<u32>,
}
