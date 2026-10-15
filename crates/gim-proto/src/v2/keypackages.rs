use serde::{Deserialize, Serialize};

/// `UploadKeyPackagesRequest`: `POST /v2/keypackages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadKeyPackagesRequest {
    /// TLS-encoded MLS KeyPackages (1-100).
    #[serde(with = "super::base64::list")]
    pub key_packages: Vec<Vec<u8>>,
    /// When true, `key_packages` holds exactly one package, which replaces the
    /// device's last-resort KeyPackage; otherwise they join the one-time pool.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub last_resort: bool,
}

/// `KeyPackageCount`: upload response and `GET /v2/keypackages/count`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageCount {
    /// Unclaimed one-time KeyPackages of the calling device.
    pub available: u32,
    pub has_last_resort: bool,
}

/// `ClaimTarget`: a user (every active device in its DeviceList) or one
/// device of a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimTarget {
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// `ClaimKeyPackagesRequest`: `POST /v2/keypackages/claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimKeyPackagesRequest {
    pub targets: Vec<ClaimTarget>,
}

/// `ClaimKeyPackagesResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimKeyPackagesResponse {
    pub key_packages: Vec<ClaimedKeyPackage>,
    /// Targets that are unknown or have no KeyPackage at all.
    pub missing: Vec<ClaimTarget>,
}

/// `ClaimedKeyPackage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedKeyPackage {
    pub user_id: String,
    pub device_id: String,
    /// TLS-encoded MLS KeyPackage.
    #[serde(with = "super::base64::bytes")]
    pub key_package: Vec<u8>,
    /// True if this is the device's reusable last-resort package.
    pub last_resort: bool,
}
