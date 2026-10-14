use gim_common::DeviceId;
use serde::{Deserialize, Serialize};

/// `UploadKeyPackagesRequest`: `POST /v1/keypackages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadKeyPackagesRequest {
    /// One-time TLS-encoded MLS KeyPackages (0-100).
    #[serde(with = "super::base64::list")]
    pub key_packages: Vec<Vec<u8>>,
    /// Replaces the device's last-resort package, which is never consumed.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::base64::option"
    )]
    pub last_resort: Option<Vec<u8>>,
}

/// `KeyPackageCount`: upload response and `GET /v1/keypackages/count`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageCount {
    /// Unclaimed one-time key packages of the calling device.
    pub available: u64,
    pub has_last_resort: bool,
}

/// `ClaimKeyPackagesRequest`: `POST /v1/keypackages/claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimKeyPackagesRequest {
    /// 1-100 unique devices; one package is claimed for each.
    pub device_ids: Vec<DeviceId>,
}

/// `ClaimKeyPackagesResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimKeyPackagesResponse {
    pub key_packages: Vec<ClaimedKeyPackage>,
    /// Requested devices that are unknown or have no key package at all.
    pub missing: Vec<DeviceId>,
}

/// `ClaimedKeyPackage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedKeyPackage {
    pub device_id: DeviceId,
    /// TLS-encoded MLS KeyPackage.
    #[serde(with = "super::base64::bytes")]
    pub key_package: Vec<u8>,
    /// True if this is the device's reusable last-resort package.
    pub last_resort: bool,
}
