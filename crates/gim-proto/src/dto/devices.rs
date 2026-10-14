use gim_common::{DeviceId, UserId};
use serde::{Deserialize, Serialize};

/// `Health`: `GET /healthz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub status: HealthStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
}

/// `RegisterDeviceRequest`: `POST /v1/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    /// 3-32 chars of `a-z`, `0-9`, `_`.
    pub handle: String,
    /// 1-64 chars.
    pub display_name: String,
}

/// `RegisterDeviceResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// Bearer token for this device; returned once.
    pub token: String,
    /// Current head cursor; start the event stream from here.
    pub cursor: u64,
}

/// `Me`: `GET /v1/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Me {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub handle: String,
    pub display_name: String,
}

/// `User`: `GET /v1/users?handle=` and `GET /v1/users/{user_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub user_id: UserId,
    pub handle: String,
    pub display_name: String,
}

/// Query of `GET /v1/users`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsersQuery {
    pub handle: String,
}

/// `UserDevices`: `GET /v1/users/{user_id}/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDevices {
    pub devices: Vec<Device>,
}

/// `Device`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub device_id: DeviceId,
    /// Unix milliseconds.
    pub created_at: i64,
}
