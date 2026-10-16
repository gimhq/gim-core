use serde::{Deserialize, Serialize};

/// Error code of a 409 on `POST /v2/groups/{gid}/commits` and `/messages`.
pub const STALE_EPOCH: &str = "stale_epoch";
/// Error code of a 410 on `GET /v2/events` and of a stream error frame.
pub const CURSOR_EXPIRED: &str = "cursor_expired";
/// Error code of a 400 on `PUT /v2/users/{user_id}/hosting-record`: the
/// record does not verify or its lifetime is out of range.
pub const INVALID_HOSTING_RECORD: &str = "invalid_hosting_record";
/// Error code of a 409 on `PUT /v2/users/{user_id}/hosting-record`: the
/// hub stores a record with a higher seq, or another one with the same seq.
pub const STALE_HOSTING_RECORD: &str = "stale_hosting_record";
/// Error code of a 403 on a federated request of a user without a valid
/// hosting record listing the hub.
pub const HOSTING_RECORD_REQUIRED: &str = "hosting_record_required";
/// Error code of a 502: a peer hub refused the request.
pub const PEER_REFUSED: &str = "peer_refused";
/// Error code of a 503 (with `Retry-After`): a peer hub did not answer.
pub const PEER_UNAVAILABLE: &str = "peer_unavailable";
/// Error code of a 409 on `POST /v2/keypackages`: the upload contains a
/// KeyPackage this hub already claimed from another hub.
pub const DUPLICATE_KEY_PACKAGE: &str = "duplicate_key_package";
/// Marker in the message of a 400 `validation_failed` on
/// `POST /v2/groups/{gid}/commits`: an Add's KeyPackage was not claimed
/// through this hub.
pub const KP_NOT_CLAIMED: &str = "kp_not_claimed";

/// `Health`: `GET /healthz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub status: HealthStatus,
    /// Hub build version.
    pub version: String,
}

/// `HubInfo`: `GET /v2/hub` (no token), so a client can check that a URL
/// belongs to the `hub_id` listed in its hosting record before signing in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubInfo {
    pub hub_id: String,
    /// The hub's 32-byte Ed25519 root public key; `hub_id` derives from it.
    #[serde(with = "super::base64::bytes")]
    pub hub_root_pubkey: Vec<u8>,
    /// Hub version.
    pub version: String,
}

/// `HealthStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
}

/// `Error`: the body of every non-2xx JSON response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

/// `ErrorBody`: the inner `error` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable snake_case code, e.g. `not_found`.
    pub code: String,
    pub message: String,
}

/// `StaleEpochError`: 409 body when a message or Commit is for a past epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleEpochError {
    pub error: ErrorBody,
    pub current_epoch: u64,
}

/// `CursorExpiredError`: 410 body when events after the cursor were pruned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorExpiredError {
    pub error: ErrorBody,
    /// Current head cursor; resync, then continue from here.
    pub cursor: u64,
}

/// `BlobCreated`: 201 of `POST /v2/blobs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobCreated {
    pub blob_id: String,
    pub size: u64,
}

/// `PushProvider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushProvider {
    Apns,
    Fcm,
    #[serde(rename = "unifiedpush")]
    UnifiedPush,
    Log,
}

/// `PushRegistration`: `PUT /v2/push/registration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistration {
    pub provider: PushProvider,
    /// APNs device token (hex), FCM registration token, UnifiedPush endpoint
    /// URL, or any string for `log`.
    pub token: String,
    /// APNs topic or FCM app ID; ignored by other providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// APNs only: deliver through the sandbox environment.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sandbox: bool,
    /// UnifiedPush only: RFC 8291 Web Push public key (base64url of the
    /// 65-byte uncompressed P-256 point).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p256dh: Option<String>,
    /// UnifiedPush only: RFC 8291 authentication secret (base64url of 16
    /// bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}
