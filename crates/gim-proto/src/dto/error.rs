use serde::{Deserialize, Serialize};

/// Error code of a 409 on `POST /v1/groups/{group_id}/messages`.
pub const STALE_EPOCH: &str = "stale_epoch";
/// Error code of a 410 on `GET /v1/events` and of a stream error frame.
pub const CURSOR_EXPIRED: &str = "cursor_expired";

/// `Error`: the body of every non-2xx JSON response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

/// The inner `error` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable snake_case code, e.g. `not_found`.
    pub code: String,
    pub message: String,
}

/// `StaleEpochError`: 409 body when a commit does not carry the current epoch.
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
