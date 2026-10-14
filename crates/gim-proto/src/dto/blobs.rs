use serde::{Deserialize, Serialize};

/// `BlobCreated`: `POST /v1/blobs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobCreated {
    pub blob_id: String,
    /// Stored size in bytes.
    pub size: u64,
}
