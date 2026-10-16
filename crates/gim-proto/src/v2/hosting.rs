use serde::{Deserialize, Serialize};

/// `CreateHostingEntryRequest`: `POST /v2/users/{user_id}/hosting-entry`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateHostingEntryRequest {
    /// Priority of the hub in the record (0-255, lower is preferred);
    /// absent means 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
}

/// `HostingEntry`: 200 of `POST /v2/users/{user_id}/hosting-entry`, the
/// hub's signed entry for the caller's hosting record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingEntry {
    pub hub_id: String,
    /// The hub's 32-byte Ed25519 root public key.
    #[serde(with = "super::base64::bytes")]
    pub hub_root_pubkey: Vec<u8>,
    pub priority: u8,
    /// gim-core CBOR `HostingEntry` `[hub_root_pubkey, priority, hub_sig]`.
    #[serde(with = "super::base64::bytes")]
    pub entry: Vec<u8>,
}

/// `PutHostingRecordRequest`: `PUT /v2/users/{user_id}/hosting-record`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutHostingRecordRequest {
    /// gim-core CBOR `SignedHostingRecord`, at most 8192 bytes.
    #[serde(with = "super::base64::bytes")]
    pub hosting_record: Vec<u8>,
}

/// `HostingRecord`: `GET`/`PUT /v2/users/{user_id}/hosting-record`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingRecord {
    pub user_id: String,
    /// gim-core CBOR `SignedHostingRecord`.
    #[serde(with = "super::base64::bytes")]
    pub hosting_record: Vec<u8>,
    pub seq: u64,
    /// Unix milliseconds, exclusive.
    pub expires_at: i64,
    /// Whether the user is local to this hub and the record lists it.
    pub hosted: bool,
}

/// `HostingRecordExpiring`: data of `hosting_record.expiring`, sent when
/// less than 48 hours remain on the receiving user's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingRecordExpiring {
    pub user_id: String,
    /// Expiry of the stored record, Unix milliseconds.
    pub expires_at: i64,
    /// `seq` of the stored record.
    pub seq: u64,
}

/// `HostingRecordHub`: a hub entry of a hosting record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingRecordHub {
    pub hub_id: String,
    /// Lower is preferred.
    pub priority: u8,
}

/// `HostingRecordUpdated`: data of `hosting_record.updated`, the receiving
/// user's record as stored by this hub after its listed hubs or their
/// priorities changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingRecordUpdated {
    pub user_id: String,
    /// `seq` of the stored record; dedup across hubs by it.
    pub seq: u64,
    /// Expiry of the stored record, Unix milliseconds.
    pub expires_at: i64,
    /// Whether the record lists this hub.
    pub hosted: bool,
    pub hubs: Vec<HostingRecordHub>,
}
