use gim_common::{ClientId, DeviceId, GroupId, UserId};
use serde::{Deserialize, Serialize};

/// `MessageKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Commit,
    Welcome,
    Application,
}

/// `SendMessageRequest`: `POST /v1/groups/{group_id}/messages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Idempotency key, unique per sending device and group (1-64 chars).
    pub client_id: ClientId,
    pub epoch: u64,
    pub kind: MessageKind,
    /// Opaque MLS message bytes (MLSMessage / Welcome).
    #[serde(with = "super::base64::bytes")]
    pub payload: Vec<u8>,
    /// Required for `welcome`, rejected for other kinds (1-500).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<DeviceId>>,
}

/// `Message`: a stored message as returned by send, history and events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub group_id: GroupId,
    /// Per-group sequence number, starting at 1.
    pub seq: u64,
    pub sender_device_id: DeviceId,
    pub sender_user_id: UserId,
    pub client_id: ClientId,
    pub kind: MessageKind,
    pub epoch: u64,
    #[serde(with = "super::base64::bytes")]
    pub payload: Vec<u8>,
    /// Welcome only: the addressed devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<DeviceId>>,
    /// Unix milliseconds.
    pub created_at: i64,
}

/// `MessageList`: `GET /v1/groups/{group_id}/messages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageList {
    pub messages: Vec<Message>,
    /// True if more messages exist after the last returned one.
    pub has_more: bool,
}

/// Query of `GET /v1/groups/{group_id}/messages`; absent fields use the
/// server defaults (`after_seq=0`, `limit=100`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagesQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_seq: Option<u64>,
    /// 1-500.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}
