use serde::{Deserialize, Serialize};

/// `GroupKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Direct,
    Group,
}

/// `Group`: delivery-service view of a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// `<owner hub_id>/<random_128 base32lower>`, assigned by the owning hub.
    pub gid: String,
    pub kind: GroupKind,
    /// Current MLS epoch, read by the hub from accepted Commits.
    pub epoch: u64,
    /// Highest `seq` stored in the group.
    pub last_seq: u64,
    pub created_by_user_id: String,
    pub created_by_device_id: String,
    /// Unix milliseconds.
    pub created_at: i64,
    pub members: Vec<GroupMember>,
}

/// `GroupMember`: one device of a group member, also a Welcome recipient.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupMember {
    pub user_id: String,
    pub device_id: String,
}

/// `GroupList`: `GET /v2/groups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupList {
    pub groups: Vec<Group>,
}

/// `CreateGroupRequest`: `POST /v2/groups`; members are added by Commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub kind: GroupKind,
}

/// `SubmitCommitRequest`: `POST /v2/groups/{gid}/commits`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitCommitRequest {
    /// Idempotency key, unique per sending device and group (1-64 chars).
    pub client_id: String,
    /// MLSMessage carrying the Commit as a PublicMessage (TLS encoding).
    #[serde(with = "super::base64::bytes")]
    pub mls_message: Vec<u8>,
    /// MLS Welcome for the devices added by this Commit.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::base64::option"
    )]
    pub welcome: Option<Vec<u8>>,
    /// Devices the Welcome is addressed to (1-500); required with `welcome`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_recipients: Option<Vec<GroupMember>>,
    /// Ratchet tree (TLS encoding) when the Welcome does not carry it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::base64::option"
    )]
    pub ratchet_tree: Option<Vec<u8>>,
}

/// `CommitResult`: 201 (200 with `duplicate` on a resend of the same Commit
/// or Proposal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitResult {
    pub seq: u64,
    /// Epoch after the Commit; unchanged for a Proposal.
    pub epoch: u64,
    pub duplicate: bool,
}

/// `MessageKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Commit,
    Application,
    /// A standalone handshake Proposal (e.g. a member's self-Remove),
    /// pending until a Commit references it.
    Proposal,
    /// Any kind this client does not know yet.
    #[serde(other)]
    Unknown,
}

/// `Message`: one entry of a group's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub gid: String,
    pub seq: u64,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub client_id: String,
    /// Opaque id assigned by the owning hub, identical on every hub storing
    /// the message (cross-hub dedup key).
    pub message_id: String,
    pub kind: MessageKind,
    pub epoch: u64,
    /// MLSMessage: PublicMessage for Commits and Proposals, PrivateMessage
    /// otherwise.
    #[serde(with = "super::base64::bytes")]
    pub mls_message: Vec<u8>,
    /// Unix milliseconds.
    pub created_at: i64,
}

/// `SendMessageRequest`: `POST /v2/groups/{gid}/messages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Idempotency key, unique per sending device and group (1-64 chars).
    pub client_id: String,
    /// MLSMessage carrying an application PrivateMessage (TLS encoding).
    #[serde(with = "super::base64::bytes")]
    pub mls_message: Vec<u8>,
}

/// `MessageList`: `GET /v2/groups/{gid}/messages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageList {
    pub messages: Vec<Message>,
    pub has_more: bool,
}

/// Query of `GET /v2/groups/{gid}/messages`; absent fields use the hub
/// defaults (`from_seq=1`, `limit=100`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagesQuery {
    /// First `seq` to return (inclusive, >= 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_seq: Option<u64>,
    /// 1-500.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}
