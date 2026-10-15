//! The network boundary of [`crate::Client`], in domain terms. The gim-server
//! HTTP/WebSocket implementation maps it onto the gim-proto DTOs; tests use
//! [`crate::testing::FakeTransport`].
//!
//! The transport is stateless with respect to authentication: every call
//! after registration carries the device's [`AccessToken`], so one transport
//! can serve several clients.

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, MessageKind, UserInfo};
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use serde::{Deserialize, Serialize};

/// Bearer token of a registered device.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessToken(String);

impl AccessToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken(..)")
    }
}

/// Result of [`Transport::register_device`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub device: DeviceRef,
    pub token: AccessToken,
    /// Head of the device's event stream; sync starts after it.
    pub cursor: u64,
}

/// Delivery-service view of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_id: GroupId,
    pub kind: ChatKind,
    pub epoch: u64,
    /// Fan-out list.
    pub members: Vec<DeviceRef>,
}

/// A message to post to a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMessage {
    /// Idempotency key: a repeated post returns the first `seq`.
    pub client_id: ClientId,
    pub epoch: u64,
    pub kind: MessageKind,
    pub payload: Vec<u8>,
    /// Welcome recipients; empty for other kinds.
    pub recipients: Vec<DeviceRef>,
}

/// Result of [`Transport::fetch_events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBatch {
    pub events: Vec<IncomingEvent>,
    /// Pass as `cursor` next time.
    pub next_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("network error: {0}")]
    Network(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    /// The event cursor is older than the server's retention; resync, then
    /// continue from the head `cursor`.
    #[error("cursor expired; head is {cursor}")]
    Gone { cursor: u64 },
    #[error("server error: {0}")]
    Server(String),
}

/// Error of [`Transport::post_message`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PostError {
    /// A commit was posted for an epoch that is no longer current.
    #[error("commit epoch {commit_epoch} is not the current epoch")]
    EpochConflict { commit_epoch: u64 },
    #[error(transparent)]
    Transport(#[from] TransportError),
}

pub type TransportResult<T> = Result<T, TransportError>;

#[async_trait]
pub trait Transport: Send + Sync {
    /// Registers a new device; a known handle gets another device of the
    /// same user.
    async fn register_device(
        &self,
        handle: &str,
        display_name: &str,
    ) -> TransportResult<Registration>;

    async fn find_user(
        &self,
        token: &AccessToken,
        handle: &str,
    ) -> TransportResult<Option<UserInfo>>;

    async fn list_devices(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Vec<DeviceRef>>;

    /// Uploads one-time KeyPackages and optionally replaces the last-resort
    /// one (all TLS-serialized `MlsMessage`s).
    async fn upload_key_packages(
        &self,
        token: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: Option<Vec<u8>>,
    ) -> TransportResult<()>;

    /// Claims one KeyPackage of `device`; `NotFound` if it has none.
    async fn claim_key_package(
        &self,
        token: &AccessToken,
        device: &DeviceRef,
    ) -> TransportResult<Vec<u8>>;

    /// Creates a server group; the caller and `members` form its fan-out
    /// list.
    async fn create_group(
        &self,
        token: &AccessToken,
        kind: ChatKind,
        members: &[DeviceRef],
    ) -> TransportResult<GroupId>;

    async fn group_info(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
    ) -> TransportResult<GroupInfo>;

    async fn add_group_members(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()>;

    async fn remove_group_members(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()>;

    /// Posts a message and returns its per-group `seq`.
    async fn post_message(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        message: OutgoingMessage,
    ) -> Result<u64, PostError>;

    /// Events after `cursor` (`None`: from the start), waiting up to `wait`
    /// for the first one. [`TransportError::Gone`] if `cursor` expired.
    async fn fetch_events(
        &self,
        token: &AccessToken,
        cursor: Option<u64>,
        wait: Duration,
    ) -> TransportResult<EventBatch>;

    /// Up to `limit` messages of the group with `seq > after_seq`, ascending.
    async fn group_messages(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        after_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>>;

    /// Uploads the already-encrypted blob in `file`; returns its id.
    async fn upload_blob(&self, token: &AccessToken, file: &Path) -> TransportResult<String>;

    /// Downloads a blob, or the given byte range of it.
    async fn download_blob(
        &self,
        token: &AccessToken,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>>;
}
