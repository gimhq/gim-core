//! The network boundary of [`crate::Client`], in domain terms. The gim-hub
//! API v2 HTTP/WebSocket implementation maps it onto the gim-proto v2 DTOs;
//! tests use [`crate::testing::FakeTransport`].
//!
//! The transport is stateless with respect to authentication: every call
//! after sign-in carries the device's [`AccessToken`], so one transport can
//! serve several clients. Identity objects (DeviceList, AuthResponse,
//! recovery backup) are opaque gim-identity CBOR bytes here.

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, IncomingEvent};
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use serde::{Deserialize, Serialize};

/// Bearer token of a signed-in device.
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

/// Result of [`Transport::auth_challenge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// gim-identity AuthChallenge bytes, signed as is into an AuthResponse.
    pub challenge: Vec<u8>,
    /// `hub_id` of the hub: the challenge's audience.
    pub hub_id: String,
}

/// Result of [`Transport::create_session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub token: AccessToken,
    /// Unix milliseconds; sign in again after this.
    pub expires_at_ms: u64,
}

/// A user of the hub directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub user_id: UserId,
    /// Signed gim-identity DeviceList.
    pub device_list: Vec<u8>,
    pub handle: Option<String>,
    /// The hub has no profiles; only test transports know one.
    pub display_name: Option<String>,
}

/// Delivery-service view of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_id: GroupId,
    pub kind: ChatKind,
    pub epoch: u64,
    pub last_seq: u64,
    /// Member devices, as the hub read them from the commits.
    pub members: Vec<DeviceRef>,
}

/// The calling device's KeyPackages on the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPackageCount {
    /// Unclaimed one-time KeyPackages.
    pub available: u64,
    pub has_last_resort: bool,
}

/// A KeyPackage claimed for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedKeyPackage {
    pub device: DeviceRef,
    pub key_package: Vec<u8>,
}

/// A Commit (or a Proposal) to submit to a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingCommit {
    /// Idempotency key of the sending device.
    pub client_id: ClientId,
    /// The PublicMessage carrying the Commit or Proposal.
    pub mls_message: Vec<u8>,
    /// Welcome of the devices the Commit adds.
    pub welcome: Option<Vec<u8>>,
    pub welcome_recipients: Vec<DeviceRef>,
}

/// Result of [`Transport::submit_commit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitAccepted {
    pub seq: u64,
    /// Group epoch after the Commit.
    pub epoch: u64,
    /// The hub already had this Commit (a resend); still a success.
    pub duplicate: bool,
}

/// One event of the device's event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubEvent {
    /// A group event for gim-base. Welcomes are messages of kind
    /// `Welcome` at the seq of their Commit.
    Group(IncomingEvent),
    /// A user's signed DeviceList changed.
    DeviceListUpdated {
        user_id: UserId,
        device_list: Vec<u8>,
    },
}

/// Result of [`Transport::fetch_events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBatch {
    pub events: Vec<HubEvent>,
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
    /// The event cursor is older than the hub's retention; resync, then
    /// continue from the head `cursor`.
    #[error("cursor expired; head is {cursor}")]
    Gone { cursor: u64 },
    #[error("server error: {0}")]
    Server(String),
    /// 413: the payload exceeds the hub's size limit; resending cannot
    /// succeed.
    #[error("too large: {0}")]
    TooLarge(String),
    /// The hub refused this device's sign-in for good (401
    /// `invalid_signature` or `device_not_active`): the device was revoked
    /// or its keys are broken.
    #[error("device not active: {0}")]
    DeviceNotActive(String),
}

/// Error of [`Transport::create_session`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// 401 `invalid_challenge`: unknown, used, expired or foreign
    /// challenge; a new challenge may succeed.
    #[error("invalid challenge")]
    InvalidChallenge,
    /// 401 `invalid_signature` or `device_not_active`.
    #[error("sign-in rejected: {0}")]
    Rejected(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Error of [`Transport::submit_commit`] and [`Transport::post_message`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PostError {
    /// The message is not for the group's current epoch (409
    /// `stale_epoch`).
    #[error("stale epoch; the group is at epoch {current_epoch}")]
    StaleEpoch { current_epoch: u64 },
    #[error(transparent)]
    Transport(#[from] TransportError),
}

pub type TransportResult<T> = Result<T, TransportError>;

/// A live event stream opened by [`Transport::open_stream`].
#[async_trait]
pub trait EventStream: Send {
    /// The next events, in cursor order; `next_cursor` is the cursor of the
    /// last one. [`TransportError::Gone`] if the stream's cursor expired,
    /// [`TransportError::Unauthorized`] if the token was rejected; any
    /// error ends the stream.
    async fn next(&mut self) -> TransportResult<EventBatch>;
}

#[async_trait]
pub trait Transport: Send + Sync {
    /// Stores the user's signed DeviceList (no token: it bootstraps the
    /// user). `Conflict` if it does not supersede the stored one.
    async fn put_device_list(&self, user_id: &UserId, device_list: Vec<u8>) -> TransportResult<()>;

    /// A sign-in challenge for `device`, which must be active in its user's
    /// stored DeviceList ([`TransportError::NotFound`] otherwise).
    async fn auth_challenge(&self, device: &DeviceRef) -> TransportResult<Challenge>;

    /// Redeems a gim-identity AuthResponse for a session token.
    async fn create_session(&self, response: Vec<u8>) -> Result<SessionToken, SessionError>;

    async fn put_recovery_backup(
        &self,
        token: &AccessToken,
        user_id: &UserId,
        backup: Vec<u8>,
    ) -> TransportResult<()>;

    /// The user's sealed recovery backup (no token: the restore path of a
    /// user without devices); `None` if there is none.
    async fn recovery_backup(&self, user_id: &UserId) -> TransportResult<Option<Vec<u8>>>;

    /// Relays a sealed link bundle to the new device that showed
    /// `link_id`; the hub keeps it for `expires_in` (at most 600 s).
    async fn post_link_bundle(
        &self,
        token: &AccessToken,
        link_id: &str,
        sealed_bundle: Vec<u8>,
        expires_in: Duration,
    ) -> TransportResult<()>;

    /// Fetches the link bundle of `link_id` (no token), waiting up to
    /// `wait` (at most 30 s) for it; the hub deletes it once fetched.
    /// `None` if none arrived.
    async fn fetch_link_bundle(
        &self,
        link_id: &str,
        wait: Duration,
    ) -> TransportResult<Option<Vec<u8>>>;

    /// The user's signed DeviceList; `None` if the user is unknown.
    async fn device_list(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Option<Vec<u8>>>;

    /// Looks a user up by id; `None` if there is no such user.
    async fn user(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Option<UserRecord>>;

    /// The owner of `handle` in the hub directory, if claimed.
    async fn find_handle(
        &self,
        token: &AccessToken,
        handle: &str,
    ) -> TransportResult<Option<UserId>>;

    /// Claims `handle` for the calling user; `Conflict` if another user
    /// holds it.
    async fn claim_handle(&self, token: &AccessToken, handle: &str) -> TransportResult<()>;

    async fn release_handle(&self, token: &AccessToken, handle: &str) -> TransportResult<()>;

    /// Publishes the calling user's display name where the transport keeps
    /// profiles. The hub has none: a no-op by default.
    async fn publish_display_name(&self, _token: &AccessToken, _name: &str) -> TransportResult<()> {
        Ok(())
    }

    /// Uploads one-time KeyPackages, or with `last_resort` exactly one that
    /// replaces the last-resort KeyPackage (TLS-serialized `MlsMessage`s).
    async fn upload_key_packages(
        &self,
        token: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: bool,
    ) -> TransportResult<()>;

    async fn key_package_count(&self, token: &AccessToken) -> TransportResult<KeyPackageCount>;

    /// Claims one KeyPackage of every active device of `users`; devices
    /// without any are left out.
    async fn claim_key_packages(
        &self,
        token: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<Vec<ClaimedKeyPackage>>;

    /// Creates a group (epoch 0, the caller as its only member); the hub
    /// assigns its id.
    async fn create_group(&self, token: &AccessToken, kind: ChatKind) -> TransportResult<GroupId>;

    async fn group_info(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
    ) -> TransportResult<GroupInfo>;

    /// The groups the calling device is a member of.
    async fn list_groups(&self, token: &AccessToken) -> TransportResult<Vec<GroupInfo>>;

    /// Submits a Commit (with its Welcome) or a Proposal.
    async fn submit_commit(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        commit: OutgoingCommit,
    ) -> Result<CommitAccepted, PostError>;

    /// Posts an application message and returns its per-group `seq`;
    /// idempotent on `client_id`.
    async fn post_message(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        client_id: ClientId,
        mls_message: Vec<u8>,
    ) -> Result<u64, PostError>;

    /// Events after `cursor` (`None`: from the start), waiting up to `wait`
    /// for the first one. [`TransportError::Gone`] if `cursor` expired.
    async fn fetch_events(
        &self,
        token: &AccessToken,
        cursor: Option<u64>,
        wait: Duration,
    ) -> TransportResult<EventBatch>;

    /// Opens the live event stream after `cursor`: it replays the pending
    /// events, then pushes new ones. `Ok(None)` if the transport or hub has
    /// no live stream; the caller long-polls [`Transport::fetch_events`]
    /// instead.
    async fn open_stream(
        &self,
        _token: &AccessToken,
        _cursor: Option<u64>,
    ) -> TransportResult<Option<Box<dyn EventStream>>> {
        Ok(None)
    }

    /// Up to `limit` unacknowledged Welcomes of the calling device, oldest
    /// first, as messages of kind `Welcome`.
    async fn pending_welcomes(
        &self,
        token: &AccessToken,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>>;

    /// Acknowledges the device's Welcome to the group.
    async fn ack_welcome(&self, token: &AccessToken, group_id: &GroupId) -> TransportResult<()>;

    /// Up to `limit` messages of the group with `seq >= from_seq`,
    /// ascending.
    async fn group_messages(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        from_seq: u64,
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
