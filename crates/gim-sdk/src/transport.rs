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

/// Result of [`Transport::claim_key_packages_federated`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyPackageClaim {
    pub key_packages: Vec<ClaimedKeyPackage>,
    /// Users whose hub could not be reached, refused the request or timed
    /// out (federation); claiming them again later may succeed.
    pub unavailable: Vec<UserId>,
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

/// A hub's signed consent to host the calling user: result of
/// [`Transport::create_hosting_entry`]. Unverified; the client checks it
/// before putting it into its hosting record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingEntryGrant {
    pub hub_id: String,
    /// The hub's 32-byte Ed25519 root public key.
    pub hub_root_public_key: Vec<u8>,
    pub priority: u8,
    /// gim-identity HostingEntry.
    pub entry: Vec<u8>,
}

/// A hub's identity: result of [`Transport::hub_info`]. Unverified; the
/// client checks that `hub_id` derives from `hub_root_public_key` and the
/// proof of possession for the URL it contacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubIdentity {
    pub hub_id: String,
    /// The hub's 32-byte Ed25519 root public key.
    pub hub_root_public_key: Vec<u8>,
    pub version: String,
    /// The hub's normalized public client API URL, if it has one.
    pub public_url: Option<String>,
    /// Only for a request with a nonce: the root key's signature over the
    /// nonce, `hub_id` and `public_url` (gim-identity hub proof).
    pub proof: Option<Vec<u8>>,
}

/// A user's hosting record as a hub stores it. Unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHostingRecord {
    /// gim-identity SignedHostingRecord.
    pub record: Vec<u8>,
    pub seq: u64,
    /// Unix milliseconds, exclusive.
    pub expires_at_ms: u64,
    /// Whether the record lists the answering hub (for its local users).
    pub hosted: bool,
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
    /// The user's hosting record on the hub expires soon: publish a renewed
    /// one.
    HostingRecordExpiring {
        user_id: UserId,
        /// Unix milliseconds.
        expires_at_ms: u64,
        seq: u64,
    },
    /// The hubs listed by the user's hosting record, or their priorities,
    /// changed: read the record again.
    HostingRecordUpdated { user_id: UserId, seq: u64 },
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
    /// 5xx, 408, 429 or an unusable response: the hub may have applied the
    /// request; resend it unchanged.
    #[error("server error: {0}")]
    Server(String),
    /// A definite 4xx without a dedicated variant (400 `validation_failed`,
    /// 403 `forbidden` / `not_member`, 422, ...): the hub did not apply the
    /// request and resending it unchanged cannot succeed. `code` is the
    /// hub's error code, empty if the body had none.
    #[error("rejected ({status} {code}): {message}")]
    Rejected {
        status: u16,
        code: String,
        message: String,
    },
    /// 413: the payload exceeds the hub's size limit; resending cannot
    /// succeed.
    #[error("too large: {0}")]
    TooLarge(String),
    /// The hub refused this device's sign-in for good (401
    /// `invalid_signature` or `device_not_active`): the device was revoked
    /// or its keys are broken.
    #[error("device not active: {0}")]
    DeviceNotActive(String),
    /// The hub at the contacted URL did not prove that it is the expected
    /// hub at that URL (`GET /v2/hub` proof of possession, or the URL of
    /// its sign-in challenge): a wrong URL or a relay. Nothing that needs a
    /// session is sent there.
    #[error("hub not verified: {0}")]
    HubNotVerified(String),
    /// 429 `rate_limited` or 503 `peer_unavailable` of a public read or a
    /// blob download that kept failing within its retry budget; try again
    /// after `retry_after_secs`.
    #[error("retry after {retry_after_secs} s ({status}): {reason}")]
    RetryLater {
        status: u16,
        retry_after_secs: u64,
        reason: String,
    },
    /// 403 `hosting_record_required`: a federated request of a user
    /// without a valid hosting record listing the hub.
    #[error("hosting record required: {0}")]
    HostingRecordRequired(String),
    /// 503 `peer_unavailable`: the hub owning the group (or hosting the
    /// user) could not be reached. The request may have been applied
    /// there; resend it unchanged, after `retry_after_secs` if given.
    #[error("peer hub unavailable: {reason}")]
    PeerUnavailable {
        retry_after_secs: Option<u64>,
        reason: String,
    },
    /// 502 `peer_refused`: the peer hub refused the federated request;
    /// resend it unchanged later.
    #[error("peer hub refused the request: {0}")]
    PeerRefused(String),
}

impl TransportError {
    /// The delay the hub asked for before a retry, if any.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::PeerUnavailable {
                retry_after_secs, ..
            } => retry_after_secs.map(Duration::from_secs),
            Self::RetryLater {
                retry_after_secs, ..
            } => Some(Duration::from_secs(*retry_after_secs)),
            _ => None,
        }
    }

    /// A federated request failed at a peer hub (502/503); retry it
    /// unchanged later.
    pub fn is_peer_failure(&self) -> bool {
        matches!(self, Self::PeerUnavailable { .. } | Self::PeerRefused(_))
    }

    /// Whether the hub may have applied a request that failed this way
    /// (network errors, timeouts, 5xx incl. peer hub failures, 429); such
    /// requests are resent unchanged. Every other error is a definite
    /// answer: the request was not applied.
    pub fn outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::Server(_) | Self::RetryLater { .. }
        ) || self.is_peer_failure()
    }
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
    /// The client API base URL of the hub, where the transport has one.
    fn base_url(&self) -> Option<String> {
        None
    }

    /// The hub's identity (no token), so the client can check that the
    /// hub behind this transport is the `hub_id` it expects before
    /// signing in. With a `nonce`, the hub proves possession of its root
    /// key for its public URL; a hub without one answers 400
    /// ([`TransportError::Rejected`]). Transports without a hub identity
    /// answer [`TransportError::NotFound`].
    async fn hub_info(&self, _nonce: Option<&[u8; 32]>) -> TransportResult<HubIdentity> {
        Err(TransportError::NotFound(
            "hub identity is not supported".into(),
        ))
    }

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

    /// The user's signed DeviceList; `None` if the user is unknown. A
    /// public read: the token is optional (the hub ignores it), so it works
    /// before sign-in. 429 and 503 with `Retry-After` are retried within a
    /// bounded budget, then fail with [`TransportError::RetryLater`].
    async fn device_list(
        &self,
        token: Option<&AccessToken>,
        user_id: &UserId,
    ) -> TransportResult<Option<Vec<u8>>>;

    /// Looks a user up by id; `None` if there is no such user. A public
    /// read like [`Transport::device_list`].
    async fn user(
        &self,
        token: Option<&AccessToken>,
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
    /// replaces the last-resort KeyPackage (bare TLS-serialized KeyPackages).
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

    /// Like [`Transport::claim_key_packages`], also listing the users whose
    /// hub could not be reached (federation). Transports without
    /// federation report none.
    async fn claim_key_packages_federated(
        &self,
        token: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<KeyPackageClaim> {
        Ok(KeyPackageClaim {
            key_packages: self.claim_key_packages(token, users).await?,
            unavailable: vec![],
        })
    }

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

    /// Submits a Commit (with its Welcome) or a Proposal. For a group
    /// owned by another hub it may fail with
    /// [`TransportError::PeerUnavailable`] or [`TransportError::PeerRefused`];
    /// resubmit the same bytes.
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
    /// ascending. Unknown kinds are left out; empty only at the end of
    /// the history.
    async fn group_messages(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        from_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>>;

    /// The calling user's hosting entry signed by this hub. Transports
    /// without hosting records answer [`TransportError::NotFound`].
    async fn create_hosting_entry(
        &self,
        _token: &AccessToken,
        user_id: &UserId,
        _priority: u8,
    ) -> TransportResult<HostingEntryGrant> {
        Err(TransportError::NotFound(format!(
            "no hosting entry for {user_id}: hosting records are not supported"
        )))
    }

    /// Stores the user's signed hosting record (no token: it is
    /// self-certifying). [`TransportError::Conflict`] (409
    /// `stale_hosting_record`) if the hub stores a record with a higher
    /// seq, or another one with the same seq.
    async fn put_hosting_record(
        &self,
        user_id: &UserId,
        _record: Vec<u8>,
    ) -> TransportResult<StoredHostingRecord> {
        Err(TransportError::NotFound(format!(
            "no hosting record for {user_id}: hosting records are not supported"
        )))
    }

    /// The user's current hosting record; `None` if there is none or it
    /// expired. A public read like [`Transport::device_list`].
    async fn hosting_record(
        &self,
        _user_id: &UserId,
    ) -> TransportResult<Option<StoredHostingRecord>> {
        Ok(None)
    }

    /// Uploads the already-encrypted blob in `file`; returns its id.
    async fn upload_blob(&self, token: &AccessToken, file: &Path) -> TransportResult<String>;

    /// Downloads a blob, or the given byte range of it. `blob_id` is opaque
    /// (`<origin hub_id>/b_<random>` or a legacy `b_<random>`).
    async fn download_blob(
        &self,
        token: &AccessToken,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>>;
}
