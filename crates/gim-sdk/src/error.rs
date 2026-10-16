use gim_base::BaseError;
use gim_crypto::{CryptoError, MediaError};

use crate::transport::{PostError, TransportError};
use crate::SecretStorageError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not logged in")]
    NotLoggedIn,
    /// The hub keeps rejecting this device's session token: sync stops.
    #[error("device is not registered")]
    NotRegistered,
    /// The hub refused this device's sign-in for good (`invalid_signature`
    /// or `device_not_active`: revoked, or its keys are broken). The
    /// session was cleared; the device needs a new identity or a new link.
    #[error("device not active on the hub: {0}")]
    DeviceNotActive(String),
    #[error("already logged in")]
    AlreadyLoggedIn,
    #[error("invalid stored session: {0}")]
    InvalidSession(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The commit kept losing against concurrent commits.
    #[error("commit rejected after {0} attempts: epoch conflict")]
    CommitConflict(u32),
    /// A gim-identity object (DeviceList, challenge, recovery backup) could
    /// not be built or did not verify.
    #[error("identity error: {0}")]
    Identity(String),
    #[error(transparent)]
    Transport(TransportError),
    #[error(transparent)]
    Base(#[from] BaseError),
    #[error(transparent)]
    SecretStorage(#[from] SecretStorageError),
    #[error(transparent)]
    Media(#[from] MediaError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("blocking task failed: {0}")]
    Task(String),
    /// [`crate::Client::remove_hub`] without `confirm_owned_groups`: the hub
    /// owns (sequences) `group_count` groups this user is in. They stay
    /// reachable through the other members' hubs after the removal, but
    /// the owning hub is not migrated.
    #[error("hub {hub_id} owns {group_count} groups of this user")]
    HubOwnsGroups { hub_id: String, group_count: u32 },
    /// The hub is the only one listed by the hosting record: it cannot be
    /// removed.
    #[error("hub {0} is the only listed hub")]
    LastHub(String),
    /// The hub is the home hub (the client's own transport): it cannot be
    /// removed.
    #[error("hub {0} is the home hub")]
    HomeHub(String),
    /// The drain check before removing the hub failed: something sent
    /// through it is not settled yet. Try again later.
    #[error("hub {hub_id} is not drained: {reason}")]
    HubNotDrained { hub_id: String, reason: String },
}

impl ClientError {
    pub(crate) fn identity(err: impl std::fmt::Display) -> Self {
        Self::Identity(err.to_string())
    }
}

impl From<CryptoError> for ClientError {
    fn from(err: CryptoError) -> Self {
        Self::Base(err.into())
    }
}

impl From<TransportError> for ClientError {
    fn from(err: TransportError) -> Self {
        match err {
            TransportError::DeviceNotActive(reason) => Self::DeviceNotActive(reason),
            err => Self::Transport(err),
        }
    }
}

impl From<PostError> for ClientError {
    fn from(err: PostError) -> Self {
        match err {
            PostError::StaleEpoch { .. } => {
                Self::Transport(TransportError::Conflict(err.to_string()))
            }
            PostError::Transport(err) => err.into(),
        }
    }
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;
