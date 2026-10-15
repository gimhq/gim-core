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
