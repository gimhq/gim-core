use gim_base::BaseError;
use gim_crypto::{CryptoError, MediaError};

use crate::transport::{PostError, TransportError};
use crate::SecretStorageError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not logged in")]
    NotLoggedIn,
    /// The hub no longer accepts this device (sign-in rejected, e.g. the
    /// device was revoked): it needs a new identity or a new link.
    #[error("device is not registered")]
    NotRegistered,
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
    Transport(#[from] TransportError),
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

impl From<PostError> for ClientError {
    fn from(err: PostError) -> Self {
        match err {
            PostError::StaleEpoch { .. } => {
                Self::Transport(TransportError::Conflict(err.to_string()))
            }
            PostError::Transport(err) => Self::Transport(err),
        }
    }
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;
