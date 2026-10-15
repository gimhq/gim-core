use gim_base::BaseError;
use gim_crypto::CryptoError;

use crate::transport::{PostError, TransportError};
use crate::SecretStorageError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("already logged in")]
    AlreadyLoggedIn,
    #[error("invalid stored session: {0}")]
    InvalidSession(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The commit kept losing against concurrent commits.
    #[error("commit rejected after {0} attempts: epoch conflict")]
    CommitConflict(u32),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Base(#[from] BaseError),
    #[error(transparent)]
    SecretStorage(#[from] SecretStorageError),
    #[error("blocking task failed: {0}")]
    Task(String),
}

impl From<CryptoError> for ClientError {
    fn from(err: CryptoError) -> Self {
        Self::Base(err.into())
    }
}

impl From<PostError> for ClientError {
    fn from(err: PostError) -> Self {
        match err {
            PostError::EpochConflict { .. } => {
                Self::Transport(TransportError::Conflict(err.to_string()))
            }
            PostError::Transport(err) => Self::Transport(err),
        }
    }
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;
