use std::fmt::Display;

use gim_crypto::CryptoError;
use gim_proto::ProtoError;

/// Error raised by a [`crate::StateStore`] backend.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("store error: {0}")]
pub struct StoreError(pub String);

impl StoreError {
    pub fn new(reason: impl Display) -> Self {
        Self(reason.to_string())
    }
}

/// Error returned by every gim-base operation. Any error returned from inside
/// a store transaction rolls the whole transaction back.
#[derive(Debug, thiserror::Error)]
pub enum BaseError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Proto(#[from] ProtoError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("random number generator failed: {0}")]
    Random(String),
}

pub type Result<T, E = BaseError> = std::result::Result<T, E>;
