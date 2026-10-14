use std::fmt::Display;

use gim_common::GimCommonError;

/// Error returned by every [`crate::MlsEngine`] operation.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    #[error("unknown group: {group_id}")]
    UnknownGroup { group_id: String },
    #[error("no pending commit")]
    NoPendingCommit,
    #[error("mls error: {reason}")]
    Mls { reason: String },
    #[error("store error: {reason}")]
    Store { reason: String },
    #[error("wrong epoch: {reason}")]
    WrongEpoch { reason: String },
}

impl CryptoError {
    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            reason: reason.into(),
        }
    }

    pub(crate) fn mls(err: impl Display) -> Self {
        Self::Mls {
            reason: err.to_string(),
        }
    }

    pub(crate) fn store(err: impl Display) -> Self {
        Self::Store {
            reason: err.to_string(),
        }
    }
}

impl From<GimCommonError> for CryptoError {
    fn from(err: GimCommonError) -> Self {
        Self::invalid(err.to_string())
    }
}
