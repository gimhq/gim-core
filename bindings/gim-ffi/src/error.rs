/// Error returned by every fallible gim-core call.
///
/// Kotlin: `GimException.<Variant>`; Swift: `GimError.<Variant>`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum GimError {
    /// The server could not be reached or the connection broke.
    #[error("network error: {reason}")]
    Network { reason: String },
    /// The call needs a session: create an identity, restore one from its
    /// recovery code or link this device first. Also returned after
    /// `sign_out` and once the hub reports this device as revoked.
    #[error("not registered")]
    NotRegistered,
    /// An argument was rejected before anything was sent.
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    /// The chat, message, user or media does not exist locally or on the server.
    #[error("not found: {reason}")]
    NotFound { reason: String },
    /// MLS or media encryption/decryption failed.
    #[error("crypto error: {reason}")]
    Crypto { reason: String },
    /// The local database or file system failed.
    #[error("storage error: {reason}")]
    Storage { reason: String },
    /// The hub answered with a non-success HTTP status.
    #[error("server error {status}: {reason}")]
    Server { status: u16, reason: String },
    /// The hub is throttling the call (HTTP 429 `rate_limited`) or a remote
    /// hub is unavailable (HTTP 503 `peer_unavailable`), and gim-core's
    /// bounded retries are used up; try again after `retry_after_secs`.
    #[error("retry after {retry_after_secs} s ({status}): {reason}")]
    RetryLater {
        status: u16,
        retry_after_secs: u64,
        reason: String,
    },
    /// The operation was cancelled (sign-out, `stop_sync`, `cancel_send`).
    #[error("cancelled")]
    Cancelled,
    /// The call is part of the API contract but not implemented yet.
    #[error("not implemented")]
    NotImplemented,
    /// A bug or an unexpected failure inside gim-core or a platform callback.
    #[error("internal error: {reason}")]
    Internal { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for GimError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Internal { reason: e.reason }
    }
}

impl From<gim_sdk::ClientError> for GimError {
    fn from(err: gim_sdk::ClientError) -> Self {
        use gim_sdk::ClientError as E;
        match err {
            E::NotLoggedIn | E::NotRegistered | E::DeviceNotActive(_) => Self::NotRegistered,
            E::AlreadyLoggedIn | E::InvalidInput(_) => Self::InvalidInput {
                reason: err.to_string(),
            },
            E::CommitConflict(_) => Self::Server {
                status: 409,
                reason: err.to_string(),
            },
            E::Transport(err) => err.into(),
            E::Base(err) => err.into(),
            E::Media(_) | E::Identity(_) => Self::Crypto {
                reason: err.to_string(),
            },
            E::InvalidSession(_) | E::SecretStorage(_) | E::Io(_) => Self::Storage {
                reason: err.to_string(),
            },
            E::Task(_) => Self::Internal {
                reason: err.to_string(),
            },
        }
    }
}

impl From<gim_sdk::TransportError> for GimError {
    fn from(err: gim_sdk::TransportError) -> Self {
        use gim_sdk::TransportError as E;
        let reason = err.to_string();
        match err {
            E::Network(_) => Self::Network { reason },
            E::NotFound(_) => Self::NotFound { reason },
            E::Unauthorized => Self::Server {
                status: 401,
                reason,
            },
            E::Conflict(_) => Self::Server {
                status: 409,
                reason,
            },
            E::Gone { .. } => Self::Server {
                status: 410,
                reason,
            },
            E::Server(_) => Self::Server {
                status: 500,
                reason,
            },
            E::TooLarge(_) => Self::InvalidInput { reason },
            E::DeviceNotActive(_) => Self::NotRegistered,
            E::HostingRecordRequired(_) => Self::Server {
                status: 403,
                reason,
            },
            E::RetryLater {
                status,
                retry_after_secs,
                reason,
            } => Self::RetryLater {
                status,
                retry_after_secs,
                reason,
            },
            E::PeerUnavailable {
                retry_after_secs: Some(retry_after_secs),
                ..
            } => Self::RetryLater {
                status: 503,
                retry_after_secs,
                reason,
            },
            E::PeerUnavailable {
                retry_after_secs: None,
                ..
            } => Self::Server {
                status: 503,
                reason,
            },
            E::PeerRefused(_) => Self::Server {
                status: 502,
                reason,
            },
        }
    }
}

impl From<gim_base::BaseError> for GimError {
    fn from(err: gim_base::BaseError) -> Self {
        use gim_base::BaseError as E;
        let reason = err.to_string();
        match err {
            E::Store(_) => Self::Storage { reason },
            E::Crypto(_) => Self::Crypto { reason },
            E::NotFound(_) => Self::NotFound { reason },
            E::InvalidState(_) => Self::InvalidInput { reason },
            E::Proto(_) | E::Random(_) => Self::Internal { reason },
        }
    }
}

impl From<gim_base::StoreError> for GimError {
    fn from(err: gim_base::StoreError) -> Self {
        Self::Storage {
            reason: err.to_string(),
        }
    }
}

impl From<gim_ui::UiError> for GimError {
    fn from(err: gim_ui::UiError) -> Self {
        match err {
            gim_ui::UiError::Client(err) => err.into(),
            gim_ui::UiError::Base(err) => err.into(),
            gim_ui::UiError::Task(_) => Self::Internal {
                reason: err.to_string(),
            },
        }
    }
}

impl From<std::io::Error> for GimError {
    fn from(err: std::io::Error) -> Self {
        Self::Storage {
            reason: err.to_string(),
        }
    }
}

impl From<tokio::task::JoinError> for GimError {
    fn from(err: tokio::task::JoinError) -> Self {
        Self::Internal {
            reason: err.to_string(),
        }
    }
}

/// Parses an id argument; a malformed id is `InvalidInput`.
pub(crate) fn parse_id<T: TryFrom<String, Error = gim_common::GimCommonError>>(
    what: &str,
    value: String,
) -> Result<T, GimError> {
    T::try_from(value).map_err(|e| GimError::InvalidInput {
        reason: format!("{what}: {e}"),
    })
}
