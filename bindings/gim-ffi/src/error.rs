/// Error returned by every fallible gim-core call.
///
/// Kotlin: `GimException.<Variant>`; Swift: `GimError.<Variant>`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum GimError {
    /// The server could not be reached or the connection broke.
    #[error("network error: {reason}")]
    Network { reason: String },
    /// The call needs a session; call `register` first.
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
    /// gim-server answered with a non-success HTTP status.
    #[error("server error {status}: {reason}")]
    Server { status: u16, reason: String },
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
