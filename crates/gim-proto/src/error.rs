/// Error returned when encoding or decoding wire types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    /// The value violates a schema rule (e.g. `reply_to` on a reaction).
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    /// The envelope version is 0 or newer than this build understands.
    #[error("unsupported envelope version {version}")]
    UnsupportedVersion { version: u64 },
    /// The bytes are not a well-formed envelope.
    #[error("malformed envelope: {reason}")]
    Malformed { reason: String },
}

impl ProtoError {
    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            reason: reason.into(),
        }
    }

    pub(crate) fn malformed(reason: impl std::fmt::Display) -> Self {
        Self::Malformed {
            reason: reason.to_string(),
        }
    }
}
