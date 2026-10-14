/// Error returned by the validated constructors in this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GimCommonError {
    #[error("invalid {kind}: {reason}")]
    InvalidId { kind: &'static str, reason: String },
}
