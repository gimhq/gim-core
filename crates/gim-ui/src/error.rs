use gim_base::BaseError;
use gim_sdk::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum UiError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Base(#[from] BaseError),
    #[error("blocking task failed: {0}")]
    Task(String),
}

pub type Result<T, E = UiError> = std::result::Result<T, E>;
