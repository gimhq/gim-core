use std::fmt::Display;

/// Platform secure storage (Keychain / Keystore) for the device session
/// secret. Implemented by the native app through gim-ffi.
pub trait SecretStorage: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStorageError>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretStorageError>;
    fn delete(&self, key: &str) -> Result<(), SecretStorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("secret storage error: {0}")]
pub struct SecretStorageError(pub String);

impl SecretStorageError {
    pub fn new(reason: impl Display) -> Self {
        Self(reason.to_string())
    }
}
