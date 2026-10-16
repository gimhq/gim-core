use std::sync::Arc;

use crate::callbacks::Callbacks;
use crate::GimError;

/// Services the native app provides to gim-core. Implemented in Kotlin/Swift
/// and passed to `create_client`. Methods may be called from any Rust thread.
#[uniffi::export(with_foreign)]
pub trait PlatformHooks: Send + Sync {
    /// Reads a secret from the platform keystore (Keychain / Android Keystore).
    /// Returns `None` when the key does not exist. Throw when the keystore
    /// cannot be read (e.g. locked before first unlock): gim-core then fails
    /// the call instead of treating the secret as absent, so it never
    /// replaces an existing database key.
    fn secure_store_get(&self, key: String) -> Result<Option<Vec<u8>>, GimError>;

    /// Writes a secret to the platform keystore, replacing any existing value.
    fn secure_store_set(&self, key: String, value: Vec<u8>) -> Result<(), GimError>;

    /// Deletes a secret from the platform keystore; a missing key is not an error.
    fn secure_store_delete(&self, key: String);

    /// Absolute path of an app-private directory. The SQLite database and the
    /// media cache live under it.
    fn data_dir(&self) -> String;

    /// Current network reachability. Changes are pushed with
    /// `GimClient::set_network_reachable`.
    fn is_network_reachable(&self) -> bool;
}

/// gim-sdk [`gim_sdk::SecretStorage`] over the platform keystore hooks.
/// Fails once the client's callbacks are closed.
pub(crate) struct HookSecrets {
    pub(crate) hooks: Arc<dyn PlatformHooks>,
    pub(crate) callbacks: Arc<Callbacks>,
}

impl HookSecrets {
    fn call<R>(
        &self,
        f: impl FnOnce(&dyn PlatformHooks) -> Result<R, GimError>,
    ) -> Result<R, gim_sdk::SecretStorageError> {
        self.callbacks
            .call(|| f(&*self.hooks))
            .unwrap_or(Err(GimError::NotRegistered))
            .map_err(gim_sdk::SecretStorageError::new)
    }
}

impl gim_sdk::SecretStorage for HookSecrets {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, gim_sdk::SecretStorageError> {
        self.call(|hooks| hooks.secure_store_get(key.to_string()))
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), gim_sdk::SecretStorageError> {
        self.call(|hooks| hooks.secure_store_set(key.to_string(), value.to_vec()))
    }

    fn delete(&self, key: &str) -> Result<(), gim_sdk::SecretStorageError> {
        self.call(|hooks| {
            hooks.secure_store_delete(key.to_string());
            Ok(())
        })
    }
}
