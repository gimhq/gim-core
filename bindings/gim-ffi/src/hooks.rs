use std::sync::Arc;

use crate::callbacks::{Callbacks, Foreign};
use crate::GimError;

/// Services the native app provides to gim-core. Implemented in Kotlin/Swift
/// and passed to `create_client`. Called on gim-core's callback thread; do
/// not call back into gim-core from it.
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
    pub(crate) hooks: Arc<Foreign<dyn PlatformHooks>>,
    pub(crate) callbacks: Arc<Callbacks>,
}

impl HookSecrets {
    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&(dyn PlatformHooks + 'static)) -> Result<R, GimError> + Send + 'static,
    ) -> Result<R, gim_sdk::SecretStorageError> {
        self.callbacks
            .call(|| self.hooks.call(f))
            .unwrap_or(Err(GimError::NotRegistered))
            .map_err(gim_sdk::SecretStorageError::new)
    }
}

impl gim_sdk::SecretStorage for HookSecrets {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, gim_sdk::SecretStorageError> {
        let key = key.to_string();
        self.call(move |hooks| hooks.secure_store_get(key))
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), gim_sdk::SecretStorageError> {
        let (key, value) = (key.to_string(), value.to_vec());
        self.call(move |hooks| hooks.secure_store_set(key, value))
    }

    fn delete(&self, key: &str) -> Result<(), gim_sdk::SecretStorageError> {
        let key = key.to_string();
        self.call(move |hooks| {
            hooks.secure_store_delete(key);
            Ok(())
        })
    }
}
