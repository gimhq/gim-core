use crate::GimError;

/// Services the native app provides to gim-core. Implemented in Kotlin/Swift
/// and passed to `create_client`. Methods may be called from any Rust thread.
#[uniffi::export(with_foreign)]
pub trait PlatformHooks: Send + Sync {
    /// Reads a secret from the platform keystore (Keychain / Android Keystore).
    /// Returns `None` when the key does not exist.
    fn secure_store_get(&self, key: String) -> Option<Vec<u8>>;

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
