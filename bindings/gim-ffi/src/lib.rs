//! The only UniFFI crate: `GimClient`, listener traits and platform-hook
//! callbacks, as a thin mapping over gim-ui / gim-sdk. Built as
//! `libgim_core.{so,a,dylib}`.

uniffi::setup_scaffolding!();

/// Version of the gim core library.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Name of the MLS ciphersuite every gim group uses.
#[uniffi::export]
pub fn ciphersuite_name() -> String {
    format!("{:?}", gim_crypto::CIPHERSUITE)
}

#[cfg(test)]
mod tests {
    #[test]
    fn metadata() {
        assert_eq!(super::core_version(), "0.1.0");
        assert_eq!(
            super::ciphersuite_name(),
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        );
    }
}
