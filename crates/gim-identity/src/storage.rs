//! Encryption of what a user stores on a gim app server: a key derived from
//! the root key, so every own device (and a restore from the recovery code)
//! can read it and the server cannot.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{IdentityError, RootKey};

/// HKDF-SHA256 `info` of the storage key.
pub const STORAGE_KEY_INFO: &[u8] = b"gim/app-storage/v1";

const NONCE_LEN: usize = 12;

/// AES-256-GCM key for the user's app-server slots:
/// `HKDF-SHA256(salt = none, ikm = root seed, info = STORAGE_KEY_INFO)`.
pub struct StorageKey(Zeroizing<[u8; 32]>);

impl StorageKey {
    pub fn derive(root: &RootKey) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, root.to_seed().as_ref())
            .expand(STORAGE_KEY_INFO, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        Self(key)
    }

    /// `nonce(12) || AES-256-GCM(plaintext, aad = slot)`: the slot name is
    /// bound, so the server cannot swap two slots.
    pub fn seal(&self, slot: &str, plaintext: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| IdentityError::Random(e.to_string()))?;
        self.seal_with_nonce(slot, plaintext, nonce)
    }

    fn seal_with_nonce(
        &self,
        slot: &str,
        plaintext: &[u8],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, IdentityError> {
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: slot.as_bytes(),
                },
            )
            .map_err(|_| IdentityError::Decode("cannot seal".into()))?;
        Ok([nonce.as_slice(), &ciphertext].concat())
    }

    /// Opens what [`StorageKey::seal`] sealed for `slot`.
    pub fn open(&self, slot: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        if sealed.len() < NONCE_LEN {
            return Err(IdentityError::Decode("sealed slot too short".into()));
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: slot.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| IdentityError::BadSignature)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(self.0.as_ref()).expect("a 32-byte key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_slot_opens_only_under_its_name_and_key() {
        let root = RootKey::from_seed(&[7; 32]);
        let key = StorageKey::derive(&root);
        let sealed = key.seal("settings", b"blocked: bob").unwrap();
        assert_eq!(
            key.open("settings", &sealed).unwrap().as_slice(),
            b"blocked: bob"
        );
        assert!(key.open("contacts", &sealed).is_err());
        let other = StorageKey::derive(&RootKey::from_seed(&[8; 32]));
        assert!(other.open("settings", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(key.open("settings", &tampered).is_err());
        assert!(key.open("settings", &sealed[..5]).is_err());
    }

    #[test]
    fn sealing_is_deterministic_for_a_nonce() {
        let key = StorageKey::derive(&RootKey::from_seed(&[7; 32]));
        let a = key.seal_with_nonce("s", b"x", [1; NONCE_LEN]).unwrap();
        let b = key.seal_with_nonce("s", b"x", [1; NONCE_LEN]).unwrap();
        assert_eq!(a, b);
        assert_ne!(key.seal("s", b"x").unwrap(), key.seal("s", b"x").unwrap());
    }
}
