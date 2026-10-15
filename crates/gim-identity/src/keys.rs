use std::fmt;

use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::IdentityError;

macro_rules! key_pair {
    ($(#[$smeta:meta])* $secret:ident, $(#[$pmeta:meta])* $public:ident) => {
        $(#[$smeta])*
        ///
        /// The secret is zeroized on drop and never printed by `Debug`.
        pub struct $secret(pub(crate) SigningKey);

        impl $secret {
            /// Derives the key from a 32-byte Ed25519 seed.
            pub fn from_seed(seed: &[u8; 32]) -> Self {
                Self(SigningKey::from_bytes(seed))
            }

            /// Generates a key from the operating system RNG.
            pub fn generate() -> Result<Self, IdentityError> {
                let mut seed = Zeroizing::new([0u8; 32]);
                getrandom::getrandom(seed.as_mut())
                    .map_err(|e| IdentityError::Random(e.to_string()))?;
                Ok(Self::from_seed(&seed))
            }

            pub fn public(&self) -> $public {
                $public(self.0.verifying_key())
            }
        }

        impl fmt::Debug for $secret {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($secret))
                    .field("public", &self.public())
                    .finish_non_exhaustive()
            }
        }

        $(#[$pmeta])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $public(pub(crate) VerifyingKey);

        impl $public {
            /// Parses a compressed Edwards point; rejects invalid and
            /// small-order points.
            pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
                let key = VerifyingKey::from_bytes(bytes).map_err(|_| IdentityError::InvalidKey)?;
                if key.is_weak() {
                    return Err(IdentityError::InvalidKey);
                }
                Ok(Self(key))
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $public {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($public), HEXLOWER.encode(self.as_bytes()))
            }
        }
    };
}

key_pair!(
    /// A user's Ed25519 root signing key; it certifies the user's devices.
    RootKey,
    /// Public half of a [`RootKey`]; `user_id` is derived from it.
    RootPublicKey
);
key_pair!(
    /// A device's Ed25519 signing key.
    DeviceSigningKey,
    /// Public half of a [`DeviceSigningKey`]; `device_id` is derived from it.
    DevicePublicKey
);

/// `context || 0x00 || tbs`, the message every signature covers.
fn signing_input(context: &[u8], tbs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(context.len() + 1 + tbs.len());
    message.extend_from_slice(context);
    message.push(0);
    message.extend_from_slice(tbs);
    message
}

pub(crate) fn sign(key: &SigningKey, context: &[u8], tbs: &[u8]) -> [u8; 64] {
    key.sign(&signing_input(context, tbs)).to_bytes()
}

/// Strict Ed25519 verification (rejects non-canonical and small-order
/// encodings).
pub(crate) fn verify(
    key: &VerifyingKey,
    context: &[u8],
    tbs: &[u8],
    sig: &[u8; 64],
) -> Result<(), IdentityError> {
    key.verify_strict(&signing_input(context, tbs), &Signature::from_bytes(sig))
        .map_err(|_| IdentityError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_secret() {
        let seed = [0x42; 32];
        let key = RootKey::from_seed(&seed);
        let debug = format!("{key:?}");
        assert!(debug.contains(&HEXLOWER.encode(key.public().as_bytes())));
        assert!(!debug.contains(&HEXLOWER.encode(&seed)));
    }

    #[test]
    fn generate_differs() {
        let a = DeviceSigningKey::generate().unwrap();
        let b = DeviceSigningKey::generate().unwrap();
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn rejects_small_order_key() {
        // The identity point.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(matches!(
            RootPublicKey::from_bytes(&identity),
            Err(IdentityError::InvalidKey)
        ));
    }
}
