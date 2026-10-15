//! Recovery code and root-key backup encryption.
//!
//! A [`RecoveryCode`] is 24 random bytes shown to the user as Crockford
//! base32. The root key seed is sealed under an Argon2id-derived AES-256-GCM
//! key into a backup blob that can be stored on an untrusted hub. The
//! normative format is the "Recovery backup" section of `docs/identity.md`.

use std::{fmt, str::FromStr};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use ciborium::Value;
use data_encoding::{Encoding, Specification};
use gim_common::UserId;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{cbor, IdentityError, RootKey, FORMAT_VERSION};

/// Length of a recovery code in bytes.
pub const RECOVERY_CODE_LEN: usize = 24;
/// Length of the Argon2id salt in bytes.
pub const SALT_LEN: usize = 16;
/// Length of the AES-256-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 192 bits in 5-bit symbols.
const CODE_CHARS: usize = 39;
const GROUP: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("invalid recovery code: {0}")]
    InvalidCode(&'static str),
    /// Wrong recovery code or a tampered backup; the two are
    /// indistinguishable by design.
    #[error("backup decryption failed")]
    Decrypt,
    #[error("backup belongs to a different user")]
    UserMismatch,
    #[error("backup KDF parameters are below the minimum")]
    WeakParams,
    #[error("backup KDF parameters exceed the maximum")]
    ExcessiveParams,
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

fn decode_error(reason: &str) -> RecoveryError {
    IdentityError::Decode(reason.to_string()).into()
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, IdentityError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::getrandom(bytes.as_mut()).map_err(|e| IdentityError::Random(e.to_string()))?;
    Ok(bytes)
}

/// Uppercase Crockford base32, most significant bit first, no padding.
/// Decoding is case-insensitive, maps `I`/`L` to `1` and `O` to `0`,
/// ignores `-` and ASCII whitespace and rejects non-zero trailing bits.
fn crockford() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str(CROCKFORD);
    spec.translate.from.push_str("abcdefghjkmnpqrstvwxyzIiLlOo");
    spec.translate.to.push_str("ABCDEFGHJKMNPQRSTVWXYZ111100");
    spec.ignore.push_str("- \t\n\x0c\r");
    spec.check_trailing_bits = true;
    spec.encoding()
        .expect("valid Crockford base32 specification")
}

/// A 24-byte recovery code. Displayed as 39 Crockford base32 characters in
/// groups of four separated by `-`; zeroized on drop; `Debug` redacts it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode([u8; RECOVERY_CODE_LEN]);

impl RecoveryCode {
    /// Generates a code from the operating system RNG.
    pub fn generate() -> Result<Self, IdentityError> {
        Ok(Self(*random::<RECOVERY_CODE_LEN>()?))
    }

    /// Wraps raw code bytes (test vectors).
    #[doc(hidden)]
    pub fn from_bytes(bytes: [u8; RECOVERY_CODE_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = Zeroizing::new(crockford().encode(&self.0));
        let mut grouped = Zeroizing::new(String::with_capacity(CODE_CHARS + CODE_CHARS / GROUP));
        for (i, c) in text.chars().enumerate() {
            if i > 0 && i % GROUP == 0 {
                grouped.push('-');
            }
            grouped.push(c);
        }
        f.write_str(&grouped)
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl FromStr for RecoveryCode {
    type Err = RecoveryError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = Zeroizing::new(crockford().decode(text.as_bytes()).map_err(|e| {
            RecoveryError::InvalidCode(match e.kind {
                data_encoding::DecodeKind::Symbol => "invalid character",
                data_encoding::DecodeKind::Trailing => "non-zero padding bits",
                _ => "wrong length",
            })
        })?);
        let bytes = <[u8; RECOVERY_CODE_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| RecoveryError::InvalidCode("wrong length"))?;
        Ok(Self(bytes))
    }
}

/// Argon2id cost parameters: memory in KiB, iterations, parallelism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    /// Parameters every backup is sealed with.
    pub const DEFAULT: Self = Self::new(65536, 3, 1);

    /// Minimum accepted when opening, so a hub cannot downgrade the cost.
    #[cfg(not(feature = "test-params"))]
    pub const FLOOR: Self = Self::new(19456, 2, 1);
    /// Minimum accepted when opening. Lowered by the `test-params` feature;
    /// production builds MUST NOT enable it.
    #[cfg(feature = "test-params")]
    pub const FLOOR: Self = Self::new(64, 1, 1);

    /// Maximum accepted when opening, so a hub cannot make a client spend
    /// unbounded memory or CPU. Not affected by the `test-params` feature.
    pub const CEILING: Self = Self::new(262144, 16, 8);

    /// Arbitrary parameters. Only for tests with low-cost sealing
    /// (`test-params` feature); production code seals with [`Self::DEFAULT`].
    pub const fn new(m_kib: u32, t: u32, p: u32) -> Self {
        Self { m_kib, t, p }
    }

    pub fn m_kib(&self) -> u32 {
        self.m_kib
    }

    pub fn t(&self) -> u32 {
        self.t
    }

    pub fn p(&self) -> u32 {
        self.p
    }

    fn at_least(&self, floor: &Self) -> bool {
        self.m_kib >= floor.m_kib && self.t >= floor.t && self.p >= floor.p
    }

    fn at_most(&self, ceiling: &Self) -> bool {
        self.m_kib <= ceiling.m_kib && self.t <= ceiling.t && self.p <= ceiling.p
    }

    fn derive_key(
        &self,
        code: &RecoveryCode,
        salt: &[u8; SALT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
        let params = Params::new(self.m_kib, self.t, self.p, Some(32))
            .map_err(|_| RecoveryError::WeakParams)?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&code.0, salt, key.as_mut())
            .map_err(|_| RecoveryError::WeakParams)?;
        Ok(key)
    }

    fn to_value(self) -> Value {
        Value::Array(vec![
            Value::Integer(self.m_kib.into()),
            Value::Integer(self.t.into()),
            Value::Integer(self.p.into()),
        ])
    }

    fn from_value(value: Value) -> Result<Self, RecoveryError> {
        let [m_kib, t, p] = cbor::array(value)?;
        let field = |value| -> Result<u32, RecoveryError> {
            u32::try_from(cbor::uint(value)?).map_err(|_| decode_error("KDF parameter overflow"))
        };
        Ok(Self::new(field(m_kib)?, field(t)?, field(p)?))
    }
}

/// `[1, user_id, [m_kib, t, p], salt]`, the AEAD associated data.
fn header(user_id: &str, params: KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Integer(FORMAT_VERSION.into()),
        Value::Text(user_id.to_string()),
        params.to_value(),
        Value::Bytes(salt.to_vec()),
    ]))
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

/// Seals the root key seed under `code` with [`KdfParams::DEFAULT`] and a
/// random salt and nonce.
pub fn seal_root_key_backup(root: &RootKey, code: &RecoveryCode) -> Result<Vec<u8>, RecoveryError> {
    seal(
        root,
        code,
        KdfParams::DEFAULT,
        &*random::<SALT_LEN>()?,
        &*random::<NONCE_LEN>()?,
    )
}

/// Seals with explicit parameters, salt and nonce (low-cost tests and test
/// vectors). Never reuse a salt/nonce pair outside tests.
#[cfg(feature = "test-params")]
#[doc(hidden)]
pub fn seal_root_key_backup_with(
    root: &RootKey,
    code: &RecoveryCode,
    params: KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, RecoveryError> {
    seal(root, code, params, salt, nonce)
}

fn seal(
    root: &RootKey,
    code: &RecoveryCode,
    params: KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, RecoveryError> {
    let user_id = root.public().user_id();
    let aad = header(user_id.as_str(), params, salt);
    let seed = Zeroizing::new(root.0.to_bytes());
    let plaintext = Zeroizing::new(cbor::encode(&Value::Array(vec![
        Value::Integer(FORMAT_VERSION.into()),
        Value::Bytes(seed.to_vec()),
    ])));
    let key = params.derive_key(code, salt)?;
    let ciphertext = cipher(&key)
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .expect("AES-GCM encryption of a short message cannot fail");
    Ok(cbor::encode(&Value::Array(vec![
        Value::Integer(FORMAT_VERSION.into()),
        Value::Text(user_id.as_str().to_string()),
        params.to_value(),
        Value::Bytes(salt.to_vec()),
        Value::Bytes(nonce.to_vec()),
        Value::Bytes(ciphertext),
    ])))
}

/// Opens a backup produced by [`seal_root_key_backup`] for
/// `expected_user_id`.
///
/// The blob MUST be deterministic CBOR, so re-encoding its decoded header
/// reproduces the transmitted header bytes used as associated data.
pub fn open_root_key_backup(
    blob: &[u8],
    code: &RecoveryCode,
    expected_user_id: &UserId,
) -> Result<RootKey, RecoveryError> {
    let [_, user_id, params, salt, nonce, ciphertext] = cbor::decode_body::<6>(blob)?;
    let user_id = cbor::text(user_id)?;
    if user_id != expected_user_id.as_str() {
        return Err(RecoveryError::UserMismatch);
    }
    let params = KdfParams::from_value(params)?;
    if !params.at_least(&KdfParams::FLOOR) {
        return Err(RecoveryError::WeakParams);
    }
    if !params.at_most(&KdfParams::CEILING) {
        return Err(RecoveryError::ExcessiveParams);
    }
    let salt: [u8; SALT_LEN] = cbor::bytes_value(salt)?
        .try_into()
        .map_err(|_| decode_error("salt is not 16 bytes"))?;
    let nonce: [u8; NONCE_LEN] = cbor::bytes_value(nonce)?
        .try_into()
        .map_err(|_| decode_error("nonce is not 12 bytes"))?;
    let ciphertext = cbor::bytes_value(ciphertext)?;

    let aad = header(&user_id, params, &salt);
    let key = params.derive_key(code, &salt)?;
    let plaintext = Zeroizing::new(
        cipher(&key)
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RecoveryError::Decrypt)?,
    );

    let [version, seed] = cbor::array(cbor::decode(&plaintext)?)?;
    let version = cbor::uint(version)?;
    if version != FORMAT_VERSION {
        return Err(IdentityError::UnsupportedVersion(version).into());
    }
    let seed = Zeroizing::new(cbor::bytes_value(seed)?);
    let seed: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| decode_error("root seed is not 32 bytes"))?;
    let root = RootKey::from_seed(seed);
    if root.public().user_id() != *expected_user_id {
        return Err(IdentityError::UserIdMismatch.into());
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_floor_rejects_weak_params() {
        let floor = KdfParams::new(19456, 2, 1);
        assert!(KdfParams::DEFAULT.at_least(&floor));
        assert!(floor.at_least(&floor));
        for weak in [
            KdfParams::new(19455, 2, 1),
            KdfParams::new(65536, 1, 1),
            KdfParams::new(65536, 3, 0),
        ] {
            assert!(!weak.at_least(&floor), "{weak:?}");
        }
    }

    #[test]
    fn ceiling_bounds_each_field() {
        let ceiling = KdfParams::CEILING;
        assert_eq!(ceiling, KdfParams::new(262144, 16, 8));
        assert!(KdfParams::DEFAULT.at_most(&ceiling));
        assert!(ceiling.at_most(&ceiling));
        for excessive in [
            KdfParams::new(262145, 16, 8),
            KdfParams::new(262144, 17, 8),
            KdfParams::new(262144, 16, 9),
        ] {
            assert!(!excessive.at_most(&ceiling), "{excessive:?}");
        }
    }

    /// A blob with the given parameters and a dummy ciphertext; the bounds
    /// are checked before deriving, so Argon2 never runs at these costs.
    fn blob_with(params: KdfParams, user_id: &str) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Text(user_id.to_string()),
            params.to_value(),
            Value::Bytes(vec![0; SALT_LEN]),
            Value::Bytes(vec![0; NONCE_LEN]),
            Value::Bytes(vec![0; 52]),
        ]))
    }

    #[test]
    fn open_rejects_excessive_params_before_deriving() {
        let user_id = RootKey::from_seed(&[0; 32]).public().user_id();
        let code = RecoveryCode::from_bytes([0; RECOVERY_CODE_LEN]);
        for excessive in [
            KdfParams::new(262145, 16, 8),
            KdfParams::new(262144, 17, 8),
            KdfParams::new(262144, 16, 9),
            KdfParams::new(u32::MAX, u32::MAX, u32::MAX),
        ] {
            assert!(matches!(
                open_root_key_backup(&blob_with(excessive, user_id.as_str()), &code, &user_id),
                Err(RecoveryError::ExcessiveParams)
            ));
        }
    }

    #[test]
    fn debug_redacts_code() {
        let code = RecoveryCode::from_bytes([0xab; RECOVERY_CODE_LEN]);
        let debug = format!("{code:?}");
        assert!(!debug.contains(&code.to_string()));
        assert!(!debug.to_ascii_lowercase().contains("abab"));
    }
}
