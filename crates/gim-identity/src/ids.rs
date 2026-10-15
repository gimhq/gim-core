use data_encoding::BASE32_NOPAD;
use gim_common::{DeviceId, UserId};
use sha2::{Digest, Sha256};

use crate::{DevicePublicKey, IdentityError, RootPublicKey};

const USER_PREFIX: &str = "u";
const DEVICE_PREFIX: &str = "d";
/// Multihash header: sha2-256 code, 32-byte digest.
const MULTIHASH_SHA256: [u8; 2] = [0x12, 0x20];
const USER_HASH_LEN: usize = 34;
const DEVICE_HASH_LEN: usize = 16;

/// RFC 4648 base32, lowercase, no padding.
fn base32(bytes: &[u8]) -> String {
    BASE32_NOPAD.encode(bytes).to_ascii_lowercase()
}

/// Inverse of [`base32`]; rejects uppercase, padding and non-zero trailing
/// bits so every value has exactly one encoding.
fn decode_base32(text: &str) -> Option<Vec<u8>> {
    if !text.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return None;
    }
    BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .ok()
}

impl RootPublicKey {
    /// `"u" + base32(0x12 0x20 || SHA-256(root_pubkey))`.
    pub fn user_id(&self) -> UserId {
        let mut multihash = MULTIHASH_SHA256.to_vec();
        multihash.extend_from_slice(&Sha256::digest(self.as_bytes()));
        UserId::new(format!("{USER_PREFIX}{}", base32(&multihash))).expect("valid user id")
    }
}

impl DevicePublicKey {
    /// `"d" + base32(SHA-256(device_sig_pubkey)[..16])`.
    pub fn device_id(&self) -> DeviceId {
        let digest = Sha256::digest(self.as_bytes());
        DeviceId::new(format!(
            "{DEVICE_PREFIX}{}",
            base32(&digest[..DEVICE_HASH_LEN])
        ))
        .expect("valid device id")
    }
}

/// Validates the syntax of a derived user id (prefix, alphabet, multihash
/// header and length).
pub fn parse_user_id(text: &str) -> Result<UserId, IdentityError> {
    let invalid = |reason: &str| IdentityError::InvalidUserId(reason.to_string());
    let body = text
        .strip_prefix(USER_PREFIX)
        .ok_or_else(|| invalid("missing 'u' prefix"))?;
    let bytes = decode_base32(body).ok_or_else(|| invalid("not lowercase unpadded base32"))?;
    if bytes.len() != USER_HASH_LEN || bytes[..2] != MULTIHASH_SHA256 {
        return Err(invalid("not a sha2-256 multihash"));
    }
    UserId::new(text).map_err(|e| invalid(&e.to_string()))
}

/// Validates the syntax of a derived device id (prefix, alphabet, length).
pub fn parse_device_id(text: &str) -> Result<DeviceId, IdentityError> {
    let invalid = |reason: &str| IdentityError::InvalidDeviceId(reason.to_string());
    let body = text
        .strip_prefix(DEVICE_PREFIX)
        .ok_or_else(|| invalid("missing 'd' prefix"))?;
    let bytes = decode_base32(body).ok_or_else(|| invalid("not lowercase unpadded base32"))?;
    if bytes.len() != DEVICE_HASH_LEN {
        return Err(invalid("not 16 bytes"));
    }
    DeviceId::new(text).map_err(|e| invalid(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceSigningKey, RootKey};

    #[test]
    fn derived_ids_parse() {
        let user = RootKey::from_seed(&[1; 32]).public().user_id();
        assert_eq!(user.as_str().len(), 56);
        assert_eq!(parse_user_id(user.as_str()).unwrap(), user);
        let device = DeviceSigningKey::from_seed(&[2; 32]).public().device_id();
        assert_eq!(device.as_str().len(), 27);
        assert_eq!(parse_device_id(device.as_str()).unwrap(), device);
    }

    #[test]
    fn rejects_malformed_ids() {
        let user = RootKey::from_seed(&[1; 32]).public().user_id();
        let device = DeviceSigningKey::from_seed(&[2; 32]).public().device_id();
        let user = user.as_str();
        let device = device.as_str();
        for bad in [
            "",
            "u",
            &user[1..],
            &format!("d{}", &user[1..]),
            &user.to_ascii_uppercase(),
            &format!("{user}a"),
            &user[..user.len() - 1],
            &format!("{}1", &user[..user.len() - 1]),
            // Non-zero trailing bits.
            &format!("{}7", &user[..user.len() - 1]),
            // Valid base32 of 34 bytes without the multihash header.
            &format!("u{}", base32(&[0u8; 34])),
            device,
        ] {
            assert!(parse_user_id(bad).is_err(), "{bad}");
        }
        for bad in [
            "",
            "d",
            &device[1..],
            &device.to_ascii_uppercase(),
            &format!("{device}a"),
            &format!("{}7", &device[..device.len() - 1]),
            &format!("d{}", base32(&[0u8; 17])),
            user,
        ] {
            assert!(parse_device_id(bad).is_err(), "{bad}");
        }
    }
}
