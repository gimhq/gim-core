use ciborium::Value;
use gim_common::{DeviceId, UserId};

use crate::cbor;
use crate::keys::{sign, verify};
use crate::{DevicePublicKey, IdentityError, RootKey, RootPublicKey, FORMAT_VERSION};

/// Signature context of a [`SignedDeviceCert`].
pub const DEVICE_CERT_CONTEXT: &[u8] = b"gim/device-cert/v1";

/// A verified device certificate: the root key vouches that
/// `device_public_key` belongs to `user_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub device_public_key: DevicePublicKey,
    /// Unix time in milliseconds.
    pub created_at: u64,
    pub seq: u64,
}

/// `[tbs: bstr, sig: bstr(64)]` where `tbs` is the CBOR body
/// `[1, user_id, device_id, device_sig_pubkey, created_at, seq]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceCert {
    tbs: Vec<u8>,
    sig: [u8; 64],
}

impl SignedDeviceCert {
    /// Certifies `device` under `root`.
    pub fn issue(root: &RootKey, device: &DevicePublicKey, created_at: u64, seq: u64) -> Self {
        let tbs = cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Text(root.public().user_id().into()),
            Value::Text(device.device_id().into()),
            Value::Bytes(device.as_bytes().to_vec()),
            Value::Integer(created_at.into()),
            Value::Integer(seq.into()),
        ]));
        let sig = sign(&root.0, DEVICE_CERT_CONTEXT, &tbs);
        Self { tbs, sig }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode_signed(&self.tbs, &self.sig)
    }

    /// Parses the outer `[tbs, sig]` structure; call [`Self::verify`] to
    /// check it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (tbs, sig) = cbor::decode_signed(bytes)?;
        Ok(Self { tbs, sig })
    }

    /// Checks the signature over the received `tbs`, the version, and that
    /// both ids are derived from the keys.
    pub fn verify(&self, root: &RootPublicKey) -> Result<DeviceCert, IdentityError> {
        verify(&root.0, DEVICE_CERT_CONTEXT, &self.tbs, &self.sig)?;
        let [_, user_id, device_id, device_public_key, created_at, seq] =
            cbor::decode_body(&self.tbs)?;
        let user_id = cbor::text(user_id)?;
        let device_id = cbor::text(device_id)?;
        let device_public_key = DevicePublicKey::from_bytes(&cbor::key(device_public_key)?)?;
        let created_at = cbor::uint(created_at)?;
        let seq = cbor::uint(seq)?;

        let expected_user = root.user_id();
        if user_id != expected_user.as_str() {
            return Err(IdentityError::UserIdMismatch);
        }
        let expected_device = device_public_key.device_id();
        if device_id != expected_device.as_str() {
            return Err(IdentityError::DeviceIdMismatch);
        }
        Ok(DeviceCert {
            user_id: expected_user,
            device_id: expected_device,
            device_public_key,
            created_at,
            seq,
        })
    }

    #[cfg(test)]
    pub(crate) fn sign_raw(root: &RootKey, body: &Value) -> Self {
        let tbs = cbor::encode(body);
        let sig = sign(&root.0, DEVICE_CERT_CONTEXT, &tbs);
        Self { tbs, sig }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceSigningKey;

    fn body(user_id: &str, device_id: &str, key: &DevicePublicKey, version: u64) -> Value {
        Value::Array(vec![
            Value::Integer(version.into()),
            Value::Text(user_id.into()),
            Value::Text(device_id.into()),
            Value::Bytes(key.as_bytes().to_vec()),
            Value::Integer(7.into()),
            Value::Integer(1.into()),
        ])
    }

    #[test]
    fn rejects_signed_mismatches() {
        let root = RootKey::from_seed(&[1; 32]);
        let other_root = RootKey::from_seed(&[9; 32]);
        let device = DeviceSigningKey::from_seed(&[2; 32]).public();
        let other_device = DeviceSigningKey::from_seed(&[3; 32]).public();
        let user = root.public().user_id();
        let device_id = device.device_id();

        let ok =
            SignedDeviceCert::sign_raw(&root, &body(user.as_str(), device_id.as_str(), &device, 1));
        assert!(ok.verify(&root.public()).is_ok());

        let wrong_user = SignedDeviceCert::sign_raw(
            &root,
            &body(
                other_root.public().user_id().as_str(),
                device_id.as_str(),
                &device,
                1,
            ),
        );
        assert!(matches!(
            wrong_user.verify(&root.public()),
            Err(IdentityError::UserIdMismatch)
        ));

        let wrong_device = SignedDeviceCert::sign_raw(
            &root,
            &body(user.as_str(), other_device.device_id().as_str(), &device, 1),
        );
        assert!(matches!(
            wrong_device.verify(&root.public()),
            Err(IdentityError::DeviceIdMismatch)
        ));

        let v2 =
            SignedDeviceCert::sign_raw(&root, &body(user.as_str(), device_id.as_str(), &device, 2));
        assert!(matches!(
            v2.verify(&root.public()),
            Err(IdentityError::UnsupportedVersion(2))
        ));
    }
}
