//! Device authentication against a hub: the hub issues an [`AuthChallenge`],
//! the device answers with a signed [`AuthResponse`].

use ciborium::Value;
use gim_common::{DeviceId, DeviceRef, UserId};

use crate::cbor;
use crate::ids::{parse_device_id, parse_user_id};
use crate::keys::{sign, verify};
use crate::{DeviceSigningKey, IdentityError, SignedDeviceList, FORMAT_VERSION};

/// Signature context of an [`AuthResponse`].
pub const AUTH_RESPONSE_CONTEXT: &[u8] = b"gim/auth-response/v1";

/// An unsigned login challenge issued by the hub `audience`. The hub keeps
/// track of what it issued; nonce single-use is enforced hub-side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    /// `hub_id` of the issuing hub.
    pub audience: String,
    pub nonce: [u8; 32],
    /// Unix time in milliseconds.
    pub issued_at: u64,
    /// Unix time in milliseconds, exclusive.
    pub expires_at: u64,
}

impl AuthChallenge {
    /// `[1, audience, nonce, issued_at, expires_at]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Text(self.audience.clone()),
            Value::Bytes(self.nonce.to_vec()),
            Value::Integer(self.issued_at.into()),
            Value::Integer(self.expires_at.into()),
        ]))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let [_, audience, nonce, issued_at, expires_at] = cbor::decode_body(bytes)?;
        Ok(Self {
            audience: cbor::text(audience)?,
            nonce: cbor::bytes_value(nonce)?
                .try_into()
                .map_err(|_| IdentityError::Decode("nonce is not 32 bytes".into()))?,
            issued_at: cbor::uint(issued_at)?,
            expires_at: cbor::uint(expires_at)?,
        })
    }
}

/// `[1, challenge: bstr, user_id, device_id, sig: bstr(64)]`; `sig` covers
/// `[challenge, user_id, device_id]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    challenge: Vec<u8>,
    user_id: UserId,
    device_id: DeviceId,
    sig: [u8; 64],
}

impl AuthResponse {
    /// Answers the exact `challenge` bytes as `device_key` of `user_id`; the
    /// device id is derived from `device_key`.
    pub fn sign(challenge: &[u8], device_key: &DeviceSigningKey, user_id: &UserId) -> Self {
        let device_id = device_key.public().device_id();
        let sig = sign(
            &device_key.0,
            AUTH_RESPONSE_CONTEXT,
            &Self::tbs(challenge, user_id, &device_id),
        );
        Self {
            challenge: challenge.to_vec(),
            user_id: user_id.clone(),
            device_id,
            sig,
        }
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Bytes(self.challenge.clone()),
            Value::Text(self.user_id.to_string()),
            Value::Text(self.device_id.to_string()),
            Value::Bytes(self.sig.to_vec()),
        ]))
    }

    /// Parses the response; call [`Self::verify`] to check it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let [_, challenge, user_id, device_id, sig] = cbor::decode_body(bytes)?;
        Ok(Self {
            challenge: cbor::bytes_value(challenge)?,
            user_id: parse_user_id(&cbor::text(user_id)?)?,
            device_id: parse_device_id(&cbor::text(device_id)?)?,
            sig: cbor::bytes_value(sig)?
                .try_into()
                .map_err(|_| IdentityError::Decode("signature is not 64 bytes".into()))?,
        })
    }

    /// Hub-side check, in the documented order: `device_list` verifies for
    /// the response's user and the device is certified in it and not
    /// revoked (this yields the verifying key); `sig` verifies under the
    /// certified device key; only then the challenge decodes, is addressed
    /// to `expected_audience` and has not expired at `now`. The hub must
    /// also check that it issued the challenge and that its nonce is unused.
    pub fn verify(
        &self,
        expected_audience: &str,
        now: u64,
        device_list: &SignedDeviceList,
    ) -> Result<DeviceRef, IdentityError> {
        let list = device_list.verify(&self.user_id)?;
        if list.is_revoked(&self.device_id) {
            return Err(IdentityError::Revoked(self.device_id.clone()));
        }
        let cert = list
            .certs()
            .find(|cert| cert.device_id == self.device_id)
            .ok_or_else(|| IdentityError::UnknownDevice(self.device_id.clone()))?;
        verify(
            &cert.device_public_key.0,
            AUTH_RESPONSE_CONTEXT,
            &Self::tbs(&self.challenge, &self.user_id, &self.device_id),
            &self.sig,
        )?;
        let challenge = AuthChallenge::from_bytes(&self.challenge)?;
        if challenge.audience != expected_audience {
            return Err(IdentityError::AudienceMismatch);
        }
        if now >= challenge.expires_at {
            return Err(IdentityError::Expired);
        }
        Ok(DeviceRef::new(self.user_id.clone(), self.device_id.clone()))
    }

    /// `[challenge, user_id, device_id]`, the bytes `sig` covers.
    fn tbs(challenge: &[u8], user_id: &UserId, device_id: &DeviceId) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Bytes(challenge.to_vec()),
            Value::Text(user_id.to_string()),
            Value::Text(device_id.to_string()),
        ]))
    }
}
