//! gim's self-certifying MLS credential: the user's root public key plus the
//! root-signed certificate of the device's signature key. The wire format is
//! specified in `docs/identity.md` ("MLS credential").

use ciborium::Value;
use gim_common::{DeviceRef, UserId};
use gim_identity::{DeviceCert, DeviceList, RootPublicKey, SignedDeviceCert};
use openmls::prelude::{Credential, CredentialType};

use crate::CryptoError;

/// MLS credential type of a [`GimCredential`] (private-use range).
pub const GIM_CREDENTIAL_TYPE: u16 = 0xF001;

/// First element of the credential content.
const CREDENTIAL_VERSION: u64 = 1;

/// Source of the latest verified [`DeviceList`] per user, consulted for
/// revocations. A lookup that knows no list for a user means no revocations
/// are known for it.
pub trait DeviceListLookup {
    fn device_list(&self, user_id: &UserId) -> Option<DeviceList>;
}

/// A [`DeviceListLookup`] that knows no device lists.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDeviceLists;

impl DeviceListLookup for NoDeviceLists {
    fn device_list(&self, _user_id: &UserId) -> Option<DeviceList> {
        None
    }
}

/// Content of an MLS credential of type [`GIM_CREDENTIAL_TYPE`]:
/// CBOR `[1, root_pubkey: bstr(32), signed_device_cert: bstr]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GimCredential {
    root_public_key: RootPublicKey,
    signed_cert: SignedDeviceCert,
}

impl GimCredential {
    pub fn new(root_public_key: RootPublicKey, signed_cert: SignedDeviceCert) -> Self {
        Self {
            root_public_key,
            signed_cert,
        }
    }

    pub fn root_public_key(&self) -> &RootPublicKey {
        &self.root_public_key
    }

    pub fn signed_cert(&self) -> &SignedDeviceCert {
        &self.signed_cert
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_cbor(&Value::Array(vec![
            Value::Integer(CREDENTIAL_VERSION.into()),
            Value::Bytes(self.root_public_key.as_bytes().to_vec()),
            Value::Bytes(self.signed_cert.to_bytes()),
        ]))
    }

    /// Parses the content; rejects any encoding other than the canonical
    /// one. Does not verify the certificate (see [`GimCredential::verify`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| invalid(format!("malformed CBOR: {e}")))?;
        if encode_cbor(&value) != bytes {
            return Err(invalid("not deterministic CBOR"));
        }
        let Value::Array(items) = value else {
            return Err(invalid("content is not an array"));
        };
        let [version, root, cert]: [Value; 3] = items
            .try_into()
            .map_err(|_| invalid("content is not an array of 3 items"))?;
        let version = match version {
            Value::Integer(int) => u64::try_from(int).ok(),
            _ => None,
        };
        if version != Some(CREDENTIAL_VERSION) {
            return Err(invalid("unsupported credential version"));
        }
        let (Value::Bytes(root), Value::Bytes(cert)) = (root, cert) else {
            return Err(invalid("expected byte strings"));
        };
        let root: [u8; 32] = root
            .try_into()
            .map_err(|_| invalid("root public key is not 32 bytes"))?;
        Ok(Self {
            root_public_key: RootPublicKey::from_bytes(&root).map_err(invalid)?,
            signed_cert: SignedDeviceCert::from_bytes(&cert).map_err(invalid)?,
        })
    }

    /// Checks the chain: the cert verifies under the root key and its
    /// `user_id` is derived from it.
    pub fn verify(&self) -> Result<DeviceCert, CryptoError> {
        self.signed_cert
            .verify(&self.root_public_key)
            .map_err(invalid)
    }

    /// The MLS credential carrying this content.
    pub fn to_mls(&self) -> Credential {
        Credential::new(CredentialType::Other(GIM_CREDENTIAL_TYPE), self.encode())
    }

    /// Parses an MLS credential; any type other than
    /// [`GIM_CREDENTIAL_TYPE`] is rejected.
    pub fn from_mls(credential: &Credential) -> Result<Self, CryptoError> {
        if credential.credential_type() != CredentialType::Other(GIM_CREDENTIAL_TYPE) {
            return Err(invalid(format!(
                "credential type {:?} is not a gim credential",
                credential.credential_type()
            )));
        }
        Self::decode(credential.serialized_content())
    }
}

/// Validates a leaf credential: it is a [`GimCredential`] whose chain
/// verifies, whose certified device key equals `leaf_signature_key`, and
/// whose device is not revoked in the latest list `lookup` knows for the
/// user. Returns the certified device.
pub fn validate(
    credential: &Credential,
    leaf_signature_key: &[u8],
    lookup: &dyn DeviceListLookup,
) -> Result<DeviceRef, CryptoError> {
    let cert = GimCredential::from_mls(credential)?.verify()?;
    if cert.device_public_key.as_bytes().as_slice() != leaf_signature_key {
        return Err(invalid(
            "leaf signature key does not match the certified device key",
        ));
    }
    if lookup
        .device_list(&cert.user_id)
        .is_some_and(|list| list.is_revoked(&cert.device_id))
    {
        return Err(invalid(format!(
            "device {} of {} is revoked",
            cert.device_id, cert.user_id
        )));
    }
    Ok(DeviceRef::new(cert.user_id, cert.device_id))
}

fn encode_cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("writing CBOR to a Vec cannot fail");
    bytes
}

fn invalid(reason: impl ToString) -> CryptoError {
    CryptoError::InvalidCredential {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use gim_identity::{DeviceSigningKey, RootKey};

    use super::*;

    fn sample() -> (GimCredential, DeviceSigningKey) {
        let root = RootKey::from_seed(&[1; 32]);
        let device = DeviceSigningKey::from_seed(&[2; 32]);
        let cert = SignedDeviceCert::issue(&root, &device.public(), 7, 1);
        (GimCredential::new(root.public(), cert), device)
    }

    #[test]
    fn encode_decode_round_trip() {
        let (credential, _) = sample();
        let bytes = credential.encode();
        assert_eq!(GimCredential::decode(&bytes).unwrap(), credential);
        assert_eq!(GimCredential::from_mls(&credential.to_mls()).unwrap(), credential);
    }

    #[test]
    fn decode_is_strict() {
        let (credential, _) = sample();
        let bytes = credential.encode();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(GimCredential::decode(&trailing).is_err());
        for cut in 0..bytes.len() {
            assert!(GimCredential::decode(&bytes[..cut]).is_err());
        }
        let items = |version: u64, root: Vec<u8>| {
            encode_cbor(&Value::Array(vec![
                Value::Integer(version.into()),
                Value::Bytes(root),
                Value::Bytes(credential.signed_cert().to_bytes()),
            ]))
        };
        let root = credential.root_public_key().as_bytes().to_vec();
        assert!(GimCredential::decode(&items(1, root.clone())).is_ok());
        assert!(GimCredential::decode(&items(2, root.clone())).is_err());
        assert!(GimCredential::decode(&items(1, root[..31].to_vec())).is_err());
        // Indefinite-length array.
        let mut indefinite = vec![0x9f];
        indefinite.extend_from_slice(&bytes[1..]);
        indefinite.push(0xff);
        assert!(GimCredential::decode(&indefinite).is_err());
    }

    #[test]
    fn validate_checks_chain_key_and_type() {
        let (credential, device) = sample();
        let key = device.public().as_bytes().to_vec();
        let device_ref = validate(&credential.to_mls(), &key, &NoDeviceLists).unwrap();
        assert_eq!(device_ref.user_id, credential.root_public_key().user_id());
        assert_eq!(device_ref.device_id, device.public().device_id());

        let other = DeviceSigningKey::from_seed(&[3; 32]).public();
        assert!(validate(&credential.to_mls(), other.as_bytes(), &NoDeviceLists).is_err());

        let forged = GimCredential::new(
            RootKey::from_seed(&[9; 32]).public(),
            credential.signed_cert().clone(),
        );
        assert!(matches!(
            validate(&forged.to_mls(), &key, &NoDeviceLists),
            Err(CryptoError::InvalidCredential { .. })
        ));

        let basic = Credential::new(CredentialType::Basic, credential.encode());
        assert!(validate(&basic, &key, &NoDeviceLists).is_err());
    }

    #[test]
    fn validate_rejects_revoked_device() {
        struct Revoking(DeviceList);
        impl DeviceListLookup for Revoking {
            fn device_list(&self, user_id: &UserId) -> Option<DeviceList> {
                (self.0.user_id() == user_id).then(|| self.0.clone())
            }
        }
        let (credential, device) = sample();
        let list = DeviceList::new(
            *credential.root_public_key(),
            1,
            vec![credential.signed_cert().clone()],
            vec![],
        )
        .unwrap();
        let key = device.public().as_bytes().to_vec();
        assert!(validate(&credential.to_mls(), &key, &Revoking(list.clone())).is_ok());
        let revoked = list.revoke(&device.public().device_id()).unwrap();
        assert!(validate(&credential.to_mls(), &key, &Revoking(revoked)).is_err());
    }
}
