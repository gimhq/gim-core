//! gim's self-certifying MLS credential: the user's root public key plus the
//! root-signed certificate of the device's signature key. The wire format is
//! specified in `docs/identity.md` ("MLS credential").

use ciborium::Value;
use gim_common::{DeviceId, DeviceRef, UserId};
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

/// Why a credential failed validation. [`CredentialError::code`] gives the
/// stable name used by the test vectors and `docs/identity.md`.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential type {0:#06x} is not a gim credential")]
    WrongCredentialType(u16),
    #[error("credential content is not deterministic CBOR")]
    NonCanonicalCbor,
    #[error("malformed credential content: {0}")]
    MalformedContent(String),
    #[error("unsupported credential version")]
    UnsupportedVersion,
    #[error("device certificate: {0}")]
    Cert(gim_identity::IdentityError),
    #[error("leaf signature key does not match the certified device key")]
    LeafKeyMismatch,
    #[error("device {device} of {user} is revoked")]
    RevokedDevice { user: UserId, device: DeviceId },
}

impl CredentialError {
    /// Stable snake_case name of the failure.
    pub fn code(&self) -> &'static str {
        use gim_identity::IdentityError;
        match self {
            Self::WrongCredentialType(_) => "wrong_credential_type",
            Self::NonCanonicalCbor => "non_canonical_cbor",
            Self::MalformedContent(_) => "malformed_content",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Cert(IdentityError::BadSignature) => "bad_cert_signature",
            Self::Cert(IdentityError::UserIdMismatch) => "user_id_mismatch",
            Self::Cert(IdentityError::DeviceIdMismatch) => "device_id_mismatch",
            Self::Cert(_) => "invalid_cert",
            Self::LeafKeyMismatch => "leaf_key_mismatch",
            Self::RevokedDevice { .. } => "revoked_device",
        }
    }
}

impl From<CredentialError> for CryptoError {
    fn from(err: CredentialError) -> Self {
        Self::InvalidCredential {
            reason: format!("{}: {err}", err.code()),
        }
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
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        let malformed = |reason: &str| CredentialError::MalformedContent(reason.into());
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| malformed(&e.to_string()))?;
        if encode_cbor(&value) != bytes {
            return Err(CredentialError::NonCanonicalCbor);
        }
        let Value::Array(items) = value else {
            return Err(malformed("content is not an array"));
        };
        let [version, root, cert]: [Value; 3] = items
            .try_into()
            .map_err(|_| malformed("content is not an array of 3 items"))?;
        let Value::Integer(version) = version else {
            return Err(malformed("version is not an integer"));
        };
        if u64::try_from(version).ok() != Some(CREDENTIAL_VERSION) {
            return Err(CredentialError::UnsupportedVersion);
        }
        let (Value::Bytes(root), Value::Bytes(cert)) = (root, cert) else {
            return Err(malformed("expected byte strings"));
        };
        let root: [u8; 32] = root
            .try_into()
            .map_err(|_| malformed("root public key is not 32 bytes"))?;
        Ok(Self {
            root_public_key: RootPublicKey::from_bytes(&root)
                .map_err(|e| malformed(&e.to_string()))?,
            signed_cert: SignedDeviceCert::from_bytes(&cert).map_err(CredentialError::Cert)?,
        })
    }

    /// Checks the chain: the cert verifies under the root key and its
    /// `user_id` is derived from it.
    pub fn verify(&self) -> Result<DeviceCert, CredentialError> {
        self.signed_cert
            .verify(&self.root_public_key)
            .map_err(CredentialError::Cert)
    }

    /// The MLS credential carrying this content.
    pub fn to_mls(&self) -> Credential {
        Credential::new(CredentialType::Other(GIM_CREDENTIAL_TYPE), self.encode())
    }

    /// Parses an MLS credential; any type other than
    /// [`GIM_CREDENTIAL_TYPE`] is rejected.
    pub fn from_mls(credential: &Credential) -> Result<Self, CredentialError> {
        let credential_type = credential.credential_type();
        if credential_type != CredentialType::Other(GIM_CREDENTIAL_TYPE) {
            return Err(CredentialError::WrongCredentialType(credential_type.into()));
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
    Ok(check(credential, leaf_signature_key, lookup)?)
}

/// [`validate`] with the typed failure reason.
pub fn check(
    credential: &Credential,
    leaf_signature_key: &[u8],
    lookup: &dyn DeviceListLookup,
) -> Result<DeviceRef, CredentialError> {
    let cert = GimCredential::from_mls(credential)?.verify()?;
    if cert.device_public_key.as_bytes().as_slice() != leaf_signature_key {
        return Err(CredentialError::LeafKeyMismatch);
    }
    if lookup
        .device_list(&cert.user_id)
        .is_some_and(|list| list.is_revoked(&cert.device_id))
    {
        return Err(CredentialError::RevokedDevice {
            user: cert.user_id,
            device: cert.device_id,
        });
    }
    Ok(DeviceRef::new(cert.user_id, cert.device_id))
}

fn encode_cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("writing CBOR to a Vec cannot fail");
    bytes
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
        assert_eq!(
            GimCredential::from_mls(&credential.to_mls()).unwrap(),
            credential
        );
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
