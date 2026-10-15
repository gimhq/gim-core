use std::cmp::Ordering;
use std::collections::HashSet;

use ciborium::Value;
use gim_common::{DeviceId, UserId};

use crate::cbor;
use crate::ids::parse_device_id;
use crate::keys::{sign, verify};
use crate::{DeviceCert, IdentityError, RootKey, RootPublicKey, SignedDeviceCert, FORMAT_VERSION};

/// Signature context of a [`SignedDeviceList`].
pub const DEVICE_LIST_CONTEXT: &[u8] = b"gim/device-list/v1";

/// A validated device list: every cert verifies under the root key, no
/// device is listed twice, and no device is both certified and revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceList {
    user_id: UserId,
    root_public_key: RootPublicKey,
    seq: u64,
    certs: Vec<(SignedDeviceCert, DeviceCert)>,
    revoked: Vec<DeviceId>,
}

impl DeviceList {
    /// Builds an unsigned list and validates it.
    pub fn new(
        root_public_key: RootPublicKey,
        seq: u64,
        certs: Vec<SignedDeviceCert>,
        revoked: Vec<DeviceId>,
    ) -> Result<Self, IdentityError> {
        let certs = certs
            .into_iter()
            .map(|signed| {
                let cert = signed.verify(&root_public_key)?;
                Ok((signed, cert))
            })
            .collect::<Result<Vec<_>, IdentityError>>()?;
        let mut certified = HashSet::new();
        for (_, cert) in &certs {
            if !certified.insert(&cert.device_id) {
                return Err(IdentityError::DuplicateDevice(cert.device_id.clone()));
            }
        }
        let mut seen = HashSet::new();
        for device_id in &revoked {
            if certified.contains(device_id) {
                return Err(IdentityError::Revoked(device_id.clone()));
            }
            if !seen.insert(device_id) {
                return Err(IdentityError::DuplicateDevice(device_id.clone()));
            }
        }
        Ok(Self {
            user_id: root_public_key.user_id(),
            root_public_key,
            seq,
            certs,
            revoked,
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn root_public_key(&self) -> &RootPublicKey {
        &self.root_public_key
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Certified (non-revoked) devices, in list order.
    pub fn certs(&self) -> impl Iterator<Item = &DeviceCert> {
        self.certs.iter().map(|(_, cert)| cert)
    }

    pub fn revoked(&self) -> &[DeviceId] {
        &self.revoked
    }

    /// Whether `device_id` is certified by this list.
    pub fn contains(&self, device_id: &DeviceId) -> bool {
        self.certs().any(|cert| &cert.device_id == device_id)
    }

    pub fn is_revoked(&self, device_id: &DeviceId) -> bool {
        self.revoked.contains(device_id)
    }

    /// Whether `self` (received) replaces `other` (stored), per the update
    /// rules of `docs/identity.md`: `Ok(true)` for the same user with a
    /// strictly higher seq; `Ok(false)` (unchanged, a no-op) for the same seq
    /// and identical body bytes; [`IdentityError::SeqConflict`] for the same
    /// seq and different bytes; [`IdentityError::StaleSeq`] for a lower seq;
    /// [`IdentityError::UserIdMismatch`] for another user.
    pub fn supersedes(&self, other: &DeviceList) -> Result<bool, IdentityError> {
        if self.user_id != other.user_id {
            return Err(IdentityError::UserIdMismatch);
        }
        match self.seq.cmp(&other.seq) {
            Ordering::Greater => Ok(true),
            Ordering::Less => Err(IdentityError::StaleSeq(self.seq)),
            Ordering::Equal if self.encode() == other.encode() => Ok(false),
            Ordering::Equal => Err(IdentityError::SeqConflict(self.seq)),
        }
    }

    /// A copy with `cert` appended and seq + 1.
    pub fn add_cert(&self, cert: SignedDeviceCert) -> Result<Self, IdentityError> {
        let mut certs = self.signed_certs();
        certs.push(cert);
        Self::new(
            self.root_public_key,
            self.next_seq()?,
            certs,
            self.revoked.clone(),
        )
    }

    /// A copy with the cert of `device_id` moved to the revoked set and
    /// seq + 1.
    pub fn revoke(&self, device_id: &DeviceId) -> Result<Self, IdentityError> {
        if self.is_revoked(device_id) {
            return Err(IdentityError::Revoked(device_id.clone()));
        }
        if !self.contains(device_id) {
            return Err(IdentityError::UnknownDevice(device_id.clone()));
        }
        let certs = self
            .certs
            .iter()
            .filter(|(_, cert)| &cert.device_id != device_id)
            .map(|(signed, _)| signed.clone())
            .collect();
        let mut revoked = self.revoked.clone();
        revoked.push(device_id.clone());
        Self::new(self.root_public_key, self.next_seq()?, certs, revoked)
    }

    /// Signs the list; `root` must be the list's root key.
    pub fn sign(&self, root: &RootKey) -> Result<SignedDeviceList, IdentityError> {
        if root.public() != self.root_public_key {
            return Err(IdentityError::RootKeyMismatch);
        }
        let tbs = self.encode();
        let sig = sign(&root.0, DEVICE_LIST_CONTEXT, &tbs);
        Ok(SignedDeviceList { tbs, sig })
    }

    fn next_seq(&self) -> Result<u64, IdentityError> {
        self.seq.checked_add(1).ok_or(IdentityError::SeqOverflow)
    }

    fn signed_certs(&self) -> Vec<SignedDeviceCert> {
        self.certs
            .iter()
            .map(|(signed, _)| signed.clone())
            .collect()
    }

    /// The body `[1, user_id, root_pubkey, seq, [cert...], [revoked...]]`.
    fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Text(self.user_id.to_string()),
            Value::Bytes(self.root_public_key.as_bytes().to_vec()),
            Value::Integer(self.seq.into()),
            Value::Array(
                self.certs
                    .iter()
                    .map(|(signed, _)| Value::Bytes(signed.to_bytes()))
                    .collect(),
            ),
            Value::Array(
                self.revoked
                    .iter()
                    .map(|id| Value::Text(id.to_string()))
                    .collect(),
            ),
        ]))
    }
}

/// `[tbs: bstr, sig: bstr(64)]` where `tbs` is a [`DeviceList`] body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceList {
    tbs: Vec<u8>,
    sig: [u8; 64],
}

impl SignedDeviceList {
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode_signed(&self.tbs, &self.sig)
    }

    /// Parses the outer `[tbs, sig]` structure; call [`Self::verify`] to
    /// check it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (tbs, sig) = cbor::decode_signed(bytes)?;
        Ok(Self { tbs, sig })
    }

    /// Verifies the list of `user_id` in the documented order: extract only
    /// the embedded root key and check that it derives `user_id`, check the
    /// signature over the received `tbs`, then validate the body (version,
    /// body `user_id`, [`DeviceList::new`] checks).
    pub fn verify(&self, user_id: &UserId) -> Result<DeviceList, IdentityError> {
        let body = cbor::decode(&self.tbs)?;
        let root_public_key = RootPublicKey::from_bytes(&cbor::key(cbor::item(&body, 2)?)?)?;
        let derived = root_public_key.user_id();
        if &derived != user_id {
            return Err(IdentityError::UserIdMismatch);
        }
        verify(
            &root_public_key.0,
            DEVICE_LIST_CONTEXT,
            &self.tbs,
            &self.sig,
        )?;
        let [_, list_user_id, _, seq, certs, revoked] = cbor::body(body)?;
        if cbor::text(list_user_id)? != derived.as_str() {
            return Err(IdentityError::UserIdMismatch);
        }
        let seq = cbor::uint(seq)?;
        let certs = cbor::list(certs)?
            .into_iter()
            .map(|cert| SignedDeviceCert::from_bytes(&cbor::bytes_value(cert)?))
            .collect::<Result<Vec<_>, _>>()?;
        let revoked = cbor::list(revoked)?
            .into_iter()
            .map(|id| parse_device_id(&cbor::text(id)?))
            .collect::<Result<Vec<_>, _>>()?;
        DeviceList::new(root_public_key, seq, certs, revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceSigningKey;

    #[test]
    fn rejects_signed_list_with_duplicate_or_revoked_cert() {
        let root = RootKey::from_seed(&[1; 32]);
        let device = DeviceSigningKey::from_seed(&[2; 32]).public();
        let cert = SignedDeviceCert::issue(&root, &device, 0, 1);
        let user = root.public().user_id();
        let raw = |certs: Vec<Value>, revoked: Vec<Value>| {
            let tbs = cbor::encode(&Value::Array(vec![
                Value::Integer(1.into()),
                Value::Text(user.to_string()),
                Value::Bytes(root.public().as_bytes().to_vec()),
                Value::Integer(1.into()),
                Value::Array(certs),
                Value::Array(revoked),
            ]));
            let sig = sign(&root.0, DEVICE_LIST_CONTEXT, &tbs);
            SignedDeviceList { tbs, sig }
        };
        let cert_value = || Value::Bytes(cert.to_bytes());
        let id_value = || Value::Text(device.device_id().to_string());

        assert!(raw(vec![cert_value()], vec![]).verify(&user).is_ok());
        assert!(matches!(
            raw(vec![cert_value(), cert_value()], vec![]).verify(&user),
            Err(IdentityError::DuplicateDevice(_))
        ));
        assert!(matches!(
            raw(vec![cert_value()], vec![id_value()]).verify(&user),
            Err(IdentityError::Revoked(_))
        ));
        assert!(matches!(
            raw(vec![], vec![id_value(), id_value()]).verify(&user),
            Err(IdentityError::DuplicateDevice(_))
        ));
    }
}
