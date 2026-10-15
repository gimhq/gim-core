//! Device-link bundle sealing and short authentication string.
//!
//! The new device shows a [`LinkOffer`] as a QR code; the old device seals a
//! [`LinkBundle`] to it with [`seal_link_bundle`] and relays the result
//! through a hub; the new device opens it with [`open_link_bundle`]. Both
//! screens show the same [`Sas`]. The normative format is the "Device link"
//! section of `docs/identity.md`.

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::Value;
use data_encoding::BASE64URL_NOPAD;
use gim_common::DeviceId;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor;
use crate::{
    DeviceCert, DeviceList, DevicePublicKey, IdentityError, RootKey, SignedDeviceCert,
    SignedDeviceList, FORMAT_VERSION,
};

/// Prefix of the QR string form of a [`LinkOffer`].
pub const LINK_QR_PREFIX: &str = "gimlink:";
/// HKDF info label of the bundle encryption key.
pub const LINK_KEY_INFO: &[u8] = b"gim/link/key/v1";
/// HKDF info label of the short authentication string.
pub const LINK_SAS_INFO: &[u8] = b"gim/link/sas/v1";

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("link bundle does not decrypt")]
    Decrypt,
    #[error("key agreement produced an all-zero shared secret")]
    WeakKey,
    #[error("device certificate is not for the offering device")]
    CertMismatch,
    #[error("device list is not the user's or does not certify the device")]
    ListMismatch,
    #[error("device {0} is revoked by the device list")]
    Revoked(DeviceId),
    #[error("unsupported link format version {0}")]
    UnsupportedVersion(u64),
    #[error("invalid link QR string")]
    InvalidQr,
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, LinkError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::getrandom(bytes.as_mut()).map_err(|e| IdentityError::Random(e.to_string()))?;
    Ok(bytes)
}

/// [`cbor::decode_body`] reporting a version mismatch of a link structure as
/// [`LinkError::UnsupportedVersion`].
fn decode_body<const N: usize>(bytes: &[u8]) -> Result<[Value; N], LinkError> {
    cbor::decode_body(bytes).map_err(|e| match e {
        IdentityError::UnsupportedVersion(version) => LinkError::UnsupportedVersion(version),
        e => e.into(),
    })
}

fn fixed<const N: usize>(value: Value, what: &str) -> Result<[u8; N], LinkError> {
    cbor::bytes_value(value)?
        .try_into()
        .map_err(|_| IdentityError::Decode(format!("{what} is not {N} bytes")).into())
}

/// What the new device shows as a QR code:
/// `[1, link_id: bstr(16), eph_pub: bstr(32), device_sig_pubkey: bstr(32), hubs: [tstr...]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOffer {
    link_id: [u8; 16],
    eph_pub: [u8; 32],
    device_public_key: DevicePublicKey,
    hubs: Vec<String>,
}

/// The X25519 secret matching [`LinkOffer::eph_pub`]; it stays on the new
/// device. Zeroized on drop and never printed by `Debug`.
pub struct LinkSecret(StaticSecret);

impl fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkSecret(..)")
    }
}

impl LinkOffer {
    /// Creates an offer for the new device's signing key with a random
    /// `link_id` and X25519 key.
    pub fn new(
        device_public_key: DevicePublicKey,
        hubs: Vec<String>,
    ) -> Result<(Self, LinkSecret), LinkError> {
        let link_id = random::<16>()?;
        let eph_secret = random::<32>()?;
        Ok(Self::from_parts(
            *link_id,
            &eph_secret,
            device_public_key,
            hubs,
        ))
    }

    /// Deterministic [`Self::new`] for test vectors.
    #[doc(hidden)]
    pub fn from_parts(
        link_id: [u8; 16],
        eph_secret: &[u8; 32],
        device_public_key: DevicePublicKey,
        hubs: Vec<String>,
    ) -> (Self, LinkSecret) {
        let secret = StaticSecret::from(*eph_secret);
        let offer = Self {
            link_id,
            eph_pub: PublicKey::from(&secret).to_bytes(),
            device_public_key,
            hubs,
        };
        (offer, LinkSecret(secret))
    }

    pub fn link_id(&self) -> &[u8; 16] {
        &self.link_id
    }

    pub fn eph_pub(&self) -> &[u8; 32] {
        &self.eph_pub
    }

    pub fn device_public_key(&self) -> &DevicePublicKey {
        &self.device_public_key
    }

    pub fn hubs(&self) -> &[String] {
        &self.hubs
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Bytes(self.link_id.to_vec()),
            Value::Bytes(self.eph_pub.to_vec()),
            Value::Bytes(self.device_public_key.as_bytes().to_vec()),
            Value::Array(self.hubs.iter().cloned().map(Value::Text).collect()),
        ]))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LinkError> {
        let [_, link_id, eph_pub, device_public_key, hubs] = decode_body(bytes)?;
        Ok(Self {
            link_id: fixed(link_id, "link id")?,
            eph_pub: fixed(eph_pub, "ephemeral key")?,
            device_public_key: DevicePublicKey::from_bytes(&cbor::key(device_public_key)?)?,
            hubs: cbor::list(hubs)?
                .into_iter()
                .map(cbor::text)
                .collect::<Result<_, _>>()?,
        })
    }

    /// `"gimlink:" + base64url-nopad(offer bytes)`.
    pub fn to_qr_string(&self) -> String {
        format!(
            "{LINK_QR_PREFIX}{}",
            BASE64URL_NOPAD.encode(&self.to_bytes())
        )
    }

    pub fn from_qr_string(text: &str) -> Result<Self, LinkError> {
        let encoded = text
            .strip_prefix(LINK_QR_PREFIX)
            .ok_or(LinkError::InvalidQr)?;
        let bytes = BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| LinkError::InvalidQr)?;
        Self::from_bytes(&bytes)
    }
}

/// Six-digit short authentication string both devices display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sas(u32);

impl Sas {
    /// The value in `0..1_000_000`.
    pub fn value(&self) -> u32 {
        self.0
    }
}

/// `"123 456"`.
impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {:03}", self.0 / 1000, self.0 % 1000)
    }
}

/// What the old device hands to the new one. Plaintext
/// `[1, root_seed: bstr(32), cert: bstr, device_list: bstr, welcome: bstr / null]`.
pub struct LinkBundle {
    root_seed: Zeroizing<[u8; 32]>,
    cert: Vec<u8>,
    device_list: Vec<u8>,
    self_group_welcome: Option<Vec<u8>>,
}

impl fmt::Debug for LinkBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkBundle")
            .field("self_group_welcome", &self.self_group_welcome.is_some())
            .finish_non_exhaustive()
    }
}

impl LinkBundle {
    /// `cert` certifies the new device and `device_list` is the user's
    /// current list including it.
    pub fn new(
        root: &RootKey,
        cert: &SignedDeviceCert,
        device_list: &SignedDeviceList,
        self_group_welcome: Option<Vec<u8>>,
    ) -> Self {
        Self {
            root_seed: Zeroizing::new(root.0.to_bytes()),
            cert: cert.to_bytes(),
            device_list: device_list.to_bytes(),
            self_group_welcome,
        }
    }

    fn to_plaintext(&self) -> Zeroizing<Vec<u8>> {
        let mut body = Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Bytes(self.root_seed.to_vec()),
            Value::Bytes(self.cert.clone()),
            Value::Bytes(self.device_list.clone()),
            self.self_group_welcome
                .clone()
                .map_or(Value::Null, Value::Bytes),
        ]);
        let plaintext = Zeroizing::new(cbor::encode(&body));
        if let Value::Array(items) = &mut body {
            if let Value::Bytes(seed) = &mut items[1] {
                seed.zeroize();
            }
        }
        plaintext
    }
}

/// A verified bundle, as opened by the new device.
#[derive(Debug)]
pub struct OpenedLink {
    pub root: RootKey,
    /// The new device's certificate, verified under `root`.
    pub cert: DeviceCert,
    /// The user's device list; it certifies `cert.device_id`.
    pub device_list: DeviceList,
    pub self_group_welcome: Option<Vec<u8>>,
}

struct LinkKeys {
    key: Zeroizing<[u8; 32]>,
    sas: Sas,
    transcript: [u8; 32],
}

fn derive_keys(
    offer: &LinkOffer,
    shared: &SharedSecret,
    sender_pub: &[u8; 32],
) -> Result<LinkKeys, LinkError> {
    if !shared.was_contributory() {
        return Err(LinkError::WeakKey);
    }
    let transcript: [u8; 32] = Sha256::new()
        .chain_update(offer.to_bytes())
        .chain_update(sender_pub)
        .finalize()
        .into();
    let hkdf = Hkdf::<Sha256>::new(Some(&offer.link_id), shared.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand_multi_info(&[LINK_KEY_INFO, &transcript], key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let mut sas = [0u8; 4];
    hkdf.expand_multi_info(&[LINK_SAS_INFO, &transcript], &mut sas)
        .expect("4 bytes is a valid HKDF-SHA256 output length");
    Ok(LinkKeys {
        key,
        sas: Sas(u32::from_be_bytes(sas) % 1_000_000),
        transcript,
    })
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(key.into())
}

/// Old device: seals `bundle` to `offer`. Returns the sealed bytes
/// `[1, sender_eph_pub: bstr(32), nonce: bstr(12), ciphertext: bstr]` and the
/// SAS to display.
pub fn seal_link_bundle(
    offer: &LinkOffer,
    bundle: &LinkBundle,
) -> Result<(Vec<u8>, Sas), LinkError> {
    let sender_secret = random::<32>()?;
    let nonce = random::<12>()?;
    seal_link_bundle_with(offer, bundle, &sender_secret, &nonce)
}

/// Deterministic [`seal_link_bundle`] for test vectors.
#[doc(hidden)]
pub fn seal_link_bundle_with(
    offer: &LinkOffer,
    bundle: &LinkBundle,
    sender_secret: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<(Vec<u8>, Sas), LinkError> {
    let sender = StaticSecret::from(*sender_secret);
    let sender_pub = PublicKey::from(&sender).to_bytes();
    let shared = sender.diffie_hellman(&PublicKey::from(offer.eph_pub));
    let keys = derive_keys(offer, &shared, &sender_pub)?;
    let ciphertext = cipher(&keys.key)
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &bundle.to_plaintext(),
                aad: &keys.transcript,
            },
        )
        .expect("AES-256-GCM encryption of a bundle cannot fail");
    let sealed = cbor::encode(&Value::Array(vec![
        Value::Integer(FORMAT_VERSION.into()),
        Value::Bytes(sender_pub.to_vec()),
        Value::Bytes(nonce.to_vec()),
        Value::Bytes(ciphertext),
    ]));
    Ok((sealed, keys.sas))
}

/// New device: decrypts `sealed` with the secret of `offer` and verifies the
/// bundle against it. Returns the verified contents and the SAS to display.
pub fn open_link_bundle(
    offer: &LinkOffer,
    secret: &LinkSecret,
    sealed: &[u8],
) -> Result<(OpenedLink, Sas), LinkError> {
    let [_, sender_pub, nonce, ciphertext] = decode_body(sealed)?;
    let sender_pub: [u8; 32] = fixed(sender_pub, "sender key")?;
    let nonce: [u8; 12] = fixed(nonce, "nonce")?;
    let ciphertext = cbor::bytes_value(ciphertext)?;
    let shared = secret.0.diffie_hellman(&PublicKey::from(sender_pub));
    let keys = derive_keys(offer, &shared, &sender_pub)?;
    let plaintext = Zeroizing::new(
        cipher(&keys.key)
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &keys.transcript,
                },
            )
            .map_err(|_| LinkError::Decrypt)?,
    );
    Ok((verify_bundle(offer, &plaintext)?, keys.sas))
}

fn verify_bundle(offer: &LinkOffer, plaintext: &[u8]) -> Result<OpenedLink, LinkError> {
    let [_, root_seed, cert, device_list, welcome] = decode_body(plaintext)?;
    let root_seed = Zeroizing::new(cbor::bytes_value(root_seed)?);
    let root_seed: &[u8; 32] = root_seed
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::Decode("root seed is not 32 bytes".into()))?;
    let root = RootKey::from_seed(root_seed);

    let cert = SignedDeviceCert::from_bytes(&cbor::bytes_value(cert)?)?.verify(&root.public())?;
    if cert.device_public_key != offer.device_public_key {
        return Err(LinkError::CertMismatch);
    }

    let device_list = SignedDeviceList::from_bytes(&cbor::bytes_value(device_list)?)?
        .verify(&cert.user_id)
        .map_err(|e| match e {
            IdentityError::UserIdMismatch => LinkError::ListMismatch,
            e => e.into(),
        })?;
    if device_list.is_revoked(&cert.device_id) {
        return Err(LinkError::Revoked(cert.device_id));
    }
    if !device_list.contains(&cert.device_id) {
        return Err(LinkError::ListMismatch);
    }

    let self_group_welcome = match welcome {
        Value::Null => None,
        welcome => Some(cbor::bytes_value(welcome)?),
    };
    Ok(OpenedLink {
        root,
        cert,
        device_list,
        self_group_welcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceSigningKey;

    #[test]
    fn sas_display() {
        assert_eq!(Sas(123_456).to_string(), "123 456");
        assert_eq!(Sas(7).to_string(), "000 007");
    }

    #[test]
    fn debug_hides_secrets() {
        let device = DeviceSigningKey::from_seed(&[2; 32]).public();
        let (_, secret) = LinkOffer::from_parts([0; 16], &[0x42; 32], device, vec![]);
        assert_eq!(format!("{secret:?}"), "LinkSecret(..)");
        let root = RootKey::from_seed(&[0x42; 32]);
        let cert = SignedDeviceCert::issue(&root, &device, 0, 1);
        let list = DeviceList::new(root.public(), 1, vec![cert.clone()], vec![])
            .unwrap()
            .sign(&root)
            .unwrap();
        let debug = format!("{:?}", LinkBundle::new(&root, &cert, &list, None));
        assert!(!debug.contains("42"), "{debug}");
    }

    #[test]
    fn rejects_all_zero_shared_secret() {
        let root = RootKey::from_seed(&[1; 32]);
        let device = DeviceSigningKey::from_seed(&[2; 32]).public();
        let cert = SignedDeviceCert::issue(&root, &device, 0, 1);
        let list = DeviceList::new(root.public(), 1, vec![cert.clone()], vec![])
            .unwrap()
            .sign(&root)
            .unwrap();
        let bundle = LinkBundle::new(&root, &cert, &list, None);
        // The u-coordinate 0 is a small-order point.
        let offer = LinkOffer {
            link_id: [0; 16],
            eph_pub: [0; 32],
            device_public_key: device,
            hubs: vec![],
        };
        assert!(matches!(
            seal_link_bundle(&offer, &bundle),
            Err(LinkError::WeakKey)
        ));

        let (offer, secret) = LinkOffer::from_parts([0; 16], &[3; 32], device, vec![]);
        let sealed = cbor::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(vec![0; 32]),
            Value::Bytes(vec![0; 12]),
            Value::Bytes(vec![0; 16]),
        ]));
        assert!(matches!(
            open_link_bundle(&offer, &secret, &sealed),
            Err(LinkError::WeakKey)
        ));
    }
}
