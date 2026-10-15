//! Hub identity, hub runtime certificates and user hosting records.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use ciborium::Value;
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use gim_common::UserId;
use sha2::{Digest, Sha256};

use crate::cbor;
use crate::keys::{sign, verify};
use crate::{IdentityError, RootKey, RootPublicKey, FORMAT_VERSION};

/// Signature context of a [`SignedHubRuntimeCert`].
pub const HUB_RUNTIME_CERT_CONTEXT: &[u8] = b"gim/hub-runtime-cert/v1";
/// Signature context of a [`HostingEntry`] hub signature.
pub const HOSTING_ENTRY_CONTEXT: &[u8] = b"gim/hosting-entry/v1";
/// Signature context of a [`SignedHostingRecord`].
pub const HOSTING_RECORD_CONTEXT: &[u8] = b"gim/hosting-record/v1";

/// Maximum number of hubs in a hosting record.
pub const MAX_HUBS: usize = 16;

const HUB_PREFIX: &str = "h";
/// Multihash header: sha2-256 code, 32-byte digest.
const MULTIHASH_SHA256: [u8; 2] = [0x12, 0x20];
/// Identity multihash (code 0x00, length 36) of the libp2p protobuf
/// `PublicKey { Type: Ed25519 (field 1 = 1), Data (field 2, 32 bytes) }`.
const LIBP2P_ED25519_PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

/// A hub's long-term Ed25519 root key. It signs hosting entries and runtime
/// certificates; `hub_id` is derived from its public half.
///
/// The secret is zeroized on drop and never printed by `Debug`.
pub struct HubRootKey(RootKey);

impl HubRootKey {
    /// Derives the key from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(RootKey::from_seed(seed))
    }

    /// Generates a key from the operating system RNG.
    pub fn generate() -> Result<Self, IdentityError> {
        RootKey::generate().map(Self)
    }

    pub fn public(&self) -> HubRootPublicKey {
        HubRootPublicKey(self.0.public())
    }
}

impl fmt::Debug for HubRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HubRootKey")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

/// Public half of a [`HubRootKey`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HubRootPublicKey(RootPublicKey);

impl HubRootPublicKey {
    /// Parses a compressed Edwards point; rejects invalid and small-order
    /// points.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        RootPublicKey::from_bytes(bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// `"h" + base32(0x12 0x20 || SHA-256(hub_root_pubkey))`.
    pub fn hub_id(&self) -> String {
        let mut multihash = MULTIHASH_SHA256.to_vec();
        multihash.extend_from_slice(&Sha256::digest(self.as_bytes()));
        format!(
            "{HUB_PREFIX}{}",
            BASE32_NOPAD.encode(&multihash).to_ascii_lowercase()
        )
    }
}

impl fmt::Debug for HubRootPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HubRootPublicKey({})", HEXLOWER.encode(self.as_bytes()))
    }
}

/// A hub's Ed25519 runtime public key: its libp2p host key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HubRuntimePublicKey(RootPublicKey);

impl HubRuntimePublicKey {
    /// Parses a compressed Edwards point; rejects invalid and small-order
    /// points.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        RootPublicKey::from_bytes(bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for HubRuntimePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HubRuntimePublicKey({})",
            HEXLOWER.encode(self.as_bytes())
        )
    }
}

/// libp2p PeerId bytes of an Ed25519 runtime key:
/// `0x00 0x24 0x08 0x01 0x12 0x20 || pubkey`, the identity multihash of the
/// protobuf-encoded libp2p `PublicKey`.
pub fn libp2p_peer_id_bytes(runtime: &HubRuntimePublicKey) -> [u8; 38] {
    let mut bytes = [0u8; 38];
    bytes[..6].copy_from_slice(&LIBP2P_ED25519_PEER_ID_PREFIX);
    bytes[6..].copy_from_slice(runtime.as_bytes());
    bytes
}

/// A verified runtime certificate: the hub root key vouches for
/// `runtime_public_key` between `not_before` and `not_after`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubRuntimeCert {
    pub hub_root_public_key: HubRootPublicKey,
    pub runtime_public_key: HubRuntimePublicKey,
    /// Unix time in milliseconds.
    pub not_before: u64,
    /// Unix time in milliseconds, exclusive.
    pub not_after: u64,
}

/// `[tbs: bstr, sig: bstr(64)]` where `tbs` is the CBOR body
/// `[1, hub_root_pubkey, runtime_pubkey, not_before, not_after]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHubRuntimeCert {
    tbs: Vec<u8>,
    sig: [u8; 64],
}

impl SignedHubRuntimeCert {
    /// Certifies `runtime` under `hub_root`.
    pub fn issue(
        hub_root: &HubRootKey,
        runtime: &HubRuntimePublicKey,
        not_before: u64,
        not_after: u64,
    ) -> Self {
        let tbs = cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Bytes(hub_root.public().as_bytes().to_vec()),
            Value::Bytes(runtime.as_bytes().to_vec()),
            Value::Integer(not_before.into()),
            Value::Integer(not_after.into()),
        ]));
        let sig = sign(&hub_root.0 .0, HUB_RUNTIME_CERT_CONTEXT, &tbs);
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

    /// Checks the signature of `hub_root` over the received `tbs`, then the
    /// body: version, `hub_root_pubkey` equal to `hub_root`, and
    /// `not_before <= now < not_after`.
    pub fn verify(
        &self,
        hub_root: &HubRootPublicKey,
        now: u64,
    ) -> Result<HubRuntimeCert, IdentityError> {
        verify(
            &hub_root.0 .0,
            HUB_RUNTIME_CERT_CONTEXT,
            &self.tbs,
            &self.sig,
        )?;
        let [_, hub_root_public_key, runtime_public_key, not_before, not_after] =
            cbor::decode_body(&self.tbs)?;
        if cbor::key(hub_root_public_key)? != *hub_root.as_bytes() {
            return Err(IdentityError::HubKeyMismatch);
        }
        let runtime_public_key = HubRuntimePublicKey::from_bytes(&cbor::key(runtime_public_key)?)?;
        let not_before = cbor::uint(not_before)?;
        let not_after = cbor::uint(not_after)?;
        if now < not_before {
            return Err(IdentityError::NotYetValid);
        }
        if now >= not_after {
            return Err(IdentityError::Expired);
        }
        Ok(HubRuntimeCert {
            hub_root_public_key: *hub_root,
            runtime_public_key,
            not_before,
            not_after,
        })
    }
}

/// One hub of a hosting record: the hub's consent to host `user_id` with
/// `priority` (lower is preferred).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingEntry {
    hub_root_public_key: HubRootPublicKey,
    priority: u8,
    hub_sig: [u8; 64],
}

impl HostingEntry {
    /// The hub signs its consent to host `user_id`.
    pub fn sign(hub_root: &HubRootKey, user_id: &UserId, priority: u8) -> Self {
        let hub_root_public_key = hub_root.public();
        let tbs = Self::tbs(user_id.as_str(), &hub_root_public_key, priority);
        let hub_sig = sign(&hub_root.0 .0, HOSTING_ENTRY_CONTEXT, &tbs);
        Self {
            hub_root_public_key,
            priority,
            hub_sig,
        }
    }

    pub fn hub_root_public_key(&self) -> &HubRootPublicKey {
        &self.hub_root_public_key
    }

    pub fn hub_id(&self) -> String {
        self.hub_root_public_key.hub_id()
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// `[1, user_id, hub_root_pubkey, priority]`, the bytes `hub_sig` covers.
    fn tbs(user_id: &str, hub: &HubRootPublicKey, priority: u8) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Text(user_id.into()),
            Value::Bytes(hub.as_bytes().to_vec()),
            Value::Integer(priority.into()),
        ]))
    }

    fn verify(&self, user_id: &UserId) -> Result<(), IdentityError> {
        let tbs = Self::tbs(user_id.as_str(), &self.hub_root_public_key, self.priority);
        verify(
            &self.hub_root_public_key.0 .0,
            HOSTING_ENTRY_CONTEXT,
            &tbs,
            &self.hub_sig,
        )
        .map_err(|_| IdentityError::BadHubSignature(self.hub_id()))
    }

    /// `[hub_root_pubkey, priority, hub_sig]`.
    fn encode(&self) -> Value {
        Value::Array(vec![
            Value::Bytes(self.hub_root_public_key.as_bytes().to_vec()),
            Value::Integer(self.priority.into()),
            Value::Bytes(self.hub_sig.to_vec()),
        ])
    }

    fn decode(value: Value) -> Result<Self, IdentityError> {
        let [hub, priority, hub_sig] = cbor::array(value)?;
        let hub_root_public_key = HubRootPublicKey::from_bytes(&cbor::key(hub)?)?;
        let priority = u8::try_from(cbor::uint(priority)?)
            .map_err(|_| IdentityError::Decode("priority is not 0..=255".into()))?;
        let hub_sig = cbor::bytes_value(hub_sig)?
            .try_into()
            .map_err(|_| IdentityError::Decode("hub signature is not 64 bytes".into()))?;
        Ok(Self {
            hub_root_public_key,
            priority,
            hub_sig,
        })
    }
}

/// A validated hosting record: 1..=16 distinct hubs, each of which signed
/// its entry for this user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserHostingRecord {
    user_id: UserId,
    user_root_public_key: RootPublicKey,
    seq: u64,
    expires_at: u64,
    hubs: Vec<HostingEntry>,
}

impl UserHostingRecord {
    /// Builds an unsigned record and validates its hub entries.
    pub fn new(
        user_root_public_key: RootPublicKey,
        seq: u64,
        expires_at: u64,
        hubs: Vec<HostingEntry>,
    ) -> Result<Self, IdentityError> {
        if hubs.is_empty() || hubs.len() > MAX_HUBS {
            return Err(IdentityError::HubCount(hubs.len()));
        }
        let user_id = user_root_public_key.user_id();
        let mut seen = HashSet::new();
        for entry in &hubs {
            entry.verify(&user_id)?;
            if !seen.insert(*entry.hub_root_public_key.as_bytes()) {
                return Err(IdentityError::DuplicateHub(entry.hub_id()));
            }
        }
        Ok(Self {
            user_id,
            user_root_public_key,
            seq,
            expires_at,
            hubs,
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn user_root_public_key(&self) -> &RootPublicKey {
        &self.user_root_public_key
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Unix time in milliseconds, exclusive.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Hub entries in record order.
    pub fn hubs(&self) -> &[HostingEntry] {
        &self.hubs
    }

    /// The preferred hub: lowest priority value, ties broken by the
    /// smallest `hub_id`.
    pub fn primary(&self) -> &HostingEntry {
        self.hubs
            .iter()
            .min_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then_with(|| a.hub_id().cmp(&b.hub_id()))
            })
            .expect("a record has at least one hub")
    }

    /// Whether `self` (received) replaces `other` (stored), per the update
    /// rules of `docs/identity.md`: `Ok(true)` for the same user with a
    /// strictly higher seq; `Ok(false)` (unchanged, a no-op) for the same seq
    /// and identical body bytes; [`IdentityError::SeqConflict`] for the same
    /// seq and different bytes; [`IdentityError::StaleSeq`] for a lower seq;
    /// [`IdentityError::UserIdMismatch`] for another user.
    pub fn supersedes(&self, other: &UserHostingRecord) -> Result<bool, IdentityError> {
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

    /// Signs the record; `root` must be the record's user root key.
    pub fn sign(&self, root: &RootKey) -> Result<SignedHostingRecord, IdentityError> {
        if root.public() != self.user_root_public_key {
            return Err(IdentityError::RootKeyMismatch);
        }
        let tbs = self.encode();
        let sig = sign(&root.0, HOSTING_RECORD_CONTEXT, &tbs);
        Ok(SignedHostingRecord { tbs, sig })
    }

    /// The body `[1, user_id, user_root_pubkey, seq, expires_at, [entry...]]`.
    fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Text(self.user_id.to_string()),
            Value::Bytes(self.user_root_public_key.as_bytes().to_vec()),
            Value::Integer(self.seq.into()),
            Value::Integer(self.expires_at.into()),
            Value::Array(self.hubs.iter().map(HostingEntry::encode).collect()),
        ]))
    }
}

/// `[tbs: bstr, sig: bstr(64)]` where `tbs` is a [`UserHostingRecord`] body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHostingRecord {
    tbs: Vec<u8>,
    sig: [u8; 64],
}

impl SignedHostingRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode_signed(&self.tbs, &self.sig)
    }

    /// Parses the outer `[tbs, sig]` structure; call [`Self::verify`] to
    /// check it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (tbs, sig) = cbor::decode_signed(bytes)?;
        Ok(Self { tbs, sig })
    }

    /// Verifies the record in the documented order: extract only the claimed
    /// `user_id` and the embedded root key and check that the key derives
    /// it, check the user signature over the received `tbs`, then validate
    /// the body (version, [`UserHostingRecord::new`] checks,
    /// `now < expires_at`). The caller compares
    /// [`UserHostingRecord::user_id`] with the user it looked up.
    pub fn verify(&self, now: u64) -> Result<UserHostingRecord, IdentityError> {
        let body = cbor::decode(&self.tbs)?;
        let claimed = cbor::text(cbor::item(&body, 1)?)?;
        let user_root_public_key = RootPublicKey::from_bytes(&cbor::key(cbor::item(&body, 2)?)?)?;
        if claimed != user_root_public_key.user_id().as_str() {
            return Err(IdentityError::UserIdMismatch);
        }
        verify(
            &user_root_public_key.0,
            HOSTING_RECORD_CONTEXT,
            &self.tbs,
            &self.sig,
        )?;
        let [_, _, _, seq, expires_at, hubs] = cbor::body(body)?;
        let seq = cbor::uint(seq)?;
        let expires_at = cbor::uint(expires_at)?;
        let hubs = cbor::list(hubs)?
            .into_iter()
            .map(HostingEntry::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let record = UserHostingRecord::new(user_root_public_key, seq, expires_at, hubs)?;
        if now >= expires_at {
            return Err(IdentityError::Expired);
        }
        Ok(record)
    }
}
