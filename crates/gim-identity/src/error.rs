use gim_common::DeviceId;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("user id does not match the root public key")]
    UserIdMismatch,
    #[error("device id does not match the device public key")]
    DeviceIdMismatch,
    #[error("signing key is not the root key of the device list")]
    RootKeyMismatch,
    #[error("invalid Ed25519 public key")]
    InvalidKey,
    #[error("invalid user id: {0}")]
    InvalidUserId(String),
    #[error("invalid device id: {0}")]
    InvalidDeviceId(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("not deterministic CBOR")]
    NonCanonical,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u64),
    #[error("device {0} is revoked")]
    Revoked(DeviceId),
    #[error("device {0} appears more than once")]
    DuplicateDevice(DeviceId),
    #[error("device {0} is not in the device list")]
    UnknownDevice(DeviceId),
    #[error("different device lists with the same seq {0}")]
    SeqConflict(u64),
    #[error("seq {0} is lower than the stored seq")]
    StaleSeq(u64),
    #[error("device list seq overflow")]
    SeqOverflow,
    #[error("expired")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
    #[error("challenge audience does not match this hub")]
    AudienceMismatch,
    #[error("challenge audience_url does not match the hub URL, or wrong challenge version")]
    AudienceUrlMismatch,
    #[error("invalid hub URL: {0}")]
    InvalidUrl(String),
    #[error("hub root key does not match the expected hub")]
    HubKeyMismatch,
    #[error("invalid hub signature on the hosting entry of {0}")]
    BadHubSignature(String),
    #[error("hub {0} appears more than once")]
    DuplicateHub(String),
    #[error("hosting record hubs are not sorted by (priority, hub_root_pubkey)")]
    UnsortedHubs,
    #[error("the user root key is also a hub root key of the hosting record")]
    UserKeyIsHubKey,
    #[error("challenge issued_at is not before expires_at")]
    InvalidValidityWindow,
    #[error("challenge lifetime exceeds the maximum")]
    LifetimeTooLong,
    #[error("hosting record has {0} hubs, expected 1..=16")]
    HubCount(usize),
    #[error("random number generator failed: {0}")]
    Random(String),
}

impl IdentityError {
    /// Stable snake_case name of the error kind, independent of the
    /// message and payload; the `expected_error` of the negative vectors
    /// (`docs/identity.md`, "Negative vectors").
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadSignature => "bad_signature",
            Self::UserIdMismatch => "user_id_mismatch",
            Self::DeviceIdMismatch => "device_id_mismatch",
            Self::RootKeyMismatch => "root_key_mismatch",
            Self::InvalidKey => "invalid_key",
            Self::InvalidUserId(_) => "invalid_user_id",
            Self::InvalidDeviceId(_) => "invalid_device_id",
            Self::Decode(_) => "decode_error",
            Self::NonCanonical => "non_canonical_cbor",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::Revoked(_) => "device_revoked",
            Self::DuplicateDevice(_) => "duplicate_device",
            Self::UnknownDevice(_) => "unknown_device",
            Self::SeqConflict(_) => "seq_conflict",
            Self::StaleSeq(_) => "stale_seq",
            Self::SeqOverflow => "seq_overflow",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::AudienceMismatch => "audience_mismatch",
            Self::AudienceUrlMismatch => "audience_url_mismatch",
            Self::InvalidUrl(_) => "invalid_url",
            Self::HubKeyMismatch => "hub_key_mismatch",
            Self::BadHubSignature(_) => "bad_hub_signature",
            Self::DuplicateHub(_) => "duplicate_hub",
            Self::UnsortedHubs => "unsorted_hubs",
            Self::UserKeyIsHubKey => "user_key_is_hub_key",
            Self::InvalidValidityWindow => "invalid_validity_window",
            Self::LifetimeTooLong => "lifetime_too_long",
            Self::HubCount(_) => "hub_count",
            Self::Random(_) => "random",
        }
    }
}
