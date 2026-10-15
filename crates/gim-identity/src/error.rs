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
    #[error("device list seq overflow")]
    SeqOverflow,
    #[error("expired")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
    #[error("challenge audience does not match this hub")]
    AudienceMismatch,
    #[error("hub root key does not match the expected hub")]
    HubKeyMismatch,
    #[error("invalid hub signature on the hosting entry of {0}")]
    BadHubSignature(String),
    #[error("hub {0} appears more than once")]
    DuplicateHub(String),
    #[error("hosting record has {0} hubs, expected 1..=16")]
    HubCount(usize),
    #[error("random number generator failed: {0}")]
    Random(String),
}
