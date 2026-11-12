//! OpenMLS wrapper for gim: identity, KeyPackages, groups, commits and
//! application messages. Persistence goes through the [`CryptoStore`] trait,
//! which every operation takes as a parameter so callers can pass a
//! transaction-scoped store. No networking.

#![forbid(unsafe_code)]

mod config;
pub mod credential;
mod device_list_cache;
mod engine;
mod envelope;
mod error;
mod handshake;
mod media;
mod memory_store;
mod store;

pub use config::{
    CIPHERSUITE, MAXIMUM_FORWARD_DISTANCE, MAX_PAST_EPOCHS, OUT_OF_ORDER_TOLERANCE, PADDING_SIZE,
};
pub use credential::{
    CredentialError, DeviceListLookup, GimCredential, NoDeviceLists, GIM_CREDENTIAL_TYPE,
};
pub use device_list_cache::DeviceListCache;
pub use engine::{
    CommitOutput, GroupJoined, MlsEngine, PendingProposal, ProcessedMessage,
    MAX_KEY_PACKAGES_PER_CALL,
};
pub use envelope::{decrypt_to_envelope, encrypt_envelope, DecryptedMessage};
pub use error::CryptoError;
pub use handshake::{
    inspect_handshake, message_epoch, private_message_epoch, HandshakeInfo, HandshakeKind,
};
pub use media::{
    decrypt_media, encrypt_media, EncryptedMedia, MediaDecryptor, MediaEncryption, MediaEncryptor,
    MediaError, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MEDIA_HEADER_LEN, MEDIA_KEY_LEN, MEDIA_MAGIC,
};
pub use memory_store::{MemoryCryptoStore, MemoryStoreError};
pub use store::{CryptoStore, StoredIdentity};
