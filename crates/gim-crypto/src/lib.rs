//! OpenMLS wrapper for gim: identity, KeyPackages, groups, commits and
//! application messages. Persistence goes through the [`CryptoStore`] trait,
//! which every operation takes as a parameter so callers can pass a
//! transaction-scoped store. No networking.

#![forbid(unsafe_code)]

mod config;
mod engine;
mod error;
mod memory_store;
mod store;

pub use config::{
    CIPHERSUITE, MAXIMUM_FORWARD_DISTANCE, MAX_PAST_EPOCHS, OUT_OF_ORDER_TOLERANCE, PADDING_SIZE,
};
pub use engine::{
    CommitOutput, GroupJoined, MlsEngine, ProcessedMessage, MAX_KEY_PACKAGES_PER_CALL,
};
pub use error::CryptoError;
pub use memory_store::{MemoryCryptoStore, MemoryStoreError};
pub use store::{CryptoStore, StoredIdentity};
