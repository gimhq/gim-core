//! Client state machine without networking: `StateStore` trait (+ in-memory
//! impl), event/sync processing, outbox state, receipts.
//!
//! Structure follows matrix-rust-sdk's `matrix-sdk-base` (Apache-2.0): a
//! store trait with an in-memory implementation for tests, and a base client
//! that turns server events into store writes. No code is copied.

#![forbid(unsafe_code)]

mod client;
mod error;
pub mod model;
mod outbox;
mod store;

pub use client::BaseClient;
pub use error::{BaseError, Result, StoreError};
pub use outbox::{
    new_message_id, retry_delay_ms, INITIAL_RETRY_DELAY_MS, MAX_RETRY_DELAY_MS, MAX_SEND_ATTEMPTS,
};
pub use store::{MemoryStore, MemoryTxn, StateReader, StateStore, StoreTxn, WriteTarget};
