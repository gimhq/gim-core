//! Async `Client` (tokio): HTTP (reqwest, rustls), WebSocket + long-poll, sync
//! loop, outbox sender, media upload/download.
//!
//! The client talks to gim-server through the [`Transport`] trait; the
//! store is generic ([`gim_base::StateStore`]), so gim-ffi picks the SQLite
//! store and tests the in-memory one.
//!
//! Structure follows matrix-rust-sdk's `matrix-sdk` (Apache-2.0): a cheaply
//! cloneable `Client` over a shared inner state, built by a `ClientBuilder`.
//! No code is copied.

#![forbid(unsafe_code)]

mod client;
mod error;
pub mod http;
mod media;
mod outbox;
mod secrets;
mod send;
pub mod stream;
mod sync;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod transport;

pub use client::{
    Client, ClientBuilder, Session, COMMIT_POST_ATTEMPTS, KEY_PACKAGE_BATCH, MAX_COMMIT_RETRIES,
    SESSION_SECRET_KEY,
};
pub use error::{ClientError, Result};
pub use http::{HttpConfig, HttpTransport};
pub use media::DOWNLOAD_PIECE;
pub use outbox::OutboxSender;
pub use secrets::{SecretStorage, SecretStorageError};
pub use send::TYPING_INTERVAL;
pub use stream::ConnectionState;
pub use sync::{SyncSettings, BACKFILL_PAGE};
pub use transport::{EventStream, Transport, TransportError};
