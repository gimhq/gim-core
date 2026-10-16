//! Async `Client` (tokio): HTTP (reqwest, rustls), WebSocket + long-poll, sync
//! loop, outbox sender, media upload/download.
//!
//! The client talks to gim-hub (API v2) through the [`Transport`] trait; the
//! store is generic ([`gim_base::StateStore`]), so gim-ffi picks the SQLite
//! store and tests the in-memory one.
//!
//! Structure follows matrix-rust-sdk's `matrix-sdk` (Apache-2.0): a cheaply
//! cloneable `Client` over a shared inner state, built by a `ClientBuilder`.
//! No code is copied.

#![forbid(unsafe_code)]

mod auth;
mod client;
mod error;
mod history;
mod hosting;
pub mod http;
mod hubs;
mod identity;
mod invites;
mod link;
mod media;
mod outbox;
mod secrets;
mod self_group;
mod send;
pub mod stream;
mod sync;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod transport;

pub use client::{
    Client, ClientBuilder, Session, COMMIT_POST_ATTEMPTS, DEVICE_KEY_SECRET_KEY,
    ENROLLMENT_SECRET_KEY, KEY_PACKAGE_BATCH, MAX_COMMIT_RETRIES, ROOT_KEY_SECRET_KEY,
    SESSION_SECRET_KEY,
};
pub use error::{ClientError, Result};
pub use gim_identity::recovery::RecoveryCode;
pub use history::Backfill;
pub use hosting::{
    HOSTING_RECORD_CHECK_INTERVAL, HOSTING_RECORD_LIFETIME, HOSTING_RECORD_RENEW_BEFORE,
};
pub use http::{HttpConfig, HttpTransport};
pub use hubs::{HubConnector, HubStatus};
pub use invites::INVITE_RETRY_MAX;
pub use link::{LinkResult, LinkSession, PendingApproval, Sas, LINK_BUNDLE_LIFETIME, LINK_TIMEOUT};
pub use media::{DOWNLOAD_PIECE, OUTGOING_DIR};
pub use outbox::OutboxSender;
pub use secrets::{SecretStorage, SecretStorageError};
pub use self_group::DeviceInfo;
pub use send::TYPING_INTERVAL;
pub use stream::ConnectionState;
pub use sync::{SyncSettings, BACKFILL_PAGE};
pub use transport::{EventStream, Transport, TransportError};
