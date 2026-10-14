//! Wire types: gim-server REST/stream DTOs (from openapi.json) and the
//! versioned CBOR envelope schema. No crypto, no I/O.

#![forbid(unsafe_code)]

pub mod envelope;
mod error;

pub use error::ProtoError;
