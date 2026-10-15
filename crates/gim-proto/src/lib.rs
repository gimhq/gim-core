//! Wire types: gim-server v1 REST/stream DTOs (`dto`), gim-hub API v2 DTOs
//! (`v2`, from contract/hub-v2/openapi.json) and the versioned CBOR envelope
//! schema. No crypto, no I/O.

#![forbid(unsafe_code)]

pub mod dto;
pub mod envelope;
mod error;
pub mod v2;

pub use error::ProtoError;
