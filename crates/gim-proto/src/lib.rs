//! Wire types: gim-hub API v2 DTOs (`v2`, from contract/hub-v2/openapi.json)
//! and the versioned CBOR envelope schema. No crypto, no I/O.

#![forbid(unsafe_code)]

mod base64;
pub mod envelope;
mod error;
pub mod v2;

pub use error::ProtoError;
