//! HTTP requests signed with the user's root key: every request to the gim
//! meta server, and account deletion on a hub. The signature proves the
//! sender holds the root key of the user id derived from the key it
//! presents; the server needs no stored state to check it.

use data_encoding::HEXLOWER;
use gim_common::UserId;
use sha2::{Digest, Sha256};

use crate::keys::{sign, verify};
use crate::{IdentityError, RootKey, RootPublicKey};

/// Signature context of a [`RootRequestSignature`].
pub const ROOT_REQUEST_CONTEXT: &[u8] = b"gim/root-request/v1";

/// How far a request timestamp may be from the verifier's clock, either
/// way.
pub const ROOT_REQUEST_MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// What a request signature covers:
/// `method "\n" path "\n" timestamp_ms "\n" hex(SHA-256(body))`, where
/// `method` is uppercase, `path` is the request path with its query string
/// as sent, `timestamp_ms` is decimal and the digest lowercase hex.
pub fn root_request_tbs(method: &str, path: &str, timestamp_ms: u64, body: &[u8]) -> Vec<u8> {
    format!(
        "{method}\n{path}\n{timestamp_ms}\n{}",
        HEXLOWER.encode(&Sha256::digest(body))
    )
    .into_bytes()
}

/// The signature of a request: sent as the `Gim-Key` (root public key),
/// `Gim-Timestamp` and `Gim-Signature` headers, keys and signatures in
/// unpadded base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRequestSignature {
    pub public_key: RootPublicKey,
    pub timestamp_ms: u64,
    pub signature: [u8; 64],
}

impl RootKey {
    /// Signs a request to be sent at `timestamp_ms` (Unix milliseconds).
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        timestamp_ms: u64,
        body: &[u8],
    ) -> RootRequestSignature {
        let tbs = root_request_tbs(method, path, timestamp_ms, body);
        RootRequestSignature {
            public_key: self.public(),
            timestamp_ms,
            signature: sign(&self.0, ROOT_REQUEST_CONTEXT, &tbs),
        }
    }
}

impl RootRequestSignature {
    /// Checks the signature over the received request and that its
    /// timestamp is within [`ROOT_REQUEST_MAX_SKEW_MS`] of `now_ms`, and
    /// returns the user id the key derives.
    pub fn verify(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        now_ms: u64,
    ) -> Result<UserId, IdentityError> {
        if self.timestamp_ms > now_ms.saturating_add(ROOT_REQUEST_MAX_SKEW_MS) {
            return Err(IdentityError::NotYetValid);
        }
        if self.timestamp_ms.saturating_add(ROOT_REQUEST_MAX_SKEW_MS) < now_ms {
            return Err(IdentityError::Expired);
        }
        let tbs = root_request_tbs(method, path, self.timestamp_ms, body);
        verify(
            &self.public_key.0,
            ROOT_REQUEST_CONTEXT,
            &tbs,
            &self.signature,
        )?;
        Ok(self.public_key.user_id())
    }
}
