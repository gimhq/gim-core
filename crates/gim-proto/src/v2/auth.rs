use std::fmt;

use serde::{Deserialize, Serialize};

/// `AuthChallengeRequest`: `POST /v2/auth/challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallengeRequest {
    pub user_id: String,
    /// A device listed as active in the user's stored DeviceList.
    pub device_id: String,
}

/// `AuthChallenge`: single-use sign-in challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// gim-core AuthChallenge CBOR. The device signs these exact bytes into
    /// an AuthResponse (gim-core docs/identity.md).
    #[serde(with = "super::base64::bytes")]
    pub challenge: Vec<u8>,
    /// Exclusive expiry, Unix milliseconds.
    pub expires_at: i64,
    /// gim-identity `hub_id` of this hub: the challenge's `audience`.
    pub hub_id: String,
}

/// `CreateSessionRequest`: `POST /v2/auth/session`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    /// gim-core AuthResponse CBOR: the challenge bytes, user ID, device ID and
    /// the device signature.
    #[serde(with = "super::base64::bytes")]
    pub response: Vec<u8>,
}

/// `Session`: device bearer token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    /// Unix milliseconds; sign in again after this or on 401.
    pub expires_at: i64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
