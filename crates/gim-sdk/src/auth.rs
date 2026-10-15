//! Device sign-in: challenge → signed AuthResponse → session token, and
//! the automatic re-sign-in of calls rejected with 401 or made with an
//! expired token.

use std::future::Future;

use gim_base::StateStore;
use gim_common::{now_ms, DeviceRef};
use gim_identity::{AuthChallenge, AuthResponse, DeviceSigningKey, AUTH_CHALLENGE_MAX_LIFETIME_MS};
use zeroize::{Zeroize, Zeroizing};

use crate::client::{Session, DEVICE_KEY_SECRET_KEY, SESSION_SECRET_KEY};
use crate::transport::{AccessToken, Challenge, PostError, SessionToken, TransportError};
use crate::{Client, SecretStorage};

/// A token is renewed this long before it expires.
const TOKEN_RENEW_MARGIN_MS: u64 = 30_000;

/// Errors that may mean the session token was rejected.
pub(crate) trait AuthFailure {
    fn is_unauthorized(&self) -> bool;
}

impl AuthFailure for TransportError {
    fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }
}

impl AuthFailure for PostError {
    fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Transport(TransportError::Unauthorized))
    }
}

/// Reads the device signing key from secure storage.
pub(crate) fn device_key(secrets: &dyn SecretStorage) -> Result<DeviceSigningKey, TransportError> {
    let unusable = |reason: String| {
        tracing::warn!(%reason, "cannot sign in");
        TransportError::Unauthorized
    };
    let mut stored = secrets
        .get(DEVICE_KEY_SECRET_KEY)
        .map_err(|e| unusable(e.to_string()))?
        .ok_or_else(|| unusable("no device key".into()))?;
    let seed = <[u8; 32]>::try_from(stored.as_slice()).map(Zeroizing::new);
    stored.zeroize();
    let seed = seed.map_err(|_| unusable("malformed device key".into()))?;
    Ok(DeviceSigningKey::from_seed(&seed))
}

/// Checks that the challenge is addressed to the hub that issued it (and to
/// `pinned`, the hub of the session, if known) with a valid window.
fn check_challenge(challenge: &Challenge, pinned: Option<&str>) -> Result<(), TransportError> {
    let invalid =
        |reason: &str| TransportError::Server(format!("invalid auth challenge: {reason}"));
    let decoded = AuthChallenge::from_bytes(&challenge.challenge).map_err(|_| invalid("decode"))?;
    if decoded.audience != challenge.hub_id {
        return Err(invalid("audience is not the hub"));
    }
    if pinned.is_some_and(|hub| hub != decoded.audience) {
        return Err(invalid("issued by another hub"));
    }
    let lifetime = decoded.expires_at.checked_sub(decoded.issued_at);
    if !lifetime.is_some_and(|l| l > 0 && l <= AUTH_CHALLENGE_MAX_LIFETIME_MS) {
        return Err(invalid("lifetime"));
    }
    Ok(())
}

fn expired(session: &Session) -> bool {
    now_ms().saturating_add(TOKEN_RENEW_MARGIN_MS) >= session.expires_at_ms
}

impl<S: StateStore + 'static> Client<S> {
    /// Runs `call` with a valid session token: signs in first if the token
    /// expired, and once more if the hub rejects the token.
    pub(crate) async fn authed<T, E, F, Fut>(&self, call: F) -> Result<T, E>
    where
        F: Fn(AccessToken) -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: From<TransportError> + AuthFailure,
    {
        let token = self.valid_token().await?;
        match call(token.clone()).await {
            Err(err) if err.is_unauthorized() => {
                let token = self.renew_token(Some(&token)).await?;
                call(token).await
            }
            result => result,
        }
    }

    /// The current token, renewed first if it expired.
    pub(crate) async fn valid_token(&self) -> Result<AccessToken, TransportError> {
        let session = self.session().ok_or(TransportError::Unauthorized)?;
        if expired(&session) {
            return self.renew_token(None).await;
        }
        Ok(session.token)
    }

    /// Signs in again, unless another task already replaced `rejected`
    /// (or, without one, the expired token). Fails with `Unauthorized` if
    /// the hub does not accept this device any more.
    pub(crate) async fn renew_token(
        &self,
        rejected: Option<&AccessToken>,
    ) -> Result<AccessToken, TransportError> {
        let _guard = self.inner.auth_lock.lock().await;
        let session = self.session().ok_or(TransportError::Unauthorized)?;
        let current = match rejected {
            Some(rejected) => &session.token != rejected,
            None => true,
        };
        if current && !expired(&session) {
            return Ok(session.token);
        }
        let key = device_key(&*self.inner.secrets)?;
        let (token, hub_id) = self
            .sign_in(
                &session.device,
                &key,
                Some(session.hub_id.as_str()).filter(|h| !h.is_empty()),
            )
            .await?;
        let renewed = Session {
            device: session.device,
            token: token.token.clone(),
            expires_at_ms: token.expires_at_ms,
            hub_id,
        };
        if let Err(err) = self.persist_session(&renewed) {
            // The token still works for this run.
            tracing::warn!(error = %err, "cannot persist the renewed session");
        }
        self.set_session(renewed);
        Ok(token.token)
    }

    /// Answers a hub challenge as `device`; returns the session token and
    /// the hub id.
    pub(crate) async fn sign_in(
        &self,
        device: &DeviceRef,
        key: &DeviceSigningKey,
        pinned_hub: Option<&str>,
    ) -> Result<(SessionToken, String), TransportError> {
        let challenge = match self.inner.transport.auth_challenge(device).await {
            // The hub does not list the device as active.
            Err(TransportError::NotFound(_)) => return Err(TransportError::Unauthorized),
            challenge => challenge?,
        };
        check_challenge(&challenge, pinned_hub)?;
        let response = AuthResponse::sign(&challenge.challenge, key, &device.user_id);
        let token = self
            .inner
            .transport
            .create_session(response.to_bytes())
            .await?;
        Ok((token, challenge.hub_id))
    }

    pub(crate) fn persist_session(&self, session: &Session) -> crate::Result<()> {
        let encoded = serde_json::to_vec(session).expect("session serializes");
        Ok(self.inner.secrets.set(SESSION_SECRET_KEY, &encoded)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(audience: &str, hub_id: &str, issued_at: u64, expires_at: u64) -> Challenge {
        Challenge {
            challenge: AuthChallenge {
                audience: audience.into(),
                nonce: [1; 32],
                issued_at,
                expires_at,
            }
            .to_bytes(),
            hub_id: hub_id.into(),
        }
    }

    #[test]
    fn challenges_are_checked_for_audience_and_lifetime() {
        assert!(check_challenge(&challenge("h1", "h1", 0, 1000), None).is_ok());
        assert!(check_challenge(&challenge("h1", "h1", 0, 1000), Some("h1")).is_ok());
        assert!(check_challenge(&challenge("h2", "h1", 0, 1000), None).is_err());
        assert!(check_challenge(&challenge("h1", "h1", 0, 1000), Some("h2")).is_err());
        assert!(check_challenge(&challenge("h1", "h1", 1000, 1000), None).is_err());
        let too_long = AUTH_CHALLENGE_MAX_LIFETIME_MS + 1;
        assert!(check_challenge(&challenge("h1", "h1", 0, too_long), None).is_err());
        let garbage = Challenge {
            challenge: vec![1, 2, 3],
            hub_id: "h1".into(),
        };
        assert!(check_challenge(&garbage, None).is_err());
    }
}
