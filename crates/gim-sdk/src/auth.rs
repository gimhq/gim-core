//! Device sign-in: challenge → signed AuthResponse → session token, and
//! the automatic re-sign-in of calls rejected with 401 or made with an
//! expired token.

use std::future::Future;

use gim_base::StateStore;
use gim_common::{now_ms, DeviceRef};
use gim_identity::{
    AuthChallenge, AuthResponse, DeviceSigningKey, IdentityError, AUTH_CHALLENGE_MAX_LIFETIME_MS,
};
use zeroize::{Zeroize, Zeroizing};

use crate::client::{Session, DEVICE_KEY_SECRET_KEY};
use crate::hosting::Publish;
use crate::hubs::{prove_hub, ProofFailure};
use crate::transport::{
    AccessToken, Challenge, PostError, SessionError, SessionToken, Transport, TransportError,
};
use crate::{Client, SecretStorage};

/// A token is renewed this long before it expires.
const TOKEN_RENEW_MARGIN_MS: u64 = 30_000;

/// Errors that may mean the session token was rejected, or that the hub
/// needs the user's hosting record first.
pub(crate) trait AuthFailure {
    fn is_unauthorized(&self) -> bool;
    fn is_hosting_record_required(&self) -> bool;
}

impl AuthFailure for TransportError {
    fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }

    fn is_hosting_record_required(&self) -> bool {
        matches!(self, Self::HostingRecordRequired(_))
    }
}

impl AuthFailure for PostError {
    fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Transport(TransportError::Unauthorized))
    }

    fn is_hosting_record_required(&self) -> bool {
        matches!(self, Self::Transport(err) if err.is_hosting_record_required())
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

/// The hub a sign-in addresses, as `GET /v2/hub` proved it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Audience {
    /// The challenge must name this hub, if known.
    pub(crate) hub_id: Option<String>,
    /// The hub's proven, normalized public URL: the challenge must be v2
    /// with this `audience_url`. `None` for a hub without one (single-hub
    /// development): the challenge must be v1.
    pub(crate) url: Option<String>,
}

/// Checks that the challenge is addressed to the hub that issued it (and to
/// `audience`, as far as known) with a valid window.
fn check_challenge(challenge: &Challenge, audience: &Audience) -> Result<(), TransportError> {
    let invalid =
        |reason: &str| TransportError::Server(format!("invalid auth challenge: {reason}"));
    let decoded = AuthChallenge::from_bytes(&challenge.challenge).map_err(|_| invalid("decode"))?;
    if decoded.audience != challenge.hub_id {
        return Err(invalid("audience is not the hub"));
    }
    let hub_id = audience.hub_id.as_deref().unwrap_or(&challenge.hub_id);
    match decoded.check_audience(hub_id, audience.url.as_deref()) {
        Ok(()) => {}
        Err(IdentityError::AudienceMismatch) => return Err(invalid("issued by another hub")),
        Err(_) => {
            return Err(TransportError::HubNotVerified(format!(
                "the challenge (v{}) is not bound to {}",
                decoded.version(),
                audience
                    .url
                    .as_deref()
                    .unwrap_or("a hub without a public URL")
            )))
        }
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
    /// [`Client::authed_session`], and if the hub answers 403
    /// `hosting_record_required`, publishes the user's hosting record and
    /// runs `call` once more (the same request: same `client_id`, same
    /// Commit bytes). If publishing fails, the 403 is returned.
    pub(crate) async fn authed<T, E, F, Fut>(&self, call: F) -> Result<T, E>
    where
        F: Fn(AccessToken) -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: From<TransportError> + AuthFailure + std::fmt::Display,
    {
        match self.authed_session(&call).await {
            Err(err) if err.is_hosting_record_required() => {
                tracing::info!(error = %err, "publishing the hosting record and retrying");
                if let Err(publish) = self.publish_hosting_record(Publish::Now).await {
                    tracing::warn!(error = %publish, "cannot publish the hosting record");
                    return Err(err);
                }
                self.authed_session(&call).await
            }
            result => result,
        }
    }

    /// Runs `call` with a valid session token: signs in first if the token
    /// expired, and once more if the hub rejects the token.
    pub(crate) async fn authed_session<T, E, F, Fut>(&self, call: F) -> Result<T, E>
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
    /// (or, without one, the expired token). If the hub refuses this device
    /// for good ([`TransportError::DeviceNotActive`]), the session is
    /// cleared: the client is signed out.
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
        let pinned = Some(session.hub_id.as_str()).filter(|h| !h.is_empty());
        let (token, hub_id) = match self.sign_in(&session.device, &key, pinned).await {
            Err(TransportError::DeviceNotActive(reason)) => {
                tracing::warn!(%reason, "the hub refuses this device; signing out");
                if let Err(err) = self.clear_session() {
                    tracing::warn!(error = %err, "cannot delete the stored session");
                }
                return Err(TransportError::DeviceNotActive(reason));
            }
            signed_in => signed_in?,
        };
        let renewed = Session {
            device: session.device,
            token: token.token.clone(),
            expires_at_ms: token.expires_at_ms,
            hub_id,
        };
        self.set_session(renewed.clone());
        if let Err(err) = self.persist_session(&renewed) {
            // The token still works for this run.
            tracing::warn!(error = %err, "cannot persist the renewed session");
        }
        self.push_hub_changed(None, true);
        Ok(token.token)
    }

    /// Answers a challenge of the home hub as `device`, once the hub
    /// proved that it is `pinned_hub` (if given) at the client's URL; see
    /// [`Client::sign_in_on`]. [`TransportError::HubNotVerified`] if it did
    /// not: nothing is signed.
    pub(crate) async fn sign_in(
        &self,
        device: &DeviceRef,
        key: &DeviceSigningKey,
        pinned_hub: Option<&str>,
    ) -> Result<(SessionToken, String), TransportError> {
        let audience = self.prove_home_hub(pinned_hub).await?;
        self.sign_in_on(&*self.inner.transport, device, key, &audience)
            .await
    }

    /// The hub proof of the home hub at the client's URL. A hub without a
    /// public URL is accepted unbound (single-hub development); a transport
    /// without a hub identity signs in to `pinned_hub` as before.
    async fn prove_home_hub(&self, pinned_hub: Option<&str>) -> Result<Audience, TransportError> {
        let transport = &*self.inner.transport;
        let url = transport.base_url();
        match prove_hub(transport, url.as_deref(), pinned_hub, true).await {
            Ok(proven) => Ok(Audience {
                hub_id: Some(proven.hub_id),
                url: proven.url,
            }),
            Err(ProofFailure::Transport(TransportError::NotFound(reason))) => {
                tracing::debug!(%reason, "no hub identity; signing in unbound");
                Ok(Audience {
                    hub_id: pinned_hub.map(str::to_string),
                    url: None,
                })
            }
            Err(ProofFailure::Transport(err)) => Err(err),
            Err(ProofFailure::Rejected(reason)) => {
                let url = url.as_deref().unwrap_or("its URL");
                tracing::warn!(%url, %reason, "the home hub did not prove its identity");
                Err(TransportError::HubNotVerified(format!(
                    "the hub at {url} is not verified: {reason}"
                )))
            }
        }
    }

    /// Answers a challenge of the hub behind `transport` as `device`;
    /// returns the session token and the hub id. The challenge must name
    /// `audience` ([`TransportError::HubNotVerified`] for another URL or
    /// challenge version). A rejected challenge (`invalid_challenge`) is
    /// retried once with a new one; [`TransportError::DeviceNotActive`] if
    /// the hub refuses the device.
    pub(crate) async fn sign_in_on(
        &self,
        transport: &dyn Transport,
        device: &DeviceRef,
        key: &DeviceSigningKey,
        audience: &Audience,
    ) -> Result<(SessionToken, String), TransportError> {
        let mut retried = false;
        loop {
            let challenge = match transport.auth_challenge(device).await {
                // The hub does not list the device as active.
                Err(TransportError::NotFound(reason)) => {
                    return Err(TransportError::DeviceNotActive(reason))
                }
                challenge => challenge?,
            };
            check_challenge(&challenge, audience)?;
            let response = AuthResponse::sign(&challenge.challenge, key, &device.user_id);
            match transport.create_session(response.to_bytes()).await {
                Ok(token) => return Ok((token, challenge.hub_id)),
                Err(SessionError::InvalidChallenge) if !retried => retried = true,
                Err(SessionError::InvalidChallenge) => {
                    return Err(TransportError::Server(
                        "401 invalid_challenge for a fresh challenge".into(),
                    ))
                }
                Err(SessionError::Rejected(reason)) => {
                    return Err(TransportError::DeviceNotActive(reason))
                }
                Err(SessionError::Transport(err)) => return Err(err),
            }
        }
    }

    /// Persists `session` with the sessions on the other hubs.
    pub(crate) fn persist_session(&self, session: &Session) -> crate::Result<()> {
        self.write_session_secret(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://hub.example.eu";

    fn challenge(
        audience: &str,
        hub_id: &str,
        url: Option<&str>,
        issued_at: u64,
        expires_at: u64,
    ) -> Challenge {
        Challenge {
            challenge: AuthChallenge {
                audience: audience.into(),
                audience_url: url.map(str::to_string),
                nonce: [1; 32],
                issued_at,
                expires_at,
            }
            .to_bytes(),
            hub_id: hub_id.into(),
        }
    }

    fn to(hub_id: Option<&str>, url: Option<&str>) -> Audience {
        Audience {
            hub_id: hub_id.map(str::to_string),
            url: url.map(str::to_string),
        }
    }

    #[test]
    fn challenges_are_checked_for_audience_and_lifetime() {
        let any = Audience::default();
        assert!(check_challenge(&challenge("h1", "h1", None, 0, 1000), &any).is_ok());
        let h1 = to(Some("h1"), None);
        assert!(check_challenge(&challenge("h1", "h1", None, 0, 1000), &h1).is_ok());
        assert!(check_challenge(&challenge("h2", "h1", None, 0, 1000), &any).is_err());
        let h2 = to(Some("h2"), None);
        assert!(check_challenge(&challenge("h1", "h1", None, 0, 1000), &h2).is_err());
        assert!(check_challenge(&challenge("h1", "h1", None, 1000, 1000), &any).is_err());
        let too_long = AUTH_CHALLENGE_MAX_LIFETIME_MS + 1;
        assert!(check_challenge(&challenge("h1", "h1", None, 0, too_long), &any).is_err());
        let garbage = Challenge {
            challenge: vec![1, 2, 3],
            hub_id: "h1".into(),
        };
        assert!(check_challenge(&garbage, &any).is_err());
    }

    #[test]
    fn challenges_are_bound_to_the_proven_url() {
        let bound = to(Some("h1"), Some(URL));
        assert!(check_challenge(&challenge("h1", "h1", Some(URL), 0, 1000), &bound).is_ok());
        let not_bound = |result| matches!(result, Err(TransportError::HubNotVerified(_)));
        // v1 from a hub that proved a public URL.
        assert!(not_bound(check_challenge(
            &challenge("h1", "h1", None, 0, 1000),
            &bound
        )));
        // v2 for another URL.
        assert!(not_bound(check_challenge(
            &challenge("h1", "h1", Some("https://relay.example.eu"), 0, 1000),
            &bound
        )));
        // v2 from a hub without a public URL.
        assert!(not_bound(check_challenge(
            &challenge("h1", "h1", Some(URL), 0, 1000),
            &to(Some("h1"), None)
        )));
    }
}
