//! The hub registry (multi-homing): the hubs listed by the user's hosting
//! record, the client API URL of each, and this device's session on each.
//!
//! The hub the client was built with (its transport) is the home hub: it is
//! bootstrapped with `GET /v2/hub` and serves every existing single-hub code
//! path. Hosting records name hubs by `hub_id` only, so the URLs are learned
//! from the bootstrap and from the own other devices through the self group
//! (`self.hubs`). A URL is used only once `GET /v2/hub` there proved the
//! listed `hub_id` (derived from the returned root key); then the device
//! signs in there with that `hub_id` as the challenge audience. Removed hubs
//! are only marked: draining them comes with hub removal.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use gim_base::model::{HubRecord, HubState};
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_common::now_ms;
use gim_identity::{HubRootPublicKey, UserHostingRecord};
use gim_proto::envelope::{Content, HubLocation};
use serde::{Deserialize, Serialize};

use crate::auth::device_key;
use crate::client::{Session, SESSION_SECRET_KEY};
use crate::transport::{AccessToken, HubIdentity, Transport, TransportError, TransportResult};
use crate::{Client, ClientError, HttpTransport, Result};

/// Priority of the home hub until a hosting record says otherwise.
const HOME_HUB_PRIORITY: u8 = 0;
/// A hub session is renewed this long before it expires.
const HUB_TOKEN_RENEW_MARGIN_MS: u64 = 30_000;

/// Opens a [`Transport`] to the hub at a client API base URL. The default
/// opens an [`HttpTransport`].
pub type HubConnector = Arc<dyn Fn(&str) -> TransportResult<Arc<dyn Transport>> + Send + Sync>;

pub(crate) fn http_connector() -> HubConnector {
    Arc::new(|url: &str| {
        let url = url
            .parse()
            .map_err(|e| TransportError::Network(format!("invalid hub URL {url}: {e}")))?;
        Ok(Arc::new(HttpTransport::new(url)?) as Arc<dyn Transport>)
    })
}

/// A hub of the registry with this device's state on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubStatus {
    pub hub: HubRecord,
    /// The client's own transport reaches this hub.
    pub home: bool,
    /// This device holds a session token for the hub.
    pub signed_in: bool,
}

/// A session token on a hub other than the home hub.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HubToken {
    pub(crate) token: AccessToken,
    /// Unix milliseconds.
    pub(crate) expires_at_ms: u64,
}

impl std::fmt::Debug for HubToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubToken")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl HubToken {
    fn fresh(&self) -> bool {
        now_ms().saturating_add(HUB_TOKEN_RENEW_MARGIN_MS) < self.expires_at_ms
    }
}

/// Runtime state of a hub other than the home hub.
#[derive(Default)]
pub(crate) struct HubHandle {
    /// The transport to the verified URL, once `GET /v2/hub` there proved
    /// the hub in this run; never used before.
    verified: Option<(String, Arc<dyn Transport>)>,
    token: Option<HubToken>,
}

/// The persisted session secret: the home hub session and, next to it, the
/// sessions on the other hubs, so every sign-out and enrollment discard
/// drops them together.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredSession {
    #[serde(flatten)]
    pub(crate) session: Session,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) hubs: BTreeMap<String, HubToken>,
}

/// Where a refresh takes the listed hubs from.
pub(crate) enum Listed<'a> {
    /// Reads the hosting record from the home hub.
    Fetch,
    /// A record the caller verified.
    Known(&'a UserHostingRecord),
    /// Keeps the stored list.
    Stored,
}

/// Checks a hub's answer to `GET /v2/hub`: `hub_id` derives from the root
/// key and is `expected`, if given. Returns the root key.
fn check_identity(
    info: &HubIdentity,
    expected: Option<&str>,
) -> std::result::Result<Vec<u8>, String> {
    let key = <[u8; 32]>::try_from(info.hub_root_public_key.as_slice())
        .map_err(|_| "hub_root_pubkey is not 32 bytes".to_string())
        .and_then(|bytes| HubRootPublicKey::from_bytes(&bytes).map_err(|e| e.to_string()))?;
    if key.hub_id() != info.hub_id {
        return Err("hub_id does not derive from hub_root_pubkey".into());
    }
    if expected.is_some_and(|expected| expected != info.hub_id) {
        return Err(format!("the URL serves hub {}", info.hub_id));
    }
    Ok(key.as_bytes().to_vec())
}

/// Registry order: by priority, then hub id; the first listed one is the
/// primary hub.
fn sort(hubs: &mut [HubRecord]) {
    hubs.sort_by(|a, b| (a.priority, &a.hub_id).cmp(&(b.priority, &b.hub_id)));
}

impl<S: StateStore + 'static> Client<S> {
    /// The hubs of the own hosting record known to this device, in
    /// `(priority, hub_id)` order, including removed ones.
    pub async fn hubs(&self) -> Result<Vec<HubStatus>> {
        let mut hubs = self.run(|store, _| Ok(store.hubs()?)).await?;
        sort(&mut hubs);
        let home = self.home_hub();
        let signed_in = self.session().is_some();
        let handles = self.handles();
        Ok(hubs
            .into_iter()
            .map(|hub| {
                let home = home.as_ref() == Some(&hub.hub_id);
                let signed_in = signed_in
                    && (home || handles.get(&hub.hub_id).is_some_and(|h| h.token.is_some()));
                HubStatus {
                    hub,
                    home,
                    signed_in,
                }
            })
            .collect())
    }

    /// Records `url` as the client API base URL of the listed hub
    /// `hub_id`: checks it with `GET /v2/hub`, signs in there and shares
    /// the URL with the own other devices. A URL that serves another hub is
    /// not recorded ([`ClientError::InvalidInput`]); nothing is sent there.
    pub async fn set_hub_url(&self, hub_id: &str, url: &str) -> Result<()> {
        self.require_session()?;
        let guard = self.inner.hub_lock.lock().await;
        let id = hub_id.to_string();
        let stored = self
            .run(move |store, _| Ok(store.hubs()?.into_iter().find(|h| h.hub_id == id)))
            .await?;
        let Some(mut hub) = stored.filter(|h| h.state != HubState::Removed) else {
            return Err(ClientError::InvalidInput(format!(
                "hub {hub_id} is not listed by the hosting record"
            )));
        };
        let transport = (self.inner.hub_connector)(url)?;
        let info = transport.hub_info().await?;
        let root = check_identity(&info, Some(hub_id)).map_err(|reason| {
            tracing::warn!(%hub_id, %url, %reason, "hub URL rejected");
            ClientError::InvalidInput(format!("{url} is not hub {hub_id}: {reason}"))
        })?;
        hub.url = Some(url.to_string());
        hub.verified_root_pubkey = Some(root);
        hub.last_seen_ms = Some(now_ms());
        hub.state = HubState::Verified;
        self.save_hub(hub).await?;
        self.handles()
            .entry(hub_id.to_string())
            .or_default()
            .verified = Some((url.to_string(), transport));
        self.sign_in_hub(hub_id).await;
        // Sending may publish the hosting record, which refreshes the hubs.
        drop(guard);
        self.share_hub_locations().await;
        Ok(())
    }

    /// Updates the registry from the hosting record on the home hub: see
    /// [`Client::refresh_hubs_from`]. Also runs after every publication of
    /// the record and on `hosting_record.updated`.
    pub async fn refresh_hubs(&self) -> Result<()> {
        self.refresh_hubs_from(Listed::Fetch).await
    }

    /// Updates the registry: bootstraps the home hub, takes the listed
    /// hubs from `listed`, checks the URLs of the listed hubs not checked
    /// in this run yet and signs in where this device has no session.
    /// Failures of single hubs are logged and leave them unverified or
    /// signed out until the next refresh.
    pub(crate) async fn refresh_hubs_from(&self, listed: Listed<'_>) -> Result<()> {
        let session = self.require_session()?;
        let guard = self.inner.hub_lock.lock().await;
        let shared = self.bootstrap_home_hub(&session).await?;
        let record = match listed {
            Listed::Fetch => self.hub_hosting_record(&session.device.user_id).await?,
            Listed::Known(record) => Some(record.clone()),
            Listed::Stored => None,
        };
        if let Some(record) = record {
            self.apply_listed(&record).await?;
        }
        let home = self.home_hub();
        let hubs = self.run(|store, _| Ok(store.hubs()?)).await?;
        for hub in hubs {
            if hub.state == HubState::Removed || Some(&hub.hub_id) == home.as_ref() {
                continue;
            }
            let Some(url) = hub.url.clone() else {
                continue;
            };
            let hub_id = hub.hub_id.clone();
            let checked = self
                .handles()
                .get(&hub_id)
                .and_then(|h| h.verified.as_ref())
                .is_some_and(|(verified, _)| *verified == url);
            if checked || self.verify_hub(hub, &url).await? {
                self.sign_in_hub(&hub_id).await;
            }
        }
        // Sending may publish the hosting record, which refreshes the hubs.
        drop(guard);
        if shared {
            self.share_hub_locations().await;
        }
        Ok(())
    }

    /// [`Client::refresh_hubs_from`] that only logs failures.
    pub(crate) async fn refresh_hubs_logged(&self, listed: Listed<'_>) {
        if let Err(err) = self.refresh_hubs_from(listed).await {
            tracing::warn!(error = %err, "cannot refresh the hub registry");
        }
    }

    /// Checks the home hub with `GET /v2/hub` (it must be the hub the
    /// session signed in to) and records it, verified, with the client's
    /// own URL. Returns whether that gave the hub its first URL, which is
    /// then shared. Transports without a hub identity skip this.
    async fn bootstrap_home_hub(&self, session: &Session) -> Result<bool> {
        let info = match self.inner.transport.hub_info().await {
            Err(TransportError::NotFound(reason)) => {
                tracing::debug!(%reason, "no hub identity; single-hub mode");
                return Ok(false);
            }
            info => info?,
        };
        let pinned = Some(session.hub_id.as_str()).filter(|h| !h.is_empty());
        let root = check_identity(&info, pinned).map_err(|reason| {
            ClientError::Transport(TransportError::Server(format!(
                "the home hub identity does not verify: {reason}"
            )))
        })?;
        *self
            .inner
            .home_hub
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(info.hub_id.clone());
        let url = self.inner.transport.base_url();
        let hub_id = info.hub_id;
        self.run(move |store, _| {
            store.transaction(|txn| {
                let stored = txn.hubs()?.into_iter().find(|h| h.hub_id == hub_id);
                let shared = url.is_some() && stored.as_ref().is_none_or(|h| h.url.is_none());
                let hub = HubRecord {
                    url: url.or_else(|| stored.as_ref().and_then(|h| h.url.clone())),
                    priority: stored.as_ref().map_or(HOME_HUB_PRIORITY, |h| h.priority),
                    verified_root_pubkey: Some(root),
                    last_seen_ms: Some(now_ms()),
                    state: match stored.as_ref().map(|h| h.state) {
                        Some(HubState::Removed) => HubState::Removed,
                        _ => HubState::Verified,
                    },
                    hub_id,
                };
                txn.upsert_hub(&hub)?;
                Ok(shared)
            })
        })
        .await
    }

    /// Makes the registry follow `record`: listed hubs get its priorities
    /// (new ones are unverified until their URL is known and checked), the
    /// others are marked removed.
    async fn apply_listed(&self, record: &UserHostingRecord) -> Result<()> {
        let listed: BTreeMap<String, u8> = record
            .hubs()
            .iter()
            .map(|entry| (entry.hub_id(), entry.priority()))
            .collect();
        let home = self.home_hub();
        let removed = self
            .run(move |store, _| {
                store.transaction(|txn| {
                    let stored = txn.hubs()?;
                    let mut removed = Vec::new();
                    for mut hub in stored.iter().cloned() {
                        if listed.contains_key(&hub.hub_id) || hub.state == HubState::Removed {
                            continue;
                        }
                        hub.state = HubState::Removed;
                        removed.push(hub.hub_id.clone());
                        txn.upsert_hub(&hub)?;
                    }
                    for (hub_id, priority) in listed {
                        let hub = match stored.iter().find(|h| h.hub_id == hub_id) {
                            Some(hub) => HubRecord {
                                priority,
                                state: match hub.state {
                                    HubState::Removed if home.as_ref() == Some(&hub_id) => {
                                        HubState::Verified
                                    }
                                    HubState::Removed => HubState::Unverified,
                                    state => state,
                                },
                                ..hub.clone()
                            },
                            None => HubRecord {
                                hub_id,
                                url: None,
                                priority,
                                verified_root_pubkey: None,
                                last_seen_ms: None,
                                state: HubState::Unverified,
                            },
                        };
                        txn.upsert_hub(&hub)?;
                    }
                    Ok(removed)
                })
            })
            .await?;
        if !removed.is_empty() {
            tracing::info!(?removed, "hubs no longer listed by the hosting record");
        }
        // A hub listed again is checked again.
        let mut handles = self.handles();
        for hub_id in removed {
            if let Some(handle) = handles.get_mut(&hub_id) {
                handle.verified = None;
            }
        }
        Ok(())
    }

    /// Checks `url` for the listed `hub` with `GET /v2/hub`. On success the
    /// hub is verified and its transport kept; a URL serving another hub
    /// leaves it unverified. Network failures keep the stored state.
    async fn verify_hub(&self, mut hub: HubRecord, url: &str) -> Result<bool> {
        let checked = match (self.inner.hub_connector)(url) {
            Ok(transport) => match transport.hub_info().await {
                Ok(info) => Ok((check_identity(&info, Some(&hub.hub_id)), transport)),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };
        let (identity, transport) = match checked {
            Ok(checked) => checked,
            Err(err) => {
                tracing::warn!(hub_id = %hub.hub_id, %url, error = %err, "cannot check the hub URL");
                return Ok(false);
            }
        };
        let verified = identity.is_ok();
        match identity {
            Ok(root) => {
                hub.verified_root_pubkey = Some(root);
                hub.last_seen_ms = Some(now_ms());
                hub.state = HubState::Verified;
                self.handles()
                    .entry(hub.hub_id.clone())
                    .or_default()
                    .verified = Some((url.to_string(), transport));
            }
            Err(reason) => {
                tracing::warn!(hub_id = %hub.hub_id, %url, %reason, "hub URL rejected");
                hub.verified_root_pubkey = None;
                hub.state = HubState::Unverified;
                if let Some(handle) = self.handles().get_mut(&hub.hub_id) {
                    handle.verified = None;
                }
            }
        }
        self.save_hub(hub).await?;
        Ok(verified)
    }

    /// Signs in on the verified hub `hub_id` unless this device holds a
    /// fresh token there; the challenge must name `hub_id`. Failures are
    /// logged: they never touch the home session.
    async fn sign_in_hub(&self, hub_id: &str) {
        let transport = {
            let handles = self.handles();
            let Some(handle) = handles.get(hub_id) else {
                return;
            };
            if handle.token.as_ref().is_some_and(HubToken::fresh) {
                return;
            }
            match &handle.verified {
                Some((_, transport)) => transport.clone(),
                None => return,
            }
        };
        let Some(session) = self.session() else {
            return;
        };
        let signed_in = match device_key(&*self.inner.secrets) {
            Ok(key) => {
                self.sign_in_on(&*transport, &session.device, &key, Some(hub_id))
                    .await
            }
            Err(err) => Err(err),
        };
        match signed_in {
            Ok((token, _)) => {
                tracing::info!(%hub_id, "signed in on a listed hub");
                if let Some(handle) = self.handles().get_mut(hub_id) {
                    handle.token = Some(HubToken {
                        token: token.token,
                        expires_at_ms: token.expires_at_ms,
                    });
                }
                // The home session may have been renewed meanwhile.
                let persisted = self.session().map(|current| self.persist_session(&current));
                if let Some(Err(err)) = persisted {
                    tracing::warn!(error = %err, "cannot persist the hub session");
                }
            }
            Err(err) => tracing::warn!(%hub_id, error = %err, "cannot sign in on a listed hub"),
        }
    }

    /// Sends the URLs of the listed hubs to the own other devices. Best
    /// effort.
    pub(crate) async fn share_hub_locations(&self) {
        let hubs = match self.run(|store, _| Ok(store.hubs()?)).await {
            Ok(hubs) => hubs,
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the hub registry");
                return;
            }
        };
        let hubs: Vec<HubLocation> = hubs
            .into_iter()
            .filter(|h| h.state != HubState::Removed)
            .filter_map(|h| {
                Some(HubLocation {
                    url: h.url?,
                    hub_id: h.hub_id,
                    priority: h.priority,
                })
            })
            .collect();
        if hubs.is_empty() {
            return;
        }
        if let Err(err) = self.send_to_self_group(Content::SelfHubs { hubs }).await {
            tracing::debug!(error = %err, "cannot share the hub locations");
        }
    }

    async fn save_hub(&self, hub: HubRecord) -> Result<()> {
        self.run(move |store, _| store.transaction(|txn| Ok(txn.upsert_hub(&hub)?)))
            .await
    }

    /// The URLs of the stored hubs, to detect changes from the self group.
    pub(crate) async fn hub_urls(&self) -> Result<Vec<(String, Option<String>)>> {
        self.run(|store, _| {
            Ok(store
                .hubs()?
                .into_iter()
                .map(|h| (h.hub_id, h.url))
                .collect())
        })
        .await
    }

    /// The home hub: bootstrapped in this run, or else the hub the session
    /// signed in to.
    pub(crate) fn home_hub(&self) -> Option<String> {
        let bootstrapped = self
            .inner
            .home_hub
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        bootstrapped.or_else(|| {
            self.session()
                .map(|s| s.hub_id)
                .filter(|hub_id| !hub_id.is_empty())
        })
    }

    pub(crate) fn handles(&self) -> std::sync::MutexGuard<'_, HashMap<String, HubHandle>> {
        self.inner.hubs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The tokens of the other hubs, to persist next to `session`.
    pub(crate) fn hub_tokens(&self) -> BTreeMap<String, HubToken> {
        self.handles()
            .iter()
            .filter_map(|(hub_id, h)| Some((hub_id.clone(), h.token.clone()?)))
            .collect()
    }

    /// Loads the tokens of the other hubs from the session secret. Their
    /// URLs are checked again before any use.
    pub(crate) fn load_hub_tokens(&self, hubs: BTreeMap<String, HubToken>) {
        let mut handles = self.handles();
        handles.clear();
        for (hub_id, token) in hubs {
            handles.insert(
                hub_id,
                HubHandle {
                    verified: None,
                    token: Some(token),
                },
            );
        }
    }

    /// Writes the session secret: `session` with the other hubs' tokens.
    pub(crate) fn write_session_secret(&self, session: &Session) -> Result<()> {
        let _guard = self
            .inner
            .persist_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let stored = StoredSession {
            session: session.clone(),
            hubs: self.hub_tokens(),
        };
        let encoded = serde_json::to_vec(&stored).expect("session serializes");
        Ok(self.inner.secrets.set(SESSION_SECRET_KEY, &encoded)?)
    }
}

/// Whether the stored hubs got a new or changed URL between `before` and
/// `after` (from the self group): those need checking.
pub(crate) fn hub_urls_changed(
    before: &[(String, Option<String>)],
    after: &[(String, Option<String>)],
) -> bool {
    after
        .iter()
        .any(|entry| entry.1.is_some() && !before.contains(entry))
}

#[cfg(test)]
mod tests {
    use gim_identity::HubRootKey;

    use super::*;

    fn identity(seed: u8, hub_id: Option<String>) -> HubIdentity {
        let key = HubRootKey::from_seed(&[seed; 32]).public();
        HubIdentity {
            hub_id: hub_id.unwrap_or_else(|| key.hub_id()),
            hub_root_public_key: key.as_bytes().to_vec(),
            version: "0.1.0".into(),
        }
    }

    #[test]
    fn hub_identity_must_derive_from_its_key_and_be_the_expected_hub() {
        let a = identity(1, None);
        assert_eq!(check_identity(&a, None), Ok(a.hub_root_public_key.clone()));
        assert!(check_identity(&a, Some(&a.hub_id)).is_ok());
        let b = identity(2, None);
        assert!(check_identity(&a, Some(&b.hub_id)).is_err());
        // A hub naming another hub's id than its key derives.
        assert!(check_identity(&identity(1, Some(b.hub_id.clone())), None).is_err());
        let short = HubIdentity {
            hub_root_public_key: vec![1; 31],
            ..a.clone()
        };
        assert!(check_identity(&short, None).is_err());
    }

    #[test]
    fn only_new_or_changed_urls_need_a_check() {
        let before = vec![("a".to_string(), Some("u1".to_string()))];
        assert!(!hub_urls_changed(&before, &before));
        let removed_url = vec![("a".to_string(), None)];
        assert!(!hub_urls_changed(&before, &removed_url));
        let changed = vec![("a".to_string(), Some("u2".to_string()))];
        assert!(hub_urls_changed(&before, &changed));
        let added = vec![
            ("a".to_string(), Some("u1".to_string())),
            ("b".to_string(), Some("u3".to_string())),
        ];
        assert!(hub_urls_changed(&before, &added));
    }
}
