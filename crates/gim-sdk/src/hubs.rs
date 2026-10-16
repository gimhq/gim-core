//! The hub registry (multi-homing): the hubs listed by the user's hosting
//! record, the client API URL of each, and this device's session on each.
//!
//! The hub the client was built with (its transport) is the home hub: it is
//! bootstrapped with `GET /v2/hub` and serves every existing single-hub code
//! path. Hosting records name hubs by `hub_id` only, so the URLs are learned
//! from the bootstrap and from the own other devices through the self group
//! (`self.hubs`). A URL is used only once `GET /v2/hub?nonce=` there proved
//! the listed `hub_id` (derived from the returned root key) at that URL: the
//! root key signs the client's fresh nonce, the `hub_id` and the hub's
//! public URL, which must be the contacted URL. Until then, the hub proof is
//! the only request sent to a URL, also to one shared by another own device.
//! Then the device signs in there with that `hub_id` and URL as the
//! challenge audience (AuthChallenge v2). Removed hubs are only marked:
//! draining them comes with hub removal.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use gim_base::model::{HubRecord, HubState};
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_common::now_ms;
use gim_identity::{normalize_hub_url, HubRootPublicKey, UserHostingRecord};
use gim_proto::envelope::{Content, HubLocation};
use serde::{Deserialize, Serialize};

use crate::auth::{device_key, Audience};
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
    pub(crate) verified: Option<(String, Arc<dyn Transport>)>,
    /// A URL whose proof failed in this run: not contacted again until a
    /// URL is set on this device or the next run.
    pub(crate) rejected: Option<String>,
    pub(crate) token: Option<HubToken>,
}

impl HubHandle {
    /// The hub's URL proved its identity in this run.
    pub(crate) fn is_verified(&self) -> bool {
        self.verified.is_some()
    }
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

/// What `GET /v2/hub?nonce=` at a URL proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvenHub {
    pub(crate) hub_id: String,
    /// The hub's 32-byte root public key.
    pub(crate) root: Vec<u8>,
    /// The normalized public URL the proof binds, which sign-in challenges
    /// must name; `None` for a hub without one (single-hub development,
    /// accepted for the home hub only).
    pub(crate) url: Option<String>,
}

/// Why a hub URL was not verified.
#[derive(Debug)]
pub(crate) enum ProofFailure {
    /// The hub could not be asked; the stored state is kept.
    Transport(TransportError),
    /// The answer does not prove the expected hub at the contacted URL.
    Rejected(String),
}

/// Checks a hub's answer to `GET /v2/hub?nonce=` with `nonce` at
/// `contacted`: `hub_id` derives from the root key and is `expected`, if
/// given; with a public URL, that is `contacted` (normalized) and the proof
/// verifies under the root key.
fn check_identity(
    info: &HubIdentity,
    nonce: &[u8; 32],
    contacted: Option<&str>,
    expected: Option<&str>,
) -> std::result::Result<ProvenHub, String> {
    let key = <[u8; 32]>::try_from(info.hub_root_public_key.as_slice())
        .map_err(|_| "hub_root_pubkey is not 32 bytes".to_string())
        .and_then(|bytes| HubRootPublicKey::from_bytes(&bytes).map_err(|e| e.to_string()))?;
    if key.hub_id() != info.hub_id {
        return Err("hub_id does not derive from hub_root_pubkey".into());
    }
    if expected.is_some_and(|expected| expected != info.hub_id) {
        return Err(format!("the URL serves hub {}", info.hub_id));
    }
    let url = match &info.public_url {
        None => None,
        Some(public_url) => {
            let contacted = contacted.ok_or("the contacted URL is unknown")?;
            let contacted = normalize_hub_url(contacted).map_err(|e| e.to_string())?;
            if *public_url != contacted {
                return Err(format!(
                    "the hub's public URL is {public_url}, not {contacted}"
                ));
            }
            let proof = info
                .proof
                .as_deref()
                .and_then(|proof| <[u8; 64]>::try_from(proof).ok())
                .ok_or("no proof of possession")?;
            key.verify_hub_proof(nonce, &info.hub_id, public_url, &proof)
                .map_err(|e| format!("proof of possession: {e}"))?;
            Some(contacted)
        }
    };
    Ok(ProvenHub {
        hub_id: info.hub_id.clone(),
        root: key.as_bytes().to_vec(),
        url,
    })
}

/// Asks the hub behind `transport`, contacted at `contacted`, to prove
/// with a fresh nonce that it is the hub `expected` (if given) at that URL.
/// A hub without a public URL cannot prove (it answers the nonce with 400);
/// with `allow_unbound` (the home hub in single-hub development) it is then
/// read without a nonce and accepted unbound, otherwise rejected.
pub(crate) async fn prove_hub(
    transport: &dyn Transport,
    contacted: Option<&str>,
    expected: Option<&str>,
    allow_unbound: bool,
) -> std::result::Result<ProvenHub, ProofFailure> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| ProofFailure::Rejected(format!("no random nonce: {e}")))?;
    let info = match transport.hub_info(Some(&nonce)).await {
        Err(TransportError::Rejected { status: 400, .. }) if allow_unbound => {
            let info = transport
                .hub_info(None)
                .await
                .map_err(ProofFailure::Transport)?;
            if info.public_url.is_some() {
                return Err(ProofFailure::Rejected(
                    "the hub refused to prove its public URL".into(),
                ));
            }
            info
        }
        Err(err @ TransportError::Rejected { status: 400, .. }) => {
            return Err(ProofFailure::Rejected(format!(
                "the hub cannot prove its URL: {err}"
            )))
        }
        info => info.map_err(ProofFailure::Transport)?,
    };
    let proven =
        check_identity(&info, &nonce, contacted, expected).map_err(ProofFailure::Rejected)?;
    if proven.url.is_none() && !allow_unbound {
        return Err(ProofFailure::Rejected(
            "the hub has no public URL to prove".into(),
        ));
    }
    Ok(proven)
}

/// Registry order: by priority, then hub id; the first listed one is the
/// primary hub.
pub(crate) fn sort(hubs: &mut [HubRecord]) {
    hubs.sort_by(|a, b| (a.priority, &a.hub_id).cmp(&(b.priority, &b.hub_id)));
}

impl<S: StateStore + 'static> Client<S> {
    /// The hubs of the own hosting record known to this device, in
    /// `(priority, hub_id)` order, including removed ones.
    pub async fn hubs(&self) -> Result<Vec<HubStatus>> {
        let mut hubs = self.read(|store, _| Ok(store.hubs()?)).await?;
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

    /// A notification whenever the hub registry may have changed (a hub
    /// added, removed, verified or reprioritized, a URL shared by another
    /// own device); read [`Client::hubs`] then.
    pub fn subscribe_hub_changes(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.inner.hub_changes.subscribe()
    }

    pub(crate) fn notify_hub_changes(&self) {
        // No subscriber is fine.
        let _ = self.inner.hub_changes.send(());
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
            .read(move |store, _| Ok(store.hubs()?.into_iter().find(|h| h.hub_id == id)))
            .await?;
        let Some(mut hub) = stored.filter(|h| h.state != HubState::Removed) else {
            return Err(ClientError::InvalidInput(format!(
                "hub {hub_id} is not listed by the hosting record"
            )));
        };
        let transport = (self.inner.hub_connector)(url)?;
        let proven = match prove_hub(&*transport, Some(url), Some(hub_id), false).await {
            Ok(proven) => proven,
            Err(ProofFailure::Transport(err)) => return Err(err.into()),
            Err(ProofFailure::Rejected(reason)) => {
                tracing::warn!(%hub_id, %url, %reason, "hub URL rejected");
                return Err(ClientError::InvalidInput(format!(
                    "{url} is not hub {hub_id}: {reason}"
                )));
            }
        };
        hub.url = Some(url.to_string());
        hub.url_shared = false;
        hub.verified_root_pubkey = Some(proven.root);
        hub.last_seen_ms = Some(now_ms());
        hub.state = HubState::Verified;
        self.save_hub(hub).await?;
        {
            let mut handles = self.handles();
            let handle = handles.entry(hub_id.to_string()).or_default();
            handle.verified = Some((url.to_string(), transport));
            handle.rejected = None;
        }
        self.sign_in_hub(hub_id).await;
        // Sending may publish the hosting record, which refreshes the hubs.
        drop(guard);
        self.top_up_listed_hubs().await;
        self.inner.hubs_changed.notify_one();
        self.notify_hub_changes();
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
    /// No-op in [`crate::ClientMode::Extension`].
    pub(crate) async fn refresh_hubs_from(&self, listed: Listed<'_>) -> Result<()> {
        if self.is_extension() {
            return Ok(());
        }
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
        let hubs = self.read(|store, _| Ok(store.hubs()?)).await?;
        for hub in hubs {
            if hub.state == HubState::Removed || Some(&hub.hub_id) == home.as_ref() {
                continue;
            }
            let Some(url) = hub.url.clone() else {
                continue;
            };
            let hub_id = hub.hub_id.clone();
            let (checked, rejected) = self.handles().get(&hub_id).map_or((false, false), |h| {
                let checked = h.verified.as_ref().is_some_and(|(v, _)| *v == url);
                (checked, h.rejected.as_ref() == Some(&url))
            });
            if rejected {
                continue;
            }
            if checked || self.verify_hub(hub, &url).await? {
                self.sign_in_hub(&hub_id).await;
            }
        }
        // Sending may publish the hosting record, which refreshes the hubs.
        drop(guard);
        self.top_up_listed_hubs().await;
        self.inner.hubs_changed.notify_one();
        self.notify_hub_changes();
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
        let pinned = Some(session.hub_id.as_str()).filter(|h| !h.is_empty());
        let url = self.inner.transport.base_url();
        let proven = match prove_hub(&*self.inner.transport, url.as_deref(), pinned, true).await {
            Ok(proven) => proven,
            Err(ProofFailure::Transport(TransportError::NotFound(reason))) => {
                tracing::debug!(%reason, "no hub identity; single-hub mode");
                return Ok(false);
            }
            Err(ProofFailure::Transport(err)) => return Err(err.into()),
            Err(ProofFailure::Rejected(reason)) => {
                return Err(TransportError::HubNotVerified(format!(
                    "the home hub identity does not verify: {reason}"
                ))
                .into())
            }
        };
        *self
            .inner
            .home_hub
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(proven.hub_id.clone());
        let (hub_id, root) = (proven.hub_id, proven.root);
        self.run(move |store, _| {
            store.transaction(|txn| {
                let stored = txn.hubs()?.into_iter().find(|h| h.hub_id == hub_id);
                let shared = url.is_some() && stored.as_ref().is_none_or(|h| h.url.is_none());
                // The client's own URL is set on this device.
                let url_shared = url.is_none() && stored.as_ref().is_some_and(|h| h.url_shared);
                let hub = HubRecord {
                    url: url.or_else(|| stored.as_ref().and_then(|h| h.url.clone())),
                    url_shared,
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
                                url_shared: false,
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
                handle.rejected = None;
            }
        }
        Ok(())
    }

    /// Checks `url` for the listed `hub` with the hub proof (`GET
    /// /v2/hub?nonce=`), the only request sent there before it passes. On
    /// success the hub is verified and its transport kept; a URL that does
    /// not prove the hub leaves it unverified and is not contacted again in
    /// this run. Network failures keep the stored state.
    async fn verify_hub(&self, mut hub: HubRecord, url: &str) -> Result<bool> {
        let checked = match (self.inner.hub_connector)(url) {
            Ok(transport) => {
                match prove_hub(&*transport, Some(url), Some(&hub.hub_id), false).await {
                    Ok(proven) => Ok((Ok(proven), transport)),
                    Err(ProofFailure::Rejected(reason)) => Ok((Err(reason), transport)),
                    Err(ProofFailure::Transport(err)) => Err(err),
                }
            }
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
            Ok(proven) => {
                hub.verified_root_pubkey = Some(proven.root);
                hub.last_seen_ms = Some(now_ms());
                hub.state = HubState::Verified;
                let mut handles = self.handles();
                let handle = handles.entry(hub.hub_id.clone()).or_default();
                handle.verified = Some((url.to_string(), transport));
                handle.rejected = None;
            }
            Err(reason) => {
                tracing::warn!(hub_id = %hub.hub_id, %url, %reason, "hub URL rejected");
                hub.verified_root_pubkey = None;
                hub.state = HubState::Unverified;
                let mut handles = self.handles();
                let handle = handles.entry(hub.hub_id.clone()).or_default();
                handle.verified = None;
                handle.rejected = Some(url.to_string());
            }
        }
        self.save_hub(hub).await?;
        Ok(verified)
    }

    /// Signs in on the verified hub `hub_id` unless this device holds a
    /// fresh token there; the challenge must name `hub_id`. Failures are
    /// logged: they never touch the home session.
    async fn sign_in_hub(&self, hub_id: &str) {
        {
            let handles = self.handles();
            let Some(handle) = handles.get(hub_id) else {
                return;
            };
            if handle.token.as_ref().is_some_and(HubToken::fresh) || handle.verified.is_none() {
                return;
            }
        }
        if let Err(err) = self.renew_hub_token(hub_id).await {
            tracing::warn!(%hub_id, error = %err, "cannot sign in on a listed hub");
        }
    }

    /// A valid session token on the verified hub `hub_id`: the held one,
    /// unless it expired or is `rejected`, else a new sign-in.
    pub(crate) async fn hub_token(
        &self,
        hub_id: &str,
        rejected: Option<&AccessToken>,
    ) -> TransportResult<AccessToken> {
        let held = self.handles().get(hub_id).and_then(|h| h.token.clone());
        match held {
            Some(held) if held.fresh() && Some(&held.token) != rejected => Ok(held.token),
            _ => self.renew_hub_token(hub_id).await,
        }
    }

    /// Signs in on the verified hub `hub_id`; the challenge must name
    /// `hub_id` and its proven URL. Keeps and persists the new token.
    pub(crate) async fn renew_hub_token(&self, hub_id: &str) -> TransportResult<AccessToken> {
        let (url, transport) = self
            .handles()
            .get(hub_id)
            .and_then(|h| h.verified.clone())
            .ok_or(TransportError::Unauthorized)?;
        let audience = Audience {
            hub_id: Some(hub_id.to_string()),
            url: Some(
                normalize_hub_url(&url)
                    .map_err(|e| TransportError::HubNotVerified(e.to_string()))?,
            ),
        };
        let session = self.session().ok_or(TransportError::Unauthorized)?;
        let key = device_key(&*self.inner.secrets)?;
        let (token, _) = self
            .sign_in_on(&*transport, &session.device, &key, &audience)
            .await?;
        tracing::info!(%hub_id, "signed in on a listed hub");
        if let Some(handle) = self.handles().get_mut(hub_id) {
            handle.token = Some(HubToken {
                token: token.token.clone(),
                expires_at_ms: token.expires_at_ms,
            });
        }
        // The home session may have been renewed meanwhile.
        let persisted = self.session().map(|current| self.persist_session(&current));
        if let Some(Err(err)) = persisted {
            tracing::warn!(error = %err, "cannot persist the hub session");
        }
        Ok(token.token)
    }

    /// The listed hubs other than the home hub whose URL was verified in
    /// this run, with that URL and its transport, by hub id.
    pub(crate) fn verified_hubs(&self) -> Vec<(String, String, Arc<dyn Transport>)> {
        let home = self.home_hub();
        let mut hubs: Vec<_> = self
            .handles()
            .iter()
            .filter(|(hub_id, _)| home.as_ref() != Some(*hub_id))
            .filter_map(|(hub_id, h)| {
                let (url, transport) = h.verified.as_ref()?;
                Some((hub_id.clone(), url.clone(), transport.clone()))
            })
            .collect();
        hubs.sort_by(|a, b| a.0.cmp(&b.0));
        hubs
    }

    /// Sends the URLs of the listed hubs to the own other devices. Best
    /// effort.
    pub(crate) async fn share_hub_locations(&self) {
        let hubs = match self.read(|store, _| Ok(store.hubs()?)).await {
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

    pub(crate) async fn save_hub(&self, hub: HubRecord) -> Result<()> {
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
                    rejected: None,
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

    const URL: &str = "https://hub-a.example.eu";
    const NONCE: [u8; 32] = [7; 32];

    /// The answer of the hub `seed` claiming `hub_id`, with a proof for
    /// `url` and `nonce` if it has a public URL.
    fn identity(seed: u8, hub_id: Option<String>, url: Option<&str>) -> HubIdentity {
        let root = HubRootKey::from_seed(&[seed; 32]);
        let key = root.public();
        HubIdentity {
            hub_id: hub_id.unwrap_or_else(|| key.hub_id()),
            hub_root_public_key: key.as_bytes().to_vec(),
            version: "0.1.0".into(),
            public_url: url.map(str::to_string),
            proof: url.map(|url| root.sign_hub_proof(&NONCE, url).unwrap().to_vec()),
        }
    }

    #[test]
    fn hub_identity_must_derive_from_its_key_and_be_the_expected_hub() {
        let a = identity(1, None, None);
        let proven = check_identity(&a, &NONCE, None, None).unwrap();
        assert_eq!(proven.root, a.hub_root_public_key);
        assert_eq!(proven.url, None);
        assert!(check_identity(&a, &NONCE, None, Some(&a.hub_id)).is_ok());
        let b = identity(2, None, None);
        assert!(check_identity(&a, &NONCE, None, Some(&b.hub_id)).is_err());
        // A hub naming another hub's id than its key derives.
        let lying = identity(1, Some(b.hub_id.clone()), None);
        assert!(check_identity(&lying, &NONCE, None, None).is_err());
        let short = HubIdentity {
            hub_root_public_key: vec![1; 31],
            ..a.clone()
        };
        assert!(check_identity(&short, &NONCE, None, None).is_err());
    }

    #[test]
    fn a_public_url_must_be_the_contacted_one_and_proven() {
        let a = identity(1, None, Some(URL));
        let proven = check_identity(&a, &NONCE, Some("HTTPS://hub-a.example.eu:443/"), None);
        assert_eq!(proven.unwrap().url.as_deref(), Some(URL));
        // A relay or a wrong URL.
        assert!(check_identity(&a, &NONCE, Some("https://relay.example.eu"), None).is_err());
        assert!(check_identity(&a, &NONCE, Some("not a url"), None).is_err());
        assert!(check_identity(&a, &NONCE, None, None).is_err());
        // A proof for another nonce (a replay), a bad or a missing proof.
        assert!(check_identity(&a, &[8; 32], Some(URL), None).is_err());
        let mut tampered = a.clone();
        tampered.proof.as_mut().unwrap()[0] ^= 1;
        assert!(check_identity(&tampered, &NONCE, Some(URL), None).is_err());
        let missing = HubIdentity {
            proof: None,
            ..a.clone()
        };
        assert!(check_identity(&missing, &NONCE, Some(URL), None).is_err());
        // Signed by another hub's key.
        let foreign = HubIdentity {
            proof: identity(2, None, Some(URL)).proof,
            ..a
        };
        assert!(check_identity(&foreign, &NONCE, Some(URL), None).is_err());
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
