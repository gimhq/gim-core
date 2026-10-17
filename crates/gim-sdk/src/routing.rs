//! Submission and KeyPackages across the listed hubs (multi-homing,
//! contract `multihoming.md` §5.1, §5.4, §6.1).
//!
//! Commits, Proposals and application messages go to the primary hub
//! first (registry order). When that hub itself cannot be reached
//! (network error, timeout, 5xx other than the peer codes) the identical
//! request (same Commit bytes, same `client_id` and `mls_message`) goes to
//! the next hub; the owning hub dedups it. A 502/503 peer failure means the
//! owning hub is down, which no other hub can fix: the request is retried
//! later on the same hub order, after the `Retry-After`, and never sent to
//! the next hub because of it. Definite rejections never fail over.
//!
//! A hub that answers 404 for a group another hub owns has no replica of
//! it yet (the owner has not delivered the group there); the request goes
//! to the next hub. A 404 from the owning hub is definite.
//!
//! Groups are created on the primary hub (§2.1), which then owns them.
//! An Add is claimed and committed through one hub. A hub that answers
//! `kp_not_claimed` did not hand out the KeyPackages; the next hub is
//! tried with the same bytes, and if none takes it, the KeyPackages are
//! claimed again through that hub and the Commit rebuilt.
//!
//! Each listed hub gets its own one-time KeyPackages and its own
//! last-resort KeyPackage. Every generated KeyPackage is recorded with its
//! hub in the ledger before it is uploaded, so it never goes to another
//! hub; a 409 `duplicate_key_package` is answered with fresh ones.

use std::future::Future;
use std::sync::Arc;

use gim_base::model::ChatKind;
use gim_base::model::{HubState, KeyPackageRecord};
use gim_base::{StateStore, StoreTxn};
use gim_common::{now_ms, ClientId, GroupId, UserId};
use gim_proto::v2::{DUPLICATE_KEY_PACKAGE, KP_NOT_CLAIMED};

use crate::auth::AuthFailure;
use crate::client::{owner_hub, KEY_PACKAGE_BATCH};
use crate::hubs::sort;
use crate::transport::{
    AccessToken, ClaimedKeyPackage, CommitAccepted, KeyPackageClaim, OutgoingCommit, PostError,
    Transport, TransportError,
};
use crate::{Client, ClientError, Result};

/// Fresh KeyPackages generated for one upload after 409
/// `duplicate_key_package` answers, before the upload fails.
const DUPLICATE_KEY_PACKAGE_RETRIES: u32 = 2;

/// A hub this device can call: the home hub (the client's own transport)
/// or another listed hub whose URL proved its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HubTarget {
    /// Empty for a home hub without a hub identity (single-hub mode).
    pub(crate) hub_id: String,
    pub(crate) home: bool,
}

/// Result of a submission through the hubs.
pub(crate) struct Submission<T> {
    pub(crate) result: std::result::Result<T, PostError>,
    /// Set when no hub took the request and one of them answered
    /// `kp_not_claimed`: the first such hub.
    pub(crate) not_claimed: Option<HubTarget>,
}

/// The hub itself could not be reached or failed (network error,
/// timeout, 5xx other than 502 `peer_refused` / 503 `peer_unavailable`):
/// the identical request may go to the next hub.
pub(crate) fn hub_unreachable(err: &TransportError) -> bool {
    matches!(err, TransportError::Network(_) | TransportError::Server(_))
}

/// 404 from a hub that does not own the group: it has no replica of it
/// yet, so the owner or another hub may take the request.
fn no_replica(group_id: &GroupId, hub: &HubTarget, err: &TransportError) -> bool {
    matches!(err, TransportError::NotFound(_))
        && owner_hub(group_id).is_some_and(|owner| owner != hub.hub_id)
}

/// A hub this device cannot get a session on fails like an unreachable
/// one, so the next hub is tried.
fn no_session(hub_id: &str) -> TransportError {
    TransportError::Network(format!("no session on hub {hub_id}"))
}

/// 400 `... (kp_not_claimed)`: an Add whose KeyPackages were not claimed
/// through the hub it was submitted to.
pub(crate) fn kp_not_claimed(err: &TransportError) -> bool {
    matches!(err, TransportError::Rejected { status: 400, message, .. } if message.contains(KP_NOT_CLAIMED))
}

/// 409 `duplicate_key_package`: the hub saw one of the KeyPackages claimed
/// through another hub.
fn duplicate_key_package(err: &TransportError) -> bool {
    matches!(err, TransportError::Conflict(message) if message.contains(DUPLICATE_KEY_PACKAGE))
}

impl<S: StateStore + 'static> Client<S> {
    /// The home hub as a target.
    pub(crate) fn home_target(&self) -> HubTarget {
        HubTarget {
            hub_id: self.home_hub().unwrap_or_default(),
            home: true,
        }
    }

    /// The hubs to submit to, primary first: the verified listed hubs in
    /// registry order that this device can reach (the home hub, and the
    /// others with a verified URL in this run). The home hub is always
    /// among them, last if the registry does not list it as verified.
    pub(crate) async fn submission_hubs(&self) -> Vec<HubTarget> {
        let mut hubs = match self.read(|store, _| Ok(store.hubs()?)).await {
            Ok(hubs) => hubs,
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the hub registry; using the home hub");
                vec![]
            }
        };
        sort(&mut hubs);
        let home = self.home_target();
        let mut targets: Vec<HubTarget> = {
            let handles = self.handles();
            hubs.into_iter()
                .filter(|h| h.state == HubState::Verified)
                .filter(|h| {
                    h.hub_id == home.hub_id
                        || handles
                            .get(&h.hub_id)
                            .is_some_and(|handle| handle.is_verified())
                })
                .map(|h| HubTarget {
                    home: h.hub_id == home.hub_id,
                    hub_id: h.hub_id,
                })
                .collect()
        };
        if !targets.iter().any(|t| t.home) {
            targets.push(home);
        }
        targets
    }

    /// `hubs` with `first` moved to the front, if given.
    fn hub_order(mut hubs: Vec<HubTarget>, first: Option<&HubTarget>) -> Vec<HubTarget> {
        if let Some(first) = first {
            hubs.retain(|h| h.hub_id != first.hub_id);
            hubs.insert(0, first.clone());
        }
        hubs
    }

    /// Runs `call` on `hub` with a valid session token there: through
    /// [`Client::authed`] on the home hub; on another hub after signing in
    /// there if needed, and once more after a rejected token. A hub this
    /// device has no session on fails like an unreachable one.
    pub(crate) async fn authed_on<T, E, F, Fut>(
        &self,
        hub: &HubTarget,
        call: F,
    ) -> std::result::Result<T, E>
    where
        F: Fn(Arc<dyn Transport>, AccessToken) -> Fut,
        Fut: Future<Output = std::result::Result<T, E>>,
        E: From<TransportError> + AuthFailure + std::fmt::Display,
    {
        if hub.home {
            let transport = self.inner.transport.clone();
            return self.authed(|t| call(transport.clone(), t)).await;
        }
        let transport = self
            .verified_hubs()
            .into_iter()
            .find(|(hub_id, _, _)| *hub_id == hub.hub_id)
            .map(|(_, _, transport)| transport)
            .ok_or_else(|| no_session(&hub.hub_id))?;
        let token = self
            .hub_token(&hub.hub_id, None)
            .await
            .map_err(|_| no_session(&hub.hub_id))?;
        match call(transport.clone(), token.clone()).await {
            Err(err) if err.is_unauthorized() => {
                let token = self
                    .hub_token(&hub.hub_id, Some(&token))
                    .await
                    .map_err(|_| no_session(&hub.hub_id))?;
                call(transport, token).await
            }
            result => result,
        }
    }

    /// The hubs to read from: the home hub, then the other verified hubs
    /// in registry order.
    async fn read_hubs(&self) -> Vec<HubTarget> {
        let mut hubs = self.submission_hubs().await;
        hubs.retain(|h| !h.home);
        hubs.insert(0, self.home_target());
        hubs
    }

    /// Looks `handle` up on the home hub, then on the next verified hub in
    /// registry order while the hub asked does not know it or cannot be
    /// reached. Handles are per hub: the first hub that knows it answers,
    /// with the user id. `Ok(None)` only if every hub answered that it does
    /// not know the handle.
    pub(crate) async fn find_handle_routed(
        &self,
        handle: &str,
    ) -> std::result::Result<Option<(UserId, HubTarget)>, TransportError> {
        let mut failed = None;
        for hub in self.read_hubs().await {
            let found = self
                .authed_on(&hub, |transport, t| async move {
                    transport.find_handle(&t, handle).await
                })
                .await;
            match found {
                Ok(Some(user_id)) => return Ok(Some((user_id, hub))),
                Ok(None) => {}
                Err(err) if hub_unreachable(&err) => {
                    tracing::debug!(hub_id = %hub.hub_id, error = %err, "hub unreachable; looking the handle up on the next hub");
                    failed = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        failed.map_or(Ok(None), Err)
    }

    /// Runs a read (DeviceList, user directory, hosting record) on the home
    /// hub and, while the hub asked cannot be reached (network, 5xx), on
    /// the next verified hub in registry order. Definite answers, also
    /// rejections, never fall back.
    pub(crate) async fn read_routed<T, F, Fut>(
        &self,
        call: F,
    ) -> std::result::Result<T, TransportError>
    where
        F: Fn(Arc<dyn Transport>, AccessToken) -> Fut,
        Fut: Future<Output = std::result::Result<T, TransportError>>,
    {
        let mut failed = None;
        for hub in self.read_hubs().await {
            match self.authed_on(&hub, &call).await {
                Err(err) if hub_unreachable(&err) => {
                    tracing::debug!(hub_id = %hub.hub_id, error = %err, "hub unreachable; reading from the next hub");
                    failed = Some(err);
                }
                read => return read,
            }
        }
        Err(failed.unwrap_or_else(|| TransportError::Network("no hub to read from".into())))
    }

    /// [`Client::read_routed`] for public reads, which need no session.
    pub(crate) async fn public_read_routed<T, F, Fut>(
        &self,
        call: F,
    ) -> std::result::Result<T, TransportError>
    where
        F: Fn(Arc<dyn Transport>) -> Fut,
        Fut: Future<Output = std::result::Result<T, TransportError>>,
    {
        let others = self.verified_hubs();
        let mut transports = vec![("home".to_string(), self.inner.transport.clone())];
        for hub in self.submission_hubs().await {
            if let Some((hub_id, _, transport)) = others.iter().find(|(id, _, _)| *id == hub.hub_id)
            {
                transports.push((hub_id.clone(), transport.clone()));
            }
        }
        let mut failed = None;
        for (hub_id, transport) in transports {
            match call(transport).await {
                Err(err) if hub_unreachable(&err) => {
                    tracing::debug!(%hub_id, error = %err, "hub unreachable; reading from the next hub");
                    failed = Some(err);
                }
                read => return read,
            }
        }
        Err(failed.unwrap_or_else(|| TransportError::Network("no hub to read from".into())))
    }

    /// Creates a group on `first` (the hub of the KeyPackage claim for its
    /// first Add) or else the primary hub, on the next hub while the one
    /// asked cannot be reached. The hub that created it owns it.
    pub(crate) async fn create_group_routed(
        &self,
        kind: ChatKind,
        first: Option<&HubTarget>,
    ) -> std::result::Result<GroupId, TransportError> {
        let hubs = Self::hub_order(self.submission_hubs().await, first);
        let last = hubs.len().saturating_sub(1);
        for (i, hub) in hubs.into_iter().enumerate() {
            let created = self
                .authed_on(&hub, |transport, t| async move {
                    transport.create_group(&t, kind).await
                })
                .await;
            match created {
                Err(err) if hub_unreachable(&err) && i < last => {
                    tracing::warn!(hub_id = %hub.hub_id, error = %err, "hub unreachable; creating the group on the next hub");
                }
                Ok(group_id) => {
                    if owner_hub(&group_id)
                        .is_some_and(|owner| !hub.hub_id.is_empty() && owner != hub.hub_id)
                    {
                        tracing::warn!(%group_id, hub_id = %hub.hub_id, "the hub created a group it does not own");
                    }
                    return Ok(group_id);
                }
                created => return created,
            }
        }
        Err(TransportError::Network(
            "no hub to create the group on".into(),
        ))
    }

    /// Submits a Commit or Proposal through the hubs, `first` (the hub of
    /// an Add's claim) or else the primary first; see the module docs.
    pub(crate) async fn submit_routed(
        &self,
        group_id: &GroupId,
        commit: &OutgoingCommit,
        first: Option<&HubTarget>,
    ) -> Submission<CommitAccepted> {
        let hubs = Self::hub_order(self.submission_hubs().await, first);
        let mut unknown = None;
        let mut not_found = None;
        let mut not_claimed: Option<(HubTarget, TransportError)> = None;
        for hub in hubs {
            let submitted = self
                .authed_on(&hub, |transport, t| {
                    let commit = commit.clone();
                    async move { transport.submit_commit(&t, group_id, commit).await }
                })
                .await;
            match submitted {
                Err(PostError::Transport(err)) if hub_unreachable(&err) => {
                    tracing::warn!(hub_id = %hub.hub_id, %group_id, error = %err, "hub unreachable; submitting to the next hub");
                    unknown.get_or_insert(err);
                }
                Err(PostError::Transport(err)) if no_replica(group_id, &hub, &err) => {
                    tracing::info!(hub_id = %hub.hub_id, %group_id, "hub has no replica of the group; submitting to the next hub");
                    not_found.get_or_insert(err);
                }
                Err(PostError::Transport(err)) if kp_not_claimed(&err) => {
                    tracing::info!(hub_id = %hub.hub_id, %group_id, "KeyPackages not claimed through this hub; trying the next hub");
                    not_claimed.get_or_insert((hub, err));
                }
                result => {
                    return Submission {
                        result,
                        not_claimed: None,
                    }
                }
            }
        }
        // No hub took it. An unreachable hub may have: the outcome stays
        // unknown.
        let (hub, rejected) = not_claimed.unzip();
        let err = unknown
            .or(rejected)
            .or(not_found)
            .unwrap_or_else(|| TransportError::Network("no hub to submit to".into()));
        Submission {
            result: Err(err.into()),
            not_claimed: hub,
        }
    }

    /// Posts an application message through the hubs, the primary first,
    /// with the same `client_id` and bytes on every hub.
    pub(crate) async fn post_routed(
        &self,
        group_id: &GroupId,
        client_id: &ClientId,
        mls_message: &[u8],
    ) -> std::result::Result<u64, PostError> {
        let hubs = self.submission_hubs().await;
        let last = hubs.len().saturating_sub(1);
        for (i, hub) in hubs.into_iter().enumerate() {
            let posted = self
                .authed_on(&hub, |transport, t| {
                    let (client_id, payload) = (client_id.clone(), mls_message.to_vec());
                    async move {
                        transport
                            .post_message(&t, group_id, client_id, payload)
                            .await
                    }
                })
                .await;
            match posted {
                Err(PostError::Transport(err)) if hub_unreachable(&err) && i < last => {
                    tracing::warn!(hub_id = %hub.hub_id, %group_id, error = %err, "hub unreachable; posting to the next hub");
                }
                Err(PostError::Transport(err)) if no_replica(group_id, &hub, &err) && i < last => {
                    tracing::info!(hub_id = %hub.hub_id, %group_id, "hub has no replica of the group; posting to the next hub");
                }
                posted => return posted,
            }
        }
        Err(TransportError::Network("no hub to post to".into()).into())
    }

    /// Claims KeyPackages of `users` through the first hub that can be
    /// reached, the primary first; returns the claim and that hub.
    pub(crate) async fn claim_routed(
        &self,
        users: &[gim_common::UserId],
    ) -> Result<(KeyPackageClaim, HubTarget)> {
        let hubs = self.submission_hubs().await;
        let last = hubs.len().saturating_sub(1);
        for (i, hub) in hubs.into_iter().enumerate() {
            let claimed = self.claim_on(&hub, users).await;
            match claimed {
                Err(err) if hub_unreachable(&err) && i < last => {
                    tracing::warn!(hub_id = %hub.hub_id, error = %err, "hub unreachable; claiming through the next hub");
                }
                claimed => return Ok((claimed?, hub)),
            }
        }
        Err(TransportError::Network("no hub to claim through".into()).into())
    }

    pub(crate) async fn claim_on(
        &self,
        hub: &HubTarget,
        users: &[gim_common::UserId],
    ) -> std::result::Result<KeyPackageClaim, TransportError> {
        self.authed_on(hub, |transport, t| async move {
            transport.claim_key_packages_federated(&t, users).await
        })
        .await
    }

    /// Claims new KeyPackages of the devices of `previous` through `hub`,
    /// for an Add to rebuild after `kp_not_claimed`. Devices without one
    /// there are left out; `InvalidInput` if that is all of them.
    pub(crate) async fn reclaim_key_packages(
        &self,
        hub: &HubTarget,
        previous: &[ClaimedKeyPackage],
    ) -> Result<Vec<ClaimedKeyPackage>> {
        let mut users: Vec<_> = previous.iter().map(|k| k.device.user_id.clone()).collect();
        users.sort();
        users.dedup();
        let claimed = self.claim_on(hub, &users).await?;
        let mut seen = std::collections::BTreeSet::new();
        let key_packages: Vec<ClaimedKeyPackage> = claimed
            .key_packages
            .into_iter()
            .filter(|k| previous.iter().any(|p| p.device == k.device))
            .filter(|k| seen.insert(k.device.clone()))
            .collect();
        if key_packages.is_empty() {
            return Err(ClientError::InvalidInput(format!(
                "no device to add has a KeyPackage on hub {}",
                hub.hub_id
            )));
        }
        tracing::info!(hub_id = %hub.hub_id, devices = key_packages.len(), "KeyPackages claimed again for the hub used");
        Ok(key_packages)
    }

    /// Whether the group on `hub` is past this device's epoch: a commit
    /// was sequenced that this device has not applied, possibly its own
    /// pending one. Unknown (unreachable, ...) counts as yes.
    pub(crate) async fn group_advanced_on(&self, hub: &HubTarget, group_id: &GroupId) -> bool {
        let info = self
            .authed_on(hub, |transport, t| async move {
                transport.group_info(&t, group_id).await
            })
            .await;
        let gid = group_id.clone();
        let local = self
            .run(move |store, engine| store.transaction(|txn| Ok(engine.group_epoch(&*txn, &gid)?)))
            .await;
        match (info, local) {
            (Ok(info), Ok(local)) => info.epoch > local,
            _ => true,
        }
    }

    /// Generates KeyPackages for `hub_id` (`count` one-time ones, and a
    /// last-resort one if asked) and records them in the ledger in the
    /// same transaction.
    async fn generate_key_packages_for(
        &self,
        hub_id: &str,
        count: u32,
        last_resort: bool,
    ) -> Result<(Vec<Vec<u8>>, Option<Vec<u8>>)> {
        let hub_id = hub_id.to_string();
        self.run(move |store, engine| {
            store.transaction(|txn| {
                let one_time = engine.generate_key_packages(&*txn, count)?;
                let last = if last_resort {
                    Some(engine.generate_last_resort_key_package(&*txn)?)
                } else {
                    None
                };
                let now = now_ms();
                let all = one_time.iter().map(|k| (k, false));
                for (key_package, last_resort) in all.chain(last.iter().map(|k| (k, true))) {
                    txn.add_key_package_record(&KeyPackageRecord {
                        kp_ref: engine.key_package_ref(key_package)?,
                        hub_id: hub_id.clone(),
                        last_resort,
                        created_at_ms: now,
                    })?;
                }
                Ok((one_time, last))
            })
        })
        .await
    }

    /// Records KeyPackages generated before their hub was known (at
    /// enrollment) in the ledger for `hub_id`.
    pub(crate) async fn record_key_packages(
        &self,
        hub_id: &str,
        key_packages: Vec<(Vec<u8>, bool)>,
    ) -> Result<()> {
        let hub_id = hub_id.to_string();
        self.run(move |store, engine| {
            store.transaction(|txn| {
                let now = now_ms();
                for (key_package, last_resort) in &key_packages {
                    txn.add_key_package_record(&KeyPackageRecord {
                        kp_ref: engine.key_package_ref(key_package)?,
                        hub_id: hub_id.clone(),
                        last_resort: *last_resort,
                        created_at_ms: now,
                    })?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Uploads KeyPackages of `hub` there. On 409 `duplicate_key_package`
    /// the same number of fresh ones is generated for the hub and uploaded
    /// instead (never the same `kp_ref` again).
    async fn upload_to_hub(
        &self,
        hub: &HubTarget,
        mut key_packages: Vec<Vec<u8>>,
        last_resort: bool,
    ) -> Result<()> {
        let mut regenerated = 0;
        loop {
            let uploaded = self
                .authed_on(hub, |transport, t| {
                    let key_packages = key_packages.clone();
                    async move {
                        transport
                            .upload_key_packages(&t, key_packages, last_resort)
                            .await
                    }
                })
                .await;
            match uploaded {
                Err(err)
                    if duplicate_key_package(&err)
                        && regenerated < DUPLICATE_KEY_PACKAGE_RETRIES =>
                {
                    regenerated += 1;
                    tracing::warn!(hub_id = %hub.hub_id, error = %err, "hub refused KeyPackages as duplicates; uploading fresh ones");
                    let count = key_packages.len() as u32;
                    let (one_time, last) = if last_resort {
                        self.generate_key_packages_for(&hub.hub_id, 0, true).await?
                    } else {
                        self.generate_key_packages_for(&hub.hub_id, count, false)
                            .await?
                    };
                    key_packages = one_time.into_iter().chain(last).collect();
                }
                uploaded => return Ok(uploaded?),
            }
        }
    }

    /// Generates and uploads [`KEY_PACKAGE_BATCH`] one-time KeyPackages to
    /// `hub` (its `keypackages.low`).
    /// No-op in [`crate::ClientMode::Extension`]: the app generates them.
    pub(crate) async fn replenish_hub(&self, hub: &HubTarget) -> Result<()> {
        if self.is_extension() {
            return Ok(());
        }
        let (key_packages, _) = self
            .generate_key_packages_for(&hub.hub_id, KEY_PACKAGE_BATCH, false)
            .await?;
        self.upload_to_hub(hub, key_packages, false).await
    }

    /// Generates and uploads [`KEY_PACKAGE_BATCH`] one-time KeyPackages to
    /// the listed hub `hub_id`, for its `keypackages.low`; the other hubs
    /// are left alone. `InvalidInput` if this device cannot reach that hub.
    pub async fn replenish_hub_key_packages(&self, hub_id: &str) -> Result<()> {
        self.require_session()?;
        let hub = self
            .submission_hubs()
            .await
            .into_iter()
            .find(|h| h.hub_id == hub_id)
            .ok_or_else(|| ClientError::InvalidInput(format!("hub {hub_id} is not reachable")))?;
        self.replenish_hub(&hub).await
    }

    /// Tops `hub`'s one-time KeyPackages up to [`KEY_PACKAGE_BATCH`], plus
    /// a last-resort one if it has none. Uploads a batch if the hub cannot
    /// count them; network and auth errors are returned.
    /// No-op in [`crate::ClientMode::Extension`].
    pub(crate) async fn top_up_hub(&self, hub: &HubTarget) -> Result<()> {
        if self.is_extension() {
            return Ok(());
        }
        let counted = self
            .authed_on(hub, |transport, t| async move {
                transport.key_package_count(&t).await
            })
            .await;
        let count = match counted {
            Ok(count) => count,
            Err(
                err @ (TransportError::Network(_)
                | TransportError::Unauthorized
                | TransportError::UserSuspended { .. }),
            ) => return Err(err.into()),
            Err(err) => {
                tracing::debug!(hub_id = %hub.hub_id, error = %err, "cannot count KeyPackages; uploading a batch");
                return self.replenish_hub(hub).await;
            }
        };
        let missing = u64::from(KEY_PACKAGE_BATCH).saturating_sub(count.available);
        let missing = u32::try_from(missing).unwrap_or(KEY_PACKAGE_BATCH);
        let last_resort = !count.has_last_resort;
        if missing == 0 && !last_resort {
            return Ok(());
        }
        tracing::info!(hub_id = %hub.hub_id, missing, last_resort, "topping up KeyPackages");
        let (key_packages, last_resort) = self
            .generate_key_packages_for(&hub.hub_id, missing, last_resort)
            .await?;
        if !key_packages.is_empty() {
            self.upload_to_hub(hub, key_packages, false).await?;
        }
        if let Some(last_resort) = last_resort {
            self.upload_to_hub(hub, vec![last_resort], true).await?;
        }
        Ok(())
    }

    /// Tops up the KeyPackages of every reachable listed hub other than
    /// the home hub. Best effort: failures are logged and retried on the
    /// next registry refresh.
    pub(crate) async fn top_up_listed_hubs(&self) {
        for hub in self.submission_hubs().await {
            if hub.home {
                continue;
            }
            if let Err(err) = self.top_up_hub(&hub).await {
                tracing::warn!(hub_id = %hub.hub_id, error = %err, "cannot top up KeyPackages on a listed hub");
            }
        }
    }
}
