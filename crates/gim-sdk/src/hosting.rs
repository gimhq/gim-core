//! The user's hosting record (closed federation): the hubs that host the
//! user, each with its signed consent, signed with the user root key. It is
//! published at onboarding, renewed before it expires (when the sync loop
//! starts, daily, and on `hosting_record.expiring`), and published again
//! when a federated request answers 403 `hosting_record_required`.
//! Publication failures never block local operation: they are logged and
//! retried from the sync loop.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use gim_base::StateStore;
use gim_common::{now_ms, UserId};
use gim_identity::{HostingEntry, RootKey, SignedHostingRecord, UserHostingRecord};

use crate::hubs::Listed;
use crate::routing::HubTarget;
use crate::stream::Backoff;
use crate::transport::{HostingEntryGrant, Transport, TransportError};
use crate::{Client, ClientError, Result};

/// Lifetime of a published hosting record.
pub const HOSTING_RECORD_LIFETIME: Duration = Duration::from_secs(7 * 24 * 3600);
/// A hosting record is renewed once less than this remains.
pub const HOSTING_RECORD_RENEW_BEFORE: Duration = Duration::from_secs(3 * 24 * 3600);
/// Interval of the sync loop's renewal check.
pub const HOSTING_RECORD_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 3600);
/// Priority of the own hub's entry, the only one without multi-homing.
const OWN_HUB_PRIORITY: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Publish {
    /// Publish a new record with a fresh entry of the own hub (onboarding,
    /// 403 `hosting_record_required`).
    Now,
    /// Renew the record (same entries) if there is none or less than
    /// [`HOSTING_RECORD_RENEW_BEFORE`] remains.
    IfDue,
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Whether `record` needs no renewal at `now`.
fn fresh(record: &UserHostingRecord, now: u64) -> bool {
    record.expires_at().saturating_sub(now) >= millis(HOSTING_RECORD_RENEW_BEFORE)
}

/// Checks a hub's entry against the response that carries it: the key and
/// priority it names, and the `hub_id` derived from that key. The hub
/// signature is checked when the entry goes into the record.
fn verify_grant(grant: &HostingEntryGrant, priority: u8) -> Result<HostingEntry> {
    let invalid = |reason: &str| ClientError::Identity(format!("invalid hosting entry: {reason}"));
    let entry = HostingEntry::from_bytes(&grant.entry).map_err(ClientError::identity)?;
    if entry.hub_root_public_key().as_bytes().as_slice() != grant.hub_root_public_key.as_slice() {
        return Err(invalid("hub_root_pubkey is not the entry's"));
    }
    if entry.hub_id() != grant.hub_id {
        return Err(invalid("hub_id does not derive from hub_root_pubkey"));
    }
    if entry.priority() != grant.priority || entry.priority() != priority {
        return Err(invalid("not the requested priority"));
    }
    Ok(entry)
}

/// The next record, valid for [`HOSTING_RECORD_LIFETIME`]: `own` replaces
/// the own hub's entry of `current`, whose other entries are kept.
fn build_record(
    root: &RootKey,
    seq: u64,
    own: Option<&HostingEntry>,
    current: Option<&UserHostingRecord>,
) -> Result<SignedHostingRecord> {
    let mut hubs: Vec<HostingEntry> = current.map(|r| r.hubs().to_vec()).unwrap_or_default();
    if let Some(own) = own {
        hubs.retain(|e| e.hub_root_public_key() != own.hub_root_public_key());
        hubs.push(own.clone());
    }
    sign_record(root, seq, hubs)
}

/// A record listing `hubs`, valid for [`HOSTING_RECORD_LIFETIME`].
fn sign_record(root: &RootKey, seq: u64, hubs: Vec<HostingEntry>) -> Result<SignedHostingRecord> {
    let expires_at = now_ms().saturating_add(millis(HOSTING_RECORD_LIFETIME));
    UserHostingRecord::new(root.public(), seq, expires_at, hubs)
        .and_then(|record| record.sign(root))
        .map_err(ClientError::identity)
}

/// `entries` with `entry` in place of the entry of the same hub, if any.
pub(crate) fn with_entry(
    mut entries: Vec<HostingEntry>,
    entry: &HostingEntry,
) -> Vec<HostingEntry> {
    entries.retain(|e| e.hub_root_public_key() != entry.hub_root_public_key());
    entries.push(entry.clone());
    entries
}

fn next_seq(current: &UserHostingRecord) -> Result<u64> {
    current
        .seq()
        .checked_add(1)
        .ok_or_else(|| ClientError::Identity("hosting record seq overflow".into()))
}

impl<S: StateStore + 'static> Client<S> {
    /// [`Client::publish_hosting_record`] that only logs failures: the sync
    /// loop retries.
    pub(crate) async fn publish_hosting_record_logged(&self, mode: Publish) {
        if let Err(err) = self.publish_hosting_record(mode).await {
            tracing::warn!(error = %err, ?mode, "cannot publish the hosting record");
        }
    }

    /// Publishes the user's hosting record: reads the current one from the
    /// hub, builds the next (seq + 1, or 1) signed with the user root key
    /// and uploads it. If a newer record lands concurrently (409), it is
    /// read and the record rebuilt once; with [`Publish::IfDue`], a newer
    /// record that needs no renewal (another device renewed it) is kept.
    /// Then the hub registry follows the record now current.
    pub(crate) async fn publish_hosting_record(&self, mode: Publish) -> Result<()> {
        let current = self.publish_hosting_record_locked(mode).await?;
        // Boxed: refreshing may share the hub URLs, and sending may publish.
        Box::pin(self.refresh_hubs_logged(Listed::Known(&current))).await;
        Ok(())
    }

    /// [`Client::publish_hosting_record`] under the hosting lock; returns
    /// the record now current.
    async fn publish_hosting_record_locked(&self, mode: Publish) -> Result<UserHostingRecord> {
        let user_id = self.require_session()?.device.user_id;
        let _guard = self.inner.hosting_lock.lock().await;
        let mut current = self.hub_hosting_record(&user_id).await?;
        if mode == Publish::IfDue {
            if let Some(current) = current.as_ref().filter(|r| fresh(r, now_ms())) {
                return Ok(current.clone());
            }
        }
        let root = self.root_key()?;
        let own = match (mode, &current) {
            (Publish::IfDue, Some(_)) => None,
            _ => {
                // The home hub keeps its place (set_primary_hub).
                let home = self.home_hub();
                let priority = current
                    .as_ref()
                    .and_then(|r| r.hubs().iter().find(|e| Some(e.hub_id()) == home))
                    .map_or(OWN_HUB_PRIORITY, HostingEntry::priority);
                Some(self.own_hosting_entry(&user_id, priority).await?)
            }
        };
        let mut seq = current.as_ref().map_or(Ok(1), next_seq)?;
        let mut rebuilt = false;
        loop {
            let record = build_record(&root, seq, own.as_ref(), current.as_ref())?;
            match self
                .inner
                .transport
                .put_hosting_record(&user_id, record.to_bytes())
                .await
            {
                Ok(_) => {
                    tracing::info!(seq, "published the hosting record");
                    return record.verify(now_ms()).map_err(ClientError::identity);
                }
                Err(TransportError::Conflict(reason)) if !rebuilt => {
                    tracing::info!(%reason, "a newer hosting record landed; rebuilding");
                    rebuilt = true;
                    let newer = self.hub_hosting_record(&user_id).await?;
                    match newer {
                        Some(newer) if mode == Publish::IfDue && fresh(&newer, now_ms()) => {
                            return Ok(newer)
                        }
                        Some(newer) => {
                            seq = next_seq(&newer)?;
                            current = Some(newer);
                        }
                        // The hub keeps an expired record to order uploads
                        // but no longer serves it: a time-based seq is above
                        // any it may hold.
                        None => seq = seq.saturating_add(1).max(now_ms()),
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// The user's hosting record on the hub, verified; `None` if there is
    /// none, it expired, or it does not verify (logged).
    pub(crate) async fn hub_hosting_record(
        &self,
        user_id: &UserId,
    ) -> Result<Option<UserHostingRecord>> {
        let stored = self
            .public_read_routed(|transport| async move { transport.hosting_record(user_id).await })
            .await?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        match SignedHostingRecord::from_bytes(&stored.record).and_then(|s| s.verify(now_ms())) {
            Ok(record) if record.user_id() == user_id => Ok(Some(record)),
            Ok(record) => {
                tracing::warn!(other = %record.user_id(), "ignoring another user's hosting record");
                Ok(None)
            }
            Err(err) => {
                tracing::warn!(error = %err, "ignoring a hosting record that does not verify");
                Ok(None)
            }
        }
    }

    /// The own hub's entry for the user, checked against the response.
    async fn own_hosting_entry(&self, user_id: &UserId, priority: u8) -> Result<HostingEntry> {
        let grant = self
            .authed_session(|t| async move {
                self.inner
                    .transport
                    .create_hosting_entry(&t, user_id, priority)
                    .await
            })
            .await?;
        verify_grant(&grant, priority)
    }

    /// The entry of `hub` for the user with `priority`, co-signed there and
    /// checked against the response and the hub's id.
    pub(crate) async fn hosting_entry_on(
        &self,
        hub: &HubTarget,
        priority: u8,
    ) -> Result<HostingEntry> {
        let user_id = &self.require_session()?.device.user_id;
        let grant = self
            .authed_on(hub, |transport, t| async move {
                transport.create_hosting_entry(&t, user_id, priority).await
            })
            .await?;
        let entry = verify_grant(&grant, priority)?;
        if !hub.home && entry.hub_id() != hub.hub_id {
            return Err(ClientError::Identity(format!(
                "invalid hosting entry: hub {} signed for {}",
                hub.hub_id,
                entry.hub_id()
            )));
        }
        Ok(entry)
    }

    /// Publishes the next record of the user, listing `edit` applied to the
    /// entries of the current one (or to the home hub's own entry if there
    /// is none): uploads it to the home hub, rebuilding it once if a newer
    /// one landed meanwhile, then to the hubs of `also` (best effort: the
    /// hubs pass it on to each other). Returns the published record.
    pub(crate) async fn publish_hub_list(
        &self,
        edit: impl Fn(Vec<HostingEntry>) -> Vec<HostingEntry>,
        also: &[Arc<dyn Transport>],
    ) -> Result<UserHostingRecord> {
        let user_id = self.require_session()?.device.user_id;
        let record = {
            let _guard = self.inner.hosting_lock.lock().await;
            let root = self.root_key()?;
            let mut current = self.hub_hosting_record(&user_id).await?;
            let mut seq = current.as_ref().map_or(Ok(1), next_seq)?;
            let mut rebuilt = false;
            loop {
                let entries = match &current {
                    Some(current) => current.hubs().to_vec(),
                    None => vec![self.own_hosting_entry(&user_id, OWN_HUB_PRIORITY).await?],
                };
                let record = sign_record(&root, seq, edit(entries))?;
                match self
                    .inner
                    .transport
                    .put_hosting_record(&user_id, record.to_bytes())
                    .await
                {
                    Ok(_) => break record,
                    Err(TransportError::Conflict(reason)) if !rebuilt => {
                        tracing::info!(%reason, "a newer hosting record landed; rebuilding");
                        rebuilt = true;
                        current = self.hub_hosting_record(&user_id).await?;
                        seq = match &current {
                            Some(current) => next_seq(current)?,
                            // See publish_hosting_record_locked.
                            None => seq.saturating_add(1).max(now_ms()),
                        };
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        };
        let published = record.verify(now_ms()).map_err(ClientError::identity)?;
        tracing::info!(
            seq = published.seq(),
            "published the hosting record with a new hub list"
        );
        for transport in also {
            if let Err(err) = transport
                .put_hosting_record(&user_id, record.to_bytes())
                .await
            {
                tracing::warn!(error = %err, "cannot upload the hosting record to a listed hub");
            }
        }
        Ok(published)
    }

    /// Renews the hosting record when due: at once, then every
    /// [`HOSTING_RECORD_CHECK_INTERVAL`] and whenever
    /// `hosting_record.expiring` arrives; failures are retried with the sync
    /// backoff. Runs alongside the sync loop.
    pub(crate) async fn maintain_hosting_record(&self) -> Infallible {
        let settings = self.inner.sync_settings;
        let mut backoff = Backoff::new(settings.backoff_min, settings.backoff_max);
        loop {
            let delay = match self.publish_hosting_record(Publish::IfDue).await {
                Ok(()) => {
                    backoff.reset();
                    HOSTING_RECORD_CHECK_INTERVAL
                }
                Err(err) => {
                    let delay = backoff.next_delay();
                    tracing::warn!(error = %err, ?delay, "cannot renew the hosting record");
                    delay
                }
            };
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = self.inner.hosting_wake.notified() => {}
            }
        }
    }
}
