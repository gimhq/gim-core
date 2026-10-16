//! Hub management (multi-homing, contract `multihoming.md` §4.1, §7.1):
//! adding a hub, removing one, and changing the primary hub. Each changes
//! the hub list of the user's hosting record, which the client signs with
//! the user root key; every listed hub co-signs its own entry, with its
//! priority. The new record goes to the home hub first, then to the other
//! hubs of the old and the new list (they also pass it on to each other).
//! Afterwards the registry follows the record and the hub map is sent to
//! the own other devices (`self.hubs`).
//!
//! The home hub (the client's own transport) is never removed: the
//! session, linking and recovery go through it. A user moving away from
//! it makes another hub primary; dropping the home hub needs a client
//! built for another hub.
//!
//! Removing a hub does not migrate the groups it owns (D8): it keeps
//! sequencing them, and this user reaches them through the remaining hubs
//! (federation). The caller confirms that after a
//! [`ClientError::HubOwnsGroups`] warning.

use std::sync::Arc;

use gim_base::model::{HubRecord, HubState, Membership, OutboxState};
use gim_base::StateStore;
use gim_common::now_ms;
use gim_identity::HostingEntry;

use crate::client::owner_hub;
use crate::hosting::with_entry;
use crate::hubs::{prove_hub, sort, HubStatus, Listed, ProofFailure};
use crate::routing::HubTarget;
use crate::transport::Transport;
use crate::{Client, ClientError, Result};

impl<S: StateStore + 'static> Client<S> {
    /// Adds the hub at `url` to the user's hosting record (§4.1): checks
    /// the URL with the hub proof (`GET /v2/hub?nonce=`: the hub proves its
    /// root key for exactly this URL; [`ClientError::InvalidInput`]
    /// otherwise, with nothing else sent there), uploads the own DeviceList there, signs
    /// in with a challenge bound to the URL, gets the hub's co-signed entry (least preferred, after the
    /// listed hubs), publishes the record with it, uploads this device's
    /// KeyPackages and the recovery backup there, starts following its
    /// events (with the sync loop) and sends the hub map to the own other
    /// devices. `url` is entered on this device, so it may be contacted.
    ///
    /// Idempotent: for a listed hub, it only records `url` for it if this
    /// device has no verified URL there (as [`Client::set_hub_url`]).
    /// Returns the hub's status.
    pub async fn add_hub(&self, url: &str) -> Result<HubStatus> {
        let session = self.require_session()?;
        let _admin = self.inner.hub_admin_lock.lock().await;
        let transport = (self.inner.hub_connector)(url)?;
        let proven = match prove_hub(&*transport, Some(url), None, false).await {
            Ok(proven) => proven,
            Err(ProofFailure::Transport(err)) => return Err(err.into()),
            Err(ProofFailure::Rejected(reason)) => {
                tracing::warn!(%url, %reason, "hub URL rejected");
                return Err(ClientError::InvalidInput(format!(
                    "{url} is not a verified gim hub: {reason}"
                )));
            }
        };
        let (hub_id, root) = (proven.hub_id, proven.root);
        let listed = self.listed_hubs().await?;
        if let Some(hub) = listed.iter().find(|h| h.hub_id == hub_id) {
            let home = self.home_hub().as_ref() == Some(&hub_id);
            let verified = self.handles().get(&hub_id).is_some_and(|h| h.is_verified());
            if !home && !(verified && hub.url.as_deref() == Some(url) && !hub.url_shared) {
                self.set_hub_url(&hub_id, url).await?;
            }
            return self.hub_status(&hub_id).await;
        }
        tracing::info!(%hub_id, %url, "adding a hub");

        let user_id = session.device.user_id.clone();
        let own = user_id.clone();
        let device_list = self
            .run(move |store, _| {
                Ok(store
                    .device_lists()?
                    .into_iter()
                    .find(|(u, _)| *u == own)
                    .map(|(_, bytes)| bytes))
            })
            .await?
            .ok_or_else(|| ClientError::Identity("the own device list is unknown".into()))?;
        transport.put_device_list(&user_id, device_list).await?;
        self.handles().entry(hub_id.clone()).or_default().verified =
            Some((url.to_string(), transport.clone()));
        let target = HubTarget {
            hub_id: hub_id.clone(),
            home: false,
        };
        let added = async {
            self.renew_hub_token(&hub_id).await?;
            let priority = listed
                .iter()
                .map(|h| h.priority.saturating_add(1))
                .max()
                .unwrap_or(1);
            let entry = self.hosting_entry_on(&target, priority).await?;
            let also = self.other_hub_transports(Some(transport.clone()));
            let record = self
                .publish_hub_list(|entries| with_entry(entries, &entry), &also)
                .await?;
            Ok::<_, ClientError>((record, priority))
        }
        .await;
        let (record, priority) = match added {
            Ok(added) => added,
            Err(err) => {
                self.handles().remove(&hub_id);
                return Err(err);
            }
        };
        self.save_hub(HubRecord {
            hub_id: hub_id.clone(),
            url: Some(url.to_string()),
            url_shared: false,
            priority,
            verified_root_pubkey: Some(root),
            last_seen_ms: Some(now_ms()),
            state: HubState::Verified,
        })
        .await?;
        // Tops up the KeyPackages there and starts its sync loop.
        self.refresh_hubs_from(Listed::Known(&record)).await?;
        self.copy_recovery_backup(&target).await;
        self.share_hub_locations().await;
        self.hub_status(&hub_id).await
    }

    /// Removes the listed hub `hub_id` from the user's hosting record
    /// (§7.1 step 4). Refused for the home hub ([`ClientError::HomeHub`])
    /// and for the only listed hub ([`ClientError::LastHub`]). If the hub
    /// owns groups this user is in (their id starts with its `hub_id`),
    /// [`ClientError::HubOwnsGroups`] with their number unless
    /// `confirm_owned_groups`: they are not migrated, and stay reachable
    /// through the remaining hubs.
    ///
    /// Before the record changes, the hub is drained: its events are read
    /// up to the head and the Welcomes pending there joined (skipped if it
    /// cannot be reached; every listed hub receives the same messages), and
    /// the outbox and pending commits are flushed;
    /// [`ClientError::HubNotDrained`] if something is still unsent. Then
    /// its sync loop stops and its session is dropped. Its KeyPackage
    /// ledger rows stay, so its `kp_ref`s are never uploaded anywhere
    /// again.
    pub async fn remove_hub(&self, hub_id: &str, confirm_owned_groups: bool) -> Result<()> {
        let session = self.require_session()?;
        let _admin = self.inner.hub_admin_lock.lock().await;
        let listed = self.listed_hubs().await?;
        if !listed.iter().any(|h| h.hub_id == hub_id) {
            return Err(ClientError::InvalidInput(format!(
                "hub {hub_id} is not listed by the hosting record"
            )));
        }
        if self.home_hub().as_deref() == Some(hub_id) {
            return Err(ClientError::HomeHub(hub_id.to_string()));
        }
        if listed.len() < 2 {
            return Err(ClientError::LastHub(hub_id.to_string()));
        }
        let group_count = self.owned_group_count(hub_id).await?;
        if group_count > 0 && !confirm_owned_groups {
            return Err(ClientError::HubOwnsGroups {
                hub_id: hub_id.to_string(),
                group_count,
            });
        }

        if !self.drain_hub(&session, hub_id).await? {
            tracing::info!(%hub_id, "removing a hub that cannot be drained");
        }
        if let Err(err) = self.flush_outbox().await {
            tracing::debug!(error = %err, "outbox pass before removing a hub failed");
        }
        let (unsent, pending) = self
            .run(|store, _| {
                let unsent = store
                    .outbox_entries()?
                    .into_iter()
                    .filter(|e| e.state == OutboxState::Pending)
                    .count();
                Ok((unsent, store.pending_commits()?.len()))
            })
            .await?;
        if unsent > 0 || pending > 0 {
            return Err(ClientError::HubNotDrained {
                hub_id: hub_id.to_string(),
                reason: format!("{unsent} messages and {pending} commits not acknowledged yet"),
            });
        }

        let removed = self
            .hub_root_key_of(hub_id)
            .await?
            .ok_or_else(|| ClientError::InvalidInput(format!("hub {hub_id} is not listed")))?;
        // The removed hub learns it too: it stops hosting the user.
        let also = self.other_hub_transports(None);
        let record = self
            .publish_hub_list(
                |mut entries| {
                    entries.retain(|e| e.hub_root_public_key().as_bytes() != removed.as_slice());
                    entries
                },
                &also,
            )
            .await?;
        tracing::info!(%hub_id, group_count, "removed a hub");
        self.handles().remove(hub_id);
        let persisted = self.session().map(|current| self.persist_session(&current));
        if let Some(Err(err)) = persisted {
            tracing::warn!(error = %err, "cannot persist the hub sessions");
        }
        // Marks the hub removed and stops its sync loop.
        self.refresh_hubs_from(Listed::Known(&record)).await?;
        self.share_hub_locations().await;
        Ok(())
    }

    /// Makes the listed hub `hub_id` the primary hub: it gets priority 0
    /// and the other hubs follow in their current order. Every hub whose
    /// priority changes co-signs a new entry, so this device needs a
    /// session there (a URL verified on this device). Submissions and
    /// claims then go to the new primary first.
    pub async fn set_primary_hub(&self, hub_id: &str) -> Result<()> {
        self.require_session()?;
        let _admin = self.inner.hub_admin_lock.lock().await;
        let listed = self.listed_hubs().await?;
        let Some(position) = listed.iter().position(|h| h.hub_id == hub_id) else {
            return Err(ClientError::InvalidInput(format!(
                "hub {hub_id} is not listed by the hosting record"
            )));
        };
        if position == 0 {
            return Ok(());
        }
        let mut order = listed;
        let primary = order.remove(position);
        order.insert(0, primary);
        let reachable = self.submission_hubs().await;
        let mut entries = Vec::new();
        for (priority, hub) in order.iter().enumerate() {
            let priority = u8::try_from(priority).unwrap_or(u8::MAX);
            if hub.priority == priority {
                continue;
            }
            let target = reachable
                .iter()
                .find(|t| t.hub_id == hub.hub_id)
                .ok_or_else(|| {
                    ClientError::InvalidInput(format!(
                        "hub {} is not reachable from this device; set its URL first",
                        hub.hub_id
                    ))
                })?;
            entries.push(self.hosting_entry_on(target, priority).await?);
        }
        let also = self.other_hub_transports(None);
        let record = self
            .publish_hub_list(|current| entries.iter().fold(current, with_entry), &also)
            .await?;
        tracing::info!(%hub_id, "changed the primary hub");
        self.refresh_hubs_from(Listed::Known(&record)).await?;
        self.share_hub_locations().await;
        Ok(())
    }

    /// The listed hubs (not removed) in registry order.
    async fn listed_hubs(&self) -> Result<Vec<HubRecord>> {
        let mut hubs: Vec<HubRecord> = self
            .run(|store, _| Ok(store.hubs()?))
            .await?
            .into_iter()
            .filter(|h| h.state != HubState::Removed)
            .collect();
        sort(&mut hubs);
        Ok(hubs)
    }

    async fn hub_status(&self, hub_id: &str) -> Result<HubStatus> {
        self.hubs()
            .await?
            .into_iter()
            .find(|h| h.hub.hub_id == hub_id)
            .ok_or_else(|| ClientError::InvalidInput(format!("hub {hub_id} is not listed")))
    }

    /// The root public key of the listed hub `hub_id`, from the current
    /// hosting record.
    async fn hub_root_key_of(&self, hub_id: &str) -> Result<Option<Vec<u8>>> {
        let user_id = self.require_session()?.device.user_id;
        let record = self.hub_hosting_record(&user_id).await?;
        Ok(record.and_then(|r| {
            r.hubs()
                .iter()
                .find(|e| e.hub_id() == hub_id)
                .map(|e: &HostingEntry| e.hub_root_public_key().as_bytes().to_vec())
        }))
    }

    /// The joined chats and self groups owned by the hub `hub_id`.
    async fn owned_group_count(&self, hub_id: &str) -> Result<u32> {
        let hub_id = hub_id.to_string();
        self.run(move |store, _| {
            let mut groups: Vec<_> = store
                .chats()?
                .into_iter()
                .filter(|c| c.membership != Membership::Left)
                .map(|c| c.group_id)
                .collect();
            groups.extend(store.self_groups()?);
            groups.sort();
            groups.dedup();
            let owned = groups
                .iter()
                .filter(|g| owner_hub(g) == Some(hub_id.as_str()))
                .count();
            Ok(u32::try_from(owned).unwrap_or(u32::MAX))
        })
        .await
    }

    /// The transports of the listed hubs other than the home hub verified
    /// in this run, and `extra`.
    fn other_hub_transports(&self, extra: Option<Arc<dyn Transport>>) -> Vec<Arc<dyn Transport>> {
        self.verified_hubs()
            .into_iter()
            .map(|(_, _, transport)| transport)
            .chain(extra)
            .collect()
    }

    /// Uploads the recovery backup the home hub keeps to `hub` (§4.1 step
    /// 5). Best effort.
    async fn copy_recovery_backup(&self, hub: &HubTarget) {
        let Some(session) = self.session() else {
            return;
        };
        let user_id = &session.device.user_id;
        let backup = match self.inner.transport.recovery_backup(user_id).await {
            Ok(Some(backup)) => backup,
            Ok(None) => return,
            Err(err) => {
                tracing::debug!(error = %err, "cannot read the recovery backup");
                return;
            }
        };
        let copied = self
            .authed_on(hub, |transport, t| {
                let backup = backup.clone();
                async move { transport.put_recovery_backup(&t, user_id, backup).await }
            })
            .await;
        if let Err(err) = copied {
            tracing::warn!(hub_id = %hub.hub_id, error = %err, "cannot copy the recovery backup");
        }
    }
}
