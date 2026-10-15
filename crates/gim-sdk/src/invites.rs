//! Pending invites: users added to a chat whose hub could not be reached
//! when their KeyPackages were claimed (`unavailable` claim targets,
//! federation). The sync loop claims them again with backoff and adds them
//! once their hub answers; after [`SyncSettings::invite_ttl`] the invite is
//! dropped and surfaced as a `Removed` membership change. Kept in memory
//! only: a restart forgets them.
//!
//! [`SyncSettings::invite_ttl`]: crate::SyncSettings::invite_ttl

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::time::Duration;

use gim_base::model::{MembershipChangeKind, MembershipEvent, StateChange};
use gim_base::{BaseError, StateStore};
use gim_common::{now_ms, GroupId, UserId};

use crate::client::{CommitOp, Session};
use crate::{Client, ClientError, Result};

/// Longest delay between two claims of a pending invitee.
pub const INVITE_RETRY_MAX: Duration = Duration::from_secs(15 * 60);
/// Sleep of the retry task when no invite is pending.
const IDLE_WAIT: Duration = Duration::from_secs(3600);

/// Pending invitees per chat.
pub(crate) type PendingInvites = BTreeMap<GroupId, BTreeMap<UserId, PendingInvite>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingInvite {
    /// Unix milliseconds of the first claim.
    since_ms: u64,
    /// Claims after the first one.
    attempts: u32,
    /// Unix milliseconds of the next claim.
    next_attempt_ms: u64,
}

impl PendingInvite {
    fn expires_ms(&self, ttl_ms: u64) -> u64 {
        self.since_ms.saturating_add(ttl_ms)
    }

    /// When the invite needs attention: its next claim, or its expiry.
    fn due_ms(&self, ttl_ms: u64) -> u64 {
        self.next_attempt_ms.min(self.expires_ms(ttl_ms))
    }
}

/// What one retry pass decided for a chat's due invitees.
#[derive(Default)]
struct Outcome {
    /// Users whose KeyPackages were claimed: added by the commit.
    claimed: BTreeSet<UserId>,
    /// Still unreachable: claimed again later.
    unavailable: Vec<UserId>,
    /// Expired, unknown to their hub, or without a device: dropped.
    failed: Vec<UserId>,
}

impl<S: StateStore + 'static> Client<S> {
    /// The users added to the chat who are not members yet because their
    /// hub was unreachable; the sync loop keeps trying to add them.
    pub fn pending_invites(&self, group_id: &GroupId) -> Vec<UserId> {
        self.invites()
            .get(group_id)
            .map(|users| users.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Claims the KeyPackages of the pending invitees that are due and adds
    /// those whose hub answers; drops expired ones. Run by the sync loop.
    /// Returns when the next invite is due, if any.
    pub async fn retry_pending_invites(&self) -> Result<Option<u64>> {
        let session = self.require_session()?;
        let now = now_ms();
        let ttl = self.invite_ttl_ms();
        let due: Vec<GroupId> = self
            .invites()
            .iter()
            .filter(|(_, users)| users.values().any(|i| i.due_ms(ttl) <= now))
            .map(|(group_id, _)| group_id.clone())
            .collect();
        let mut failed = None;
        for group_id in due {
            if let Err(err) = self.retry_group_invites(&session, &group_id).await {
                tracing::debug!(%group_id, error = %err, "pending invites not added");
                failed.get_or_insert(err);
            }
        }
        match failed {
            Some(err) => Err(err),
            None => Ok(self.next_invite_due()),
        }
    }

    /// Keeps retrying the pending invites; runs alongside the sync loop.
    pub(crate) async fn maintain_pending_invites(&self) -> Infallible {
        loop {
            let wait = match self.retry_pending_invites().await {
                Ok(Some(due_ms)) => Duration::from_millis(due_ms.saturating_sub(now_ms())),
                Ok(None) => IDLE_WAIT,
                Err(_) => self.inner.sync_settings.backoff_max,
            };
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.inner.invite_wake.notified() => {}
            }
        }
    }

    /// Records `users` as pending invitees of the chat, first claim now.
    pub(crate) fn add_pending_invites(&self, group_id: &GroupId, users: &[UserId]) {
        if users.is_empty() {
            return;
        }
        tracing::info!(%group_id, ?users, "invitees' hubs unavailable; adding them later");
        let now = now_ms();
        let retry = self.invite_delay(0);
        let mut invites = self.invites();
        let chat = invites.entry(group_id.clone()).or_default();
        for user_id in users {
            chat.entry(user_id.clone()).or_insert(PendingInvite {
                since_ms: now,
                attempts: 0,
                next_attempt_ms: now + retry,
            });
        }
        drop(invites);
        self.inner.invite_wake.notify_one();
    }

    async fn retry_group_invites(&self, session: &Session, group_id: &GroupId) -> Result<()> {
        let outcome = {
            let _guard = self.inner.group_lock.lock().await;
            self.retry_group_invites_locked(session, group_id).await?
        };
        let Some(outcome) = outcome else {
            return Ok(());
        };
        if !outcome.claimed.is_empty() {
            self.share_group_info(group_id).await?;
            self.announce_profile(group_id).await;
            self.resolve_users(session, outcome.claimed).await;
        }
        Ok(())
    }

    /// `None` if the chat's invites were dropped (chat gone or left) or
    /// none was due.
    async fn retry_group_invites_locked(
        &self,
        session: &Session,
        group_id: &GroupId,
    ) -> Result<Option<Outcome>> {
        let members = match self.chat_devices(group_id).await {
            Ok(members) => members,
            Err(ClientError::InvalidInput(_) | ClientError::Base(BaseError::NotFound(_))) => {
                self.invites().remove(group_id);
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let now = now_ms();
        let ttl = self.invite_ttl_ms();
        let mut outcome = Outcome::default();
        let mut due = Vec::new();
        {
            let mut invites = self.invites();
            let Some(users) = invites.get_mut(group_id) else {
                return Ok(None);
            };
            // Added meanwhile (by another member or device).
            users.retain(|u, _| !members.iter().any(|m| m.user_id == *u));
            users.retain(|user_id, invite| {
                let expired = now >= invite.expires_ms(ttl);
                if expired {
                    outcome.failed.push(user_id.clone());
                } else if invite.next_attempt_ms <= now {
                    due.push(user_id.clone());
                }
                !expired
            });
        }
        if !due.is_empty() {
            let claim = match self.claim_key_packages(session, &due, &members).await {
                Ok(claim) => claim,
                Err(err) => {
                    self.reschedule_invites(group_id, &due);
                    self.fail_invites(session, group_id, outcome.failed).await?;
                    return Err(err);
                }
            };
            for user_id in due {
                if claim.unavailable.contains(&user_id) {
                    outcome.unavailable.push(user_id);
                } else if claim
                    .key_packages
                    .iter()
                    .any(|k| k.device.user_id == user_id)
                {
                    outcome.claimed.insert(user_id);
                } else {
                    outcome.failed.push(user_id);
                }
            }
            self.reschedule_invites(group_id, &outcome.unavailable);
            self.remove_invites(group_id, outcome.claimed.iter());
            if !claim.key_packages.is_empty() {
                tracing::info!(%group_id, users = ?outcome.claimed, "adding pending invitees");
                if let Err(err) = self
                    .commit(session, group_id, CommitOp::Add(claim.key_packages))
                    .await
                {
                    // A commit of unknown outcome stays pending with them;
                    // otherwise claim them again later.
                    if !matches!(&err, ClientError::Transport(e) if crate::client::outcome_unknown(e))
                    {
                        let claimed: Vec<UserId> = outcome.claimed.iter().cloned().collect();
                        self.restore_invites(group_id, &claimed, now);
                    }
                    self.fail_invites(session, group_id, outcome.failed).await?;
                    return Err(err);
                }
            }
        }
        self.fail_invites(session, group_id, std::mem::take(&mut outcome.failed))
            .await?;
        Ok(Some(outcome))
    }

    /// Drops the invites and surfaces each as a `Removed` membership change
    /// by this user (broadcast only, not stored).
    async fn fail_invites(
        &self,
        session: &Session,
        group_id: &GroupId,
        users: Vec<UserId>,
    ) -> Result<()> {
        if users.is_empty() {
            return Ok(());
        }
        tracing::warn!(%group_id, ?users, "pending invites failed");
        self.remove_invites(group_id, users.iter());
        let gid = group_id.clone();
        let seq = self
            .run(move |store, _| Ok(store.group_cursor(&gid)?.contiguous_seq))
            .await?;
        let now = now_ms();
        let changes: Vec<StateChange> = users
            .into_iter()
            .map(|user_id| {
                StateChange::MembershipChanged(MembershipEvent {
                    group_id: group_id.clone(),
                    seq,
                    user_id,
                    actor: session.device.user_id.clone(),
                    kind: MembershipChangeKind::Removed,
                    at_ms: now,
                })
            })
            .collect();
        self.emit(&changes);
        Ok(())
    }

    fn reschedule_invites(&self, group_id: &GroupId, users: &[UserId]) {
        let now = now_ms();
        let mut invites = self.invites();
        let Some(chat) = invites.get_mut(group_id) else {
            return;
        };
        for user_id in users {
            if let Some(invite) = chat.get_mut(user_id) {
                invite.attempts += 1;
                invite.next_attempt_ms = now + self.invite_delay(invite.attempts);
            }
        }
    }

    /// Puts claimed invitees whose commit failed back, keeping their TTL.
    fn restore_invites(&self, group_id: &GroupId, users: &[UserId], since_ms: u64) {
        let retry = now_ms() + self.invite_delay(1);
        let mut invites = self.invites();
        let chat = invites.entry(group_id.clone()).or_default();
        for user_id in users {
            chat.entry(user_id.clone()).or_insert(PendingInvite {
                since_ms,
                attempts: 1,
                next_attempt_ms: retry,
            });
        }
    }

    fn remove_invites<'a>(&self, group_id: &GroupId, users: impl Iterator<Item = &'a UserId>) {
        let mut invites = self.invites();
        if let Some(chat) = invites.get_mut(group_id) {
            for user_id in users {
                chat.remove(user_id);
            }
            if chat.is_empty() {
                invites.remove(group_id);
            }
        }
    }

    /// Delay before claim number `attempts + 1`: doubles from
    /// [`SyncSettings::invite_retry`](crate::SyncSettings::invite_retry) up
    /// to [`INVITE_RETRY_MAX`].
    fn invite_delay(&self, attempts: u32) -> u64 {
        let first = self.inner.sync_settings.invite_retry.as_millis() as u64;
        let max = INVITE_RETRY_MAX.as_millis() as u64;
        first
            .saturating_mul(1u64 << attempts.min(20))
            .min(max.max(first))
    }

    fn next_invite_due(&self) -> Option<u64> {
        let ttl = self.invite_ttl_ms();
        self.invites()
            .values()
            .flat_map(|users| users.values())
            .map(|i| i.due_ms(ttl))
            .min()
    }

    fn invite_ttl_ms(&self) -> u64 {
        self.inner.sync_settings.invite_ttl.as_millis() as u64
    }

    fn invites(&self) -> std::sync::MutexGuard<'_, PendingInvites> {
        self.inner
            .pending_invites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}
