//! Sync: fetching events after the persisted global cursor and applying
//! them in order through gim-base, with per-group seq gap backfill, Welcome
//! acknowledgement, DeviceList updates, expired cursor recovery (pending
//! Welcomes, then a resync), and the background sync loop (WebSocket stream
//! with a long-poll fallback, reconnect with backoff).
//!
//! Multi-homing (contract `multihoming.md` §6.3): every listed hub other
//! than the home hub whose URL was verified gets a loop of its own, with
//! its own cursor (event ids differ between hubs). The owner fans every
//! message out to all listed hubs, so the hubs deliver the same messages:
//! all of them feed the same application path, and gim-base applies a
//! message once per `(gid, seq)`. The owner assigns `seq` together with
//! `message_id`, so `(gid, seq)` identifies a message on every hub, and the
//! group cursors persist it as the dedup index. Welcomes are joined once
//! and acknowledged on every hub that delivers them; a 410 is recovered
//! per hub, from that hub.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use gim_base::model::{
    Chat, ChatMember, GroupMessage, IncomingEvent, Membership, MembershipChangeKind, MessageKind,
    StateChange,
};
use gim_base::{BaseClient, BaseError, StateReader, StateStore, StoreTxn};
use gim_common::{now_ms, DeviceRef, GroupId, UserId};
use gim_crypto::{inspect_handshake, CryptoError};
use tokio::sync::broadcast;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

use crate::client::Session;
use crate::hubs::{hub_urls_changed, Listed};
use crate::routing::{hub_unreachable, HubTarget};
use crate::stream::{Backoff, ConnectionState};
use crate::transport::{
    AccessToken, EventBatch, GroupInfo, HubEvent, Transport, TransportError, TransportResult,
};
use crate::{Client, ClientError, Result};

/// Shortest interval between two long-polls that returned no events.
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Messages per `group_messages` request when backfilling.
pub const BACKFILL_PAGE: u32 = 100;
/// Welcomes per `pending_welcomes` request when recovering.
const WELCOME_PAGE: u32 = 50;

/// Timing of the background sync loop ([`Client::start_sync`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSettings {
    /// First reconnect delay after a failure; doubles per failure.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// Long-poll `wait` when there is no WebSocket stream (at most 30 s).
    pub long_poll_wait: Duration,
    /// How long to long-poll before trying the WebSocket stream again once
    /// it was unavailable.
    pub stream_retry: Duration,
    /// Range of the random delay after which a member that is not the one
    /// chosen to commit a pending Proposal commits it itself, if it is still
    /// pending (the chosen member is offline).
    pub proposal_commit_delay_min: Duration,
    pub proposal_commit_delay_max: Duration,
    /// First retry delay of a pending invite (an invitee whose hub was
    /// unavailable); doubles per retry up to [`crate::INVITE_RETRY_MAX`].
    pub invite_retry: Duration,
    /// How long a pending invite is retried before it is dropped.
    pub invite_ttl: Duration,
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            long_poll_wait: Duration::from_secs(30),
            stream_retry: Duration::from_secs(300),
            proposal_commit_delay_min: Duration::from_secs(5),
            proposal_commit_delay_max: Duration::from_secs(15),
            invite_retry: Duration::from_secs(30),
            invite_ttl: Duration::from_secs(24 * 3600),
        }
    }
}

/// Result of one fetch of the event stream.
pub(crate) enum Fetched {
    Batch(EventBatch),
    /// The cursor is older than the hub's retention; `head` is where to
    /// continue after resyncing.
    Expired {
        head: u64,
    },
}

impl Fetched {
    fn from_result(result: std::result::Result<EventBatch, TransportError>) -> Result<Self> {
        match result {
            Ok(batch) => Ok(Self::Batch(batch)),
            Err(TransportError::Gone { cursor }) => Ok(Self::Expired { head: cursor }),
            Err(err) => Err(err.into()),
        }
    }
}

/// A hub the sync path reads from: the home hub (the client's transport
/// and session) or another listed hub, with this device's session there.
#[derive(Clone)]
pub(crate) struct HubLink {
    /// `None` for the home hub.
    hub_id: Option<String>,
    transport: Arc<dyn Transport>,
}

impl HubLink {
    fn is_home(&self) -> bool {
        self.hub_id.is_none()
    }

    /// For logs.
    fn name(&self) -> &str {
        self.hub_id.as_deref().unwrap_or("home")
    }
}

/// The loops of the listed hubs other than the home hub, by hub id, with
/// the URL each follows. Dropping it (the sync loop stopped) stops them.
#[derive(Default)]
struct HubLoops {
    tasks: JoinSet<()>,
    running: HashMap<String, (String, AbortHandle)>,
}

/// The best of the loops' states: `Connected` over `Syncing` over
/// `Connecting` over `Offline`.
fn best_state(states: &HashMap<Option<String>, ConnectionState>) -> ConnectionState {
    let rank = |state: &ConnectionState| match state {
        ConnectionState::Offline => 0,
        ConnectionState::Connecting => 1,
        ConnectionState::Syncing => 2,
        ConnectionState::Connected => 3,
    };
    states
        .values()
        .copied()
        .max_by_key(rank)
        .unwrap_or(ConnectionState::Offline)
}

impl<S: StateStore + 'static> Client<S> {
    /// The state of the sync loop: the best over the listed hubs it
    /// follows, so `Connected` while at least one of them is reachable.
    pub fn connection_state(&self) -> ConnectionState {
        *self
            .inner
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Every [`ConnectionState`] transition of the sync loop.
    pub fn subscribe_connection_state(&self) -> broadcast::Receiver<ConnectionState> {
        self.inner.connection_changes.subscribe()
    }

    /// Starts the background sync loop (no-op if it is running): catches up
    /// over HTTP, then follows the WebSocket stream, or long-polls where
    /// there is none. Failures are retried with exponential backoff (see
    /// [`SyncSettings`]); [`Client::network_reachable`] retries at once.
    /// Expired tokens are renewed by signing in again; the loop stops by
    /// itself only when the hub rejects the device's sign-in; see
    /// [`Client::stop_sync`]. Alongside, the user's hosting record is
    /// renewed when due: at start, daily and on `hosting_record.expiring`,
    /// and pending invites are retried (see [`Client::pending_invites`]).
    ///
    /// Fails with [`ClientError::InvalidInput`] in
    /// [`crate::ClientMode::Extension`].
    pub fn start_sync(&self) -> Result<()> {
        if self.is_extension() {
            return Err(ClientError::InvalidInput(
                "no sync loop in extension mode".into(),
            ));
        }
        let session = self.require_session()?;
        let mut task = self
            .inner
            .sync_task
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if task.as_ref().is_some_and(|t| !t.is_finished()) {
            return Ok(());
        }
        self.link_states().clear();
        let client = self.clone();
        *task = Some(tokio::spawn(async move { client.sync_loop(session).await }));
        Ok(())
    }

    /// Whether the sync loop is running: started and not stopped, by
    /// [`Client::stop_sync`] or by itself.
    pub fn is_sync_running(&self) -> bool {
        self.inner
            .sync_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|t| !t.is_finished())
    }

    /// Stops the sync loop. Returns why it stopped by itself, if it did:
    /// [`ClientError::NotRegistered`] when the hub kept rejecting the token,
    /// [`ClientError::DeviceNotActive`] when it refused the device.
    pub fn stop_sync(&self) -> Result<()> {
        let task = self
            .inner
            .sync_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let result = match task {
            // A finished task's result is ready.
            Some(task) if task.is_finished() => task.now_or_never().map_or(Ok(()), |joined| {
                joined.unwrap_or_else(|e| Err(ClientError::Task(e.to_string())))
            }),
            Some(task) => {
                task.abort();
                Ok(())
            }
            None => Ok(()),
        };
        self.link_states().clear();
        self.set_connection_state(ConnectionState::Offline);
        result
    }

    /// Fetches the pending events once (no waiting), applies them, persists
    /// the cursor and replenishes KeyPackages if the hub asked for it.
    /// Returns the applied changes, which are also broadcast (both without
    /// the self groups' changes). The other listed hubs with a verified URL
    /// are read the same way after the home hub; their failures are only
    /// logged, and a failure of the home hub is returned after them.
    pub async fn sync_once(&self) -> Result<Vec<StateChange>> {
        let session = self.require_session()?;
        let home = self.sync_hub_once(&session, &self.home_link()).await;
        let mut changes = Vec::new();
        for link in self.hub_links() {
            match self.sync_hub_once(&session, &link).await {
                Ok(applied) => changes.extend(applied),
                Err(err) => {
                    tracing::warn!(hub_id = link.name(), error = %err, "cannot sync a listed hub");
                }
            }
        }
        let mut all = home?;
        all.extend(changes);
        Ok(self.visible(all))
    }

    async fn sync_hub_once(&self, session: &Session, link: &HubLink) -> Result<Vec<StateChange>> {
        let fetched = self.fetch(link, Duration::ZERO).await?;
        self.apply_fetched(session, link, fetched).await
    }

    /// Reads the events of the listed hub `hub_id` (not the home hub) up
    /// to its head, then joins and acknowledges the Welcomes pending there:
    /// the drain check before the hub is removed. `false` if this device
    /// cannot reach the hub (not verified in this run, network, 5xx).
    pub(crate) async fn drain_hub(&self, session: &Session, hub_id: &str) -> Result<bool> {
        let Some(link) = self.hub_links().into_iter().find(|l| l.name() == hub_id) else {
            return Ok(false);
        };
        let drained = async {
            loop {
                let fetched = self.fetch(&link, Duration::ZERO).await?;
                let caught_up = matches!(&fetched, Fetched::Batch(b) if b.events.is_empty());
                self.apply_fetched(session, &link, fetched).await?;
                if caught_up {
                    break;
                }
            }
            let _guard = self.inner.group_lock.lock().await;
            self.join_pending_welcomes(session, &link).await
        }
        .await;
        match drained {
            Ok(_) => Ok(true),
            Err(ClientError::Transport(err)) if hub_unreachable(&err) => {
                tracing::warn!(%hub_id, error = %err, "cannot drain an unreachable hub");
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    /// The home hub: the client's own transport.
    pub(crate) fn home_link(&self) -> HubLink {
        HubLink {
            hub_id: None,
            transport: self.inner.transport.clone(),
        }
    }

    /// The listed hubs other than the home hub whose URL was verified in
    /// this run, by hub id.
    pub(crate) fn hub_links(&self) -> Vec<HubLink> {
        self.verified_hubs()
            .into_iter()
            .map(|(hub_id, _, transport)| HubLink {
                hub_id: Some(hub_id),
                transport,
            })
            .collect()
    }

    /// Runs `call` on the hub of `link` with a valid session token there:
    /// [`Client::authed`] on the home hub; on another hub, signs in there
    /// first if the token expired, and once more if the hub rejects it.
    pub(crate) async fn on_hub<T, F, Fut>(&self, link: &HubLink, call: F) -> TransportResult<T>
    where
        F: Fn(Arc<dyn Transport>, AccessToken) -> Fut,
        Fut: Future<Output = TransportResult<T>>,
    {
        let Some(hub_id) = &link.hub_id else {
            return self
                .authed(|token| call(link.transport.clone(), token))
                .await;
        };
        let token = self.hub_token(hub_id, None).await?;
        match call(link.transport.clone(), token.clone()).await {
            Err(TransportError::Unauthorized) => {
                let token = self.hub_token(hub_id, Some(&token)).await?;
                call(link.transport.clone(), token).await
            }
            result => result,
        }
    }

    pub(crate) fn wake_sync(&self) {
        self.inner.sync_wake.notify_one();
    }

    /// Ignored while no loop is registered, except `Offline`: a loop that
    /// was just aborted must not report a state after [`Client::stop_sync`].
    fn set_connection_state(&self, state: ConnectionState) {
        let registered = self
            .inner
            .sync_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        if !registered && state != ConnectionState::Offline {
            return;
        }
        let mut current = self
            .inner
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if *current != state {
            *current = state;
            // No subscriber is fine.
            let _ = self.inner.connection_changes.send(state);
        }
    }

    /// The sync loop of the home hub, with the loops of the other listed
    /// hubs, the hosting record renewal, the pending invite retries and
    /// the push registration alongside.
    async fn sync_loop(&self, session: Session) -> Result<()> {
        let result = tokio::select! {
            result = self.follow_events(session.clone()) => result,
            never = self.maintain_hub_loops(session) => match never {},
            never = self.maintain_hosting_record() => match never {},
            never = self.maintain_pending_invites() => match never {},
            never = self.maintain_push_registration() => match never {},
        };
        // The other hubs' loops stopped with it.
        self.link_states().clear();
        self.set_connection_state(ConnectionState::Offline);
        result
    }

    /// Keeps one loop per listed hub with a verified URL other than the
    /// home hub ([`Client::follow_hub`]): starts the loops of hubs joining
    /// the registry, stops those of hubs leaving it, and restarts a loop
    /// whose hub got another URL.
    async fn maintain_hub_loops(&self, session: Session) -> std::convert::Infallible {
        let mut loops = HubLoops::default();
        loop {
            let hubs = self.verified_hubs();
            loops.running.retain(|hub_id, (url, task)| {
                let keep = hubs.iter().any(|(id, u, _)| id == hub_id && u == url);
                if !keep {
                    tracing::info!(%hub_id, "stopping the sync of a hub");
                    task.abort();
                }
                keep
            });
            self.forget_stopped_links(&loops);
            for (hub_id, url, transport) in hubs {
                if loops.running.contains_key(&hub_id) {
                    continue;
                }
                tracing::info!(%hub_id, "starting the sync of a listed hub");
                let link = HubLink {
                    hub_id: Some(hub_id.clone()),
                    transport,
                };
                let (client, session) = (self.clone(), session.clone());
                let task = loops
                    .tasks
                    .spawn(async move { client.follow_hub(session, link).await });
                loops.running.insert(hub_id, (url, task));
            }
            tokio::select! {
                () = self.inner.hubs_changed.notified() => {}
                // Reaps stopped loops.
                Some(_) = loops.tasks.join_next() => {}
            }
        }
    }

    /// The loop of a listed hub other than the home hub: as the home loop,
    /// but it never stops by itself; any failure (also a hub refusing the
    /// session) is retried with backoff until the hub leaves the registry.
    async fn follow_hub(&self, session: Session, link: HubLink) {
        let settings = self.inner.sync_settings;
        let mut backoff = Backoff::new(settings.backoff_min, settings.backoff_max);
        let mut stream_retry_at = None;
        loop {
            let Err(err) = self
                .follow(&session, &link, &mut backoff, &mut stream_retry_at)
                .await
            else {
                continue;
            };
            stream_retry_at = None;
            self.report(&link, ConnectionState::Offline);
            let delay = backoff.next_delay();
            tracing::debug!(hub_id = link.name(), error = %err, ?delay, "hub sync failed; reconnecting");
            tokio::time::sleep(delay).await;
        }
    }

    async fn follow_events(&self, session: Session) -> Result<()> {
        let settings = self.inner.sync_settings;
        let mut backoff = Backoff::new(settings.backoff_min, settings.backoff_max);
        let mut stream_retry_at = None;
        let home = self.home_link();
        loop {
            self.report(&home, ConnectionState::Connecting);
            let Err(err) = self
                .follow(&session, &home, &mut backoff, &mut stream_retry_at)
                .await
            else {
                continue;
            };
            self.report(&home, ConnectionState::Offline);
            if let ClientError::DeviceNotActive(_) = err {
                tracing::warn!(error = %err, "sync stopped");
                return Err(err);
            }
            if matches!(err, ClientError::Transport(TransportError::Unauthorized)) {
                tracing::warn!("sign-in rejected; sync stopped");
                return Err(ClientError::NotRegistered);
            }
            // The failure may have been the network rather than a missing
            // stream: try the stream again on reconnect.
            stream_retry_at = None;
            let delay = backoff.next_delay();
            tracing::debug!(error = %err, ?delay, "sync failed; reconnecting");
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = self.inner.sync_wake.notified() => backoff.reset(),
            }
        }
    }

    /// Records the state of the loop of `link` and reports the best state
    /// of all loops: connected while at least one listed hub is reachable.
    fn report(&self, link: &HubLink, state: ConnectionState) {
        let best = {
            let mut states = self.link_states();
            states.insert(link.hub_id.clone(), state);
            best_state(&states)
        };
        self.set_connection_state(best);
    }

    /// Drops the states of the other hubs' loops that no longer run.
    fn forget_stopped_links(&self, loops: &HubLoops) {
        let best = {
            let mut states = self.link_states();
            states.retain(|hub_id, _| {
                hub_id
                    .as_ref()
                    .is_none_or(|hub_id| loops.running.contains_key(hub_id))
            });
            best_state(&states)
        };
        self.set_connection_state(best);
    }

    fn link_states(&self) -> std::sync::MutexGuard<'_, HashMap<Option<String>, ConnectionState>> {
        self.inner
            .link_states
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// One connection to the hub of `link`: catches up over HTTP, then
    /// follows the stream or long-polls. Returns `Ok` to reconnect at once
    /// (after an expired cursor, or to try the stream again).
    async fn follow(
        &self,
        session: &Session,
        link: &HubLink,
        backoff: &mut Backoff,
        stream_retry_at: &mut Option<Instant>,
    ) -> Result<()> {
        let settings = self.inner.sync_settings;
        let mut connected = false;
        loop {
            let fetched = self.fetch(link, Duration::ZERO).await?;
            if !connected {
                connected = true;
                backoff.reset();
                self.report(link, ConnectionState::Syncing);
                // A hub that missed the push registration gets it now.
                self.push_hub_changed(link.hub_id.as_deref(), false);
            }
            let caught_up = matches!(&fetched, Fetched::Batch(b) if b.events.is_empty());
            self.apply_fetched(session, link, fetched).await?;
            if caught_up {
                break;
            }
        }

        let mut stream = None;
        if stream_retry_at.is_none_or(|at| Instant::now() >= at) {
            let cursor = self.cursor(link).await?;
            match self
                .on_hub(link, |t, token| async move {
                    t.open_stream(&token, cursor).await
                })
                .await
            {
                Ok(Some(opened)) => {
                    *stream_retry_at = None;
                    stream = Some(opened);
                }
                Err(TransportError::Unauthorized) => {
                    return Err(TransportError::Unauthorized.into())
                }
                Ok(None) | Err(_) => {
                    tracing::debug!(
                        hub_id = link.name(),
                        "event stream unavailable; long-polling"
                    );
                    *stream_retry_at = Some(Instant::now() + settings.stream_retry);
                }
            }
        }
        self.report(link, ConnectionState::Connected);

        loop {
            let fetched = match stream.as_mut() {
                Some(stream) => match stream.next().await {
                    // The token expired under the open stream: sign in again
                    // and reconnect (on another hub, the next request does).
                    Err(TransportError::Unauthorized) => {
                        if link.is_home() {
                            let token = self.session().map(|s| s.token);
                            self.renew_token(token.as_ref()).await?;
                        }
                        return Ok(());
                    }
                    next => Fetched::from_result(next)?,
                },
                None => {
                    if stream_retry_at.is_some_and(|at| Instant::now() >= at) {
                        return Ok(());
                    }
                    let started = Instant::now();
                    let fetched = self.fetch(link, settings.long_poll_wait).await?;
                    if matches!(&fetched, Fetched::Batch(b) if b.events.is_empty()) {
                        // The request was not held (a transport that does
                        // not wait, or an early answer): do not spin.
                        tokio::time::sleep_until(started + MIN_POLL_INTERVAL).await;
                    }
                    fetched
                }
            };
            let expired = matches!(fetched, Fetched::Expired { .. });
            if expired {
                self.report(link, ConnectionState::Syncing);
            }
            self.apply_fetched(session, link, fetched).await?;
            if expired {
                // The stream closes after an expiry; reconnect from the head.
                return Ok(());
            }
        }
    }

    /// Fetches the events of the hub of `link` after its persisted cursor,
    /// waiting up to `wait` for the first one. Does not take the group
    /// lock.
    pub(crate) async fn fetch(&self, link: &HubLink, wait: Duration) -> Result<Fetched> {
        let cursor = self.cursor(link).await?;
        let fetched = self
            .on_hub(link, |t, token| async move {
                t.fetch_events(&token, cursor, wait).await
            })
            .await;
        Fetched::from_result(fetched)
    }

    /// The persisted event cursor on the hub of `link`: the global cursor
    /// for the home hub.
    async fn cursor(&self, link: &HubLink) -> Result<Option<u64>> {
        let hub_id = link.hub_id.clone();
        self.run(move |store, _| match hub_id {
            None => Ok(store.global_cursor()?),
            Some(hub_id) => Ok(store.hub_cursor(&hub_id)?),
        })
        .await
    }

    /// Applies fetched events under the group lock, then commits the
    /// removal of departed devices and pending Proposals, advances pending
    /// leaves, wakes the outbox (delivered receipts
    /// may have been queued), announces the own display name to the chats
    /// this device joined and resolves the profiles of new members and
    /// senders.
    /// Commits go to the home hub: from another hub's events, failing
    /// to commit is logged, so that the home hub being down does not hold
    /// back the other hubs' events.
    pub(crate) async fn apply_fetched(
        &self,
        session: &Session,
        link: &HubLink,
        fetched: Fetched,
    ) -> Result<Vec<StateChange>> {
        let guard = self.inner.group_lock.lock().await;
        let urls = self.hub_urls().await?;
        let changes = self.apply_fetched_locked(session, link, fetched).await?;
        // The app does the rest when it runs.
        if self.is_extension() {
            return Ok(changes);
        }
        let committed = match self.remove_departed(session).await {
            Ok(()) => self.commit_pending_proposals(session).await,
            err => err,
        };
        match committed {
            Err(err) if !link.is_home() => {
                tracing::debug!(hub_id = link.name(), error = %err, "cannot commit after a hub's events");
            }
            committed => committed?,
        }
        self.resume_leaves(session).await;
        drop(guard);
        if self.inner.hosting_updated.swap(false, Ordering::SeqCst) {
            self.refresh_hubs_logged(Listed::Fetch).await;
        } else if hub_urls_changed(&urls, &self.hub_urls().await?) {
            self.notify_hub_changes();
            self.refresh_hubs_logged(Listed::Stored).await;
        }
        self.wake_outbox();
        let own = &session.device.user_id;
        let joined: BTreeSet<GroupId> = self
            .visible(changes.clone())
            .into_iter()
            .filter_map(|change| match change {
                StateChange::MembershipChanged(event)
                    if &event.user_id == own && event.kind == MembershipChangeKind::Added =>
                {
                    Some(event.group_id)
                }
                _ => None,
            })
            .collect();
        for group_id in &joined {
            self.announce_profile(group_id).await;
        }
        let users = changes
            .iter()
            .flat_map(|change| match change {
                StateChange::ChatUpserted(chat) => chat
                    .members
                    .iter()
                    .map(|m| m.device.user_id.clone())
                    .collect(),
                StateChange::MessageUpserted(message) => vec![message.sender.user_id.clone()],
                _ => vec![],
            })
            .collect();
        self.resolve_users(session, users).await;
        Ok(changes)
    }

    /// [`Client::sync_once`] of the home hub for callers holding the group
    /// lock.
    pub(crate) async fn sync_locked(&self, session: &Session) -> Result<Vec<StateChange>> {
        let home = self.home_link();
        let fetched = self.fetch(&home, Duration::ZERO).await?;
        self.apply_fetched_locked(session, &home, fetched).await
    }

    async fn apply_fetched_locked(
        &self,
        session: &Session,
        link: &HubLink,
        fetched: Fetched,
    ) -> Result<Vec<StateChange>> {
        // An own commit must be merged before later commits are processed.
        // One stuck at an unreachable owning hub holds back only its group.
        let deferred = self.resolve_pending_commits_deferring(session).await?;
        match fetched {
            Fetched::Batch(batch) => {
                let events = self.defer_group_events(batch.events, &deferred).await?;
                self.apply_events_locked(session, link, events, batch.next_cursor)
                    .await
            }
            Fetched::Expired { head } => match deferred.into_values().next() {
                Some(err) => Err(err),
                None => self.recover_expired_locked(session, link, head).await,
            },
        }
    }

    /// Parks the messages of the `deferred` groups, whose own pending commit
    /// is not settled yet, and returns the other events. They are applied
    /// once the commit is merged (gim-base drains parked messages) or
    /// dropped (`Client::apply_parked`).
    async fn defer_group_events(
        &self,
        events: Vec<HubEvent>,
        deferred: &BTreeMap<GroupId, ClientError>,
    ) -> Result<Vec<HubEvent>> {
        if deferred.is_empty() {
            return Ok(events);
        }
        let (held, events): (Vec<HubEvent>, Vec<HubEvent>) = events.into_iter().partition(|e| {
            matches!(e, HubEvent::Group(IncomingEvent::Message(m)) if deferred.contains_key(&m.group_id))
        });
        if !held.is_empty() {
            tracing::debug!(
                count = held.len(),
                "holding back messages of groups with a pending commit"
            );
            self.run(move |store, _| {
                store.transaction(|txn| {
                    for event in held {
                        if let HubEvent::Group(IncomingEvent::Message(m)) = event {
                            if !txn.group_cursor(&m.group_id)?.contains(m.seq) {
                                txn.park_message(&m)?;
                            }
                        }
                    }
                    Ok(())
                })
            })
            .await?;
        }
        Ok(events)
    }

    /// Applies the group's parked messages again, e.g. after its pending
    /// commit was dropped; those still not applicable are parked again.
    pub(crate) async fn apply_parked(&self, session: &Session, group_id: &GroupId) -> Result<()> {
        let gid = group_id.clone();
        let parked = self
            .read(move |store, _| Ok(store.parked_messages(&gid)?))
            .await?;
        if parked.is_empty() {
            return Ok(());
        }
        // Applied ones are unparked by gim-base's next drain.
        let events = parked.into_iter().map(IncomingEvent::Message).collect();
        self.apply_group_events(session, &self.home_link(), events)
            .await
            .map(drop)
    }

    /// Resyncs after an expired cursor on the hub of `link`, from that
    /// hub: joins the groups of the pending Welcomes (and acknowledges
    /// them), backfills every joined chat by seq from its last contiguous
    /// seq, refreshes the known DeviceLists, surfaces the hub's groups that
    /// cannot be joined, tops up that hub's KeyPackages (a
    /// `KeyPackagesLow` may have been pruned), then continues from the head
    /// cursor. The other hubs' cursors are not touched.
    async fn recover_expired_locked(
        &self,
        session: &Session,
        link: &HubLink,
        head: u64,
    ) -> Result<Vec<StateChange>> {
        tracing::info!(
            hub_id = link.name(),
            head,
            "event cursor expired; resyncing"
        );
        let mut changes = self.join_pending_welcomes(session, link).await?;
        let revoked = self.refresh_known_device_lists(session).await?;
        self.record_revoked(session, revoked).await?;
        let chats = self
            .run(|store, _| {
                let mut chats = store.chats()?;
                for group_id in store.self_groups()? {
                    chats.extend(store.chat(&group_id)?);
                }
                Ok(chats)
            })
            .await?;
        let mut joined = BTreeSet::new();
        let mut events = Vec::new();
        for chat in chats {
            // A leaving device is still a member.
            if chat.membership == Membership::Left {
                continue;
            }
            joined.insert(chat.group_id.clone());
            let gid = chat.group_id.clone();
            let after = self
                .read(move |store, _| Ok(store.group_cursor(&gid)?.contiguous_seq))
                .await?;
            if let Some(history) = self
                .group_history_from(link, &chat.group_id, after, None)
                .await?
            {
                events.extend(history.into_iter().map(IncomingEvent::Message));
            }
        }
        let unjoined = self.unjoined_hub_groups(link, &joined).await?;
        match &link.hub_id {
            None => self.top_up_key_packages(session).await?,
            Some(hub_id) => {
                let hub = HubTarget {
                    hub_id: hub_id.clone(),
                    home: false,
                };
                self.top_up_hub(&hub).await?;
            }
        }
        changes.extend(self.apply_group_events(session, link, events).await?);
        self.set_cursor(link, head, true).await?;
        changes.extend(self.record_unjoinable(unjoined).await?);
        Ok(changes)
    }

    /// Joins the groups of every Welcome pending on the hub of `link` and
    /// acknowledges them there, page by page. Welcomes of groups already
    /// joined are acknowledged too.
    pub(crate) async fn join_pending_welcomes(
        &self,
        session: &Session,
        link: &HubLink,
    ) -> Result<Vec<StateChange>> {
        let mut changes = Vec::new();
        loop {
            let page = self
                .on_hub(link, |t, token| async move {
                    t.pending_welcomes(&token, WELCOME_PAGE).await
                })
                .await?;
            let full = page.len() == WELCOME_PAGE as usize;
            if page.is_empty() {
                break;
            }
            tracing::info!(
                hub_id = link.name(),
                count = page.len(),
                "joining pending Welcomes"
            );
            let events = page.into_iter().map(IncomingEvent::Message).collect();
            changes.extend(self.apply_group_events(session, link, events).await?);
            if !full {
                break;
            }
        }
        Ok(changes)
    }

    /// Refreshes the DeviceLists of every known user; returns the devices
    /// they newly revoke.
    async fn refresh_known_device_lists(&self, session: &Session) -> Result<Vec<DeviceRef>> {
        let own = session.device.user_id.clone();
        let users = self
            .run(move |store, _| {
                let mut users: BTreeSet<UserId> =
                    store.device_lists()?.into_iter().map(|(u, _)| u).collect();
                for chat in store.chats()? {
                    users.extend(chat.members.into_iter().map(|m| m.device.user_id));
                }
                users.insert(own);
                Ok(users)
            })
            .await?;
        let mut revoked = Vec::new();
        for user_id in users {
            revoked.extend(self.refresh_device_list(&user_id).await?);
        }
        Ok(revoked)
    }

    /// The groups of this device on the hub of `link` that are not joined
    /// here. Empty if the hub cannot list them; network and auth errors are
    /// returned.
    async fn unjoined_hub_groups(
        &self,
        link: &HubLink,
        joined: &BTreeSet<GroupId>,
    ) -> Result<Vec<GroupInfo>> {
        match self
            .on_hub(link, |t, token| async move { t.list_groups(&token).await })
            .await
        {
            Ok(groups) => Ok(groups
                .into_iter()
                .filter(|g| !joined.contains(&g.group_id))
                .collect()),
            Err(err @ (TransportError::Network(_) | TransportError::Unauthorized)) => {
                Err(err.into())
            }
            Err(err) => {
                tracing::warn!(error = %err, "cannot list groups");
                Ok(vec![])
            }
        }
    }

    /// Stores the groups that are still not joined and not stored as `Left`
    /// chats, so that they show as chats this device cannot read.
    async fn record_unjoinable(&self, groups: Vec<GroupInfo>) -> Result<Vec<StateChange>> {
        let changes = self
            .run(move |store, _| {
                store.transaction(|txn| {
                    let mut changes = Vec::new();
                    for info in groups {
                        if txn.chat(&info.group_id)?.is_some() {
                            continue;
                        }
                        tracing::warn!(group_id = %info.group_id, "no usable Welcome for a group of this device; stored as left");
                        let mut chat = Chat::new(info.group_id, info.kind, now_ms());
                        chat.membership = Membership::Left;
                        chat.members = info
                            .members
                            .into_iter()
                            .map(|device| ChatMember {
                                device,
                                display_name: None,
                            })
                            .collect();
                        txn.upsert_chat(&chat)?;
                        changes.push(StateChange::ChatUpserted(chat));
                    }
                    Ok(changes)
                })
            })
            .await?;
        self.emit(&changes);
        Ok(changes)
    }

    /// Tops the home hub's one-time KeyPackages up to
    /// [`crate::KEY_PACKAGE_BATCH`], plus a last-resort one if it has none.
    async fn top_up_key_packages(&self, _session: &Session) -> Result<()> {
        self.top_up_hub(&self.home_target()).await
    }

    /// Applies a batch of events of the hub of `link`: DeviceList updates
    /// first (a device revoked in the latest list is rejected as a sender,
    /// whatever the event order), then the group events; then persists
    /// `next_cursor` (only forward) as that hub's cursor. Every hub
    /// delivers the same DeviceList and hosting record events; applying
    /// them again changes nothing.
    async fn apply_events_locked(
        &self,
        session: &Session,
        link: &HubLink,
        events: Vec<HubEvent>,
        next_cursor: u64,
    ) -> Result<Vec<StateChange>> {
        let mut revoked = Vec::new();
        let mut group_events = Vec::with_capacity(events.len());
        for event in events {
            match event {
                HubEvent::Group(event) => group_events.push(event),
                HubEvent::DeviceListUpdated {
                    user_id,
                    device_list,
                } => match self.accept_device_list(&user_id, &device_list).await {
                    Ok(newly) => revoked.extend(newly),
                    Err(ClientError::Identity(reason)) => {
                        tracing::warn!(%user_id, %reason, "ignoring a device list update");
                    }
                    Err(err) => return Err(err),
                },
                HubEvent::HostingRecordExpiring {
                    user_id,
                    expires_at_ms,
                    seq,
                } => {
                    if user_id == session.device.user_id {
                        tracing::info!(seq, expires_at_ms, "hosting record expiring; renewing");
                        self.inner.hosting_wake.notify_one();
                    }
                }
                HubEvent::HostingRecordUpdated { user_id, seq } => {
                    if user_id == session.device.user_id {
                        tracing::info!(seq, "hosting record updated; refreshing the hubs");
                        self.inner.hosting_updated.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        self.record_revoked(session, revoked).await?;
        let changes = self.apply_group_events(session, link, group_events).await?;
        self.set_cursor(link, next_cursor, false).await?;
        Ok(changes)
    }

    /// Persists the cursor on the hub of `link` (the global cursor for the
    /// home hub): only forward, unless `reset`.
    async fn set_cursor(&self, link: &HubLink, next_cursor: u64, reset: bool) -> Result<()> {
        let hub_id = link.hub_id.clone();
        self.run(move |store, _| {
            let cursor = match &hub_id {
                None => store.global_cursor()?,
                Some(hub_id) => store.hub_cursor(hub_id)?,
            };
            if reset || cursor.is_none_or(|c| next_cursor > c) {
                store.transaction(|txn| match &hub_id {
                    None => Ok(txn.set_global_cursor(next_cursor)?),
                    Some(hub_id) => Ok(txn.set_hub_cursor(hub_id, next_cursor)?),
                })?;
            }
            Ok(())
        })
        .await
    }

    /// Applies group events of the hub of `link` in order, after
    /// backfilling seq gaps and fetching the DeviceLists of the devices
    /// they refer to that are not known yet. Messages already applied from
    /// another hub change nothing (gim-base skips a `(gid, seq)` applied
    /// before). Broadcasts the changes, acknowledges the Welcomes on that
    /// hub (also those joined from another hub) and replenishes that hub's
    /// KeyPackages if it asked to.
    pub(crate) async fn apply_group_events(
        &self,
        session: &Session,
        link: &HubLink,
        events: Vec<IncomingEvent>,
    ) -> Result<Vec<StateChange>> {
        let events = self.backfill_gaps(session, link, events).await?;
        let welcomes: BTreeSet<(GroupId, u64)> = events
            .iter()
            .filter_map(|event| match event {
                IncomingEvent::Message(m)
                    if m.kind == MessageKind::Welcome && m.sender != session.device =>
                {
                    Some((m.group_id.clone(), m.seq))
                }
                _ => None,
            })
            .collect();
        let joining = self.unapplied(welcomes.clone()).await?;
        let devices = self.referenced_devices(link, &events, &joining).await?;
        let revoked = self.fetch_device_lists(devices).await?;
        self.record_revoked(session, revoked).await?;
        let mut changes = self.apply_events_fetching_lists(session, events).await?;
        self.load_own_device_list(session).await?;
        for group_id in &joining {
            changes.extend(self.sync_chat_kind(link, group_id.clone()).await?);
        }
        self.emit(&changes);
        // Applied or unusable: either way the hub need not keep them.
        let acked: BTreeSet<GroupId> = welcomes.into_iter().map(|(gid, _)| gid).collect();
        for group_id in acked {
            self.on_hub(link, |t, token| {
                let gid = group_id.clone();
                async move { t.ack_welcome(&token, &gid).await }
            })
            .await?;
        }
        if changes.contains(&StateChange::KeyPackagesLow) {
            match &link.hub_id {
                None => self.upload_key_packages(session).await?,
                // That hub only: each hub has its own KeyPackages.
                Some(hub_id) => self.replenish_hub_key_packages(hub_id).await?,
            }
        }
        Ok(changes)
    }

    /// The groups of the `welcomes` (group, seq) not applied yet: a Welcome
    /// at an applied seq was joined from another hub.
    async fn unapplied(&self, welcomes: BTreeSet<(GroupId, u64)>) -> Result<BTreeSet<GroupId>> {
        if welcomes.is_empty() {
            return Ok(BTreeSet::new());
        }
        self.run(move |store, _| {
            let mut joining = BTreeSet::new();
            for (group_id, seq) in welcomes {
                if !store.group_cursor(&group_id)?.contains(seq) {
                    joining.insert(group_id);
                }
            }
            Ok(joining)
        })
        .await
    }

    /// Loads the own DeviceList kept by gim-base (from a `self.device_list`
    /// of another own device) into the cache, if it is newer.
    async fn load_own_device_list(&self, session: &Session) -> Result<()> {
        let own = session.device.user_id.clone();
        let user_id = own.clone();
        let stored = self
            .run(move |store, _| {
                Ok(store
                    .device_lists()?
                    .into_iter()
                    .find(|(u, _)| *u == user_id)
                    .map(|(_, bytes)| bytes))
            })
            .await?;
        let Some(bytes) = stored else {
            return Ok(());
        };
        match self.accept_device_list(&own, &bytes).await {
            Ok(revoked) => self.record_revoked(session, revoked).await,
            Err(ClientError::Identity(reason)) => {
                tracing::warn!(%reason, "ignoring the stored own device list");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Applies `events` in order. Pre-fetching lists is the normal path; as
    /// a safety net, an event failing with `device_list_unknown` is rolled
    /// back, the user's DeviceList fetched and the event applied once more,
    /// skipping it as before if it fails again.
    async fn apply_events_fetching_lists(
        &self,
        session: &Session,
        events: Vec<IncomingEvent>,
    ) -> Result<Vec<StateChange>> {
        let strict = BaseClient::new(session.device.clone()).failing_on_unknown_device_lists();
        let lenient = BaseClient::new(session.device.clone());
        let mut changes = Vec::new();
        let mut events = VecDeque::from(events);
        // The first event is a retry.
        let mut retry = false;
        while !events.is_empty() {
            let (strict, lenient) = (strict.clone(), lenient.clone());
            let (applied, rest, unknown) = self
                // One event per store lock hold.
                .run(move |store, engine| {
                    let mut changes = Vec::new();
                    let base = if retry { &lenient } else { &strict };
                    if let Some(event) = events.pop_front() {
                        match base.apply(store, engine, event.clone()) {
                            Ok(applied) => changes.extend(applied),
                            Err(BaseError::Crypto(CryptoError::DeviceListUnknown { user_id })) => {
                                events.push_front(event);
                                return Ok((changes, events, Some(user_id)));
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    Ok((changes, events, None))
                })
                .await?;
            changes.extend(applied);
            events = rest;
            retry = false;
            if let Some(user_id) = unknown {
                tracing::info!(%user_id, "unknown device list; fetching it and retrying once");
                let revoked = self.refresh_device_list(&user_id).await?;
                self.record_revoked(session, revoked).await?;
                retry = true;
            }
        }
        Ok(changes)
    }

    /// Devices whose credentials applying `events` checks: senders, added
    /// devices, and the roster on the hub of `link` of each group a Welcome
    /// joins (`joining`; its ratchet tree is only readable once joined).
    async fn referenced_devices(
        &self,
        link: &HubLink,
        events: &[IncomingEvent],
        joining: &BTreeSet<GroupId>,
    ) -> Result<BTreeSet<DeviceRef>> {
        let mut devices = referenced_in(events);
        for group_id in joining {
            let info = self
                .on_hub(link, |t, token| async move {
                    t.group_info(&token, group_id).await
                })
                .await;
            match info {
                Ok(info) => devices.extend(info.members),
                Err(err @ (TransportError::Network(_) | TransportError::Unauthorized)) => {
                    return Err(err.into())
                }
                // The join fails on the unknown members instead.
                Err(err) => tracing::debug!(%group_id, error = %err, "no roster of a joined group"),
            }
        }
        Ok(devices)
    }

    /// Inserts the missing messages of joined chats before the first event
    /// that skips them: a message with a seq above the group's next one
    /// whose predecessors were neither applied, parked, nor in the batch.
    /// Holes the hub confirms as empty are marked as applied, so they are
    /// not looked up again.
    async fn backfill_gaps(
        &self,
        _session: &Session,
        link: &HubLink,
        events: Vec<IncomingEvent>,
    ) -> Result<Vec<IncomingEvent>> {
        let mut seqs: BTreeMap<GroupId, BTreeSet<u64>> = BTreeMap::new();
        for event in &events {
            if let IncomingEvent::Message(m) = event {
                seqs.entry(m.group_id.clone()).or_default().insert(m.seq);
            }
        }
        let mut backfill: HashMap<GroupId, VecDeque<GroupMessage>> = HashMap::new();
        for (group_id, seqs) in seqs {
            let gid = group_id.clone();
            let (joined, cursor, parked) = self
                .run(move |store, _| {
                    let joined = store
                        .chat(&gid)?
                        .is_some_and(|c| c.membership != Membership::Left);
                    let parked: BTreeSet<u64> = store
                        .parked_messages(&gid)?
                        .into_iter()
                        .map(|m| m.seq)
                        .collect();
                    Ok((joined, store.group_cursor(&gid)?, parked))
                })
                .await?;
            // Without a joined chat the group is being joined (Welcome):
            // nothing before the Welcome is for this device.
            let Some(&last) = seqs.last().filter(|_| joined) else {
                continue;
            };
            let missing: BTreeSet<u64> = (cursor.contiguous_seq + 1..last)
                .filter(|s| !cursor.contains(*s) && !seqs.contains(s) && !parked.contains(s))
                .collect();
            let (Some(&from), Some(&to)) = (missing.first(), missing.last()) else {
                continue;
            };
            let Some(history) = self
                .group_history_from(link, &group_id, from - 1, Some(to))
                .await?
            else {
                continue;
            };
            let found: VecDeque<GroupMessage> = history
                .into_iter()
                .filter(|m| missing.contains(&m.seq))
                .collect();
            let absent: Vec<u64> = missing
                .iter()
                .copied()
                .filter(|s| !found.iter().any(|m| m.seq == *s))
                .collect();
            tracing::debug!(%group_id, found = found.len(), absent = absent.len(), "backfilled seq gap");
            if !absent.is_empty() {
                let gid = group_id.clone();
                self.run(move |store, _| {
                    store.transaction(|txn| {
                        let mut cursor = txn.group_cursor(&gid)?;
                        for seq in absent {
                            cursor.insert(seq);
                        }
                        Ok(txn.set_group_cursor(&gid, &cursor)?)
                    })
                })
                .await?;
            }
            backfill.insert(group_id, found);
        }
        if backfill.values().all(VecDeque::is_empty) {
            return Ok(events);
        }
        let mut merged = Vec::with_capacity(events.len());
        for event in events {
            if let IncomingEvent::Message(m) = &event {
                if let Some(queue) = backfill.get_mut(&m.group_id) {
                    while queue.front().is_some_and(|b| b.seq < m.seq) {
                        merged.extend(queue.pop_front().map(IncomingEvent::Message));
                    }
                }
            }
            merged.push(event);
        }
        Ok(merged)
    }

    /// [`Client::group_history_from`] the home hub.
    pub(crate) async fn group_history(
        &self,
        _session: &Session,
        group_id: &GroupId,
        after_seq: u64,
        until: Option<u64>,
    ) -> Result<Option<Vec<GroupMessage>>> {
        self.group_history_from(&self.home_link(), group_id, after_seq, until)
            .await
    }

    /// Messages of the group after `after_seq`, up to `until` (all if
    /// `None`), from the hub of `preferred`, or else from the first other
    /// listed hub that can serve them (every listed hub keeps a replica
    /// with the same seqs). See [`Client::group_history_on`]; if no hub
    /// serves them, the preferred hub's result is returned.
    pub(crate) async fn group_history_from(
        &self,
        preferred: &HubLink,
        group_id: &GroupId,
        after_seq: u64,
        until: Option<u64>,
    ) -> Result<Option<Vec<GroupMessage>>> {
        let first = self
            .group_history_on(preferred, group_id, after_seq, until)
            .await;
        if matches!(first, Ok(Some(_))) {
            return first;
        }
        let others = std::iter::once(self.home_link())
            .chain(self.hub_links())
            .filter(|link| link.hub_id != preferred.hub_id);
        for link in others {
            match self
                .group_history_on(&link, group_id, after_seq, until)
                .await
            {
                Ok(Some(messages)) => {
                    tracing::debug!(%group_id, from = preferred.name(), to = link.name(), "read group history from another hub");
                    return Ok(Some(messages));
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::debug!(%group_id, hub_id = link.name(), error = %err, "cannot read group history");
                }
            }
        }
        first
    }

    /// Messages of the group after `after_seq`, up to `until` (all if
    /// `None`), paging through the history on the hub of `link`. `None` if
    /// the group's history cannot be read (e.g. this device was removed):
    /// network and auth errors are returned, anything else skips the
    /// group, whose holes are then looked up again on its next message.
    async fn group_history_on(
        &self,
        link: &HubLink,
        group_id: &GroupId,
        mut after_seq: u64,
        until: Option<u64>,
    ) -> Result<Option<Vec<GroupMessage>>> {
        let mut messages = Vec::new();
        loop {
            let from_seq = after_seq + 1;
            let fetched = self
                .on_hub(link, |t, token| async move {
                    t.group_messages(&token, group_id, from_seq, BACKFILL_PAGE)
                        .await
                })
                .await;
            let page = match fetched {
                Ok(page) => page,
                Err(err @ (TransportError::Network(_) | TransportError::Unauthorized)) => {
                    return Err(err.into())
                }
                Err(err) => {
                    tracing::debug!(%group_id, error = %err, "cannot read group history");
                    return Ok(None);
                }
            };
            let Some(last) = page.last().map(|m| m.seq) else {
                break;
            };
            messages.extend(page);
            if last <= after_seq || until.is_some_and(|u| last >= u) {
                break;
            }
            after_seq = last;
        }
        Ok(Some(messages))
    }
}

/// Users whose DeviceList validating `events` needs: message senders and
/// the users of the devices a Commit adds.
fn referenced_in(events: &[IncomingEvent]) -> BTreeSet<DeviceRef> {
    let mut devices = BTreeSet::new();
    for event in events {
        match event {
            IncomingEvent::Message(m) => {
                devices.insert(m.sender.clone());
                if m.kind == MessageKind::Commit {
                    if let Ok(info) = inspect_handshake(&m.payload) {
                        devices.extend(info.added);
                    }
                }
            }
            IncomingEvent::MemberAdded { device, .. } => {
                devices.insert(device.clone());
            }
            IncomingEvent::MemberRemoved { .. } | IncomingEvent::KeyPackagesLow => {}
        }
    }
    devices
}
