//! Sync: fetching events after the persisted global cursor and applying
//! them in order through gim-base, with per-group seq gap backfill, Welcome
//! acknowledgement, DeviceList updates, expired cursor recovery (pending
//! Welcomes, then a resync), and the background sync loop (WebSocket stream
//! with a long-poll fallback, reconnect with backoff).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::Duration;

use futures_util::FutureExt;
use gim_base::model::{
    Chat, ChatMember, GroupMessage, IncomingEvent, Membership, MessageKind, StateChange,
};
use gim_base::{BaseClient, BaseError, StateReader, StateStore, StoreTxn};
use gim_common::{now_ms, DeviceRef, GroupId, UserId};
use gim_crypto::{inspect_handshake, CryptoError};
use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::client::Session;
use crate::stream::{Backoff, ConnectionState};
use crate::transport::{EventBatch, GroupInfo, HubEvent, TransportError};
use crate::{Client, ClientError, Result, KEY_PACKAGE_BATCH};

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
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            long_poll_wait: Duration::from_secs(30),
            stream_retry: Duration::from_secs(300),
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

impl<S: StateStore + 'static> Client<S> {
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
    /// [`Client::stop_sync`].
    pub fn start_sync(&self) -> Result<()> {
        let session = self.require_session()?;
        let mut task = self
            .inner
            .sync_task
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if task.as_ref().is_some_and(|t| !t.is_finished()) {
            return Ok(());
        }
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
        self.set_connection_state(ConnectionState::Offline);
        result
    }

    /// Fetches the pending events once (no waiting), applies them, persists
    /// the cursor and replenishes KeyPackages if the hub asked for it.
    /// Returns the applied changes, which are also broadcast.
    pub async fn sync_once(&self) -> Result<Vec<StateChange>> {
        let session = self.require_session()?;
        let fetched = self.fetch(&session, Duration::ZERO).await?;
        self.apply_fetched(&session, fetched).await
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

    async fn sync_loop(&self, session: Session) -> Result<()> {
        let settings = self.inner.sync_settings;
        let mut backoff = Backoff::new(settings.backoff_min, settings.backoff_max);
        let mut stream_retry_at = None;
        loop {
            self.set_connection_state(ConnectionState::Connecting);
            let Err(err) = self
                .follow(&session, &mut backoff, &mut stream_retry_at)
                .await
            else {
                continue;
            };
            self.set_connection_state(ConnectionState::Offline);
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

    /// One connection: catches up over HTTP, then follows the stream or
    /// long-polls. Returns `Ok` to reconnect at once (after an expired
    /// cursor, or to try the stream again).
    async fn follow(
        &self,
        session: &Session,
        backoff: &mut Backoff,
        stream_retry_at: &mut Option<Instant>,
    ) -> Result<()> {
        let settings = self.inner.sync_settings;
        let mut connected = false;
        loop {
            let fetched = self.fetch(session, Duration::ZERO).await?;
            if !connected {
                connected = true;
                backoff.reset();
                self.set_connection_state(ConnectionState::Syncing);
            }
            let caught_up = matches!(&fetched, Fetched::Batch(b) if b.events.is_empty());
            self.apply_fetched(session, fetched).await?;
            if caught_up {
                break;
            }
        }

        let mut stream = None;
        if stream_retry_at.is_none_or(|at| Instant::now() >= at) {
            let cursor = self.run(|store, _| Ok(store.global_cursor()?)).await?;
            match self
                .authed(|t| async move { self.inner.transport.open_stream(&t, cursor).await })
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
                    tracing::debug!("event stream unavailable; long-polling");
                    *stream_retry_at = Some(Instant::now() + settings.stream_retry);
                }
            }
        }
        self.set_connection_state(ConnectionState::Connected);

        loop {
            let fetched = match stream.as_mut() {
                Some(stream) => match stream.next().await {
                    // The token expired under the open stream: sign in again
                    // and reconnect.
                    Err(TransportError::Unauthorized) => {
                        let token = self.session().map(|s| s.token);
                        self.renew_token(token.as_ref()).await?;
                        return Ok(());
                    }
                    next => Fetched::from_result(next)?,
                },
                None => {
                    if stream_retry_at.is_some_and(|at| Instant::now() >= at) {
                        return Ok(());
                    }
                    let started = Instant::now();
                    let fetched = self.fetch(session, settings.long_poll_wait).await?;
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
                self.set_connection_state(ConnectionState::Syncing);
            }
            self.apply_fetched(session, fetched).await?;
            if expired {
                // The stream closes after an expiry; reconnect from the head.
                return Ok(());
            }
        }
    }

    /// Fetches the events after the persisted cursor, waiting up to `wait`
    /// for the first one. Does not take the group lock.
    pub(crate) async fn fetch(&self, _session: &Session, wait: Duration) -> Result<Fetched> {
        let cursor = self.run(|store, _| Ok(store.global_cursor()?)).await?;
        let fetched = self
            .authed(|t| async move { self.inner.transport.fetch_events(&t, cursor, wait).await })
            .await;
        Fetched::from_result(fetched)
    }

    /// Applies fetched events under the group lock, then commits the
    /// removal of departed devices, wakes the outbox (delivered receipts
    /// may have been queued) and resolves the profiles of new members and
    /// senders.
    pub(crate) async fn apply_fetched(
        &self,
        session: &Session,
        fetched: Fetched,
    ) -> Result<Vec<StateChange>> {
        let guard = self.inner.group_lock.lock().await;
        let changes = self.apply_fetched_locked(session, fetched).await?;
        self.remove_departed(session).await?;
        drop(guard);
        self.wake_outbox();
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

    /// [`Client::sync_once`] for callers holding the group lock.
    pub(crate) async fn sync_locked(&self, session: &Session) -> Result<Vec<StateChange>> {
        let fetched = self.fetch(session, Duration::ZERO).await?;
        self.apply_fetched_locked(session, fetched).await
    }

    async fn apply_fetched_locked(
        &self,
        session: &Session,
        fetched: Fetched,
    ) -> Result<Vec<StateChange>> {
        // An own commit must be merged before later commits are processed.
        self.resolve_pending_commits(session).await?;
        match fetched {
            Fetched::Batch(batch) => {
                self.apply_events_locked(session, batch.events, batch.next_cursor)
                    .await
            }
            Fetched::Expired { head } => self.recover_expired_locked(session, head).await,
        }
    }

    /// Resyncs after an expired cursor: joins the groups of the pending
    /// Welcomes (and acknowledges them), backfills every joined chat by seq
    /// from its last contiguous seq, refreshes the known DeviceLists,
    /// surfaces the hub's groups that cannot be joined, tops up KeyPackages
    /// (a `KeyPackagesLow` may have been pruned), then continues from the
    /// head cursor.
    async fn recover_expired_locked(
        &self,
        session: &Session,
        head: u64,
    ) -> Result<Vec<StateChange>> {
        tracing::info!(head, "event cursor expired; resyncing");
        let mut changes = self.join_pending_welcomes(session).await?;
        let revoked = self.refresh_known_device_lists(session).await?;
        self.record_revoked(session, revoked).await?;
        let chats = self.run(|store, _| Ok(store.chats()?)).await?;
        let mut joined = BTreeSet::new();
        let mut events = Vec::new();
        for chat in chats {
            if chat.membership != Membership::Joined {
                continue;
            }
            joined.insert(chat.group_id.clone());
            let gid = chat.group_id.clone();
            let after = self
                .run(move |store, _| Ok(store.group_cursor(&gid)?.contiguous_seq))
                .await?;
            if let Some(history) = self
                .group_history(session, &chat.group_id, after, None)
                .await?
            {
                events.extend(history.into_iter().map(IncomingEvent::Message));
            }
        }
        let unjoined = self.unjoined_hub_groups(&joined).await?;
        self.top_up_key_packages(session).await?;
        changes.extend(self.apply_group_events(session, events).await?);
        self.set_cursor(head, true).await?;
        changes.extend(self.record_unjoinable(unjoined).await?);
        Ok(changes)
    }

    /// Joins the groups of every pending Welcome and acknowledges them, page
    /// by page. Welcomes of groups already joined are acknowledged too.
    async fn join_pending_welcomes(&self, session: &Session) -> Result<Vec<StateChange>> {
        let mut changes = Vec::new();
        loop {
            let page = self
                .authed(|t| async move {
                    self.inner
                        .transport
                        .pending_welcomes(&t, WELCOME_PAGE)
                        .await
                })
                .await?;
            let full = page.len() == WELCOME_PAGE as usize;
            if page.is_empty() {
                break;
            }
            tracing::info!(count = page.len(), "joining pending Welcomes");
            let events = page.into_iter().map(IncomingEvent::Message).collect();
            changes.extend(self.apply_group_events(session, events).await?);
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

    /// The hub's groups of this device that are not joined here. Empty if
    /// the hub cannot list them; network and auth errors are returned.
    async fn unjoined_hub_groups(&self, joined: &BTreeSet<GroupId>) -> Result<Vec<GroupInfo>> {
        match self
            .authed(|t| async move { self.inner.transport.list_groups(&t).await })
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

    /// Tops the hub's one-time KeyPackages up to [`KEY_PACKAGE_BATCH`], plus
    /// a last-resort one if it has none. Uploads a batch if the hub cannot
    /// count them.
    async fn top_up_key_packages(&self, session: &Session) -> Result<()> {
        let counted = self
            .authed(|t| async move { self.inner.transport.key_package_count(&t).await })
            .await;
        let count = match counted {
            Ok(count) => count,
            Err(err @ (TransportError::Network(_) | TransportError::Unauthorized)) => {
                return Err(err.into())
            }
            Err(err) => {
                tracing::debug!(error = %err, "cannot count KeyPackages; uploading a batch");
                return self.upload_key_packages(session).await;
            }
        };
        let missing = u64::from(KEY_PACKAGE_BATCH).saturating_sub(count.available);
        let missing = u32::try_from(missing).unwrap_or(KEY_PACKAGE_BATCH);
        let last_resort = !count.has_last_resort;
        if missing == 0 && !last_resort {
            return Ok(());
        }
        tracing::info!(missing, last_resort, "topping up KeyPackages");
        let (key_packages, last_resort) = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    let last_resort = if last_resort {
                        Some(engine.generate_last_resort_key_package(&*txn)?)
                    } else {
                        None
                    };
                    Ok((engine.generate_key_packages(&*txn, missing)?, last_resort))
                })
            })
            .await?;
        let uploads = [
            (key_packages, false),
            (last_resort.into_iter().collect(), true),
        ];
        for (key_packages, last_resort) in uploads {
            if key_packages.is_empty() {
                continue;
            }
            self.authed(|t| {
                let key_packages = key_packages.clone();
                async move {
                    self.inner
                        .transport
                        .upload_key_packages(&t, key_packages, last_resort)
                        .await
                }
            })
            .await?;
        }
        Ok(())
    }

    /// Applies a batch of hub events: DeviceList updates first (a device
    /// revoked in the latest list is rejected as a sender, whatever the
    /// event order), then the group events; then persists `next_cursor`
    /// (only forward).
    async fn apply_events_locked(
        &self,
        session: &Session,
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
            }
        }
        self.record_revoked(session, revoked).await?;
        let changes = self.apply_group_events(session, group_events).await?;
        self.set_cursor(next_cursor, false).await?;
        Ok(changes)
    }

    /// Persists the global cursor: only forward, unless `reset`.
    async fn set_cursor(&self, next_cursor: u64, reset: bool) -> Result<()> {
        self.run(move |store, _| {
            let cursor = store.global_cursor()?;
            if reset || cursor.is_none_or(|c| next_cursor > c) {
                store.transaction(|txn| Ok(txn.set_global_cursor(next_cursor)?))?;
            }
            Ok(())
        })
        .await
    }

    /// Applies group events in order, after backfilling seq gaps and
    /// fetching the DeviceLists of the devices they refer to that are not
    /// known yet. Broadcasts the changes, acknowledges the applied Welcomes
    /// and replenishes KeyPackages if asked to.
    async fn apply_group_events(
        &self,
        session: &Session,
        events: Vec<IncomingEvent>,
    ) -> Result<Vec<StateChange>> {
        let events = self.backfill_gaps(session, events).await?;
        let devices = self.referenced_devices(session, &events).await?;
        let revoked = self.fetch_device_lists(devices).await?;
        self.record_revoked(session, revoked).await?;
        let joined: BTreeSet<GroupId> = events
            .iter()
            .filter_map(|event| match event {
                IncomingEvent::Message(m)
                    if m.kind == MessageKind::Welcome && m.sender != session.device =>
                {
                    Some(m.group_id.clone())
                }
                _ => None,
            })
            .collect();
        let mut changes = self.apply_events_fetching_lists(session, events).await?;
        for group_id in &joined {
            changes.extend(self.sync_chat_kind(session, group_id.clone()).await?);
        }
        self.emit(&changes);
        // Applied or unusable: either way the hub need not keep them.
        for group_id in joined {
            self.authed(|t| {
                let gid = group_id.clone();
                async move { self.inner.transport.ack_welcome(&t, &gid).await }
            })
            .await?;
        }
        if changes.contains(&StateChange::KeyPackagesLow) {
            self.upload_key_packages(session).await?;
        }
        Ok(changes)
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
                .run(move |store, engine| {
                    let mut changes = Vec::new();
                    let mut base = if retry { &lenient } else { &strict };
                    while let Some(event) = events.pop_front() {
                        match base.apply(store, engine, event.clone()) {
                            Ok(applied) => changes.extend(applied),
                            Err(BaseError::Crypto(CryptoError::DeviceListUnknown { user_id })) => {
                                events.push_front(event);
                                return Ok((changes, events, Some(user_id)));
                            }
                            Err(err) => return Err(err),
                        }
                        base = &strict;
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
    /// devices, and the hub roster of each group a Welcome joins (its
    /// ratchet tree is only readable once joined).
    async fn referenced_devices(
        &self,
        session: &Session,
        events: &[IncomingEvent],
    ) -> Result<BTreeSet<DeviceRef>> {
        let mut devices = referenced_in(events);
        let joining: BTreeSet<&GroupId> = events
            .iter()
            .filter_map(|event| match event {
                IncomingEvent::Message(m)
                    if m.kind == MessageKind::Welcome && m.sender != session.device =>
                {
                    Some(&m.group_id)
                }
                _ => None,
            })
            .collect();
        for group_id in joining {
            let info = self
                .authed(|t| async move { self.inner.transport.group_info(&t, group_id).await })
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
        session: &Session,
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
                        .is_some_and(|c| c.membership == Membership::Joined);
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
                .group_history(session, &group_id, from - 1, Some(to))
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

    /// Messages of the group after `after_seq`, up to `until` (all if
    /// `None`), paging through the hub history. `None` if the group's
    /// history cannot be read (e.g. this device was removed): network and
    /// auth errors are returned, anything else skips the group, whose holes
    /// are then looked up again on its next message.
    pub(crate) async fn group_history(
        &self,
        _session: &Session,
        group_id: &GroupId,
        mut after_seq: u64,
        until: Option<u64>,
    ) -> Result<Option<Vec<GroupMessage>>> {
        let mut messages = Vec::new();
        loop {
            let from_seq = after_seq + 1;
            let fetched = self
                .authed(|t| async move {
                    self.inner
                        .transport
                        .group_messages(&t, group_id, from_seq, BACKFILL_PAGE)
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
