//! Sync: fetching events after the persisted global cursor and applying
//! them in order through gim-base, with per-group seq gap backfill, expired
//! cursor recovery, and the background sync loop (WebSocket stream with a
//! long-poll fallback, reconnect with backoff).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::Duration;

use futures_util::FutureExt;
use gim_base::model::{GroupMessage, IncomingEvent, Membership, MessageKind, StateChange};
use gim_base::{BaseClient, StateReader, StateStore, StoreTxn};
use gim_common::{DeviceRef, GroupId};
use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::client::Session;
use crate::stream::{Backoff, ConnectionState};
use crate::transport::{EventBatch, TransportError};
use crate::{Client, ClientError, Result};

/// Messages per `group_messages` request when backfilling.
pub const BACKFILL_PAGE: u32 = 100;

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
    /// The cursor is older than the server's retention; `head` is where to
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
    /// [`SyncSettings`]); [`Client::network_reachable`] retries at once. The
    /// loop stops by itself only when the server rejects the token; see
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

    /// Stops the sync loop. Returns why it stopped by itself, if it did:
    /// [`ClientError::NotRegistered`] when the token was rejected.
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
    /// the cursor and replenishes KeyPackages if the server asked for it.
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

    /// Makes the transport resolve the devices of stored chats, which
    /// membership events refer to by device id only.
    pub(crate) async fn seed_device_directory(&self, session: &Session) -> Result<()> {
        let mut devices = self
            .run(|store, _| {
                Ok(store
                    .chats()?
                    .into_iter()
                    .flat_map(|chat| chat.members.into_iter().map(|m| m.device))
                    .collect::<BTreeSet<DeviceRef>>())
            })
            .await?;
        devices.insert(session.device.clone());
        let devices: Vec<DeviceRef> = devices.into_iter().collect();
        self.inner.transport.seed_device_directory(&devices);
        Ok(())
    }

    async fn sync_loop(&self, session: Session) -> Result<()> {
        if let Err(err) = self.seed_device_directory(&session).await {
            tracing::warn!(error = %err, "cannot seed the device directory");
        }
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
            if matches!(err, ClientError::Transport(TransportError::Unauthorized)) {
                tracing::warn!("token rejected; sync stopped");
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
                .inner
                .transport
                .open_stream(&session.token, cursor)
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
                Some(stream) => Fetched::from_result(stream.next().await)?,
                None => {
                    if stream_retry_at.is_some_and(|at| Instant::now() >= at) {
                        return Ok(());
                    }
                    self.fetch(session, settings.long_poll_wait).await?
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
    pub(crate) async fn fetch(&self, session: &Session, wait: Duration) -> Result<Fetched> {
        let cursor = self.run(|store, _| Ok(store.global_cursor()?)).await?;
        let fetched = self
            .inner
            .transport
            .fetch_events(&session.token, cursor, wait)
            .await;
        Fetched::from_result(fetched)
    }

    /// Applies fetched events under the group lock, then commits the
    /// removal of departed devices and wakes the outbox (delivered receipts
    /// may have been queued).
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
                self.apply_events_locked(session, batch.events, batch.next_cursor, false)
                    .await
            }
            Fetched::Expired { head } => self.recover_expired_locked(session, head).await,
        }
    }

    /// Resyncs after an expired cursor: backfills every joined chat by seq
    /// from its last contiguous seq, then continues from the head cursor.
    async fn recover_expired_locked(
        &self,
        session: &Session,
        head: u64,
    ) -> Result<Vec<StateChange>> {
        tracing::info!(head, "event cursor expired; backfilling joined chats");
        let chats = self.run(|store, _| Ok(store.chats()?)).await?;
        let mut events = Vec::new();
        for chat in chats {
            if chat.membership != Membership::Joined {
                continue;
            }
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
        self.apply_events_locked(session, events, head, true).await
    }

    /// Applies `events` in order, backfilling seq gaps first, then persists
    /// `next_cursor` (only forward, unless `reset`), broadcasts the changes
    /// and replenishes KeyPackages if asked to.
    async fn apply_events_locked(
        &self,
        session: &Session,
        events: Vec<IncomingEvent>,
        next_cursor: u64,
        reset: bool,
    ) -> Result<Vec<StateChange>> {
        let events = self.backfill_gaps(session, events).await?;
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
        {
            let mut departed = self.departed();
            for event in &events {
                if let IncomingEvent::MemberRemoved { group_id, device } = event {
                    if *device != session.device {
                        departed
                            .entry(group_id.clone())
                            .or_default()
                            .insert(device.clone());
                    }
                }
            }
        }
        let base = BaseClient::new(session.device.clone());
        let mut changes = self
            .run(move |store, engine| {
                let mut changes = Vec::new();
                for event in events {
                    changes.extend(base.apply(store, engine, event)?);
                }
                Ok(changes)
            })
            .await?;
        for group_id in joined {
            changes.extend(self.sync_chat_kind(session, group_id).await?);
        }
        self.run(move |store, _| {
            let cursor = store.global_cursor()?;
            if reset || cursor.is_none_or(|c| next_cursor > c) {
                store.transaction(|txn| Ok(txn.set_global_cursor(next_cursor)?))?;
            }
            Ok(())
        })
        .await?;
        self.emit(&changes);
        if changes.contains(&StateChange::KeyPackagesLow) {
            self.upload_key_packages(session).await?;
        }
        Ok(changes)
    }

    /// Inserts the missing messages of joined chats before the first event
    /// that skips them: a message with a seq above the group's next one
    /// whose predecessors were neither applied, parked, nor in the batch.
    /// Holes the server confirms as empty (e.g. Welcomes to other devices
    /// take seqs too) are marked as applied, so they are not looked up
    /// again.
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
    /// `None`), paging through the server history. `None` if the group's
    /// history cannot be read (e.g. this device was removed): network and
    /// auth errors are returned, anything else skips the group, whose holes
    /// are then looked up again on its next message.
    async fn group_history(
        &self,
        session: &Session,
        group_id: &GroupId,
        mut after_seq: u64,
        until: Option<u64>,
    ) -> Result<Option<Vec<GroupMessage>>> {
        let mut messages = Vec::new();
        loop {
            let page = match self
                .inner
                .transport
                .group_messages(&session.token, group_id, after_seq, BACKFILL_PAGE)
                .await
            {
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
