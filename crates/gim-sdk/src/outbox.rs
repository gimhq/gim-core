//! Outbox sender: posts the entries queued in the gim-base outbox, one chat
//! at a time in creation order, with the entry's message id as `client_id`
//! on every attempt (gim-server is idempotent on it).

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gim_base::model::{MessageKind, OutboxEntry, OutboxKind, OutboxState};
use gim_base::{BaseClient, BaseError, StateStore};
use gim_common::{now_ms, ClientId, MessageId};
use tokio::task::JoinHandle;

use crate::client::{outcome_unknown, Session};
use crate::transport::{OutgoingMessage, PostError};
use crate::{Client, ClientError, Result};

/// Sleep of the sender task when nothing is scheduled.
const IDLE_WAIT: Duration = Duration::from_secs(60);

/// The running outbox sender task; stops when dropped.
#[derive(Debug)]
pub struct OutboxSender {
    task: JoinHandle<()>,
}

impl Drop for OutboxSender {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl<S: StateStore + 'static> Client<S> {
    /// Starts the background sender. It runs an outbox pass when woken (by
    /// an enqueue, a sync that queued receipts, or
    /// [`Client::network_reachable`]) and when the next retry is due.
    pub fn start_outbox_sender(&self) -> OutboxSender {
        let client = self.clone();
        OutboxSender {
            task: tokio::spawn(async move {
                loop {
                    let wait = match client.flush_outbox().await {
                        Ok(Some(due_ms)) => Duration::from_millis(due_ms.saturating_sub(now_ms())),
                        Ok(None) | Err(_) => IDLE_WAIT,
                    };
                    tokio::select! {
                        () = client.inner.outbox_wake.notified() => {}
                        () = tokio::time::sleep(wait) => {}
                    }
                }
            }),
        }
    }

    /// The network is back: entries waiting for their backoff are retried
    /// on the next pass, which is started now.
    pub fn network_reachable(&self) {
        self.inner.force_flush.store(true, Ordering::SeqCst);
        self.wake_outbox();
    }

    pub(crate) fn wake_outbox(&self) {
        self.inner.outbox_wake.notify_one();
    }

    /// One outbox pass: for each chat, sends its due entries in creation
    /// order and stops at the first one that has to wait (backoff), so
    /// messages of a chat never overtake each other. Failed entries are
    /// skipped until [`Client::retry_send`]. Returns when the next waiting
    /// entry is due, if any.
    pub async fn flush_outbox(&self) -> Result<Option<u64>> {
        let session = self.require_session()?;
        let _flush = self.inner.flush_lock.lock().await;
        let force = self.inner.force_flush.swap(false, Ordering::SeqCst);
        let entries = self.run(|store, _| Ok(store.outbox_entries()?)).await?;
        let mut blocked = BTreeSet::new();
        for entry in entries {
            if entry.state != OutboxState::Pending || blocked.contains(&entry.group_id) {
                continue;
            }
            if !force && entry.next_attempt_at_ms > now_ms() {
                blocked.insert(entry.group_id);
                continue;
            }
            let group_id = entry.group_id.clone();
            if !self.send_entry(&session, entry).await? {
                blocked.insert(group_id);
            }
        }
        let entries = self.run(|store, _| Ok(store.outbox_entries()?)).await?;
        Ok(next_due(&entries))
    }

    /// Uploads (media) and posts one entry. Returns `false` if it has to be
    /// retried later.
    async fn send_entry(&self, session: &Session, entry: OutboxEntry) -> Result<bool> {
        let id = entry.message_id.clone();
        let base = BaseClient::new(session.device.clone());
        if let OutboxKind::MediaUpload(pending) = entry.kind {
            let media = match self.upload_media(session, &id, pending).await {
                Ok(media) => media,
                Err(err) => return self.record_failure(&base, &id, err).await,
            };
            let (mid, b) = (id.clone(), base.clone());
            match self
                .run(move |store, _| b.complete_media_upload(store, &mid, media))
                .await
            {
                Ok(changes) => self.emit(&changes),
                // Cancelled while uploading.
                Err(ClientError::Base(BaseError::NotFound(_))) => return Ok(true),
                Err(err) => return Err(err),
            }
        }
        let group_id = entry.group_id;
        let _guard = self.inner.group_lock.lock().await;
        // A commit of unknown outcome must be settled before encrypting.
        if let Err(err) = self.settle_commit(session, &group_id).await {
            return self.record_failure(&base, &id, err).await;
        }
        let (mid, b) = (id.clone(), base.clone());
        let prepared = match self
            .run(move |store, engine| b.prepare(store, engine, &mid))
            .await
        {
            Ok(prepared) => prepared,
            // Sent (own echo) or cancelled meanwhile.
            Err(ClientError::Base(BaseError::NotFound(_))) => return Ok(true),
            Err(err) => return self.record_failure(&base, &id, err).await,
        };
        let message = OutgoingMessage {
            client_id: ClientId::new(id.as_str()).expect("message ids are client ids"),
            epoch: prepared.epoch,
            kind: MessageKind::Application,
            payload: prepared.payload,
            recipients: vec![],
        };
        match self
            .inner
            .transport
            .post_message(&session.token, &group_id, message)
            .await
        {
            Ok(seq) => {
                self.mark_applied(&group_id, seq).await?;
                let changes = self
                    .run(move |store, _| base.mark_sent(store, &id, seq))
                    .await?;
                self.emit(&changes);
                Ok(true)
            }
            Err(PostError::Transport(err)) => self.record_failure(&base, &id, err.into()).await,
            // Not expected for application messages; the next attempt
            // re-encrypts at the then current epoch.
            Err(err @ PostError::EpochConflict { .. }) => {
                self.record_failure(&base, &id, ClientError::from(err)).await
            }
        }
    }

    /// Records a failed attempt; retryable errors get a backoff, others make
    /// the entry `Failed`. Returns whether the chat may go on.
    async fn record_failure(
        &self,
        base: &BaseClient,
        message_id: &MessageId,
        err: ClientError,
    ) -> Result<bool> {
        let retryable = match &err {
            ClientError::Transport(err) => outcome_unknown(err),
            ClientError::Base(BaseError::Store(_)) | ClientError::Task(_) => return Err(err),
            _ => false,
        };
        let (id, base, error) = (message_id.clone(), base.clone(), err.to_string());
        let changes = match self
            .run(move |store, _| base.mark_failed(store, &id, &error, retryable, now_ms()))
            .await
        {
            Ok(changes) => changes,
            Err(ClientError::Base(BaseError::NotFound(_))) => return Ok(true),
            Err(err) => return Err(err),
        };
        self.emit(&changes);
        Ok(!retryable)
    }

    /// Manually retries a `Failed` (or backing-off) message now.
    pub async fn retry_send(&self, message_id: &MessageId) -> Result<()> {
        let session = self.require_session()?;
        let (id, base) = (message_id.clone(), BaseClient::new(session.device));
        let changes = self
            .run(move |store, _| base.retry(store, &id, now_ms()))
            .await?;
        self.emit(&changes);
        self.flush_outbox().await?;
        Ok(())
    }

    /// Drops an unsent message. A payload already posted may still be
    /// delivered.
    pub async fn cancel_send(&self, message_id: &MessageId) -> Result<()> {
        let session = self.require_session()?;
        // Not in the middle of posting it.
        let _guard = self.inner.group_lock.lock().await;
        let (id, base) = (message_id.clone(), BaseClient::new(session.device));
        let changes = self.run(move |store, _| base.cancel(store, &id)).await?;
        self.emit(&changes);
        Ok(())
    }
}

/// Earliest retry time over the first pending entry of each chat.
fn next_due(entries: &[OutboxEntry]) -> Option<u64> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .filter(|e| e.state == OutboxState::Pending && seen.insert(e.group_id.clone()))
        .map(|e| e.next_attempt_at_ms)
        .min()
}
