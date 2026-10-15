//! Outbox state machine. Every send gets a message id that doubles as the
//! gim-server `client_id`, so retries are idempotent.
//!
//! Message send state: `Pending → Sent → Delivered → Read`, or `Failed`
//! after [`MAX_SEND_ATTEMPTS`] failed attempts or a permanent error. The
//! outbox entry lives while the message is `Pending` or `Failed`.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use gim_common::{GroupId, MessageId};
use gim_crypto::{encrypt_envelope, MlsEngine};
use gim_proto::envelope::{self, Content, Envelope, MediaInfo, ReceiptKind};

use crate::client::load_chat;
use crate::model::{
    Membership, Message, MessageContent, OutboxEntry, OutboxKind, OutboxState, PendingMedia,
    PreparedPayload, SendState, StateChange,
};
use crate::{BaseClient, BaseError, Result, StateReader, StateStore, StoreTxn};

/// Failed attempts after which an entry becomes `Failed`.
pub const MAX_SEND_ATTEMPTS: u32 = 8;
/// Retry delay after the first failure.
pub const INITIAL_RETRY_DELAY_MS: u64 = 1_000;
/// Upper bound of the retry delay.
pub const MAX_RETRY_DELAY_MS: u64 = 300_000;

/// Delay before the next attempt after `attempts` failures: exponential from
/// [`INITIAL_RETRY_DELAY_MS`] up to [`MAX_RETRY_DELAY_MS`], minus up to 25%
/// jitter derived from the message id so retries of different messages
/// spread out.
pub fn retry_delay_ms(message_id: &MessageId, attempts: u32) -> u64 {
    let exponent = attempts.saturating_sub(1).min(20);
    let base = (INITIAL_RETRY_DELAY_MS << exponent).min(MAX_RETRY_DELAY_MS);
    let mut hasher = DefaultHasher::new();
    (message_id, attempts).hash(&mut hasher);
    base - hasher.finish() % (base / 4 + 1)
}

/// A random 128-bit message id in lowercase hex.
pub fn new_message_id() -> Result<MessageId> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| BaseError::Random(e.to_string()))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(MessageId::new(hex).expect("32 hex digits are a valid id"))
}

fn not_found(message_id: &MessageId) -> BaseError {
    BaseError::NotFound(format!("outbox entry {message_id}"))
}

impl BaseClient {
    /// Queues an envelope for sending and applies it locally right away
    /// (text and media get a `Pending` message row; edits, deletes,
    /// reactions and group info update their target). Returns the message
    /// id, which is also the `client_id`.
    pub fn enqueue<S: StateStore>(
        &self,
        store: &S,
        group_id: &GroupId,
        content: Content,
        reply_to: Option<MessageId>,
        now_ms: u64,
    ) -> Result<(MessageId, Vec<StateChange>)> {
        let message_id = new_message_id()?;
        let envelope = Envelope {
            reply_to,
            ..Envelope::new(message_id.clone(), now_ms, content)
        };
        envelope::encode(&envelope)?;
        store.transaction(|txn| {
            self.check_joined(txn, group_id)?;
            let mut changes = Vec::new();
            self.apply_envelope(
                txn,
                group_id,
                None,
                &self.own,
                envelope.clone(),
                now_ms,
                &mut changes,
            )?;
            txn.upsert_outbox(&new_entry(
                message_id.clone(),
                group_id,
                OutboxKind::Envelope(envelope),
                now_ms,
            ))?;
            Ok((message_id, changes))
        })
    }

    /// Queues a media message whose file still has to be encrypted and
    /// uploaded; see [`BaseClient::complete_media_upload`].
    pub fn enqueue_media<S: StateStore>(
        &self,
        store: &S,
        group_id: &GroupId,
        media: PendingMedia,
        reply_to: Option<MessageId>,
        now_ms: u64,
    ) -> Result<(MessageId, Vec<StateChange>)> {
        let message_id = new_message_id()?;
        store.transaction(|txn| {
            self.check_joined(txn, group_id)?;
            let mut changes = Vec::new();
            let message = Message {
                message_id: message_id.clone(),
                group_id: group_id.clone(),
                seq: None,
                sender: self.own.clone(),
                sent_at_ms: now_ms,
                content: MessageContent::PendingMedia(media.clone()),
                reply_to,
                edited: false,
                deleted: false,
                reactions: Default::default(),
                send_state: None,
                receipts: Default::default(),
            };
            self.insert_message(txn, message, now_ms, &mut changes)?;
            txn.upsert_outbox(&new_entry(
                message_id.clone(),
                group_id,
                OutboxKind::MediaUpload(media),
                now_ms,
            ))?;
            Ok((message_id, changes))
        })
    }

    /// Records the uploaded blob of a queued media message; the entry is
    /// then sent like any envelope.
    pub fn complete_media_upload<S: StateStore>(
        &self,
        store: &S,
        message_id: &MessageId,
        media: MediaInfo,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let mut entry = txn
                .outbox_entry(message_id)?
                .ok_or_else(|| not_found(message_id))?;
            let OutboxKind::MediaUpload(pending) = &entry.kind else {
                return Err(BaseError::InvalidState(format!(
                    "{message_id} is not a media upload"
                )));
            };
            let mut message = txn
                .message(message_id)?
                .ok_or_else(|| BaseError::NotFound(format!("message {message_id}")))?;
            // The caption may have been edited while uploading.
            let caption = match &message.content {
                MessageContent::PendingMedia(p) => p.caption.clone(),
                _ => pending.caption.clone(),
            };
            let envelope = Envelope {
                reply_to: message.reply_to.clone(),
                ..Envelope::new(
                    message_id.clone(),
                    message.sent_at_ms,
                    Content::Media {
                        media: media.clone(),
                        caption: caption.clone(),
                    },
                )
            };
            entry.kind = OutboxKind::Envelope(envelope);
            message.content = MessageContent::Media { media, caption };
            txn.upsert_outbox(&entry)?;
            txn.upsert_message(&message)?;
            Ok(vec![StateChange::MessageUpserted(message)])
        })
    }

    /// Returns the MLS ciphertext to post for a pending entry, encrypting at
    /// the group's current epoch. A payload prepared at an older epoch is
    /// re-encrypted; one prepared at the current epoch is reused.
    pub fn prepare<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        message_id: &MessageId,
    ) -> Result<PreparedPayload> {
        store.transaction(|txn| {
            let mut entry = txn
                .outbox_entry(message_id)?
                .ok_or_else(|| not_found(message_id))?;
            if entry.state != OutboxState::Pending {
                return Err(BaseError::InvalidState(format!("{message_id} has failed")));
            }
            let OutboxKind::Envelope(envelope) = entry.kind.clone() else {
                return Err(BaseError::InvalidState(format!(
                    "{message_id} media is not uploaded"
                )));
            };
            let epoch = engine.group_epoch(&*txn, &entry.group_id)?;
            if let Some(prepared) = &entry.prepared {
                if prepared.epoch == epoch {
                    return Ok(prepared.clone());
                }
            }
            let prepared = PreparedPayload {
                epoch,
                payload: encrypt_envelope(engine, &*txn, &entry.group_id, &envelope)?,
            };
            entry.prepared = Some(prepared.clone());
            txn.upsert_outbox(&entry)?;
            Ok(prepared)
        })
    }

    /// gim-server accepted the message at `seq`. Idempotent; also applied
    /// when the own echo arrives first.
    pub fn mark_sent<S: StateStore>(
        &self,
        store: &S,
        message_id: &MessageId,
        seq: u64,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let mut changes = Vec::new();
            self.mark_sent_in(txn, message_id, seq, &mut changes)?;
            Ok(changes)
        })
    }

    /// Records a failed attempt. Retryable failures are scheduled with
    /// [`retry_delay_ms`] until [`MAX_SEND_ATTEMPTS`]; then, or for a
    /// permanent failure, the entry and its message become `Failed`.
    pub fn mark_failed<S: StateStore>(
        &self,
        store: &S,
        message_id: &MessageId,
        error: &str,
        retryable: bool,
        now_ms: u64,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let mut entry = txn
                .outbox_entry(message_id)?
                .ok_or_else(|| not_found(message_id))?;
            entry.attempts += 1;
            entry.last_error = Some(error.to_string());
            let mut changes = Vec::new();
            if retryable && entry.attempts < MAX_SEND_ATTEMPTS {
                entry.next_attempt_at_ms = now_ms + retry_delay_ms(message_id, entry.attempts);
            } else {
                entry.state = OutboxState::Failed;
                set_send_state(
                    txn,
                    message_id,
                    SendState::Pending,
                    SendState::Failed,
                    &mut changes,
                )?;
            }
            txn.upsert_outbox(&entry)?;
            Ok(changes)
        })
    }

    /// Manual retry: resets the attempt count and makes the entry due now.
    pub fn retry<S: StateStore>(
        &self,
        store: &S,
        message_id: &MessageId,
        now_ms: u64,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let mut entry = txn
                .outbox_entry(message_id)?
                .ok_or_else(|| not_found(message_id))?;
            entry.state = OutboxState::Pending;
            entry.attempts = 0;
            entry.next_attempt_at_ms = now_ms;
            entry.last_error = None;
            txn.upsert_outbox(&entry)?;
            let mut changes = Vec::new();
            set_send_state(
                txn,
                message_id,
                SendState::Failed,
                SendState::Pending,
                &mut changes,
            )?;
            Ok(changes)
        })
    }

    /// Drops an unsent entry and its message row. A payload that was already
    /// posted may still be delivered.
    pub fn cancel<S: StateStore>(
        &self,
        store: &S,
        message_id: &MessageId,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let entry = txn
                .outbox_entry(message_id)?
                .ok_or_else(|| not_found(message_id))?;
            txn.remove_outbox(message_id)?;
            let mut changes = Vec::new();
            if txn.message(message_id)?.is_some() {
                txn.remove_message(message_id)?;
                let group_id = entry.group_id;
                let mut chat = load_chat(txn, &group_id, entry.created_at_ms)?;
                if chat.last_message_id.as_ref() == Some(message_id) {
                    chat.last_message_id = txn
                        .messages(&group_id, None, 1)?
                        .pop()
                        .map(|m| m.message_id);
                    txn.upsert_chat(&chat)?;
                    changes.push(StateChange::ChatUpserted(chat));
                }
                changes.push(StateChange::MessageRemoved {
                    group_id,
                    message_id: message_id.clone(),
                });
            }
            Ok(changes)
        })
    }

    /// Queues a receipt, merging it into a not yet prepared receipt of the
    /// same kind for the group if there is one.
    pub(crate) fn enqueue_receipt<T: StoreTxn>(
        &self,
        txn: &mut T,
        group_id: &GroupId,
        kind: ReceiptKind,
        ids: Vec<MessageId>,
        now_ms: u64,
    ) -> Result<MessageId> {
        for mut entry in txn.outbox_entries()? {
            if &entry.group_id != group_id
                || entry.state != OutboxState::Pending
                || entry.prepared.is_some()
            {
                continue;
            }
            if let OutboxKind::Envelope(Envelope {
                content:
                    Content::Receipt {
                        kind: pending_kind,
                        message_ids,
                    },
                ..
            }) = &mut entry.kind
            {
                if *pending_kind == kind {
                    for id in ids {
                        if !message_ids.contains(&id) {
                            message_ids.push(id);
                        }
                    }
                    txn.upsert_outbox(&entry)?;
                    return Ok(entry.message_id);
                }
            }
        }
        let message_id = new_message_id()?;
        let envelope = Envelope::new(
            message_id.clone(),
            now_ms,
            Content::Receipt {
                kind,
                message_ids: ids,
            },
        );
        txn.upsert_outbox(&new_entry(
            message_id.clone(),
            group_id,
            OutboxKind::Envelope(envelope),
            now_ms,
        ))?;
        Ok(message_id)
    }

    fn check_joined<T: StoreTxn>(&self, txn: &T, group_id: &GroupId) -> Result<()> {
        match txn.chat(group_id)? {
            None => Err(BaseError::NotFound(format!("chat {group_id}"))),
            Some(chat) if chat.membership == Membership::Left => {
                Err(BaseError::InvalidState(format!("left chat {group_id}")))
            }
            Some(_) => Ok(()),
        }
    }
}

fn new_entry(
    message_id: MessageId,
    group_id: &GroupId,
    kind: OutboxKind,
    now_ms: u64,
) -> OutboxEntry {
    OutboxEntry {
        message_id,
        group_id: group_id.clone(),
        kind,
        state: OutboxState::Pending,
        attempts: 0,
        next_attempt_at_ms: now_ms,
        last_error: None,
        prepared: None,
        created_at_ms: now_ms,
    }
}

fn set_send_state<T: StoreTxn>(
    txn: &mut T,
    message_id: &MessageId,
    from: SendState,
    to: SendState,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if let Some(mut message) = txn.message(message_id)? {
        if message.send_state == Some(from) {
            message.send_state = Some(to);
            txn.upsert_message(&message)?;
            changes.push(StateChange::MessageUpserted(message));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_grows_and_is_capped() {
        let id = new_message_id().unwrap();
        let mut previous_max = 0;
        for attempts in 1..=MAX_SEND_ATTEMPTS + 20 {
            let exponent = attempts.saturating_sub(1).min(20);
            let base = (INITIAL_RETRY_DELAY_MS << exponent).min(MAX_RETRY_DELAY_MS);
            let delay = retry_delay_ms(&id, attempts);
            assert!(
                delay <= base && delay >= base - base / 4,
                "{attempts}: {delay}"
            );
            assert!(base >= previous_max);
            previous_max = base;
        }
        assert_eq!(previous_max, MAX_RETRY_DELAY_MS);
        let first = retry_delay_ms(&id, 1);
        assert!((750..=1_000).contains(&first));
    }

    #[test]
    fn message_ids_are_unique_hex() {
        let a = new_message_id().unwrap();
        let b = new_message_id().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 32);
        assert!(a.as_str().bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
