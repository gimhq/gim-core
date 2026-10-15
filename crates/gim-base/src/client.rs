//! Event processing: turns stream events into state rows inside one store
//! transaction per event, MLS state included.

use std::collections::{BTreeMap, BTreeSet};

use gim_common::{now_ms, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{decrypt_to_envelope, CryptoError, DecryptedMessage, MlsEngine, ProcessedMessage};
use gim_proto::envelope::{Content, Envelope, ReceiptKind};

use crate::model::{
    to_message_id, Chat, ChatKind, ChatMember, DepartedMember, GroupMessage, IncomingEvent,
    Membership, MembershipChangeKind, MembershipEvent, Message, MessageContent, MessageKind,
    PendingCommit, SendState, StateChange,
};
use crate::{Result, StateReader, StateStore, StoreTxn};

/// Client state machine of one device, without networking. Every operation
/// runs in one [`StateStore::transaction`] and returns the resulting
/// [`StateChange`]s (empty if nothing changed).
#[derive(Debug, Clone)]
pub struct BaseClient {
    pub(crate) own: DeviceRef,
}

enum Outcome {
    Applied,
    /// Not processable yet (future epoch, or Welcome not applied yet).
    Parked,
}

impl BaseClient {
    pub fn new(own: DeviceRef) -> Self {
        Self { own }
    }

    pub fn own_device(&self) -> &DeviceRef {
        &self.own
    }

    /// Creates the MLS group and its chat. Members are added afterwards with
    /// [`MlsEngine::add_members`] and [`BaseClient::merge_own_commit`].
    pub fn create_chat<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
        kind: ChatKind,
        name: Option<String>,
        now_ms: u64,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            engine.create_group(&*txn, group_id)?;
            let mut chat = Chat::new(group_id.clone(), kind, now_ms);
            chat.name = name;
            chat.members = chat_members(txn, &engine.group_members(&*txn, group_id)?)?;
            txn.upsert_chat(&chat)?;
            Ok(vec![StateChange::ChatUpserted(chat)])
        })
    }

    /// Merges this device's pending commit after the hub accepted it at
    /// `seq`, deletes the persisted [`crate::model::PendingCommit`] and
    /// updates the chat members.
    pub fn merge_own_commit<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
        seq: u64,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            engine.merge_pending_commit(&*txn, group_id)?;
            txn.remove_pending_commit(group_id)?;
            let mut changes = Vec::new();
            let own_user = self.own.user_id.clone();
            self.update_membership(txn, engine, group_id, seq, &own_user, None, &mut changes)?;
            mark_applied(txn, group_id, seq)?;
            self.drain_parked(txn, engine, group_id, &mut changes)?;
            Ok(changes)
        })
    }

    /// Deletes the chat, its messages and outbox entries, and the local MLS
    /// group.
    pub fn forget_chat<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            if engine.has_group(&*txn, group_id)? {
                engine.delete_group(&*txn, group_id)?;
            }
            txn.remove_chat(group_id)?;
            Ok(vec![StateChange::ChatRemoved(group_id.clone())])
        })
    }

    /// Records that this device left the group, after it left the group's
    /// fan-out list: deletes the local MLS group, marks the chat `Left` and
    /// records the own user's `Left` membership event, like other members
    /// record it from the removal commit. This device never sees that
    /// commit, so the event takes the seq after the last one applied here.
    /// A chat that is not joined only loses its MLS group.
    pub fn leave_chat<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            if engine.has_group(&*txn, group_id)? {
                engine.delete_group(&*txn, group_id)?;
            }
            let Some(mut chat) = txn.chat(group_id)? else {
                return Ok(vec![]);
            };
            if chat.membership != Membership::Joined {
                return Ok(vec![]);
            }
            let cursor = txn.group_cursor(group_id)?;
            let applied = cursor
                .ahead
                .last()
                .copied()
                .unwrap_or(cursor.contiguous_seq);
            chat.membership = Membership::Left;
            chat.updated_at_ms = chat.updated_at_ms.max(now_ms);
            let event = MembershipEvent {
                group_id: group_id.clone(),
                seq: applied.max(chat.last_seq) + 1,
                user_id: self.own.user_id.clone(),
                actor: self.own.user_id.clone(),
                kind: MembershipChangeKind::Left,
                at_ms: now_ms,
            };
            txn.upsert_chat(&chat)?;
            txn.add_membership_event(&event)?;
            Ok(vec![
                StateChange::ChatUpserted(chat),
                StateChange::MembershipChanged(event),
            ])
        })
    }

    /// Reconciles MLS pending commits with the persisted
    /// [`crate::model::PendingCommit`] records; run at startup before any
    /// group work. An MLS pending commit without a record can never be
    /// posted and is cleared; a record whose MLS group has no pending commit
    /// can never be merged and is dropped. Idempotent; returns the groups
    /// that were repaired.
    pub fn reconcile_pending_commits<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
    ) -> Result<Vec<GroupId>> {
        let records: BTreeMap<GroupId, PendingCommit> = store
            .pending_commits()?
            .into_iter()
            .map(|c| (c.group_id.clone(), c))
            .collect();
        let groups = store.transaction(|txn| Ok(engine.group_ids(&*txn)?))?;
        let mut repaired = Vec::new();
        for group_id in &groups {
            let dangling = match records.get(group_id) {
                Some(_) => {
                    let dangling = !has_mls_pending_commit(store, engine, group_id)?;
                    if dangling {
                        store.transaction(|txn| Ok(txn.remove_pending_commit(group_id)?))?;
                    }
                    dangling
                }
                None => {
                    store.transaction(|txn| match engine.clear_pending_commit(&*txn, group_id) {
                        Ok(()) => Ok(true),
                        Err(CryptoError::NoPendingCommit) => Ok(false),
                        Err(err) => Err(err.into()),
                    })?
                }
            };
            if dangling {
                repaired.push(group_id.clone());
            }
        }
        for group_id in records.into_keys() {
            if !groups.contains(&group_id) {
                store.transaction(|txn| Ok(txn.remove_pending_commit(&group_id)?))?;
                repaired.push(group_id);
            }
        }
        Ok(repaired)
    }

    /// Applies one stream event in one transaction.
    ///
    /// Idempotent: a message whose (group, seq) was already applied, or whose
    /// envelope message id is already stored, changes nothing. Messages that
    /// cannot be processed yet (future epoch, or before the Welcome) are
    /// parked and retried after the next commit or Welcome of the group.
    /// Undecryptable or malformed messages are skipped. Store errors roll
    /// everything back, MLS state included.
    pub fn apply<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        event: IncomingEvent,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let mut changes = Vec::new();
            match event {
                IncomingEvent::Message(message) => {
                    self.apply_message(txn, engine, message, &mut changes)?
                }
                // Membership comes from MLS commits and Welcomes.
                IncomingEvent::MemberAdded { .. } => {}
                IncomingEvent::MemberRemoved { group_id, device } => {
                    if device != self.own {
                        // Normally removed by the commit already applied;
                        // a hub-side removal leaves it in the MLS tree.
                        if engine.has_group(&*txn, &group_id)?
                            && engine.group_members(&*txn, &group_id)?.contains(&device)
                        {
                            txn.add_departed_member(&DepartedMember { group_id, device })?;
                        }
                    } else if let Some(mut chat) = txn.chat(&group_id)? {
                        if chat.membership == Membership::Joined {
                            chat.membership = Membership::Left;
                            txn.upsert_chat(&chat)?;
                            changes.push(StateChange::ChatUpserted(chat));
                        }
                    }
                }
                IncomingEvent::KeyPackagesLow => changes.push(StateChange::KeyPackagesLow),
            }
            Ok(changes)
        })
    }

    /// Records the joined groups' members among `devices` (revoked in their
    /// user's DeviceList) as departed, so that a remaining member removes
    /// them by a commit.
    pub fn record_revoked<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        devices: &[DeviceRef],
    ) -> Result<()> {
        store.transaction(|txn| {
            for chat in txn.chats()? {
                let gid = &chat.group_id;
                if chat.membership != Membership::Joined || !engine.has_group(&*txn, gid)? {
                    continue;
                }
                for member in engine.group_members(&*txn, gid)? {
                    if devices.contains(&member) && member != self.own {
                        txn.add_departed_member(&DepartedMember {
                            group_id: gid.clone(),
                            device: member,
                        })?;
                    }
                }
            }
            Ok(())
        })
    }

    /// Marks the chat read up to its latest message: resets the unread count
    /// and enqueues a read receipt for the other users' messages. Returns the
    /// receipt's outbox id, if one was needed.
    pub fn mark_read<S: StateStore>(
        &self,
        store: &S,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<(Option<MessageId>, Vec<StateChange>)> {
        store.transaction(|txn| {
            let mut chat = txn
                .chat(group_id)?
                .ok_or_else(|| crate::BaseError::NotFound(format!("chat {group_id}")))?;
            let newer = txn.messages_after(group_id, chat.last_read_seq)?;
            let ids: Vec<MessageId> = newer
                .iter()
                .filter(|m| m.sender.user_id != self.own.user_id && !m.deleted)
                .map(|m| m.message_id.clone())
                .collect();
            let mut changes = Vec::new();
            let last_seq = newer.iter().filter_map(|m| m.seq).max();
            if last_seq.is_some() || chat.unread_count != 0 {
                chat.last_read_seq = last_seq.unwrap_or(chat.last_read_seq);
                chat.unread_count = 0;
                txn.upsert_chat(&chat)?;
                changes.push(StateChange::ChatUpserted(chat));
            }
            let receipt = if ids.is_empty() {
                None
            } else {
                Some(self.enqueue_receipt(txn, group_id, ReceiptKind::Read, ids, now_ms)?)
            };
            Ok((receipt, changes))
        })
    }

    fn apply_message<T: StoreTxn>(
        &self,
        txn: &mut T,
        engine: &MlsEngine,
        message: GroupMessage,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let group_id = &message.group_id;
        if txn.group_cursor(group_id)?.contains(message.seq) {
            return Ok(());
        }
        match self.process(txn, engine, &message, changes)? {
            Outcome::Parked => txn.park_message(&message)?,
            Outcome::Applied => {
                mark_applied(txn, group_id, message.seq)?;
                if message.kind != MessageKind::Application {
                    self.drain_parked(txn, engine, group_id, changes)?;
                }
            }
        }
        Ok(())
    }

    /// Retries parked messages of the group until none makes progress.
    fn drain_parked<T: StoreTxn>(
        &self,
        txn: &mut T,
        engine: &MlsEngine,
        group_id: &GroupId,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        loop {
            let mut progressed = false;
            for message in txn.parked_messages(group_id)? {
                if txn.group_cursor(group_id)?.contains(message.seq) {
                    txn.unpark_message(group_id, message.seq)?;
                    continue;
                }
                if let Outcome::Applied = self.process(txn, engine, &message, changes)? {
                    txn.unpark_message(group_id, message.seq)?;
                    mark_applied(txn, group_id, message.seq)?;
                    progressed = true;
                }
            }
            if !progressed {
                return Ok(());
            }
        }
    }

    fn process<T: StoreTxn>(
        &self,
        txn: &mut T,
        engine: &MlsEngine,
        message: &GroupMessage,
        changes: &mut Vec<StateChange>,
    ) -> Result<Outcome> {
        // OpenMLS cannot process this device's own messages: an own commit
        // was merged when the hub accepted it, an own application message
        // only confirms the send.
        if message.sender == self.own {
            if message.kind == MessageKind::Application {
                if let Some(client_id) = &message.client_id {
                    self.mark_sent_in(txn, &to_message_id(client_id), message.seq, changes)?;
                }
            }
            return Ok(Outcome::Applied);
        }
        if message.kind == MessageKind::Welcome {
            return self.process_welcome(txn, engine, message, changes);
        }
        // Not even decrypted: the hub names a sender revoked in its user's
        // latest DeviceList (gim-crypto checks the decrypted sender too).
        if message.kind == MessageKind::Application && engine.is_revoked(&message.sender) {
            return Ok(Outcome::Applied);
        }
        let group_id = &message.group_id;
        let decrypted = match decrypt_to_envelope(engine, &*txn, group_id, &message.payload) {
            Ok(decrypted) => decrypted,
            Err(CryptoError::WrongEpoch { .. }) => return Ok(Outcome::Parked),
            Err(CryptoError::UnknownGroup { .. }) => {
                return Ok(if txn.chat(group_id)?.is_none() {
                    Outcome::Parked
                } else {
                    // Left or forgotten group.
                    Outcome::Applied
                });
            }
            Err(err @ (CryptoError::Store { .. } | CryptoError::NoPendingCommit)) => {
                return Err(err.into())
            }
            // Undecryptable or malformed: skip it so it cannot block the group.
            Err(
                CryptoError::InvalidInput { .. }
                | CryptoError::Mls { .. }
                | CryptoError::InvalidCredential { .. },
            ) => return Ok(Outcome::Applied),
        };
        match decrypted {
            DecryptedMessage::Envelope {
                sender, envelope, ..
            } => self.apply_envelope(
                txn,
                group_id,
                Some(message.seq),
                &sender,
                envelope,
                now_ms(),
                changes,
            )?,
            DecryptedMessage::Handshake(ProcessedMessage::Commit {
                sender,
                removed,
                self_removed,
                ..
            }) => {
                let removed = self_removed.then_some(removed.as_slice());
                self.update_membership(
                    txn,
                    engine,
                    group_id,
                    message.seq,
                    &sender.user_id,
                    removed,
                    changes,
                )?
            }
            DecryptedMessage::Handshake(ProcessedMessage::Proposal {
                removed: Some(device),
                ..
            }) if device != self.own => {
                // A member leaving (or proposed for removal): one of the
                // others commits it.
                txn.add_departed_member(&DepartedMember {
                    group_id: group_id.clone(),
                    device,
                })?;
            }
            DecryptedMessage::Handshake(_) => {}
        }
        Ok(Outcome::Applied)
    }

    fn process_welcome<T: StoreTxn>(
        &self,
        txn: &mut T,
        engine: &MlsEngine,
        message: &GroupMessage,
        changes: &mut Vec<StateChange>,
    ) -> Result<Outcome> {
        let joined = match engine.join_from_welcome(&*txn, &message.payload) {
            Ok(joined) => joined,
            Err(err @ CryptoError::Store { .. }) => return Err(err.into()),
            // Duplicate (group already joined) or invalid Welcome.
            Err(_) => return Ok(Outcome::Applied),
        };
        let group_id = &message.group_id;
        if &joined.group_id != group_id {
            engine.delete_group(&*txn, &joined.group_id)?;
            return Ok(Outcome::Applied);
        }
        let now = now_ms();
        let mut chat = txn
            .chat(group_id)?
            .unwrap_or_else(|| Chat::new(group_id.clone(), ChatKind::Group, now));
        chat.membership = Membership::Joined;
        chat.members = chat_members(txn, &joined.members)?;
        chat.updated_at_ms = chat.updated_at_ms.max(now);
        txn.upsert_chat(&chat)?;
        changes.push(StateChange::ChatUpserted(chat));
        let event = MembershipEvent {
            group_id: group_id.clone(),
            seq: message.seq,
            user_id: self.own.user_id.clone(),
            actor: message.sender.user_id.clone(),
            kind: MembershipChangeKind::Added,
            at_ms: now,
        };
        txn.add_membership_event(&event)?;
        changes.push(StateChange::MembershipChanged(event));
        // Messages that arrived before the Welcome may be decryptable now;
        // anything older than the Welcome is not for this device.
        self.drain_parked(txn, engine, group_id, changes)?;
        let mut cursor = txn.group_cursor(group_id)?;
        cursor.advance_to(message.seq);
        txn.set_group_cursor(group_id, &cursor)?;
        Ok(Outcome::Applied)
    }

    /// Refreshes the member list after the commit of `actor` at `seq` and
    /// records the users it added or removed (`Left` for those who left the
    /// fan-out list themselves). `removed` is set when the
    /// commit removed this device; the group is gone then.
    #[allow(clippy::too_many_arguments)]
    fn update_membership<T: StoreTxn>(
        &self,
        txn: &mut T,
        engine: &MlsEngine,
        group_id: &GroupId,
        seq: u64,
        actor: &UserId,
        removed: Option<&[DeviceRef]>,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let now = now_ms();
        let mut chat = load_chat(txn, group_id, now)?;
        let users_before = member_users(&chat);
        let members = match removed {
            Some(removed) => {
                chat.membership = Membership::Left;
                chat.members.retain(|m| !removed.contains(&m.device));
                Vec::new()
            }
            None => {
                let members = engine.group_members(&*txn, group_id)?;
                chat.members = chat_members(txn, &members)?;
                members
            }
        };
        // Departed members no longer in the tree need no removal commit.
        let mut departed_users = BTreeSet::new();
        for departed in txn.departed_members()? {
            if &departed.group_id == group_id && !members.contains(&departed.device) {
                departed_users.insert(departed.device.user_id.clone());
                txn.remove_departed_member(&departed)?;
            }
        }
        chat.updated_at_ms = chat.updated_at_ms.max(now);
        let users_after = member_users(&chat);
        txn.upsert_chat(&chat)?;
        changes.push(StateChange::ChatUpserted(chat));
        let added = users_after
            .difference(&users_before)
            .map(|u| (u, MembershipChangeKind::Added));
        // A user who left the fan-out list by themselves is removed from
        // the tree by another member's commit.
        let gone = users_before.difference(&users_after).map(|u| {
            let kind = if u == actor || departed_users.contains(u) {
                MembershipChangeKind::Left
            } else {
                MembershipChangeKind::Removed
            };
            (u, kind)
        });
        for (user_id, kind) in added.chain(gone) {
            let event = MembershipEvent {
                group_id: group_id.clone(),
                seq,
                user_id: user_id.clone(),
                actor: actor.clone(),
                kind,
                at_ms: now,
            };
            txn.add_membership_event(&event)?;
            changes.push(StateChange::MembershipChanged(event));
        }
        Ok(())
    }

    /// Applies messages of the group's server history that are older than
    /// the stored timeline (gim-sdk's history backfill), in one
    /// transaction. Only application messages of other devices are
    /// decrypted: handshakes are long applied, own messages cannot be
    /// decrypted, and messages from before this device joined (or whose
    /// keys are gone) fail to decrypt and are skipped. Text and media are
    /// inserted without counting as unread; typing and group info are
    /// stale and ignored. The group cursor is not touched: these seqs were
    /// applied (or passed over) already. Idempotent through message ids.
    pub fn apply_history<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        messages: Vec<GroupMessage>,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let mut changes = Vec::new();
            for message in messages {
                if message.kind != MessageKind::Application || message.sender == self.own {
                    continue;
                }
                let group_id = &message.group_id;
                let decrypted = match decrypt_to_envelope(engine, &*txn, group_id, &message.payload)
                {
                    Ok(decrypted) => decrypted,
                    Err(err @ (CryptoError::Store { .. } | CryptoError::NoPendingCommit)) => {
                        return Err(err.into())
                    }
                    Err(_) => continue,
                };
                let DecryptedMessage::Envelope {
                    sender, envelope, ..
                } = decrypted
                else {
                    continue;
                };
                self.apply_history_envelope(
                    txn,
                    group_id,
                    message.seq,
                    &sender,
                    envelope,
                    &mut changes,
                )?;
            }
            Ok(changes)
        })
    }

    fn apply_history_envelope<T: StoreTxn>(
        &self,
        txn: &mut T,
        group_id: &GroupId,
        seq: u64,
        sender: &DeviceRef,
        envelope: Envelope,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let content = match envelope.content {
            Content::Typing { .. } | Content::GroupInfo { .. } => return Ok(()),
            Content::Text { body } => MessageContent::Text { body },
            Content::Media { media, caption } => MessageContent::Media { media, caption },
            _ => {
                return self.apply_envelope(
                    txn,
                    group_id,
                    Some(seq),
                    sender,
                    envelope,
                    now_ms(),
                    changes,
                )
            }
        };
        if txn.message(&envelope.message_id)?.is_some() {
            return Ok(());
        }
        let message = Message {
            message_id: envelope.message_id,
            group_id: group_id.clone(),
            seq: Some(seq),
            sender: sender.clone(),
            sent_at_ms: envelope.sent_at_ms,
            content,
            reply_to: envelope.reply_to,
            edited: false,
            deleted: false,
            reactions: Default::default(),
            send_state: (sender.user_id == self.own.user_id).then_some(SendState::Sent),
            receipts: Default::default(),
        };
        txn.upsert_message(&message)?;
        let mut chat = load_chat(txn, group_id, message.sent_at_ms)?;
        if seq > chat.last_seq {
            chat.last_seq = seq;
            chat.last_message_id = Some(message.message_id.clone());
            txn.upsert_chat(&chat)?;
            changes.push(StateChange::ChatUpserted(chat));
        }
        changes.push(StateChange::MessageUpserted(message));
        Ok(())
    }

    /// Folds an envelope into the state. `seq` is `None` for an envelope this
    /// device is about to send (applied locally at enqueue time, since own
    /// messages are never decrypted).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_envelope<T: StoreTxn>(
        &self,
        txn: &mut T,
        group_id: &GroupId,
        seq: Option<u64>,
        sender: &DeviceRef,
        envelope: Envelope,
        now_ms: u64,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let Envelope {
            message_id,
            sent_at_ms,
            reply_to,
            content,
            ..
        } = envelope;
        let message = |content| Message {
            message_id,
            group_id: group_id.clone(),
            seq,
            sender: sender.clone(),
            sent_at_ms,
            content,
            reply_to,
            edited: false,
            deleted: false,
            reactions: Default::default(),
            send_state: None,
            receipts: Default::default(),
        };
        match content {
            Content::Text { body } => {
                self.insert_message(txn, message(MessageContent::Text { body }), now_ms, changes)
            }
            Content::Media { media, caption } => self.insert_message(
                txn,
                message(MessageContent::Media { media, caption }),
                now_ms,
                changes,
            ),
            Content::Edit { target, new_body } => {
                self.update_target(txn, group_id, &target, sender, true, changes, |m| {
                    match &mut m.content {
                        MessageContent::Text { body } => *body = new_body,
                        MessageContent::Media { caption, .. } => *caption = Some(new_body),
                        MessageContent::PendingMedia(pending) => pending.caption = Some(new_body),
                    }
                    m.edited = true;
                })
            }
            Content::Delete { target } => {
                self.update_target(txn, group_id, &target, sender, true, changes, |m| {
                    m.deleted = true;
                    m.content = MessageContent::Text {
                        body: String::new(),
                    };
                    m.reply_to = None;
                    m.reactions.clear();
                })
            }
            Content::Reaction {
                target,
                emoji,
                remove,
            } => self.update_target(txn, group_id, &target, sender, false, changes, |m| {
                let emojis = m.reactions.entry(sender.user_id.clone()).or_default();
                if remove {
                    emojis.remove(&emoji);
                } else {
                    emojis.insert(emoji);
                }
                if emojis.is_empty() {
                    m.reactions.remove(&sender.user_id);
                }
            }),
            Content::Receipt { kind, message_ids } => {
                if sender.user_id != self.own.user_id {
                    for id in &message_ids {
                        self.apply_receipt(txn, group_id, sender, kind, id, changes)?;
                    }
                }
                Ok(())
            }
            Content::Typing { active } => {
                if seq.is_some() {
                    changes.push(StateChange::Typing {
                        group_id: group_id.clone(),
                        user_id: sender.user_id.clone(),
                        active,
                    });
                }
                Ok(())
            }
            Content::GroupInfo { name, avatar } => {
                let mut chat = load_chat(txn, group_id, now_ms)?;
                if name.is_some() {
                    chat.name = name;
                }
                if avatar.is_some() {
                    chat.avatar = avatar;
                }
                txn.upsert_chat(&chat)?;
                changes.push(StateChange::ChatUpserted(chat));
                Ok(())
            }
        }
    }

    /// Inserts a text or media message unless its id is already stored.
    pub(crate) fn insert_message<T: StoreTxn>(
        &self,
        txn: &mut T,
        mut message: Message,
        now_ms: u64,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        if txn.message(&message.message_id)?.is_some() {
            return Ok(());
        }
        let own_user = message.sender.user_id == self.own.user_id;
        if own_user {
            message.send_state = Some(if message.seq.is_some() {
                SendState::Sent
            } else {
                SendState::Pending
            });
        }
        txn.upsert_message(&message)?;
        let group_id = &message.group_id;
        let mut chat = load_chat(txn, group_id, now_ms)?;
        match message.seq {
            Some(seq) if seq < chat.last_seq => {}
            seq => {
                chat.last_seq = seq.unwrap_or(chat.last_seq);
                chat.last_message_id = Some(message.message_id.clone());
            }
        }
        chat.updated_at_ms = chat.updated_at_ms.max(message.sent_at_ms);
        if !own_user && message.seq.is_some_and(|seq| seq > chat.last_read_seq) {
            chat.unread_count += 1;
            self.enqueue_receipt(
                txn,
                group_id,
                ReceiptKind::Delivered,
                vec![message.message_id.clone()],
                now_ms,
            )?;
        }
        txn.upsert_chat(&chat)?;
        changes.push(StateChange::MessageUpserted(message));
        changes.push(StateChange::ChatUpserted(chat));
        Ok(())
    }

    /// Applies `update` to a live message of the group. With `author_only`,
    /// only the message's author (any of their devices) may change it.
    #[allow(clippy::too_many_arguments)]
    fn update_target<T: StoreTxn>(
        &self,
        txn: &mut T,
        group_id: &GroupId,
        target: &MessageId,
        sender: &DeviceRef,
        author_only: bool,
        changes: &mut Vec<StateChange>,
        update: impl FnOnce(&mut Message),
    ) -> Result<()> {
        let Some(mut message) = txn.message(target)? else {
            return Ok(());
        };
        if &message.group_id != group_id
            || message.deleted
            || (author_only && message.sender.user_id != sender.user_id)
        {
            return Ok(());
        }
        let before = message.clone();
        update(&mut message);
        if message != before {
            txn.upsert_message(&message)?;
            changes.push(StateChange::MessageUpserted(message));
        }
        Ok(())
    }

    fn apply_receipt<T: StoreTxn>(
        &self,
        txn: &mut T,
        group_id: &GroupId,
        sender: &DeviceRef,
        kind: ReceiptKind,
        target: &MessageId,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let Some(mut message) = txn.message(target)? else {
            return Ok(());
        };
        if &message.group_id != group_id || message.send_state.is_none() {
            return Ok(());
        }
        let before = message.clone();
        let best = message.receipts.entry(sender.clone()).or_insert(kind);
        if kind == ReceiptKind::Read {
            *best = ReceiptKind::Read;
        }
        if let (Some(chat), Some(current)) = (txn.chat(group_id)?, message.send_state) {
            if let Some(aggregate) = aggregate_receipts(&message, &chat, &self.own.user_id) {
                if aggregate.rank() > current.rank() {
                    message.send_state = Some(aggregate);
                }
            }
        }
        if message != before {
            txn.upsert_message(&message)?;
            changes.push(StateChange::MessageUpserted(message));
        }
        Ok(())
    }

    /// Records that the hub accepted an own message at `seq`.
    pub(crate) fn mark_sent_in<T: StoreTxn>(
        &self,
        txn: &mut T,
        message_id: &MessageId,
        seq: u64,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        if txn.outbox_entry(message_id)?.is_some() {
            txn.remove_outbox(message_id)?;
        }
        let Some(mut message) = txn.message(message_id)? else {
            return Ok(());
        };
        let before = message.clone();
        message.seq.get_or_insert(seq);
        if let Some(state) = message.send_state {
            if state.rank() < SendState::Sent.rank() {
                message.send_state = Some(SendState::Sent);
            }
        }
        if message == before {
            return Ok(());
        }
        txn.upsert_message(&message)?;
        let mut chat = load_chat(txn, &message.group_id, message.sent_at_ms)?;
        if seq >= chat.last_seq {
            chat.last_seq = seq;
            chat.last_message_id = Some(message_id.clone());
            txn.upsert_chat(&chat)?;
            changes.push(StateChange::ChatUpserted(chat));
        }
        changes.push(StateChange::MessageUpserted(message));
        Ok(())
    }
}

/// Delivered (or Read) once every device of every other user in the chat
/// reported it; `None` while some device has not.
fn aggregate_receipts(message: &Message, chat: &Chat, own_user: &UserId) -> Option<SendState> {
    let mut all_read = true;
    let mut any = false;
    for member in chat
        .members
        .iter()
        .filter(|m| &m.device.user_id != own_user)
    {
        any = true;
        match message.receipts.get(&member.device)? {
            ReceiptKind::Read => {}
            ReceiptKind::Delivered => all_read = false,
        }
    }
    any.then_some(if all_read {
        SendState::Read
    } else {
        SendState::Delivered
    })
}

/// Whether the group has an MLS pending commit. gim-crypto has no read for
/// it, so this clears it in a transaction that is then rolled back.
fn has_mls_pending_commit<S: StateStore>(
    store: &S,
    engine: &MlsEngine,
    group_id: &GroupId,
) -> Result<bool> {
    const PROBE: &str = "pending commit probe";
    let probed = store.transaction(|txn| match engine.clear_pending_commit(&*txn, group_id) {
        Ok(()) => Err(crate::BaseError::InvalidState(PROBE.into())),
        Err(CryptoError::NoPendingCommit) => Ok(false),
        Err(err) => Err(err.into()),
    });
    match probed {
        Err(crate::BaseError::InvalidState(reason)) if reason == PROBE => Ok(true),
        probed => probed,
    }
}

fn mark_applied<T: StoreTxn>(txn: &mut T, group_id: &GroupId, seq: u64) -> Result<()> {
    let mut cursor = txn.group_cursor(group_id)?;
    cursor.insert(seq);
    txn.set_group_cursor(group_id, &cursor)?;
    Ok(())
}

/// The stored chat, or a new joined group chat if there is none yet.
pub(crate) fn load_chat<T: StoreTxn>(txn: &T, group_id: &GroupId, now_ms: u64) -> Result<Chat> {
    Ok(txn
        .chat(group_id)?
        .unwrap_or_else(|| Chat::new(group_id.clone(), ChatKind::Group, now_ms)))
}

fn member_users(chat: &Chat) -> BTreeSet<UserId> {
    chat.members
        .iter()
        .map(|m| m.device.user_id.clone())
        .collect()
}

fn chat_members<T: StoreTxn>(txn: &T, devices: &[DeviceRef]) -> Result<Vec<ChatMember>> {
    devices
        .iter()
        .map(|device| {
            Ok(ChatMember {
                device: device.clone(),
                display_name: txn.user(&device.user_id)?.map(|u| u.display_name),
            })
        })
        .collect()
}
