//! Event processing: turns stream events into state rows inside one store
//! transaction per event, MLS state included.

use std::collections::{BTreeMap, BTreeSet};

use gim_common::{now_ms, ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{decrypt_to_envelope, CryptoError, DecryptedMessage, MlsEngine, ProcessedMessage};
use gim_identity::SignedDeviceList;
use gim_proto::envelope::{Contact, Content, Envelope, HubLocation, ReceiptKind};

use crate::model::{
    to_message_id, Chat, ChatKind, ChatMember, DepartedMember, GroupMessage, HubRecord, HubState,
    IncomingEvent, Membership, MembershipChangeKind, MembershipEvent, Message, MessageContent,
    MessageKind, PendingCommit, PendingLeave, SendState, StateChange, UserInfo,
};
use crate::{Result, StateReader, StateStore, StoreTxn};

/// Client state machine of one device, without networking. Every operation
/// runs in one [`StateStore::transaction`] and returns the resulting
/// [`StateChange`]s (empty if nothing changed).
#[derive(Debug, Clone)]
pub struct BaseClient {
    pub(crate) own: DeviceRef,
    /// See [`BaseClient::failing_on_unknown_device_lists`].
    fail_on_unknown_lists: bool,
}

enum Outcome {
    Applied,
    /// Not processable yet (future epoch, or Welcome not applied yet).
    Parked,
}

impl BaseClient {
    pub fn new(own: DeviceRef) -> Self {
        Self {
            own,
            fail_on_unknown_lists: false,
        }
    }

    /// Makes [`BaseClient::apply`] fail with
    /// [`CryptoError::DeviceListUnknown`], rolling the event back, where it
    /// would otherwise skip a message whose credential names a user without
    /// a known DeviceList: the caller fetches the list and applies the event
    /// again.
    pub fn failing_on_unknown_device_lists(mut self) -> Self {
        self.fail_on_unknown_lists = true;
        self
    }

    fn rejects(&self, err: CryptoError) -> Result<Outcome> {
        match err {
            err @ CryptoError::DeviceListUnknown { .. } if self.fail_on_unknown_lists => {
                Err(err.into())
            }
            _ => Ok(Outcome::Applied),
        }
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

    /// Creates the MLS group and chat of a new self group (the MLS group
    /// of the own user's devices, hidden from [`StateReader::chats`]) and
    /// records it as the current one.
    pub fn create_self_group<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<()> {
        store.transaction(|txn| {
            engine.create_group(&*txn, group_id)?;
            let mut chat = Chat::new(group_id.clone(), ChatKind::Group, now_ms);
            chat.members = chat_members(txn, &engine.group_members(&*txn, group_id)?)?;
            txn.upsert_chat(&chat)?;
            txn.add_self_group(group_id)?;
            Ok(())
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
            let left = engine.pending_commit_leavers(&*txn, group_id)?;
            engine.merge_pending_commit(&*txn, group_id)?;
            txn.remove_pending_commit(group_id)?;
            let mut changes = Vec::new();
            let own_user = self.own.user_id.clone();
            self.update_membership(
                txn,
                engine,
                group_id,
                seq,
                &own_user,
                None,
                &left,
                &mut changes,
            )?;
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

    /// Records that this device left the group without applying the commit
    /// that removed it: deletes the local MLS group and the pending leave,
    /// marks the chat `Left` and records the own user's `Left` membership
    /// event, like other members record it from the removal commit. The
    /// event takes the seq after the last one applied here. A chat that is
    /// left already only loses its MLS group.
    pub fn leave_chat<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            let mut changes = Vec::new();
            self.finish_leave(txn, engine, group_id, now_ms, &mut changes)?;
            Ok(changes)
        })
    }

    fn finish_leave<T: StoreTxn>(
        &self,
        txn: &mut T,
        engine: &MlsEngine,
        group_id: &GroupId,
        now_ms: u64,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        if engine.has_group(&*txn, group_id)? {
            engine.delete_group(&*txn, group_id)?;
        }
        txn.remove_pending_leave(group_id)?;
        let Some(mut chat) = txn.chat(group_id)? else {
            return Ok(());
        };
        if chat.membership == Membership::Left {
            return Ok(());
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
        changes.push(StateChange::ChatUpserted(chat));
        changes.push(StateChange::MembershipChanged(event));
        Ok(())
    }

    /// Starts leaving a joined group: creates a Remove proposal for this
    /// device's leaf at the current epoch, keeps it as the group's
    /// [`PendingLeave`] (posted with `client_id`) and marks the chat
    /// `Leaving`. The device stays a member until another member commits
    /// the proposal.
    pub fn start_leave<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
        client_id: ClientId,
        now_ms: u64,
    ) -> Result<(PendingLeave, Vec<StateChange>)> {
        store.transaction(|txn| {
            let mut chat = txn
                .chat(group_id)?
                .ok_or_else(|| crate::BaseError::NotFound(format!("chat {group_id}")))?;
            if chat.membership != Membership::Joined {
                return Err(crate::BaseError::InvalidState(format!(
                    "chat {group_id} is not joined"
                )));
            }
            let leave = PendingLeave {
                group_id: group_id.clone(),
                client_id,
                epoch: engine.group_epoch(&*txn, group_id)?,
                payload: engine.leave_group(&*txn, group_id)?,
                attempts: 1,
                accepted: false,
            };
            txn.upsert_pending_leave(&leave)?;
            chat.membership = Membership::Leaving;
            chat.updated_at_ms = chat.updated_at_ms.max(now_ms);
            txn.upsert_chat(&chat)?;
            Ok((leave, vec![StateChange::ChatUpserted(chat)]))
        })
    }

    /// Replaces the pending leave by a fresh proposal for the group's
    /// current epoch, after an epoch ended without removing this device;
    /// counts an attempt.
    pub fn renew_leave<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
        client_id: ClientId,
    ) -> Result<PendingLeave> {
        store.transaction(|txn| {
            let mut leave = txn.pending_leave(group_id)?.ok_or_else(|| {
                crate::BaseError::NotFound(format!("pending leave of {group_id}"))
            })?;
            leave.epoch = engine.group_epoch(&*txn, group_id)?;
            leave.payload = engine.leave_group(&*txn, group_id)?;
            leave.client_id = client_id;
            leave.attempts += 1;
            leave.accepted = false;
            txn.upsert_pending_leave(&leave)?;
            Ok(leave)
        })
    }

    /// Records that the hub accepted the pending leave posted with
    /// `client_id`.
    pub fn leave_accepted<S: StateStore>(
        &self,
        store: &S,
        group_id: &GroupId,
        client_id: &ClientId,
    ) -> Result<()> {
        store.transaction(|txn| {
            if let Some(mut leave) = txn
                .pending_leave(group_id)?
                .filter(|l| &l.client_id == client_id)
            {
                leave.accepted = true;
                txn.upsert_pending_leave(&leave)?;
            }
            Ok(())
        })
    }

    /// Gives up leaving after the hub refused the proposal for good: drops
    /// it (and the group's other pending proposals) and returns the chat to
    /// `Joined`.
    pub fn abort_leave<S: StateStore>(
        &self,
        store: &S,
        engine: &MlsEngine,
        group_id: &GroupId,
    ) -> Result<Vec<StateChange>> {
        store.transaction(|txn| {
            txn.remove_pending_leave(group_id)?;
            if engine.has_group(&*txn, group_id)? {
                engine.clear_pending_proposals(&*txn, group_id)?;
            }
            let Some(mut chat) = txn
                .chat(group_id)?
                .filter(|c| c.membership == Membership::Leaving)
            else {
                return Ok(vec![]);
            };
            chat.membership = Membership::Joined;
            txn.upsert_chat(&chat)?;
            Ok(vec![StateChange::ChatUpserted(chat)])
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
                        match chat.membership {
                            // Removed after asking to: done leaving, even
                            // without the removal commit.
                            Membership::Leaving => {
                                self.finish_leave(txn, engine, &group_id, now_ms(), &mut changes)?
                            }
                            Membership::Joined => {
                                chat.membership = Membership::Left;
                                txn.upsert_chat(&chat)?;
                                changes.push(StateChange::ChatUpserted(chat));
                            }
                            Membership::Left => {}
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
            for gid in joined_groups(txn)? {
                let gid = &gid;
                if !engine.has_group(&*txn, gid)? {
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
            // Nothing is sent from a chat being left.
            let leaving = chat.membership == Membership::Leaving;
            let last_seq = newer.iter().filter_map(|m| m.seq).max();
            if last_seq.is_some() || chat.unread_count != 0 {
                chat.last_read_seq = last_seq.unwrap_or(chat.last_read_seq);
                chat.unread_count = 0;
                txn.upsert_chat(&chat)?;
                changes.push(StateChange::ChatUpserted(chat));
            }
            let receipt = if ids.is_empty() || leaving {
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
                err @ (CryptoError::InvalidInput { .. }
                | CryptoError::Mls { .. }
                | CryptoError::InvalidCredential { .. }
                | CryptoError::DeviceListUnknown { .. }),
            ) => return self.rejects(err),
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
                left,
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
                    &left,
                    changes,
                )?
            }
            // A Proposal is kept pending in the MLS group; gim-sdk has a
            // member commit it by reference.
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
            Err(err) => return self.rejects(err),
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
    /// records the users it added or removed (`Left` for those who left
    /// themselves: by their own proposal, `left`, or by leaving the fan-out
    /// list). `removed` is set when the commit removed this device; the
    /// group is gone then, and so is its pending leave.
    #[allow(clippy::too_many_arguments)]
    fn update_membership<T: StoreTxn>(
        &self,
        txn: &mut T,
        engine: &MlsEngine,
        group_id: &GroupId,
        seq: u64,
        actor: &UserId,
        removed: Option<&[DeviceRef]>,
        left: &[DeviceRef],
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let now = now_ms();
        let mut chat = load_chat(txn, group_id, now)?;
        let users_before = member_users(&chat);
        let members = match removed {
            Some(removed) => {
                chat.membership = Membership::Left;
                chat.members.retain(|m| !removed.contains(&m.device));
                txn.remove_pending_leave(group_id)?;
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
        let left_users: BTreeSet<&UserId> = left.iter().map(|d| &d.user_id).collect();
        let gone = users_before.difference(&users_after).map(|u| {
            let kind = if u == actor || departed_users.contains(u) || left_users.contains(u) {
                MembershipChangeKind::Left
            } else {
                MembershipChangeKind::Removed
            };
            (u, kind)
        });
        let mut events: Vec<(&UserId, MembershipChangeKind, &UserId)> = added
            .chain(gone)
            .map(|(user_id, kind)| (user_id, kind, actor))
            .collect();
        if removed.is_some() && left.contains(&self.own) {
            // This device left by its own proposal: recorded as its own
            // `Left`, as when the removal commit is not seen.
            let own_user = &self.own.user_id;
            events.retain(|(user_id, ..)| *user_id != own_user);
            events.push((own_user, MembershipChangeKind::Left, own_user));
        }
        for (user_id, kind, actor) in events {
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
            Content::Profile { display_name } => {
                self.apply_profile(txn, &sender.user_id, display_name, changes)
            }
            // Self group contents: only from the own user's devices.
            _ if sender.user_id != self.own.user_id => Ok(()),
            Content::SelfDeviceList { device_list } => {
                txn.add_self_group(group_id)?;
                self.apply_own_device_list(txn, &device_list)
            }
            Content::SelfProfile { display_name } => {
                txn.add_self_group(group_id)?;
                let own_user = self.own.user_id.clone();
                self.apply_profile(txn, &own_user, display_name, changes)
            }
            Content::SelfContacts { contacts } => {
                txn.add_self_group(group_id)?;
                for contact in contacts {
                    self.apply_contact(txn, contact)?;
                }
                Ok(())
            }
            Content::SelfReadMarker {
                group_id: chat_id,
                seq,
            } => {
                txn.add_self_group(group_id)?;
                self.apply_read_marker(txn, &chat_id, seq, changes)
            }
            Content::SelfHubs { hubs } => {
                txn.add_self_group(group_id)?;
                apply_hub_locations(txn, hubs)
            }
        }
    }

    /// Stores `display_name` as the user's display name (an empty one is
    /// ignored) and renames the user's members in every chat.
    fn apply_profile<T: StoreTxn>(
        &self,
        txn: &mut T,
        user_id: &UserId,
        display_name: String,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        if display_name.is_empty() {
            return Ok(());
        }
        let mut user = txn.user(user_id)?.unwrap_or_else(|| UserInfo {
            user_id: user_id.clone(),
            handle: String::new(),
            display_name: String::new(),
        });
        if user.display_name == display_name {
            return Ok(());
        }
        user.display_name = display_name.clone();
        txn.upsert_user(&user)?;
        for mut chat in txn.chats()? {
            let mut renamed = false;
            for member in &mut chat.members {
                if &member.device.user_id == user_id
                    && member.display_name.as_ref() != Some(&display_name)
                {
                    member.display_name = Some(display_name.clone());
                    renamed = true;
                }
            }
            if renamed {
                txn.upsert_chat(&chat)?;
                changes.push(StateChange::ChatUpserted(chat));
            }
        }
        Ok(())
    }

    /// Keeps the own user's DeviceList from the self group if it verifies
    /// and supersedes the stored one; gim-sdk loads it into its cache.
    fn apply_own_device_list<T: StoreTxn>(&self, txn: &mut T, bytes: &[u8]) -> Result<()> {
        let own_user = &self.own.user_id;
        let Ok(list) = SignedDeviceList::from_bytes(bytes).and_then(|l| l.verify(own_user)) else {
            return Ok(());
        };
        let stored = txn
            .device_lists()?
            .into_iter()
            .find(|(user_id, _)| user_id == own_user)
            .and_then(|(_, bytes)| {
                SignedDeviceList::from_bytes(&bytes)
                    .and_then(|l| l.verify(own_user))
                    .ok()
            });
        if stored.is_none_or(|stored| list.supersedes(&stored).unwrap_or(false)) {
            txn.upsert_device_list(own_user, bytes)?;
        }
        Ok(())
    }

    /// Adds a contact shared by another own device to the user directory
    /// cache; known names and handles are kept.
    fn apply_contact<T: StoreTxn>(&self, txn: &mut T, contact: Contact) -> Result<()> {
        if contact.user_id == self.own.user_id {
            return Ok(());
        }
        let stored = txn.user(&contact.user_id)?;
        let mut user = stored.clone().unwrap_or_else(|| UserInfo {
            user_id: contact.user_id.clone(),
            handle: String::new(),
            display_name: String::new(),
        });
        if user.handle.is_empty() {
            user.handle = contact.handle.unwrap_or_default();
        }
        if user.display_name.is_empty() {
            user.display_name = contact.display_name.unwrap_or_default();
        }
        if stored.as_ref() != Some(&user) {
            txn.upsert_user(&user)?;
        }
        Ok(())
    }

    /// Marks the chat read up to `seq`, as another own device did.
    fn apply_read_marker<T: StoreTxn>(
        &self,
        txn: &mut T,
        group_id: &GroupId,
        seq: u64,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let Some(mut chat) = txn.chat(group_id)? else {
            return Ok(());
        };
        if seq <= chat.last_read_seq {
            return Ok(());
        }
        let unread = txn
            .messages_after(group_id, seq)?
            .iter()
            .filter(|m| m.sender.user_id != self.own.user_id && !m.deleted)
            .count();
        chat.last_read_seq = seq;
        chat.unread_count = u32::try_from(unread).unwrap_or(u32::MAX);
        txn.upsert_chat(&chat)?;
        changes.push(StateChange::ChatUpserted(chat));
        Ok(())
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
            // Nothing is sent from a chat being left.
            if chat.membership != Membership::Leaving {
                self.enqueue_receipt(
                    txn,
                    group_id,
                    ReceiptKind::Delivered,
                    vec![message.message_id.clone()],
                    now_ms,
                )?;
            }
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

/// Records the URLs another own device shared for the hubs of the hosting
/// record. A new or changed URL is marked shared and stays unverified until
/// the hub proof there passes; a hub no longer listed stays removed. Rows for hubs the
/// stored record does not list yet are added; the client uses only listed
/// hubs.
fn apply_hub_locations<T: StoreTxn>(txn: &mut T, hubs: Vec<HubLocation>) -> Result<()> {
    let stored = txn.hubs()?;
    for location in hubs {
        let hub = match stored.iter().find(|h| h.hub_id == location.hub_id) {
            Some(hub) if hub.url.as_ref() == Some(&location.url) => continue,
            Some(hub) => HubRecord {
                url: Some(location.url),
                url_shared: true,
                verified_root_pubkey: None,
                state: match hub.state {
                    HubState::Removed => HubState::Removed,
                    _ => HubState::Unverified,
                },
                ..hub.clone()
            },
            None => HubRecord {
                hub_id: location.hub_id,
                url: Some(location.url),
                url_shared: true,
                priority: location.priority,
                verified_root_pubkey: None,
                last_seen_ms: None,
                state: HubState::Unverified,
            },
        };
        txn.upsert_hub(&hub)?;
    }
    Ok(())
}

/// The stored chat, or a new joined group chat if there is none yet.
pub(crate) fn load_chat<T: StoreTxn>(txn: &T, group_id: &GroupId, now_ms: u64) -> Result<Chat> {
    Ok(txn
        .chat(group_id)?
        .unwrap_or_else(|| Chat::new(group_id.clone(), ChatKind::Group, now_ms)))
}

/// Joined chats and joined self groups.
fn joined_groups<T: StoreTxn>(txn: &T) -> Result<Vec<GroupId>> {
    let mut groups: Vec<GroupId> = txn
        .chats()?
        .into_iter()
        .filter(|c| c.membership == Membership::Joined)
        .map(|c| c.group_id)
        .collect();
    for group_id in txn.self_groups()? {
        if txn
            .chat(&group_id)?
            .is_some_and(|c| c.membership == Membership::Joined)
        {
            groups.push(group_id);
        }
    }
    Ok(groups)
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
