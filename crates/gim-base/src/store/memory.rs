//! In-memory [`StateStore`] + [`CryptoStore`] for tests.
//!
//! A transaction works on a clone of the committed state (rows and MLS
//! storage) and replaces the committed state only when it succeeds.
//! Transactions are serialized. Writes through the store's own
//! [`CryptoStore`] impl bypass transactions and are overwritten by the next
//! commit, so use them only while no transaction is open (e.g. to create
//! the identity at setup).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use gim_common::{GroupId, MessageId, UserId};
use gim_crypto::{CryptoStore, StoredIdentity};
use openmls_memory_storage::MemoryStorage;

use super::{StateReader, StateStore, StoreResult, StoreTxn};
use crate::model::{
    Chat, DepartedMember, GroupCursor, GroupMessage, MediaCacheEntry, MembershipEvent, Message,
    OutboxEntry, OutboxState, PendingCommit, UserInfo,
};
use crate::{BaseError, StoreError};

/// Kind of row write that [`MemoryStore::fail_writes`] makes fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteTarget {
    Chat,
    Message,
    Outbox,
    GroupCursor,
}

#[derive(Debug, Clone, Default)]
struct Rows {
    chats: BTreeMap<GroupId, Chat>,
    messages: BTreeMap<MessageId, Message>,
    outbox: BTreeMap<MessageId, OutboxEntry>,
    global_cursor: Option<u64>,
    group_cursors: BTreeMap<GroupId, GroupCursor>,
    parked: BTreeMap<(GroupId, u64), GroupMessage>,
    media: BTreeMap<String, MediaCacheEntry>,
    users: BTreeMap<UserId, UserInfo>,
    pending_commits: BTreeMap<GroupId, PendingCommit>,
    departed: BTreeSet<DepartedMember>,
    membership: BTreeMap<(GroupId, u64, UserId), MembershipEvent>,
}

#[derive(Debug, Default)]
struct CryptoState {
    mls: MemoryStorage,
    identity: RwLock<Option<StoredIdentity>>,
    group_ids: RwLock<BTreeSet<GroupId>>,
}

impl CryptoState {
    fn snapshot(&self) -> StoreResult<Self> {
        Ok(Self {
            mls: MemoryStorage {
                values: RwLock::new(read(&self.mls.values)?.clone()),
            },
            identity: RwLock::new(read(&self.identity)?.clone()),
            group_ids: RwLock::new(read(&self.group_ids)?.clone()),
        })
    }

    fn replace_with(&self, other: Self) -> StoreResult<()> {
        *write(&self.mls.values)? = into_inner(other.mls.values)?;
        *write(&self.identity)? = into_inner(other.identity)?;
        *write(&self.group_ids)? = into_inner(other.group_ids)?;
        Ok(())
    }

    fn load_identity(&self) -> StoreResult<Option<StoredIdentity>> {
        Ok(read(&self.identity)?.clone())
    }

    fn save_identity(&self, identity: &StoredIdentity) -> StoreResult<()> {
        *write(&self.identity)? = Some(identity.clone());
        Ok(())
    }

    fn group_ids(&self) -> StoreResult<BTreeSet<GroupId>> {
        Ok(read(&self.group_ids)?.clone())
    }

    fn add_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        write(&self.group_ids)?.insert(group_id.clone());
        Ok(())
    }

    fn remove_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        write(&self.group_ids)?.remove(group_id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    txn_lock: Mutex<()>,
    rows: RwLock<Rows>,
    crypto: CryptoState,
    fail_on: Mutex<Option<WriteTarget>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Failure injection: while set, writes of `target` inside a transaction
    /// return an error.
    pub fn fail_writes(&self, target: Option<WriteTarget>) {
        *self.fail_on.lock().unwrap_or_else(|e| e.into_inner()) = target;
    }
}

/// Transaction of a [`MemoryStore`]: a private copy of the whole state.
#[derive(Debug)]
pub struct MemoryTxn {
    rows: Rows,
    crypto: CryptoState,
    fail_on: Option<WriteTarget>,
}

impl MemoryTxn {
    fn check(&self, target: WriteTarget) -> StoreResult<()> {
        if self.fail_on == Some(target) {
            return Err(StoreError::new(format!(
                "injected {target:?} write failure"
            )));
        }
        Ok(())
    }
}

impl StateStore for MemoryStore {
    type Txn<'a> = MemoryTxn;

    fn transaction<R, F>(&self, f: F) -> Result<R, BaseError>
    where
        F: FnOnce(&mut MemoryTxn) -> Result<R, BaseError>,
    {
        let _serialized = lock(&self.txn_lock)?;
        let mut txn = MemoryTxn {
            rows: read(&self.rows)?.clone(),
            crypto: self.crypto.snapshot()?,
            fail_on: *lock(&self.fail_on)?,
        };
        let result = f(&mut txn)?;
        *write(&self.rows)? = txn.rows;
        self.crypto.replace_with(txn.crypto)?;
        Ok(result)
    }
}

impl StateReader for MemoryStore {
    fn chats(&self) -> StoreResult<Vec<Chat>> {
        read(&self.rows)?.chats()
    }

    fn chat(&self, group_id: &GroupId) -> StoreResult<Option<Chat>> {
        read(&self.rows)?.chat(group_id)
    }

    fn messages(
        &self,
        group_id: &GroupId,
        before_seq: Option<u64>,
        limit: usize,
    ) -> StoreResult<Vec<Message>> {
        read(&self.rows)?.messages(group_id, before_seq, limit)
    }

    fn messages_after(&self, group_id: &GroupId, after_seq: u64) -> StoreResult<Vec<Message>> {
        read(&self.rows)?.messages_after(group_id, after_seq)
    }

    fn message(&self, message_id: &MessageId) -> StoreResult<Option<Message>> {
        read(&self.rows)?.message(message_id)
    }

    fn outbox_entry(&self, message_id: &MessageId) -> StoreResult<Option<OutboxEntry>> {
        read(&self.rows)?.outbox_entry(message_id)
    }

    fn outbox_entries(&self) -> StoreResult<Vec<OutboxEntry>> {
        read(&self.rows)?.outbox_entries()
    }

    fn outbox_due(&self, now_ms: u64, limit: usize) -> StoreResult<Vec<OutboxEntry>> {
        read(&self.rows)?.outbox_due(now_ms, limit)
    }

    fn global_cursor(&self) -> StoreResult<Option<u64>> {
        read(&self.rows)?.global_cursor()
    }

    fn group_cursor(&self, group_id: &GroupId) -> StoreResult<GroupCursor> {
        read(&self.rows)?.group_cursor(group_id)
    }

    fn parked_messages(&self, group_id: &GroupId) -> StoreResult<Vec<GroupMessage>> {
        read(&self.rows)?.parked_messages(group_id)
    }

    fn media(&self, blob_id: &str) -> StoreResult<Option<MediaCacheEntry>> {
        read(&self.rows)?.media(blob_id)
    }

    fn media_entries(&self) -> StoreResult<Vec<MediaCacheEntry>> {
        read(&self.rows)?.media_entries()
    }

    fn user(&self, user_id: &UserId) -> StoreResult<Option<UserInfo>> {
        read(&self.rows)?.user(user_id)
    }

    fn pending_commit(&self, group_id: &GroupId) -> StoreResult<Option<PendingCommit>> {
        Ok(read(&self.rows)?.pending_commits.get(group_id).cloned())
    }

    fn pending_commits(&self) -> StoreResult<Vec<PendingCommit>> {
        Ok(read(&self.rows)?
            .pending_commits
            .values()
            .cloned()
            .collect())
    }

    fn departed_members(&self) -> StoreResult<Vec<DepartedMember>> {
        Ok(read(&self.rows)?.departed.iter().cloned().collect())
    }

    fn membership_events(&self, group_id: &GroupId) -> StoreResult<Vec<MembershipEvent>> {
        read(&self.rows)?.membership_events(group_id)
    }
}

impl StateReader for MemoryTxn {
    fn chats(&self) -> StoreResult<Vec<Chat>> {
        self.rows.chats()
    }

    fn chat(&self, group_id: &GroupId) -> StoreResult<Option<Chat>> {
        self.rows.chat(group_id)
    }

    fn messages(
        &self,
        group_id: &GroupId,
        before_seq: Option<u64>,
        limit: usize,
    ) -> StoreResult<Vec<Message>> {
        self.rows.messages(group_id, before_seq, limit)
    }

    fn messages_after(&self, group_id: &GroupId, after_seq: u64) -> StoreResult<Vec<Message>> {
        self.rows.messages_after(group_id, after_seq)
    }

    fn message(&self, message_id: &MessageId) -> StoreResult<Option<Message>> {
        self.rows.message(message_id)
    }

    fn outbox_entry(&self, message_id: &MessageId) -> StoreResult<Option<OutboxEntry>> {
        self.rows.outbox_entry(message_id)
    }

    fn outbox_entries(&self) -> StoreResult<Vec<OutboxEntry>> {
        self.rows.outbox_entries()
    }

    fn outbox_due(&self, now_ms: u64, limit: usize) -> StoreResult<Vec<OutboxEntry>> {
        self.rows.outbox_due(now_ms, limit)
    }

    fn global_cursor(&self) -> StoreResult<Option<u64>> {
        self.rows.global_cursor()
    }

    fn group_cursor(&self, group_id: &GroupId) -> StoreResult<GroupCursor> {
        self.rows.group_cursor(group_id)
    }

    fn parked_messages(&self, group_id: &GroupId) -> StoreResult<Vec<GroupMessage>> {
        self.rows.parked_messages(group_id)
    }

    fn media(&self, blob_id: &str) -> StoreResult<Option<MediaCacheEntry>> {
        self.rows.media(blob_id)
    }

    fn media_entries(&self) -> StoreResult<Vec<MediaCacheEntry>> {
        self.rows.media_entries()
    }

    fn user(&self, user_id: &UserId) -> StoreResult<Option<UserInfo>> {
        self.rows.user(user_id)
    }

    fn pending_commit(&self, group_id: &GroupId) -> StoreResult<Option<PendingCommit>> {
        Ok(self.rows.pending_commits.get(group_id).cloned())
    }

    fn pending_commits(&self) -> StoreResult<Vec<PendingCommit>> {
        Ok(self.rows.pending_commits.values().cloned().collect())
    }

    fn departed_members(&self) -> StoreResult<Vec<DepartedMember>> {
        Ok(self.rows.departed.iter().cloned().collect())
    }

    fn membership_events(&self, group_id: &GroupId) -> StoreResult<Vec<MembershipEvent>> {
        self.rows.membership_events(group_id)
    }
}

impl StoreTxn for MemoryTxn {
    fn upsert_chat(&mut self, chat: &Chat) -> StoreResult<()> {
        self.check(WriteTarget::Chat)?;
        self.rows.chats.insert(chat.group_id.clone(), chat.clone());
        Ok(())
    }

    fn remove_chat(&mut self, group_id: &GroupId) -> StoreResult<()> {
        self.check(WriteTarget::Chat)?;
        let rows = &mut self.rows;
        rows.chats.remove(group_id);
        rows.messages.retain(|_, m| &m.group_id != group_id);
        rows.outbox.retain(|_, e| &e.group_id != group_id);
        rows.group_cursors.remove(group_id);
        rows.parked.retain(|(g, _), _| g != group_id);
        rows.pending_commits.remove(group_id);
        rows.departed.retain(|d| &d.group_id != group_id);
        rows.membership.retain(|(g, _, _), _| g != group_id);
        Ok(())
    }

    fn upsert_message(&mut self, message: &Message) -> StoreResult<()> {
        self.check(WriteTarget::Message)?;
        self.rows
            .messages
            .insert(message.message_id.clone(), message.clone());
        Ok(())
    }

    fn remove_message(&mut self, message_id: &MessageId) -> StoreResult<()> {
        self.check(WriteTarget::Message)?;
        self.rows.messages.remove(message_id);
        Ok(())
    }

    fn upsert_outbox(&mut self, entry: &OutboxEntry) -> StoreResult<()> {
        self.check(WriteTarget::Outbox)?;
        self.rows
            .outbox
            .insert(entry.message_id.clone(), entry.clone());
        Ok(())
    }

    fn remove_outbox(&mut self, message_id: &MessageId) -> StoreResult<()> {
        self.check(WriteTarget::Outbox)?;
        self.rows.outbox.remove(message_id);
        Ok(())
    }

    fn set_global_cursor(&mut self, cursor: u64) -> StoreResult<()> {
        self.check(WriteTarget::GroupCursor)?;
        self.rows.global_cursor = Some(cursor);
        Ok(())
    }

    fn set_group_cursor(&mut self, group_id: &GroupId, cursor: &GroupCursor) -> StoreResult<()> {
        self.check(WriteTarget::GroupCursor)?;
        self.rows
            .group_cursors
            .insert(group_id.clone(), cursor.clone());
        Ok(())
    }

    fn park_message(&mut self, message: &GroupMessage) -> StoreResult<()> {
        self.rows
            .parked
            .insert((message.group_id.clone(), message.seq), message.clone());
        Ok(())
    }

    fn unpark_message(&mut self, group_id: &GroupId, seq: u64) -> StoreResult<()> {
        self.rows.parked.remove(&(group_id.clone(), seq));
        Ok(())
    }

    fn upsert_media(&mut self, entry: &MediaCacheEntry) -> StoreResult<()> {
        self.rows.media.insert(entry.blob_id.clone(), entry.clone());
        Ok(())
    }

    fn remove_media(&mut self, blob_id: &str) -> StoreResult<()> {
        self.rows.media.remove(blob_id);
        Ok(())
    }

    fn upsert_user(&mut self, user: &UserInfo) -> StoreResult<()> {
        self.rows.users.insert(user.user_id.clone(), user.clone());
        Ok(())
    }

    fn upsert_pending_commit(&mut self, commit: &PendingCommit) -> StoreResult<()> {
        self.rows
            .pending_commits
            .insert(commit.group_id.clone(), commit.clone());
        Ok(())
    }

    fn remove_pending_commit(&mut self, group_id: &GroupId) -> StoreResult<()> {
        self.rows.pending_commits.remove(group_id);
        Ok(())
    }

    fn add_departed_member(&mut self, member: &DepartedMember) -> StoreResult<()> {
        self.rows.departed.insert(member.clone());
        Ok(())
    }

    fn remove_departed_member(&mut self, member: &DepartedMember) -> StoreResult<()> {
        self.rows.departed.remove(member);
        Ok(())
    }

    fn add_membership_event(&mut self, event: &MembershipEvent) -> StoreResult<()> {
        let key = (event.group_id.clone(), event.seq, event.user_id.clone());
        self.rows.membership.insert(key, event.clone());
        Ok(())
    }
}

impl CryptoStore for MemoryTxn {
    type MlsStorage = MemoryStorage;
    type Error = StoreError;

    fn mls_storage(&self) -> &MemoryStorage {
        &self.crypto.mls
    }

    fn load_identity(&self) -> StoreResult<Option<StoredIdentity>> {
        self.crypto.load_identity()
    }

    fn save_identity(&self, identity: &StoredIdentity) -> StoreResult<()> {
        self.crypto.save_identity(identity)
    }

    fn group_ids(&self) -> StoreResult<BTreeSet<GroupId>> {
        self.crypto.group_ids()
    }

    fn add_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        self.crypto.add_group_id(group_id)
    }

    fn remove_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        self.crypto.remove_group_id(group_id)
    }
}

impl CryptoStore for MemoryStore {
    type MlsStorage = MemoryStorage;
    type Error = StoreError;

    fn mls_storage(&self) -> &MemoryStorage {
        &self.crypto.mls
    }

    fn load_identity(&self) -> StoreResult<Option<StoredIdentity>> {
        self.crypto.load_identity()
    }

    fn save_identity(&self, identity: &StoredIdentity) -> StoreResult<()> {
        self.crypto.save_identity(identity)
    }

    fn group_ids(&self) -> StoreResult<BTreeSet<GroupId>> {
        self.crypto.group_ids()
    }

    fn add_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        self.crypto.add_group_id(group_id)
    }

    fn remove_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        self.crypto.remove_group_id(group_id)
    }
}

/// Timeline order: by seq, unsent (no seq) last, then by send time and id.
fn timeline_key(m: &Message) -> (u64, u64, &MessageId) {
    (m.seq.unwrap_or(u64::MAX), m.sent_at_ms, &m.message_id)
}

impl Rows {
    fn chats(&self) -> StoreResult<Vec<Chat>> {
        let mut chats: Vec<Chat> = self.chats.values().cloned().collect();
        chats.sort_by_key(|c| std::cmp::Reverse(c.updated_at_ms));
        Ok(chats)
    }

    fn chat(&self, group_id: &GroupId) -> StoreResult<Option<Chat>> {
        Ok(self.chats.get(group_id).cloned())
    }

    fn group_messages(&self, group_id: &GroupId) -> Vec<&Message> {
        let mut messages: Vec<&Message> = self
            .messages
            .values()
            .filter(|m| &m.group_id == group_id)
            .collect();
        messages.sort_by(|a, b| timeline_key(a).cmp(&timeline_key(b)));
        messages
    }

    fn messages(
        &self,
        group_id: &GroupId,
        before_seq: Option<u64>,
        limit: usize,
    ) -> StoreResult<Vec<Message>> {
        let messages: Vec<&Message> = self
            .group_messages(group_id)
            .into_iter()
            .filter(|m| before_seq.is_none_or(|before| m.seq.is_some_and(|s| s < before)))
            .collect();
        let start = messages.len().saturating_sub(limit);
        Ok(messages[start..].iter().map(|m| (*m).clone()).collect())
    }

    fn messages_after(&self, group_id: &GroupId, after_seq: u64) -> StoreResult<Vec<Message>> {
        Ok(self
            .group_messages(group_id)
            .into_iter()
            .filter(|m| m.seq.is_some_and(|s| s > after_seq))
            .cloned()
            .collect())
    }

    fn message(&self, message_id: &MessageId) -> StoreResult<Option<Message>> {
        Ok(self.messages.get(message_id).cloned())
    }

    fn outbox_entry(&self, message_id: &MessageId) -> StoreResult<Option<OutboxEntry>> {
        Ok(self.outbox.get(message_id).cloned())
    }

    fn outbox_entries(&self) -> StoreResult<Vec<OutboxEntry>> {
        let mut entries: Vec<OutboxEntry> = self.outbox.values().cloned().collect();
        entries.sort_by(|a, b| {
            (a.created_at_ms, &a.message_id).cmp(&(b.created_at_ms, &b.message_id))
        });
        Ok(entries)
    }

    fn outbox_due(&self, now_ms: u64, limit: usize) -> StoreResult<Vec<OutboxEntry>> {
        Ok(self
            .outbox_entries()?
            .into_iter()
            .filter(|e| e.state == OutboxState::Pending && e.next_attempt_at_ms <= now_ms)
            .take(limit)
            .collect())
    }

    fn global_cursor(&self) -> StoreResult<Option<u64>> {
        Ok(self.global_cursor)
    }

    fn group_cursor(&self, group_id: &GroupId) -> StoreResult<GroupCursor> {
        Ok(self
            .group_cursors
            .get(group_id)
            .cloned()
            .unwrap_or_default())
    }

    fn parked_messages(&self, group_id: &GroupId) -> StoreResult<Vec<GroupMessage>> {
        Ok(self
            .parked
            .range((group_id.clone(), 0)..=(group_id.clone(), u64::MAX))
            .map(|(_, m)| m.clone())
            .collect())
    }

    fn media(&self, blob_id: &str) -> StoreResult<Option<MediaCacheEntry>> {
        Ok(self.media.get(blob_id).cloned())
    }

    fn media_entries(&self) -> StoreResult<Vec<MediaCacheEntry>> {
        let mut entries: Vec<MediaCacheEntry> = self.media.values().cloned().collect();
        entries.sort_by_key(|e| e.last_access_ms);
        Ok(entries)
    }

    fn user(&self, user_id: &UserId) -> StoreResult<Option<UserInfo>> {
        Ok(self.users.get(user_id).cloned())
    }

    fn membership_events(&self, group_id: &GroupId) -> StoreResult<Vec<MembershipEvent>> {
        Ok(self
            .membership
            .iter()
            .filter(|((g, _, _), _)| g == group_id)
            .map(|(_, e)| e.clone())
            .collect())
    }
}

fn poisoned<T>(_: T) -> StoreError {
    StoreError::new("memory store lock poisoned")
}

fn lock<T>(mutex: &Mutex<T>) -> StoreResult<MutexGuard<'_, T>> {
    mutex.lock().map_err(poisoned)
}

fn read<T>(lock: &RwLock<T>) -> StoreResult<RwLockReadGuard<'_, T>> {
    lock.read().map_err(poisoned)
}

fn write<T>(lock: &RwLock<T>) -> StoreResult<RwLockWriteGuard<'_, T>> {
    lock.write().map_err(poisoned)
}

fn into_inner<T>(lock: RwLock<T>) -> StoreResult<T> {
    lock.into_inner().map_err(poisoned)
}
