//! Persistence boundary of gim-base.
//!
//! The traits are synchronous: rusqlite is synchronous, and gim-sdk calls the
//! store through `spawn_blocking`.
//!
//! # Why generic instead of `dyn`
//!
//! A transaction must also be a gim-crypto [`CryptoStore`], so that MLS state
//! and the rows derived from it commit atomically. `CryptoStore` has
//! associated types (its OpenMLS `StorageProvider` is not object safe), so a
//! transaction cannot be a trait object. [`StateStore`] therefore exposes its
//! transaction as a generic associated type and gim-sdk is generic over the
//! store (`Client<S: StateStore>`, typically holding `Arc<SqliteStore>`).
//! The read side, [`StateReader`], is object safe and can be used as
//! `Arc<dyn StateReader>` where only reads are needed.

mod memory;

use gim_common::{GroupId, MessageId, UserId};
use gim_crypto::CryptoStore;

pub use memory::{MemoryStore, MemoryTxn, WriteTarget};

use crate::model::{
    Chat, DepartedMember, GroupCursor, GroupMessage, HubRecord, KeyPackageRecord, MediaCacheEntry,
    MembershipEvent, Message, OutboxEntry, PendingCommit, PendingInvite, PendingLeave, UserInfo,
};
use crate::{BaseError, StoreError};

type StoreResult<T> = Result<T, StoreError>;

/// Reads, available on the store (committed state) and on a transaction
/// (including its own uncommitted writes).
pub trait StateReader {
    /// All chats except the self groups, most recently updated first.
    fn chats(&self) -> StoreResult<Vec<Chat>>;
    /// Any chat, the self groups included.
    fn chat(&self, group_id: &GroupId) -> StoreResult<Option<Chat>>;

    /// Up to `limit` messages of the group in timeline order (ascending
    /// `seq`, unsent own messages last), the latest ones before
    /// `before_seq` (`None`: the latest overall, unsent included).
    fn messages(
        &self,
        group_id: &GroupId,
        before_seq: Option<u64>,
        limit: usize,
    ) -> StoreResult<Vec<Message>>;
    /// Messages with `seq > after_seq`, ascending.
    fn messages_after(&self, group_id: &GroupId, after_seq: u64) -> StoreResult<Vec<Message>>;
    fn message(&self, message_id: &MessageId) -> StoreResult<Option<Message>>;

    fn outbox_entry(&self, message_id: &MessageId) -> StoreResult<Option<OutboxEntry>>;
    /// All entries in creation order.
    fn outbox_entries(&self) -> StoreResult<Vec<OutboxEntry>>;
    /// Pending entries with `next_attempt_at_ms <= now_ms`, in creation
    /// order, at most `limit`.
    fn outbox_due(&self, now_ms: u64, limit: usize) -> StoreResult<Vec<OutboxEntry>>;

    /// Global event-stream cursor (the home hub's).
    fn global_cursor(&self) -> StoreResult<Option<u64>>;
    /// Event-stream cursor on a listed hub other than the home hub.
    fn hub_cursor(&self, hub_id: &str) -> StoreResult<Option<u64>>;
    /// Applied seqs of the group (default if none).
    fn group_cursor(&self, group_id: &GroupId) -> StoreResult<GroupCursor>;
    /// Messages kept for retry (wrong epoch, Welcome not yet applied),
    /// ascending by seq.
    fn parked_messages(&self, group_id: &GroupId) -> StoreResult<Vec<GroupMessage>>;

    fn media(&self, blob_id: &str) -> StoreResult<Option<MediaCacheEntry>>;
    /// All media cache entries, least recently accessed first.
    fn media_entries(&self) -> StoreResult<Vec<MediaCacheEntry>>;

    fn user(&self, user_id: &UserId) -> StoreResult<Option<UserInfo>>;

    fn pending_commit(&self, group_id: &GroupId) -> StoreResult<Option<PendingCommit>>;
    /// All pending commits, by group id.
    fn pending_commits(&self) -> StoreResult<Vec<PendingCommit>>;

    fn pending_leave(&self, group_id: &GroupId) -> StoreResult<Option<PendingLeave>>;
    /// All pending leaves, by group id.
    fn pending_leaves(&self) -> StoreResult<Vec<PendingLeave>>;

    /// All pending invites, by group id then user id.
    fn pending_invites(&self) -> StoreResult<Vec<PendingInvite>>;

    /// All departed-member candidates, by group id then device.
    fn departed_members(&self) -> StoreResult<Vec<DepartedMember>>;

    /// Membership events of the group, ascending by seq, then user id.
    fn membership_events(&self, group_id: &GroupId) -> StoreResult<Vec<MembershipEvent>>;

    /// Latest known signed DeviceList bytes (gim-identity CBOR) of every
    /// user, by user id.
    fn device_lists(&self) -> StoreResult<Vec<(UserId, Vec<u8>)>>;

    /// The self groups (MLS groups of the own user's devices), oldest
    /// first; the last one is current. Their chats are hidden from
    /// [`StateReader::chats`].
    fn self_groups(&self) -> StoreResult<Vec<GroupId>>;

    /// The hubs of the own user's hosting record known to this device, by
    /// hub id.
    fn hubs(&self) -> StoreResult<Vec<HubRecord>>;

    /// The KeyPackage ledger: every KeyPackage generated for a hub, by
    /// `kp_ref`.
    fn key_package_records(&self) -> StoreResult<Vec<KeyPackageRecord>>;
}

/// A write transaction over state rows and MLS state. Dropping it without
/// a successful return from the [`StateStore::transaction`] closure rolls
/// back everything, MLS state included.
pub trait StoreTxn: StateReader + CryptoStore {
    fn upsert_chat(&mut self, chat: &Chat) -> StoreResult<()>;
    /// Removes the chat with its messages, outbox entries, cursor, parked
    /// messages, pending commit, pending leave, pending invites,
    /// departed-member candidates, membership events and self group record.
    fn remove_chat(&mut self, group_id: &GroupId) -> StoreResult<()>;

    fn upsert_message(&mut self, message: &Message) -> StoreResult<()>;
    fn remove_message(&mut self, message_id: &MessageId) -> StoreResult<()>;

    fn upsert_outbox(&mut self, entry: &OutboxEntry) -> StoreResult<()>;
    fn remove_outbox(&mut self, message_id: &MessageId) -> StoreResult<()>;

    fn set_global_cursor(&mut self, cursor: u64) -> StoreResult<()>;
    fn set_hub_cursor(&mut self, hub_id: &str, cursor: u64) -> StoreResult<()>;
    fn set_group_cursor(&mut self, group_id: &GroupId, cursor: &GroupCursor) -> StoreResult<()>;
    /// Keeps a message for retry; replaces any parked message with the same
    /// (group, seq).
    fn park_message(&mut self, message: &GroupMessage) -> StoreResult<()>;
    fn unpark_message(&mut self, group_id: &GroupId, seq: u64) -> StoreResult<()>;

    fn upsert_media(&mut self, entry: &MediaCacheEntry) -> StoreResult<()>;
    fn remove_media(&mut self, blob_id: &str) -> StoreResult<()>;

    fn upsert_user(&mut self, user: &UserInfo) -> StoreResult<()>;

    /// Replaces the group's pending commit, if any.
    fn upsert_pending_commit(&mut self, commit: &PendingCommit) -> StoreResult<()>;
    fn remove_pending_commit(&mut self, group_id: &GroupId) -> StoreResult<()>;

    /// Replaces the group's pending leave, if any.
    fn upsert_pending_leave(&mut self, leave: &PendingLeave) -> StoreResult<()>;
    fn remove_pending_leave(&mut self, group_id: &GroupId) -> StoreResult<()>;

    /// Replaces the pending invite of the same (group, user), if any.
    fn upsert_pending_invite(&mut self, invite: &PendingInvite) -> StoreResult<()>;
    fn remove_pending_invite(&mut self, group_id: &GroupId, user_id: &UserId) -> StoreResult<()>;

    /// Records a candidate; recording it again changes nothing.
    fn add_departed_member(&mut self, member: &DepartedMember) -> StoreResult<()>;
    fn remove_departed_member(&mut self, member: &DepartedMember) -> StoreResult<()>;

    /// Replaces any event with the same (group, seq, user).
    fn add_membership_event(&mut self, event: &MembershipEvent) -> StoreResult<()>;

    /// Replaces the user's stored DeviceList bytes.
    fn upsert_device_list(&mut self, user_id: &UserId, device_list: &[u8]) -> StoreResult<()>;

    /// Records a self group as the current one, unless it is recorded
    /// already.
    fn add_self_group(&mut self, group_id: &GroupId) -> StoreResult<()>;

    /// Replaces the hub with the same id, if any.
    fn upsert_hub(&mut self, hub: &HubRecord) -> StoreResult<()>;
    fn remove_hub(&mut self, hub_id: &str) -> StoreResult<()>;

    /// Records a KeyPackage in the ledger. Fails if its `kp_ref` is
    /// recorded already: a KeyPackage belongs to one hub, ever.
    fn add_key_package_record(&mut self, record: &KeyPackageRecord) -> StoreResult<()>;

    /// Deletes every row and all MLS state, the device identity included
    /// (an unfinished enrollment is discarded this way).
    fn clear(&mut self) -> StoreResult<()>;
}

/// State and MLS storage of one device.
pub trait StateStore: StateReader + Send + Sync {
    type Txn<'a>: StoreTxn
    where
        Self: 'a;

    /// Runs `f` in one transaction: commits if it returns `Ok`, rolls back
    /// state rows and MLS state if it returns `Err`.
    fn transaction<R, F>(&self, f: F) -> Result<R, BaseError>
    where
        F: FnOnce(&mut Self::Txn<'_>) -> Result<R, BaseError>;
}
