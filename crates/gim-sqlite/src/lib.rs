//! rusqlite (bundled) implementation of `StateStore` + `CryptoStore` on one
//! database, migrations, and a shared transaction so MLS state and message
//! rows commit atomically.
//!
//! OpenMLS state is stored by `openmls_sqlite_storage` (MIT, used as a
//! dependency) in the same database file; its provider borrows the
//! connection that holds the open transaction, so its writes are part of it.

#![forbid(unsafe_code)]

mod migrations;
mod reader;
mod rows;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use gim_base::model::{
    Chat, DepartedMember, GroupCursor, GroupMessage, MediaCacheEntry, MembershipEvent, Message,
    OutboxEntry, PendingCommit, UserInfo,
};
use gim_base::{BaseError, StateReader, StateStore, StoreError, StoreTxn, WriteTarget};
use gim_common::{DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{CryptoStore, StoredIdentity};
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};

pub use migrations::SCHEMA_VERSION;

use reader::{bound, membership_kind_str, outbox_state_str, sql_err, Reader};
use rows::{
    encode, ChatData, MemberRow, MessageData, OutboxData, OutboxKindRow, ParkedData,
    PendingCommitData,
};

type StoreResult<T> = Result<T, StoreError>;

/// File name of the database inside the data directory.
pub const DATABASE_FILE_NAME: &str = "gim.sqlite3";

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// serde codec of the OpenMLS storage provider values.
#[derive(Debug, Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// OpenMLS storage of a [`SqliteTxn`], writing through its transaction.
pub type MlsStorage<'a> = SqliteStorageProvider<JsonCodec, &'a Connection>;

/// State and MLS storage of one device in one SQLite database.
///
/// One connection behind a mutex: reads and transactions are serialized.
/// There is no store-level [`CryptoStore`] (a `Connection` is not `Sync`);
/// MLS state is reached through [`StateStore::transaction`].
pub struct SqliteStore {
    conn: Mutex<Connection>,
    #[cfg(feature = "testing")]
    fail_on: Mutex<Option<WriteTarget>>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Opens (creating if needed) `<data_dir>/gim.sqlite3` and migrates it.
    /// A missing `data_dir` is created owner-only on Unix, since the
    /// database (and its -wal/-shm files) holds the device's private keys.
    pub fn open(data_dir: impl AsRef<Path>) -> StoreResult<Self> {
        let data_dir = data_dir.as_ref();
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(data_dir).map_err(StoreError::new)?;
        let conn = Connection::open(data_dir.join(DATABASE_FILE_NAME)).map_err(sql_err)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        Self::init(Connection::open_in_memory().map_err(sql_err)?)
    }

    fn init(mut conn: Connection) -> StoreResult<Self> {
        conn.busy_timeout(BUSY_TIMEOUT).map_err(sql_err)?;
        // In-memory databases report "memory"; nothing to check.
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))
            .map_err(sql_err)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(sql_err)?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(sql_err)?;
        migrations::migrate(&mut conn)?;
        SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut conn)
            .run_migrations()
            .map_err(StoreError::new)?;
        Ok(Self {
            conn: Mutex::new(conn),
            #[cfg(feature = "testing")]
            fail_on: Mutex::new(None),
        })
    }

    /// Failure injection: while set, writes of `target` inside a transaction
    /// return an error (same targets as `MemoryStore::fail_writes`).
    #[cfg(feature = "testing")]
    pub fn fail_writes(&self, target: Option<WriteTarget>) {
        *self.fail_on.lock().unwrap_or_else(PoisonError::into_inner) = target;
    }

    /// A panic inside a transaction poisons the mutex, but the dropped
    /// rusqlite transaction has rolled back, so the connection is usable.
    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A transaction of a [`SqliteStore`]: one rusqlite [`Transaction`] that
/// carries state rows and MLS state. Dropped without commit, it rolls back.
pub struct SqliteTxn<'a> {
    txn: Transaction<'a>,
    mls: MlsStorage<'a>,
    #[cfg(feature = "testing")]
    fail_on: Option<WriteTarget>,
}

impl SqliteTxn<'_> {
    fn check(&self, _target: WriteTarget) -> StoreResult<()> {
        #[cfg(feature = "testing")]
        if self.fail_on == Some(_target) {
            return Err(StoreError::new(format!(
                "injected {_target:?} write failure"
            )));
        }
        Ok(())
    }

    fn execute(&self, sql: &str, params: impl rusqlite::Params) -> StoreResult<()> {
        self.txn
            .prepare_cached(sql)
            .and_then(|mut stmt| stmt.execute(params))
            .map_err(sql_err)?;
        Ok(())
    }
}

impl StateStore for SqliteStore {
    type Txn<'a> = SqliteTxn<'a>;

    fn transaction<R, F>(&self, f: F) -> Result<R, BaseError>
    where
        F: FnOnce(&mut SqliteTxn<'_>) -> Result<R, BaseError>,
    {
        let conn = self.conn();
        let mut txn = SqliteTxn {
            txn: Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)
                .map_err(sql_err)?,
            mls: SqliteStorageProvider::new(&*conn),
            #[cfg(feature = "testing")]
            fail_on: *self.fail_on.lock().unwrap_or_else(PoisonError::into_inner),
        };
        let result = f(&mut txn)?;
        txn.txn.commit().map_err(sql_err)?;
        Ok(result)
    }
}

macro_rules! delegate_reader {
    ($ty:ty, |$this:ident| $conn:expr) => {
        impl StateReader for $ty {
            fn chats(&self) -> StoreResult<Vec<Chat>> {
                let $this = self;
                Reader($conn).chats()
            }

            fn chat(&self, group_id: &GroupId) -> StoreResult<Option<Chat>> {
                let $this = self;
                Reader($conn).chat(group_id)
            }

            fn messages(
                &self,
                group_id: &GroupId,
                before_seq: Option<u64>,
                limit: usize,
            ) -> StoreResult<Vec<Message>> {
                let $this = self;
                Reader($conn).messages(group_id, before_seq, limit)
            }

            fn messages_after(
                &self,
                group_id: &GroupId,
                after_seq: u64,
            ) -> StoreResult<Vec<Message>> {
                let $this = self;
                Reader($conn).messages_after(group_id, after_seq)
            }

            fn message(&self, message_id: &MessageId) -> StoreResult<Option<Message>> {
                let $this = self;
                Reader($conn).message(message_id)
            }

            fn outbox_entry(&self, message_id: &MessageId) -> StoreResult<Option<OutboxEntry>> {
                let $this = self;
                Reader($conn).outbox_entry(message_id)
            }

            fn outbox_entries(&self) -> StoreResult<Vec<OutboxEntry>> {
                let $this = self;
                Reader($conn).outbox_entries()
            }

            fn outbox_due(&self, now_ms: u64, limit: usize) -> StoreResult<Vec<OutboxEntry>> {
                let $this = self;
                Reader($conn).outbox_due(now_ms, limit)
            }

            fn global_cursor(&self) -> StoreResult<Option<u64>> {
                let $this = self;
                Reader($conn).global_cursor()
            }

            fn group_cursor(&self, group_id: &GroupId) -> StoreResult<GroupCursor> {
                let $this = self;
                Reader($conn).group_cursor(group_id)
            }

            fn parked_messages(&self, group_id: &GroupId) -> StoreResult<Vec<GroupMessage>> {
                let $this = self;
                Reader($conn).parked_messages(group_id)
            }

            fn media(&self, blob_id: &str) -> StoreResult<Option<MediaCacheEntry>> {
                let $this = self;
                Reader($conn).media(blob_id)
            }

            fn media_entries(&self) -> StoreResult<Vec<MediaCacheEntry>> {
                let $this = self;
                Reader($conn).media_entries()
            }

            fn user(&self, user_id: &UserId) -> StoreResult<Option<UserInfo>> {
                let $this = self;
                Reader($conn).user(user_id)
            }

            fn pending_commit(&self, group_id: &GroupId) -> StoreResult<Option<PendingCommit>> {
                let $this = self;
                Reader($conn).pending_commit(group_id)
            }

            fn pending_commits(&self) -> StoreResult<Vec<PendingCommit>> {
                let $this = self;
                Reader($conn).pending_commits()
            }

            fn departed_members(&self) -> StoreResult<Vec<DepartedMember>> {
                let $this = self;
                Reader($conn).departed_members()
            }

            fn membership_events(&self, group_id: &GroupId) -> StoreResult<Vec<MembershipEvent>> {
                let $this = self;
                Reader($conn).membership_events(group_id)
            }
        }
    };
}

delegate_reader!(SqliteStore, |store| &store.conn());
delegate_reader!(SqliteTxn<'_>, |txn| &txn.txn);

impl StoreTxn for SqliteTxn<'_> {
    fn upsert_chat(&mut self, chat: &Chat) -> StoreResult<()> {
        self.check(WriteTarget::Chat)?;
        let data = encode(&ChatData {
            kind: chat.kind.into(),
            name: chat.name.clone(),
            avatar: chat.avatar.as_ref().map(Into::into),
            members: chat.members.iter().map(MemberRow::from).collect(),
            unread_count: chat.unread_count,
            last_message_id: chat.last_message_id.clone(),
            last_seq: chat.last_seq,
            last_read_seq: chat.last_read_seq,
            membership: chat.membership.into(),
        })?;
        self.execute(
            "INSERT OR REPLACE INTO chats (group_id, updated_at_ms, data) VALUES (?1, ?2, ?3)",
            params![chat.group_id.as_str(), chat.updated_at_ms, data],
        )
    }

    fn remove_chat(&mut self, group_id: &GroupId) -> StoreResult<()> {
        self.check(WriteTarget::Chat)?;
        for table in [
            "chats",
            "messages",
            "outbox",
            "group_cursors",
            "parked_messages",
            "pending_commits",
            "departed_members",
            "membership_events",
        ] {
            self.execute(
                &format!("DELETE FROM {table} WHERE group_id = ?1"),
                [group_id.as_str()],
            )?;
        }
        Ok(())
    }

    fn upsert_message(&mut self, message: &Message) -> StoreResult<()> {
        self.check(WriteTarget::Message)?;
        let data = encode(&MessageData {
            sender: message.sender.clone(),
            content: (&message.content).into(),
            reply_to: message.reply_to.clone(),
            edited: message.edited,
            deleted: message.deleted,
            reactions: message.reactions.clone(),
            send_state: message.send_state.map(Into::into),
            receipts: message
                .receipts
                .iter()
                .map(|(device, kind)| (device.clone(), *kind))
                .collect(),
        })?;
        self.execute(
            "INSERT OR REPLACE INTO messages (message_id, group_id, seq, sent_at_ms, data) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                message.message_id.as_str(),
                message.group_id.as_str(),
                message.seq,
                message.sent_at_ms,
                data
            ],
        )
    }

    fn remove_message(&mut self, message_id: &MessageId) -> StoreResult<()> {
        self.check(WriteTarget::Message)?;
        self.execute(
            "DELETE FROM messages WHERE message_id = ?1",
            [message_id.as_str()],
        )
    }

    fn upsert_outbox(&mut self, entry: &OutboxEntry) -> StoreResult<()> {
        self.check(WriteTarget::Outbox)?;
        let data = encode(&OutboxData {
            kind: OutboxKindRow::try_from(&entry.kind)?,
            attempts: entry.attempts,
            last_error: entry.last_error.clone(),
            prepared: entry.prepared.as_ref().map(Into::into),
        })?;
        self.execute(
            "INSERT OR REPLACE INTO outbox \
             (message_id, group_id, state, next_attempt_at_ms, created_at_ms, data) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.message_id.as_str(),
                entry.group_id.as_str(),
                outbox_state_str(entry.state),
                entry.next_attempt_at_ms,
                entry.created_at_ms,
                data
            ],
        )
    }

    fn remove_outbox(&mut self, message_id: &MessageId) -> StoreResult<()> {
        self.check(WriteTarget::Outbox)?;
        self.execute(
            "DELETE FROM outbox WHERE message_id = ?1",
            [message_id.as_str()],
        )
    }

    fn set_global_cursor(&mut self, cursor: u64) -> StoreResult<()> {
        self.check(WriteTarget::GroupCursor)?;
        self.execute(
            "INSERT INTO sync_state (id, global_cursor) VALUES (1, ?1) \
             ON CONFLICT (id) DO UPDATE SET global_cursor = excluded.global_cursor",
            [cursor],
        )
    }

    fn set_group_cursor(&mut self, group_id: &GroupId, cursor: &GroupCursor) -> StoreResult<()> {
        self.check(WriteTarget::GroupCursor)?;
        self.execute(
            "INSERT OR REPLACE INTO group_cursors (group_id, contiguous_seq, ahead) \
             VALUES (?1, ?2, ?3)",
            params![
                group_id.as_str(),
                cursor.contiguous_seq,
                encode(&cursor.ahead)?
            ],
        )
    }

    fn park_message(&mut self, message: &GroupMessage) -> StoreResult<()> {
        let data = encode(&ParkedData {
            sender: message.sender.clone(),
            kind: message.kind.into(),
            payload: serde_bytes::ByteBuf::from(message.payload.clone()),
            client_id: message.client_id.clone(),
        })?;
        self.execute(
            "INSERT OR REPLACE INTO parked_messages (group_id, seq, data) VALUES (?1, ?2, ?3)",
            params![message.group_id.as_str(), message.seq, data],
        )
    }

    fn unpark_message(&mut self, group_id: &GroupId, seq: u64) -> StoreResult<()> {
        self.execute(
            "DELETE FROM parked_messages WHERE group_id = ?1 AND seq = ?2",
            params![group_id.as_str(), bound(seq)],
        )
    }

    fn upsert_media(&mut self, entry: &MediaCacheEntry) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO media_cache (blob_id, local_path, size, last_access_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                entry.blob_id,
                entry.local_path,
                entry.size,
                entry.last_access_ms
            ],
        )
    }

    fn remove_media(&mut self, blob_id: &str) -> StoreResult<()> {
        self.execute("DELETE FROM media_cache WHERE blob_id = ?1", [blob_id])
    }

    fn upsert_user(&mut self, user: &UserInfo) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO users (user_id, handle, display_name) VALUES (?1, ?2, ?3)",
            params![user.user_id.as_str(), user.handle, user.display_name],
        )
    }

    fn upsert_pending_commit(&mut self, commit: &PendingCommit) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO pending_commits (group_id, data) VALUES (?1, ?2)",
            params![
                commit.group_id.as_str(),
                encode(&PendingCommitData::from(commit))?
            ],
        )
    }

    fn remove_pending_commit(&mut self, group_id: &GroupId) -> StoreResult<()> {
        self.execute(
            "DELETE FROM pending_commits WHERE group_id = ?1",
            [group_id.as_str()],
        )
    }

    fn add_departed_member(&mut self, member: &DepartedMember) -> StoreResult<()> {
        self.execute(
            "INSERT OR IGNORE INTO departed_members (group_id, user_id, device_id) \
             VALUES (?1, ?2, ?3)",
            params![
                member.group_id.as_str(),
                member.device.user_id.as_str(),
                member.device.device_id.as_str()
            ],
        )
    }

    fn remove_departed_member(&mut self, member: &DepartedMember) -> StoreResult<()> {
        self.execute(
            "DELETE FROM departed_members \
             WHERE group_id = ?1 AND user_id = ?2 AND device_id = ?3",
            params![
                member.group_id.as_str(),
                member.device.user_id.as_str(),
                member.device.device_id.as_str()
            ],
        )
    }

    fn add_membership_event(&mut self, event: &MembershipEvent) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO membership_events \
             (group_id, seq, user_id, actor, kind, at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.group_id.as_str(),
                event.seq,
                event.user_id.as_str(),
                event.actor.as_str(),
                membership_kind_str(event.kind),
                event.at_ms
            ],
        )
    }
}

impl<'a> CryptoStore for SqliteTxn<'a> {
    type MlsStorage = MlsStorage<'a>;
    type Error = StoreError;

    fn mls_storage(&self) -> &MlsStorage<'a> {
        &self.mls
    }

    fn load_identity(&self) -> StoreResult<Option<StoredIdentity>> {
        let mut stmt = self
            .txn
            .prepare_cached(
                "SELECT user_id, device_id, signature_private_key, signature_public_key \
                 FROM crypto_identity WHERE id = 1",
            )
            .map_err(sql_err)?;
        let mut rows = stmt.query([]).map_err(sql_err)?;
        let Some(row) = rows.next().map_err(sql_err)? else {
            return Ok(None);
        };
        let user_id: String = row.get(0).map_err(sql_err)?;
        let device_id: String = row.get(1).map_err(sql_err)?;
        Ok(Some(StoredIdentity {
            device: DeviceRef::parse(&user_id, &device_id).map_err(StoreError::new)?,
            signature_private_key: row.get(2).map_err(sql_err)?,
            signature_public_key: row.get(3).map_err(sql_err)?,
        }))
    }

    fn save_identity(&self, identity: &StoredIdentity) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO crypto_identity \
             (id, user_id, device_id, signature_private_key, signature_public_key) \
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                identity.device.user_id.as_str(),
                identity.device.device_id.as_str(),
                identity.signature_private_key,
                identity.signature_public_key
            ],
        )
    }

    fn group_ids(&self) -> StoreResult<BTreeSet<GroupId>> {
        let mut stmt = self
            .txn
            .prepare_cached("SELECT group_id FROM crypto_groups")
            .map_err(sql_err)?;
        let mut rows = stmt.query([]).map_err(sql_err)?;
        let mut ids = BTreeSet::new();
        while let Some(row) = rows.next().map_err(sql_err)? {
            ids.insert(
                GroupId::new(row.get::<_, String>(0).map_err(sql_err)?).map_err(StoreError::new)?,
            );
        }
        Ok(ids)
    }

    fn add_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        self.execute(
            "INSERT OR IGNORE INTO crypto_groups (group_id) VALUES (?1)",
            [group_id.as_str()],
        )
    }

    fn remove_group_id(&self, group_id: &GroupId) -> StoreResult<()> {
        self.execute(
            "DELETE FROM crypto_groups WHERE group_id = ?1",
            [group_id.as_str()],
        )
    }
}
