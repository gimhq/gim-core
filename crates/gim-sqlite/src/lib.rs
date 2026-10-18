//! rusqlite (bundled SQLCipher) implementation of `StateStore` +
//! `CryptoStore` on one encrypted database, migrations, and a shared
//! transaction so MLS state and message rows commit atomically.
//!
//! OpenMLS state is stored by `openmls_sqlite_storage` (MIT, used as a
//! dependency) in the same database file; its provider borrows the
//! connection that holds the open transaction, so its writes are part of it.

#![forbid(unsafe_code)]

mod migrations;
mod reader;
mod rows;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use gim_base::model::{
    Chat, DepartedMember, GroupCursor, GroupMessage, HubRecord, KeyPackageRecord, MediaCacheEntry,
    MembershipEvent, Message, OutboxEntry, PendingCommit, PendingInvite, PendingLeave, UserInfo,
};
use gim_base::{BaseError, StateReader, StateStore, StoreError, StoreTxn, WriteTarget};
use gim_common::{DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{CryptoStore, StoredIdentity};
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use rusqlite::{params, Connection, ErrorCode, Transaction, TransactionBehavior};
use zeroize::Zeroizing;

pub use migrations::{APPLICATION_ID, SCHEMA_VERSION};

use reader::{bound, hub_state_str, membership_kind_str, outbox_state_str, sql_err, Reader};
use rows::{
    encode, ChatData, MemberRow, MessageData, OutboxData, OutboxKindRow, ParkedData,
    PendingCommitData, PendingLeaveData,
};

type StoreResult<T> = Result<T, StoreError>;

/// File name of the database inside the data directory.
pub const DATABASE_FILE_NAME: &str = "gim.sqlite3";

/// How long a statement waits for another connection's write lock. The
/// app and its extension (iOS NSE) share the file; their writes are
/// serialized by the store lock above this crate (gim-sdk `StoreLock`), so
/// SQLite only waits out the other process's WAL checkpoints and the rare
/// write outside of it.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Page cache of a store opened by [`SqliteStore::open_for_extension`], in
/// KiB (SQLite's default is about 2 MiB).
const EXTENSION_CACHE_KIB: i64 = 512;

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

/// Length of a [`DbKey`] in bytes.
pub const DB_KEY_LEN: usize = 32;

/// Raw 256-bit SQLCipher key of the database. Zeroized on drop; `Debug`
/// does not print it.
pub struct DbKey(Zeroizing<[u8; DB_KEY_LEN]>);

impl DbKey {
    pub fn new(bytes: [u8; DB_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// `PRAGMA key` statement with the key as a raw blob literal, which
    /// skips SQLCipher's passphrase derivation.
    fn pragma(&self) -> Zeroizing<String> {
        let mut sql = Zeroizing::new(String::with_capacity(20 + 2 * DB_KEY_LEN));
        sql.push_str("PRAGMA key = \"x'");
        for byte in self.0.iter() {
            let _ = write!(sql, "{byte:02x}");
        }
        sql.push_str("'\";");
        sql
    }
}

impl std::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DbKey(..)")
    }
}

/// Error opening the database file.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The file cannot be read with the key: a wrong key, an M1 plaintext
    /// database, or not a database at all.
    #[error("database cannot be decrypted with this key")]
    NotADatabase,
    /// The file decrypts but is not a database of this build: a foreign
    /// `application_id` or a newer schema.
    #[error("incompatible database: {0}")]
    Incompatible(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl OpenError {
    pub fn is_not_a_database(&self) -> bool {
        matches!(self, Self::NotADatabase)
    }

    /// Whether [`SqliteStore::open_or_reset`] discards the file. Never true
    /// for I/O or other SQLite errors.
    fn resets(&self) -> bool {
        matches!(self, Self::NotADatabase | Self::Incompatible(_))
    }
}

impl From<OpenError> for StoreError {
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::Store(err) => err,
            err => StoreError::new(err),
        }
    }
}

impl From<OpenError> for BaseError {
    fn from(err: OpenError) -> Self {
        StoreError::from(err).into()
    }
}

impl SqliteStore {
    /// Opens (creating if needed) `<data_dir>/gim.sqlite3` encrypted with
    /// `key` and migrates it. A missing `data_dir` is created owner-only on
    /// Unix, since the database (and its -wal/-shm files) holds the
    /// device's private keys.
    ///
    /// Fails with [`OpenError::NotADatabase`] if the file does not decrypt
    /// with `key` (including M1 plaintext databases) and with
    /// [`OpenError::Incompatible`] if it is not a database of this build;
    /// the file is left untouched.
    pub fn open(data_dir: impl AsRef<Path>, key: &DbKey) -> Result<Self, OpenError> {
        let path = create_data_dir(data_dir.as_ref())?;
        Self::open_file(&path, key)
    }

    /// Like [`Self::open`] for an app extension (the iOS Notification
    /// Service Extension, limited to about 24 MB of memory) running next to
    /// the app on the same file: a small page cache. Never resets: a
    /// database it cannot open fails, and only the app may discard it.
    /// Forward migrations run as in [`Self::open`]; the caller holds the
    /// store lock while opening.
    pub fn open_for_extension(data_dir: impl AsRef<Path>, key: &DbKey) -> Result<Self, OpenError> {
        let store = Self::open(data_dir, key)?;
        store
            .conn()
            .pragma_update(None, "cache_size", -EXTENSION_CACHE_KIB)
            .map_err(sql_err)?;
        Ok(store)
    }

    /// Like [`Self::open`], but replaces a database that fails with
    /// [`OpenError::NotADatabase`] or [`OpenError::Incompatible`] by a new
    /// empty one. `discard_existing` deletes any existing database first
    /// (a new key cannot decrypt it). Returns whether local state was
    /// deleted.
    pub fn open_or_reset(
        data_dir: impl AsRef<Path>,
        key: &DbKey,
        discard_existing: bool,
    ) -> Result<(Self, bool), OpenError> {
        let path = create_data_dir(data_dir.as_ref())?;
        let discarded = discard_existing && delete_database(&path)?;
        match Self::open_file(&path, key) {
            Err(err) if err.resets() => {
                delete_database(&path)?;
                Ok((Self::open_file(&path, key)?, true))
            }
            opened => Ok((opened?, discarded)),
        }
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        Self::init(Connection::open_in_memory().map_err(sql_err)?)
    }

    fn open_file(path: &Path, key: &DbKey) -> Result<Self, OpenError> {
        let conn = Connection::open(path).map_err(sql_err)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(sql_err)?;
        // Must be the first statement on the connection.
        conn.execute_batch(&key.pragma()).map_err(sql_err)?;
        let tables: u64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .map_err(|err| match err.sqlite_error_code() {
                Some(ErrorCode::NotADatabase) => OpenError::NotADatabase,
                _ => sql_err(err).into(),
            })?;
        let application_id = migrations::application_id(&conn)?;
        let version = migrations::schema_version(&conn)?;
        let fresh = application_id == 0 && version == 0 && tables == 0;
        if !fresh && application_id != APPLICATION_ID {
            return Err(OpenError::Incompatible(format!(
                "application_id {application_id:#x}"
            )));
        }
        if version > SCHEMA_VERSION {
            return Err(OpenError::Incompatible(format!(
                "schema v{version} is newer than this build (v{SCHEMA_VERSION})"
            )));
        }
        Self::init(conn).map_err(OpenError::from)
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

/// Creates `data_dir` (owner-only on Unix) and returns the database path.
fn create_data_dir(data_dir: &Path) -> StoreResult<std::path::PathBuf> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(data_dir).map_err(StoreError::new)?;
    Ok(data_dir.join(DATABASE_FILE_NAME))
}

/// Deletes the database at `path` and its -wal/-shm/-journal files.
/// Returns whether the database file existed.
fn delete_database(path: &Path) -> StoreResult<bool> {
    let mut existed = false;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        match std::fs::remove_file(&file) {
            Ok(()) => existed |= suffix.is_empty(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(StoreError::new(err)),
        }
    }
    Ok(existed)
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

            fn hub_cursor(&self, hub_id: &str) -> StoreResult<Option<u64>> {
                let $this = self;
                Reader($conn).hub_cursor(hub_id)
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

            fn pending_leave(&self, group_id: &GroupId) -> StoreResult<Option<PendingLeave>> {
                let $this = self;
                Reader($conn).pending_leave(group_id)
            }

            fn pending_leaves(&self) -> StoreResult<Vec<PendingLeave>> {
                let $this = self;
                Reader($conn).pending_leaves()
            }

            fn pending_invites(&self) -> StoreResult<Vec<PendingInvite>> {
                let $this = self;
                Reader($conn).pending_invites()
            }

            fn departed_members(&self) -> StoreResult<Vec<DepartedMember>> {
                let $this = self;
                Reader($conn).departed_members()
            }

            fn membership_events(&self, group_id: &GroupId) -> StoreResult<Vec<MembershipEvent>> {
                let $this = self;
                Reader($conn).membership_events(group_id)
            }

            fn device_lists(&self) -> StoreResult<Vec<(UserId, Vec<u8>)>> {
                let $this = self;
                Reader($conn).device_lists()
            }

            fn self_groups(&self) -> StoreResult<Vec<GroupId>> {
                let $this = self;
                Reader($conn).self_groups()
            }

            fn hubs(&self) -> StoreResult<Vec<HubRecord>> {
                let $this = self;
                Reader($conn).hubs()
            }

            fn key_package_records(&self) -> StoreResult<Vec<KeyPackageRecord>> {
                let $this = self;
                Reader($conn).key_package_records()
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
            "pending_leaves",
            "pending_invites",
            "departed_members",
            "membership_events",
            "self_groups",
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
            failure: entry.failure.map(Into::into),
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

    fn set_hub_cursor(&mut self, hub_id: &str, cursor: u64) -> StoreResult<()> {
        self.check(WriteTarget::GroupCursor)?;
        self.execute(
            "INSERT OR REPLACE INTO hub_cursors (hub_id, cursor) VALUES (?1, ?2)",
            params![hub_id, cursor],
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

    fn upsert_pending_leave(&mut self, leave: &PendingLeave) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO pending_leaves (group_id, data) VALUES (?1, ?2)",
            params![
                leave.group_id.as_str(),
                encode(&PendingLeaveData::from(leave))?
            ],
        )
    }

    fn remove_pending_leave(&mut self, group_id: &GroupId) -> StoreResult<()> {
        self.execute(
            "DELETE FROM pending_leaves WHERE group_id = ?1",
            [group_id.as_str()],
        )
    }

    fn upsert_pending_invite(&mut self, invite: &PendingInvite) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO pending_invites \
             (group_id, user_id, created_at_ms, next_retry_at_ms, attempts) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                invite.group_id.as_str(),
                invite.user_id.as_str(),
                invite.created_at_ms,
                invite.next_retry_at_ms,
                invite.attempts
            ],
        )
    }

    fn remove_pending_invite(&mut self, group_id: &GroupId, user_id: &UserId) -> StoreResult<()> {
        self.execute(
            "DELETE FROM pending_invites WHERE group_id = ?1 AND user_id = ?2",
            [group_id.as_str(), user_id.as_str()],
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

    fn upsert_device_list(&mut self, user_id: &UserId, device_list: &[u8]) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO device_lists (user_id, data) VALUES (?1, ?2)",
            params![user_id.as_str(), device_list],
        )
    }
    fn add_self_group(&mut self, group_id: &GroupId) -> StoreResult<()> {
        self.execute(
            "INSERT OR IGNORE INTO self_groups (group_id) VALUES (?1)",
            [group_id.as_str()],
        )
    }

    fn upsert_hub(&mut self, hub: &HubRecord) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO hubs \
             (hub_id, url, priority, verified_root_pubkey, last_seen_ms, state, url_shared) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                hub.hub_id,
                hub.url,
                hub.priority,
                hub.verified_root_pubkey,
                hub.last_seen_ms,
                hub_state_str(hub.state),
                hub.url_shared
            ],
        )
    }

    fn remove_hub(&mut self, hub_id: &str) -> StoreResult<()> {
        self.execute("DELETE FROM hubs WHERE hub_id = ?1", [hub_id])
    }

    fn add_key_package_record(&mut self, record: &KeyPackageRecord) -> StoreResult<()> {
        self.execute(
            "INSERT INTO key_package_ledger (kp_ref, hub_id, last_resort, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.kp_ref,
                record.hub_id,
                record.last_resort,
                record.created_at_ms
            ],
        )
    }

    fn clear(&mut self) -> StoreResult<()> {
        // Every table but SQLite's own and the OpenMLS migration history,
        // so the OpenMLS tables are covered without naming them.
        let tables = self
            .txn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' \
                 AND name <> 'openmls_sqlite_storage_migrations'",
            )
            .and_then(|mut stmt| {
                stmt.query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(sql_err)?;
        self.txn
            .pragma_update(None, "defer_foreign_keys", true)
            .map_err(sql_err)?;
        for table in tables {
            self.txn
                .execute(&format!("DELETE FROM \"{table}\""), [])
                .map_err(sql_err)?;
        }
        Ok(())
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
                "SELECT user_id, device_id, signature_private_key, signature_public_key, \
                 credential FROM crypto_identity WHERE id = 1",
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
            credential: row.get(4).map_err(sql_err)?,
        }))
    }

    fn save_identity(&self, identity: &StoredIdentity) -> StoreResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO crypto_identity \
             (id, user_id, device_id, signature_private_key, signature_public_key, credential) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                identity.device.user_id.as_str(),
                identity.device.device_id.as_str(),
                identity.signature_private_key,
                identity.signature_public_key,
                identity.credential
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_credential_round_trip() {
        let store = SqliteStore::open_in_memory().unwrap();
        for credential in [vec![7u8; 48], vec![8u8; 40]] {
            let identity = StoredIdentity {
                device: DeviceRef::parse("alice", "phone").unwrap(),
                signature_private_key: vec![1; 32],
                signature_public_key: vec![2; 32],
                credential,
            };
            store
                .transaction(|txn| Ok(txn.save_identity(&identity)?))
                .unwrap();
            let loaded = store.transaction(|txn| Ok(txn.load_identity()?)).unwrap();
            assert_eq!(loaded, Some(identity));
        }
    }
}
