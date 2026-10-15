//! SQLCipher encryption of the database file and the reset of M1 (plaintext),
//! undecryptable and foreign databases.

mod common;

use std::path::{Path, PathBuf};

use common::key;
use gim_base::model::UserInfo;
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_common::UserId;
use gim_sqlite::{
    DbKey, OpenError, SqliteStore, APPLICATION_ID, DATABASE_FILE_NAME, SCHEMA_VERSION,
};
use rusqlite::Connection;

const PLAINTEXT_HEADER: &[u8] = b"SQLite format 3\0";

fn db(dir: &Path) -> PathBuf {
    dir.join(DATABASE_FILE_NAME)
}

fn other_key() -> DbKey {
    DbKey::new([9; 32])
}

fn alice() -> UserInfo {
    UserInfo {
        user_id: UserId::new("alice").unwrap(),
        handle: "alice".into(),
        display_name: "Alice".into(),
    }
}

fn add_alice(store: &SqliteStore) {
    store
        .transaction(|txn| Ok(txn.upsert_user(&alice())?))
        .unwrap();
}

fn has_alice(store: &SqliteStore) -> bool {
    store.user(&alice().user_id).unwrap().is_some()
}

/// A raw connection keyed like [`key`].
fn raw_keyed(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", "07".repeat(32)))
        .unwrap();
    conn
}

fn open_err(dir: &Path, key: &DbKey) -> OpenError {
    match SqliteStore::open(dir, key) {
        Ok(_) => panic!("opened"),
        Err(err) => err,
    }
}

#[test]
fn file_is_encrypted_and_reopens_with_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(dir.path(), &key()).unwrap();
    add_alice(&store);
    drop(store);

    let bytes = std::fs::read(db(dir.path())).unwrap();
    assert!(!bytes.is_empty());
    assert!(!bytes.starts_with(PLAINTEXT_HEADER));
    assert!(!bytes.windows(5).any(|w| w == b"alice"));

    let store = SqliteStore::open(dir.path(), &key()).unwrap();
    assert!(has_alice(&store));
    let conn = raw_keyed(&db(dir.path()));
    let app_id: i32 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap();
    assert_eq!(app_id, APPLICATION_ID);
}

#[test]
fn wrong_key_is_not_a_database_and_keeps_the_file() {
    let dir = tempfile::tempdir().unwrap();
    add_alice(&SqliteStore::open(dir.path(), &key()).unwrap());
    let before = std::fs::read(db(dir.path())).unwrap();

    let err = open_err(dir.path(), &other_key());
    assert!(err.is_not_a_database(), "{err:?}");
    assert_eq!(std::fs::read(db(dir.path())).unwrap(), before);
    assert!(has_alice(&SqliteStore::open(dir.path(), &key()).unwrap()));
}

#[test]
fn open_or_reset_replaces_an_undecryptable_database() {
    let dir = tempfile::tempdir().unwrap();
    add_alice(&SqliteStore::open(dir.path(), &key()).unwrap());

    let (store, reset) = SqliteStore::open_or_reset(dir.path(), &other_key(), false).unwrap();
    assert!(reset);
    assert!(!has_alice(&store));
    add_alice(&store);
    drop(store);
    // The new database is keyed with the new key.
    assert!(open_err(dir.path(), &key()).is_not_a_database());
    let (store, reset) = SqliteStore::open_or_reset(dir.path(), &other_key(), false).unwrap();
    assert!(!reset);
    assert!(has_alice(&store));
}

#[test]
fn m1_plaintext_database_is_reset() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(dir.path());
    // An M1 database: plaintext (SQLCipher without a key), schema v4.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE chats (group_id TEXT PRIMARY KEY, updated_at_ms INTEGER, data BLOB);
             INSERT INTO chats VALUES ('crew', 7, x'00');
             PRAGMA user_version = 4;",
        )
        .unwrap();
    }
    std::fs::write(
        dir.path().join(format!("{DATABASE_FILE_NAME}-journal")),
        b"x",
    )
    .unwrap();
    assert!(std::fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));

    assert!(open_err(dir.path(), &key()).is_not_a_database());
    assert!(std::fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));

    let (store, reset) = SqliteStore::open_or_reset(dir.path(), &key(), false).unwrap();
    assert!(reset);
    add_alice(&store);
    drop(store);
    assert!(!std::fs::read(&path).unwrap().starts_with(PLAINTEXT_HEADER));
    assert!(!dir
        .path()
        .join(format!("{DATABASE_FILE_NAME}-journal"))
        .exists());
    let store = SqliteStore::open(dir.path(), &key()).unwrap();
    assert!(has_alice(&store));
    assert!(store.chats().unwrap().is_empty());
}

#[test]
fn foreign_application_id_is_reset() {
    let dir = tempfile::tempdir().unwrap();
    {
        let conn = raw_keyed(&db(dir.path()));
        conn.execute_batch("CREATE TABLE other (x); PRAGMA application_id = 4660;")
            .unwrap();
    }
    let err = open_err(dir.path(), &key());
    assert!(matches!(err, OpenError::Incompatible(_)), "{err:?}");

    let (store, reset) = SqliteStore::open_or_reset(dir.path(), &key(), false).unwrap();
    assert!(reset);
    add_alice(&store);
}

#[test]
fn newer_schema_is_reset() {
    let dir = tempfile::tempdir().unwrap();
    add_alice(&SqliteStore::open(dir.path(), &key()).unwrap());
    raw_keyed(&db(dir.path()))
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    let err = open_err(dir.path(), &key());
    assert!(matches!(err, OpenError::Incompatible(_)), "{err:?}");

    let (store, reset) = SqliteStore::open_or_reset(dir.path(), &key(), false).unwrap();
    assert!(reset);
    assert!(!has_alice(&store));
}

#[test]
fn discard_existing_deletes_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let (store, reset) = SqliteStore::open_or_reset(dir.path(), &key(), true).unwrap();
    assert!(!reset, "nothing to discard");
    add_alice(&store);
    drop(store);

    let (store, reset) = SqliteStore::open_or_reset(dir.path(), &key(), true).unwrap();
    assert!(reset);
    assert!(!has_alice(&store));
}

#[test]
fn other_open_errors_never_delete() {
    let dir = tempfile::tempdir().unwrap();
    // The database path is a directory: SQLite cannot open it.
    std::fs::create_dir(db(dir.path())).unwrap();
    std::fs::write(db(dir.path()).join("keep"), b"x").unwrap();
    match SqliteStore::open_or_reset(dir.path(), &key(), false) {
        Err(OpenError::Store(_)) => {}
        other => panic!("{:?}", other.map(|(_, reset)| reset)),
    }
    assert!(db(dir.path()).join("keep").is_file());
}

#[test]
fn key_debug_is_redacted() {
    assert_eq!(format!("{:?}", key()), "DbKey(..)");
}
