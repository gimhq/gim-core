//! One database file shared by the app and an app extension (iOS NSE):
//! two connections write and read concurrently, and the extension never
//! resets a database it cannot open.

mod common;

use std::sync::Arc;

use common::key;
use gim_base::model::UserInfo;
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_common::UserId;
use gim_sqlite::{DbKey, OpenError, SqliteStore, DATABASE_FILE_NAME, SCHEMA_VERSION};
use rusqlite::Connection;

fn user(name: &str) -> UserInfo {
    UserInfo {
        user_id: UserId::new(name).unwrap(),
        handle: name.into(),
        display_name: name.into(),
    }
}

#[test]
fn app_and_extension_write_the_same_file_concurrently() {
    let dir = tempfile::tempdir().unwrap();
    let app = Arc::new(SqliteStore::open(dir.path(), &key()).unwrap());
    let extension = Arc::new(SqliteStore::open_for_extension(dir.path(), &key()).unwrap());
    let writers: Vec<_> = [("app", app.clone()), ("nse", extension.clone())]
        .into_iter()
        .map(|(prefix, store)| {
            std::thread::spawn(move || {
                for i in 0..50 {
                    let user = user(&format!("{prefix}{i}"));
                    store
                        .transaction(|txn| Ok(txn.upsert_user(&user)?))
                        .unwrap();
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    for store in [&app, &extension] {
        for prefix in ["app", "nse"] {
            for i in 0..50 {
                let id = UserId::new(format!("{prefix}{i}")).unwrap();
                assert!(store.user(&id).unwrap().is_some(), "{prefix}{i}");
            }
        }
    }
    let conn = Connection::open(dir.path().join(DATABASE_FILE_NAME)).unwrap();
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", "07".repeat(32)))
        .unwrap();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn extension_never_resets_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(dir.path(), &key()).unwrap();
    store
        .transaction(|txn| Ok(txn.upsert_user(&user("alice"))?))
        .unwrap();
    drop(store);

    let wrong = DbKey::new([9; 32]);
    assert!(matches!(
        SqliteStore::open_for_extension(dir.path(), &wrong),
        Err(OpenError::NotADatabase)
    ));
    // A newer app version migrated the file: the older extension fails.
    let conn = Connection::open(dir.path().join(DATABASE_FILE_NAME)).unwrap();
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", "07".repeat(32)))
        .unwrap();
    conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);
    assert!(matches!(
        SqliteStore::open_for_extension(dir.path(), &key()),
        Err(OpenError::Incompatible(_))
    ));

    let conn = Connection::open(dir.path().join(DATABASE_FILE_NAME)).unwrap();
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", "07".repeat(32)))
        .unwrap();
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    drop(conn);
    let store = SqliteStore::open_for_extension(dir.path(), &key()).unwrap();
    assert!(store.user(&user("alice").user_id).unwrap().is_some());
}
