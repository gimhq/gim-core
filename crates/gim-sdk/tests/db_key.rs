//! `ClientBuilder::open`: the database key comes from SecretStorage, a new
//! key resets the database, and a failing SecretStorage fails the open.

use std::path::Path;
use std::sync::Arc;

use gim_base::model::UserInfo;
use gim_base::{BaseError, StateReader, StateStore, StoreTxn};
use gim_common::UserId;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::{ClientBuilder, ClientError, SecretStorage, SecretStorageError};
use gim_sqlite::{DbKey, SqliteStore, DATABASE_FILE_NAME};

type Builder = ClientBuilder<SqliteStore>;

/// Opens the store through the SDK; returns it and whether it was reset.
fn open(
    dir: &Path,
    secrets: Arc<dyn SecretStorage>,
) -> Result<(Arc<SqliteStore>, bool), ClientError> {
    let mut reset = false;
    let builder = Builder::open(Arc::new(FakeTransport::new()), secrets, |key, new_key| {
        let opened =
            SqliteStore::open_or_reset(dir, &DbKey::new(*key), new_key).map_err(BaseError::from)?;
        reset = opened.1;
        Ok::<_, BaseError>(opened)
    })?;
    let client = builder.data_dir(dir).build()?;
    Ok((client.store().clone(), reset))
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

fn stored_key(secrets: &MemorySecretStorage) -> Option<Vec<u8>> {
    secrets.get(Builder::DB_KEY_SECRET_KEY).unwrap()
}

#[test]
fn creates_a_key_and_reopens_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(MemorySecretStorage::new());
    let (store, reset) = open(dir.path(), secrets.clone()).unwrap();
    assert!(!reset);
    assert_eq!(Builder::DB_KEY_SECRET_KEY, "gim.db_key.v1");
    let key = stored_key(&secrets).unwrap();
    assert_eq!(key.len(), Builder::DB_KEY_LEN);
    add_alice(&store);
    drop(store);

    let bytes = std::fs::read(dir.path().join(DATABASE_FILE_NAME)).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3\0"));

    let (store, reset) = open(dir.path(), secrets.clone()).unwrap();
    assert!(!reset);
    assert!(has_alice(&store));
    assert_eq!(stored_key(&secrets).unwrap(), key);
}

#[test]
fn lost_key_resets_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(MemorySecretStorage::new());
    let (store, _) = open(dir.path(), secrets.clone()).unwrap();
    add_alice(&store);
    drop(store);
    let old_key = stored_key(&secrets).unwrap();

    secrets.delete(Builder::DB_KEY_SECRET_KEY).unwrap();
    let (store, reset) = open(dir.path(), secrets.clone()).unwrap();
    assert!(reset);
    assert!(!has_alice(&store));
    assert_ne!(stored_key(&secrets).unwrap(), old_key);
}

#[test]
fn wrong_stored_key_resets_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(MemorySecretStorage::new());
    let (store, _) = open(dir.path(), secrets.clone()).unwrap();
    add_alice(&store);
    drop(store);

    secrets
        .set(Builder::DB_KEY_SECRET_KEY, &[1; Builder::DB_KEY_LEN])
        .unwrap();
    let (store, reset) = open(dir.path(), secrets.clone()).unwrap();
    assert!(reset);
    assert!(!has_alice(&store));
}

#[test]
fn m1_plaintext_database_is_reset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DATABASE_FILE_NAME);
    // An M1 (plaintext) database file; the full fixture is in gim-sqlite.
    let mut m1 = b"SQLite format 3\0".to_vec();
    m1.resize(4096, 0);
    std::fs::write(&path, m1).unwrap();
    let secrets = Arc::new(MemorySecretStorage::new());
    // Even with a key already stored (M1 never stored one).
    secrets
        .set(Builder::DB_KEY_SECRET_KEY, &[1; Builder::DB_KEY_LEN])
        .unwrap();

    let (store, reset) = open(dir.path(), secrets).unwrap();
    assert!(reset);
    assert!(store.chats().unwrap().is_empty());
    drop(store);
    assert!(!std::fs::read(&path)
        .unwrap()
        .starts_with(b"SQLite format 3\0"));
}

/// Secret storage whose every call fails.
struct BrokenSecrets {
    fail_get: bool,
}

impl SecretStorage for BrokenSecrets {
    fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, SecretStorageError> {
        if self.fail_get {
            Err(SecretStorageError::new("keystore locked"))
        } else {
            Ok(None)
        }
    }

    fn set(&self, _key: &str, _value: &[u8]) -> Result<(), SecretStorageError> {
        Err(SecretStorageError::new("keystore locked"))
    }

    fn delete(&self, _key: &str) -> Result<(), SecretStorageError> {
        Err(SecretStorageError::new("keystore locked"))
    }
}

#[test]
fn failing_secret_storage_fails_without_touching_the_database() {
    for fail_get in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DATABASE_FILE_NAME);
        std::fs::write(&path, b"existing").unwrap();
        let err = open(dir.path(), Arc::new(BrokenSecrets { fail_get })).unwrap_err();
        assert!(matches!(err, ClientError::SecretStorage(_)), "{err:?}");
        assert_eq!(std::fs::read(&path).unwrap(), b"existing");
    }
}

#[test]
fn malformed_stored_key_fails() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(MemorySecretStorage::new());
    secrets.set(Builder::DB_KEY_SECRET_KEY, &[1; 16]).unwrap();
    let err = open(dir.path(), secrets).unwrap_err();
    assert!(matches!(err, ClientError::SecretStorage(_)), "{err:?}");
    assert!(!dir.path().join(DATABASE_FILE_NAME).exists());
}
