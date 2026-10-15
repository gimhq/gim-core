//! File-backed [`SecretStorage`] of a CLI profile.
//!
//! `secrets.json` maps each key to its base64 value. It is rewritten
//! atomically (temp file + rename) with mode 0600, and never read while
//! group or other permission bits are set. Meant for the CLI only: the apps
//! keep the session in the platform keychain/keystore.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use gim_sdk::{SecretStorage, SecretStorageError};

pub const SECRETS_FILE: &str = "secrets.json";

pub struct FileSecretStorage {
    path: PathBuf,
    /// Serializes read-modify-write cycles within the process.
    lock: Mutex<()>,
}

impl FileSecretStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    fn load(&self) -> Result<BTreeMap<String, String>, SecretStorageError> {
        let err = |e: &dyn std::fmt::Display| {
            SecretStorageError::new(format!("{}: {e}", self.path.display()))
        };
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(err(&e)),
        };
        if !metadata.is_file() {
            return Err(err(&"not a regular file"));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(err(&format_args!(
                "refusing to read: mode {mode:03o} gives group/other access (chmod 600 it)"
            )));
        }
        let data = fs::read(&self.path).map_err(|e| err(&e))?;
        serde_json::from_slice(&data).map_err(|e| err(&e))
    }

    fn save(&self, secrets: &BTreeMap<String, String>) -> Result<(), SecretStorageError> {
        let err =
            |e: std::io::Error| SecretStorageError::new(format!("{}: {e}", self.path.display()));
        let tmp = tmp_path(&self.path);
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != ErrorKind::NotFound => return Err(err(e)),
            _ => {}
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(err)?;
        let data = serde_json::to_vec_pretty(secrets).expect("string map serializes");
        file.write_all(&data).map_err(err)?;
        file.sync_all().map_err(err)?;
        fs::rename(&tmp, &self.path).map_err(err)
    }

    fn update(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, String>),
    ) -> Result<(), SecretStorageError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut secrets = self.load()?;
        f(&mut secrets);
        self.save(&secrets)
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

impl SecretStorage for FileSecretStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStorageError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.load()?
            .get(key)
            .map(|value| {
                STANDARD
                    .decode(value)
                    .map_err(|e| SecretStorageError::new(format!("secret {key}: {e}")))
            })
            .transpose()
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretStorageError> {
        self.update(|secrets| {
            secrets.insert(key.to_string(), STANDARD.encode(value));
        })
    }

    fn delete(&self, key: &str) -> Result<(), SecretStorageError> {
        self.update(|secrets| {
            secrets.remove(key);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn set_get_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRETS_FILE);
        let storage = FileSecretStorage::new(&path);
        assert_eq!(storage.get("a").unwrap(), None);
        storage.set("a", b"\x00secret\xff").unwrap();
        storage.set("b", b"other").unwrap();
        assert_eq!(
            storage.get("a").unwrap().as_deref(),
            Some(&b"\x00secret\xff"[..])
        );
        // A fresh instance reads what the first one wrote.
        let reopened = FileSecretStorage::new(&path);
        assert_eq!(reopened.get("b").unwrap().as_deref(), Some(&b"other"[..]));
        reopened.delete("a").unwrap();
        assert_eq!(storage.get("a").unwrap(), None);
        assert_eq!(storage.get("b").unwrap().as_deref(), Some(&b"other"[..]));
        assert!(!tmp_path(&path).exists());
    }

    #[test]
    fn file_is_written_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRETS_FILE);
        let storage = FileSecretStorage::new(&path);
        storage.set("k", b"v").unwrap();
        assert_eq!(mode(&path), 0o600);
        let stored: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored["k"], STANDARD.encode(b"v"));
    }

    #[test]
    fn refuses_group_or_other_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRETS_FILE);
        let storage = FileSecretStorage::new(&path);
        storage.set("k", b"v").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = storage.get("k").unwrap_err();
        assert!(err.to_string().contains("mode 644"), "{err}");
        assert!(storage.set("k", b"w").is_err());
        // Left as it was.
        assert_eq!(mode(&path), 0o644);
    }
}
