//! Profile directory: `gim.sqlite3` (SQLCipher store), `secrets.json`
//! (session and database key), `config.json` (server URL), `tmp/` (media
//! temp files).

use std::fs;
use std::io::ErrorKind as IoErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gim_base::BaseError;
use gim_sdk::http::Url;
use gim_sdk::{Client, ClientBuilder, HttpTransport, Session};
use gim_sqlite::{DbKey, SqliteStore};
use serde::{Deserialize, Serialize};

use crate::error::{CliError, ErrorKind, Result};
use crate::secrets::{FileSecretStorage, SECRETS_FILE};

pub const CONFIG_FILE: &str = "config.json";

pub type GimClient = Client<SqliteStore>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

impl Config {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(CONFIG_FILE);
        match fs::read(&path) {
            Ok(data) => serde_json::from_slice(&data)
                .map_err(|e| CliError::other(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == IoErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join(CONFIG_FILE);
        let tmp = dir.join(format!("{CONFIG_FILE}.tmp"));
        let data = serde_json::to_vec_pretty(self).expect("config serializes");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

pub struct Profile {
    pub dir: PathBuf,
    pub config: Config,
}

impl Profile {
    /// Opens the profile, creating its directory (0700) if needed.
    pub fn create(dir: &Path) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        Self::load(dir)
    }

    /// Opens an existing profile; a missing directory is an unregistered
    /// profile.
    pub fn open(dir: &Path) -> Result<Self> {
        if !dir.is_dir() {
            return Err(CliError::not_registered());
        }
        Self::load(dir)
    }

    fn load(dir: &Path) -> Result<Self> {
        let dir = std::path::absolute(dir)?;
        let config = Config::load(&dir)?;
        Ok(Self { dir, config })
    }

    /// `--server`, else the configured server.
    pub fn server(&self, server: Option<&str>) -> Option<String> {
        server
            .map(str::to_string)
            .or_else(|| self.config.server.clone())
    }

    /// A client without a session.
    pub fn client(&self, server: &str) -> Result<GimClient> {
        let url = Url::parse(server)
            .map_err(|e| CliError::usage(format!("invalid server URL {server:?}: {e}")))?;
        let transport =
            HttpTransport::new(url).map_err(|e| CliError::new(ErrorKind::Server, e.to_string()))?;
        let secrets = FileSecretStorage::new(self.dir.join(SECRETS_FILE));
        let mut reset = false;
        let builder =
            ClientBuilder::open(Arc::new(transport), Arc::new(secrets), |key, new_key| {
                let opened = SqliteStore::open_or_reset(&self.dir, &DbKey::new(*key), new_key)
                    .map_err(BaseError::from)?;
                reset = opened.1;
                Ok::<_, BaseError>(opened)
            })?;
        if reset {
            // An M1 plaintext database (or one the stored key cannot
            // decrypt) was wiped.
            eprintln!(
                "gim: local database in {} was reset; local state is lost",
                self.dir.display()
            );
        }
        Ok(builder.data_dir(&self.dir).build()?)
    }
}

/// A registered client with its session restored and the store caught up.
pub struct Ctx {
    pub client: GimClient,
    pub session: Session,
    pub server: String,
}

impl Ctx {
    pub async fn connect(dir: &Path, server: Option<&str>) -> Result<Self> {
        let profile = Profile::open(dir)?;
        let server = profile
            .server(server)
            .ok_or_else(CliError::not_registered)?;
        let client = profile.client(&server)?;
        if !client.restore_session().await? {
            return Err(CliError::not_registered());
        }
        let session = client.session().ok_or_else(CliError::not_registered)?;
        // Reads must see the server's state: a failed sync fails the command.
        client.sync_once().await.map_err(|e| {
            let err = CliError::from(e);
            let kind = match err.kind {
                ErrorKind::NotFound => ErrorKind::NotFound,
                _ => ErrorKind::Server,
            };
            CliError::new(kind, format!("sync failed: {}", err.message))
        })?;
        Ok(Self {
            client,
            session,
            server,
        })
    }

    pub fn store(&self) -> &SqliteStore {
        self.client.store()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Config::load(dir.path()).unwrap(), Config::default());
        let config = Config {
            server: Some("https://gim.example.eu".into()),
        };
        config.save(dir.path()).unwrap();
        assert_eq!(Config::load(dir.path()).unwrap(), config);
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join(CONFIG_FILE)).unwrap()).unwrap();
        assert_eq!(raw, serde_json::json!({"server": "https://gim.example.eu"}));
    }

    #[test]
    fn profile_dir_is_owner_only_and_server_override_wins() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("alice");
        assert_eq!(
            Profile::open(&dir).err().map(|e| e.kind),
            Some(ErrorKind::NotFound)
        );
        let profile = Profile::create(&dir).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert_eq!(profile.server(None), None);
        Config {
            server: Some("http://a".into()),
        }
        .save(&dir)
        .unwrap();
        let profile = Profile::open(&dir).unwrap();
        assert_eq!(profile.server(None).as_deref(), Some("http://a"));
        assert_eq!(
            profile.server(Some("http://b")).as_deref(),
            Some("http://b")
        );
    }

    #[test]
    fn client_keys_the_store_from_secrets_and_wipes_an_unreadable_db() {
        use gim_sdk::SecretStorage;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("alice");
        let profile = Profile::create(&dir).unwrap();
        let db = dir.join(gim_sqlite::DATABASE_FILE_NAME);
        // Stands in for an M1 plaintext database.
        fs::write(&db, b"not an encrypted database").unwrap();
        drop(profile.client("http://127.0.0.1:1").unwrap());
        assert_ne!(fs::read(&db).unwrap(), b"not an encrypted database");
        let secrets = FileSecretStorage::new(dir.join(SECRETS_FILE));
        let key = secrets
            .get(ClientBuilder::<SqliteStore>::DB_KEY_SECRET_KEY)
            .unwrap()
            .unwrap();
        assert_eq!(key.len(), ClientBuilder::<SqliteStore>::DB_KEY_LEN);
        // Reopening with the stored key keeps the database and the key.
        let encrypted = fs::read(&db).unwrap();
        drop(profile.client("http://127.0.0.1:1").unwrap());
        assert_eq!(fs::read(&db).unwrap()[..16], encrypted[..16]);
        assert_eq!(
            secrets
                .get(ClientBuilder::<SqliteStore>::DB_KEY_SECRET_KEY)
                .unwrap(),
            Some(key)
        );
    }
}
