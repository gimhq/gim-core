//! The async client of one device.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::task::JoinHandle;

use gim_base::model::{
    AfterCommit, ChatKind, DepartedMember, Membership, MessageKind, PendingCommit, PendingWelcome,
    StateChange, UserInfo,
};
use gim_base::{
    new_message_id, BaseClient, BaseError, StateReader, StateStore, StoreError, StoreTxn,
};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{CryptoStore, MlsEngine};
use gim_proto::envelope::Content;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex, Notify};

use crate::send::TypingState;
use crate::stream::ConnectionState;
use crate::sync::SyncSettings;
use crate::transport::{AccessToken, OutgoingMessage, PostError, Transport, TransportError};
use crate::{ClientError, Result, SecretStorage, SecretStorageError};

/// One-time KeyPackages uploaded at registration and per replenish.
pub const KEY_PACKAGE_BATCH: u32 = 100;
/// Retries of a commit rejected because another commit won the epoch.
pub const MAX_COMMIT_RETRIES: u32 = 3;
/// Posts of the same commit (same `client_id`) while its outcome is
/// unknown, before the call gives up and keeps it pending.
pub const COMMIT_POST_ATTEMPTS: u32 = 3;
/// [`SecretStorage`] key of the serialized [`Session`].
pub const SESSION_SECRET_KEY: &str = "gim.session";

/// See [`ClientBuilder::DB_KEY_LEN`].
const DATABASE_KEY_LEN: usize = 32;
/// Buffered [`StateChange`]s per subscriber before it lags.
const CHANGES_CAPACITY: usize = 1024;
/// Buffered [`ConnectionState`]s per subscriber before it lags.
const CONNECTION_CAPACITY: usize = 64;
/// Delay before re-posting a commit after an unknown outcome, times the
/// attempt number.
const COMMIT_REPOST_DELAY: Duration = Duration::from_millis(100);

/// A registered device: who it is and its bearer token. Persisted in
/// [`SecretStorage`]; the MLS signature key lives in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub device: DeviceRef,
    pub token: AccessToken,
}

/// Builds a [`Client`].
pub struct ClientBuilder<S> {
    store: Arc<S>,
    transport: Arc<dyn Transport>,
    secrets: Arc<dyn SecretStorage>,
    data_dir: Option<PathBuf>,
    sync_settings: SyncSettings,
}

impl<S: StateStore + 'static> ClientBuilder<S> {
    pub fn new(
        store: Arc<S>,
        transport: Arc<dyn Transport>,
        secrets: Arc<dyn SecretStorage>,
    ) -> Self {
        Self {
            store,
            transport,
            secrets,
            data_dir: None,
            sync_settings: SyncSettings::default(),
        }
    }

    /// [`SecretStorage`] key of the local database key.
    pub const DB_KEY_SECRET_KEY: &'static str = "gim.db_key.v1";
    /// Length of the local database key in bytes.
    pub const DB_KEY_LEN: usize = DATABASE_KEY_LEN;

    /// Like [`Self::new`], over a store opened with the database key from
    /// `secrets`. Blocking: call it off the async runtime.
    ///
    /// Without a stored key a random one is created and stored first, and
    /// `open_store(key, true)` must discard any existing database, which
    /// that key cannot decrypt. `open_store` returns the store and whether
    /// it wiped local state. A failing `secrets` fails the call: the store
    /// is never opened without a key.
    pub fn open<E>(
        transport: Arc<dyn Transport>,
        secrets: Arc<dyn SecretStorage>,
        open_store: impl FnOnce(&[u8; DATABASE_KEY_LEN], bool) -> std::result::Result<(S, bool), E>,
    ) -> Result<Self>
    where
        ClientError: From<E>,
    {
        let mut key = [0u8; DATABASE_KEY_LEN];
        let new_key = match secrets.get(Self::DB_KEY_SECRET_KEY)? {
            Some(mut stored) => {
                let len = stored.len();
                if len == key.len() {
                    key.copy_from_slice(&stored);
                }
                stored.fill(0);
                if len != key.len() {
                    return Err(SecretStorageError::new(format!(
                        "stored database key has {len} bytes, expected {}",
                        Self::DB_KEY_LEN
                    ))
                    .into());
                }
                false
            }
            None => {
                rustls::crypto::ring::default_provider()
                    .secure_random
                    .fill(&mut key)
                    .map_err(|_| BaseError::Random("database key".into()))?;
                if let Err(err) = secrets.set(Self::DB_KEY_SECRET_KEY, &key) {
                    key.fill(0);
                    return Err(err.into());
                }
                true
            }
        };
        let opened = open_store(&key, new_key);
        key.fill(0);
        let (store, reset) = opened?;
        if reset {
            tracing::warn!("local database was reset; local state is lost");
        }
        Ok(Self::new(Arc::new(store), transport, secrets))
    }

    /// Timing of the sync loop; see [`SyncSettings`].
    pub fn sync_settings(mut self, settings: SyncSettings) -> Self {
        self.sync_settings = settings;
        self
    }

    /// App-private directory; temporary media files (encrypted uploads,
    /// partial downloads) go to its `tmp` subdirectory. Required.
    pub fn data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    /// A client without a session; call [`Client::register`] or
    /// [`Client::restore_session`] next.
    ///
    /// Creates the data directory and its `tmp` subdirectory owner-only
    /// (0700 on Unix). Fails with [`ClientError::InvalidInput`] if no data
    /// directory was given or if `tmp` is a symlink, not a directory, or
    /// writable by group or others.
    pub fn build(self) -> Result<Client<S>> {
        let data_dir = self
            .data_dir
            .ok_or_else(|| ClientError::InvalidInput("data_dir is required".into()))?;
        create_private_dirs(&data_dir)?;
        Ok(Client {
            inner: Arc::new(Inner {
                store: self.store,
                transport: self.transport,
                secrets: self.secrets,
                engine: MlsEngine::new(),
                session: RwLock::new(None),
                changes: broadcast::channel(CHANGES_CAPACITY).0,
                group_lock: Mutex::new(()),
                data_dir,
                flush_lock: Mutex::new(()),
                outbox_wake: Notify::new(),
                force_flush: AtomicBool::new(false),
                typing: Default::default(),
                sync_settings: self.sync_settings,
                sync_task: Default::default(),
                sync_wake: Notify::new(),
                connection: std::sync::Mutex::new(ConnectionState::Offline),
                connection_changes: broadcast::channel(CONNECTION_CAPACITY).0,
                resolved_users: Default::default(),
            }),
        })
    }
}

/// Creates `data_dir` and `data_dir/tmp` owner-only and checks that `tmp`
/// is a real directory nobody else can write to.
fn create_private_dirs(data_dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(data_dir)?;
    let tmp = data_dir.join("tmp");
    builder.recursive(false);
    match builder.create(&tmp) {
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        created => created?,
    }
    let insecure = |reason: &str| {
        ClientError::InvalidInput(format!("temp directory {}: {reason}", tmp.display()))
    };
    let metadata = std::fs::symlink_metadata(&tmp)?;
    if metadata.file_type().is_symlink() {
        return Err(insecure("is a symlink"));
    }
    if !metadata.is_dir() {
        return Err(insecure("is not a directory"));
    }
    #[cfg(unix)]
    if std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o022 != 0 {
        return Err(insecure("is writable by group or others"));
    }
    Ok(())
}

/// The client of one device. Cheap to clone; clones share all state.
pub struct Client<S> {
    pub(crate) inner: Arc<Inner<S>>,
}

impl<S> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub(crate) struct Inner<S> {
    store: Arc<S>,
    pub(crate) transport: Arc<dyn Transport>,
    secrets: Arc<dyn SecretStorage>,
    engine: MlsEngine,
    session: RwLock<Option<Session>>,
    changes: broadcast::Sender<StateChange>,
    /// Serializes everything that touches MLS group state (sync, commits,
    /// sends): a pending commit must not meet an incoming commit or an
    /// outgoing application message.
    pub(crate) group_lock: Mutex<()>,
    pub(crate) data_dir: PathBuf,
    /// Serializes outbox passes, so a media upload is never done twice.
    pub(crate) flush_lock: Mutex<()>,
    pub(crate) outbox_wake: Notify,
    /// Set when the network came back: the next pass ignores backoff.
    pub(crate) force_flush: AtomicBool,
    pub(crate) typing: std::sync::Mutex<HashMap<GroupId, TypingState>>,
    pub(crate) sync_settings: SyncSettings,
    pub(crate) sync_task: std::sync::Mutex<Option<JoinHandle<Result<()>>>>,
    /// Cuts the sync loop's reconnect wait short.
    pub(crate) sync_wake: Notify,
    pub(crate) connection: std::sync::Mutex<ConnectionState>,
    pub(crate) connection_changes: broadcast::Sender<ConnectionState>,
    /// Users found in the user directory cache or unknown to the server's
    /// directory; not looked up again.
    pub(crate) resolved_users: std::sync::Mutex<HashSet<UserId>>,
}

#[derive(Clone)]
enum CommitOp {
    Add(Vec<(DeviceRef, Vec<u8>)>),
    /// `fan_out`: also drop the removed devices from the fan-out list once
    /// the commit is accepted.
    Remove {
        devices: Vec<DeviceRef>,
        fan_out: bool,
    },
}

enum Resolved {
    /// No pending commit for the group.
    None,
    Accepted,
    /// Another commit won the epoch; the pending commit was dropped.
    Conflict,
}

/// Whether the server may have accepted a request that failed this way.
pub(crate) fn outcome_unknown(err: &TransportError) -> bool {
    matches!(err, TransportError::Network(_) | TransportError::Server(_))
}

impl<S: StateStore + 'static> Client<S> {
    pub fn store(&self) -> &Arc<S> {
        &self.inner.store
    }

    pub fn session(&self) -> Option<Session> {
        self.inner
            .session
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Every [`StateChange`] the client applies, for gim-ui.
    pub fn subscribe_changes(&self) -> broadcast::Receiver<StateChange> {
        self.inner.changes.subscribe()
    }

    /// Registers this device: creates the MLS identity, persists the
    /// session and uploads [`KEY_PACKAGE_BATCH`] KeyPackages plus a
    /// last-resort one. A handle that already exists gets a new device of
    /// that user.
    pub async fn register(&self, handle: &str, display_name: &str) -> Result<Session> {
        if self.session().is_some() {
            return Err(ClientError::AlreadyLoggedIn);
        }
        let registration = self
            .inner
            .transport
            .register_device(handle, display_name)
            .await?;
        let device = registration.device.clone();
        let me = UserInfo {
            user_id: device.user_id.clone(),
            handle: handle.to_string(),
            display_name: display_name.to_string(),
        };
        let cursor = registration.cursor;
        let (key_packages, last_resort) = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    engine.create_identity(&*txn, device)?;
                    txn.set_global_cursor(cursor)?;
                    txn.upsert_user(&me)?;
                    Ok((
                        engine.generate_key_packages(&*txn, KEY_PACKAGE_BATCH)?,
                        engine.generate_last_resort_key_package(&*txn)?,
                    ))
                })
            })
            .await?;
        let session = Session {
            device: registration.device,
            token: registration.token,
        };
        let encoded = serde_json::to_vec(&session).expect("session serializes");
        self.inner.secrets.set(SESSION_SECRET_KEY, &encoded)?;
        self.set_session(session.clone());
        self.inner
            .transport
            .upload_key_packages(&session.token, key_packages, Some(last_resort))
            .await?;
        Ok(session)
    }

    /// Restores the session persisted by [`Client::register`]; `false` if
    /// there is none, or if the store lost the device identity (database
    /// reset or deleted), in which case the stale session secret is
    /// deleted. Reconciles MLS pending commits with their records, then
    /// removes file copies under
    /// [`Client::outgoing_dir`] that no queued upload needs, and re-posts
    /// commits whose outcome was unknown when the previous run stopped.
    pub async fn restore_session(&self) -> Result<bool> {
        let Some(encoded) = self.inner.secrets.get(SESSION_SECRET_KEY)? else {
            return Ok(false);
        };
        let session: Session = serde_json::from_slice(&encoded)
            .map_err(|e| ClientError::InvalidSession(e.to_string()))?;
        let identity = self
            .run(|store, _| {
                store.transaction(|txn| {
                    let stored = txn.load_identity().map_err(StoreError::new)?;
                    Ok(stored.map(|identity| identity.device))
                })
            })
            .await?;
        let Some(identity) = identity else {
            // The local database was reset or deleted: the session cannot
            // be used without its MLS identity.
            tracing::warn!("stored session has no local identity; signing out");
            self.inner.secrets.delete(SESSION_SECRET_KEY)?;
            return Ok(false);
        };
        if identity != session.device {
            return Err(ClientError::InvalidSession(format!(
                "store identity {identity} does not match session device {}",
                session.device
            )));
        }
        let base = BaseClient::new(session.device.clone());
        let repaired = self
            .run(move |store, engine| base.reconcile_pending_commits(store, engine))
            .await?;
        if !repaired.is_empty() {
            tracing::warn!(groups = ?repaired, "dropped dangling pending commits");
        }
        self.seed_device_directory(&session).await?;
        self.set_session(session.clone());
        self.clean_outgoing().await?;
        // Finish what the previous run left: re-post its pending commits
        // (same client_id) and remove departed members. Best effort: the
        // same work is retried before the next sync, commit or send of
        // each group.
        let _guard = self.inner.group_lock.lock().await;
        let resumed = match self.resolve_pending_commits(&session).await {
            Ok(()) => self.remove_departed(&session).await,
            err => err,
        };
        if let Err(err) = resumed {
            tracing::warn!(%err, "resuming unfinished group changes failed");
        }
        Ok(true)
    }

    /// Looks a user up by handle and caches it in the user directory.
    pub async fn find_user(&self, handle: &str) -> Result<Option<UserInfo>> {
        let session = self.require_session()?;
        let user = self
            .inner
            .transport
            .find_user(&session.token, handle)
            .await?;
        if let Some(user) = user.clone() {
            self.run(move |store, _| store.transaction(|txn| Ok(txn.upsert_user(&user)?)))
                .await?;
        }
        Ok(user)
    }

    /// Creates a direct chat with every device of `user_id` (and this user's
    /// other devices).
    pub async fn create_direct_chat(&self, user_id: &UserId) -> Result<GroupId> {
        self.create_chat(ChatKind::Direct, None, std::slice::from_ref(user_id))
            .await
    }

    /// Creates a group chat with every device of `users` (and this user's
    /// other devices). The name is shared with the members in a group info
    /// message once they are added.
    pub async fn create_group_chat(
        &self,
        name: Option<String>,
        users: &[UserId],
    ) -> Result<GroupId> {
        self.create_chat(ChatKind::Group, name, users).await
    }

    /// Adds every device of `users` that is not a member yet, then shares
    /// the group name and avatar with them (a group info message: earlier
    /// ones are not readable for new members).
    pub async fn add_members(&self, group_id: &GroupId, users: &[UserId]) -> Result<()> {
        self.add_members_locked(group_id, users).await?;
        self.share_group_info(group_id).await?;
        let session = self.require_session()?;
        self.resolve_users(&session, users.iter().cloned().collect())
            .await;
        Ok(())
    }

    async fn add_members_locked(&self, group_id: &GroupId, users: &[UserId]) -> Result<()> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        let members = self.chat_devices(group_id).await?;
        let devices = self.devices_of(&session, users, &members).await?;
        let key_packages = self.claim_key_packages(&session, devices).await?;
        if key_packages.is_empty() {
            return Err(ClientError::InvalidInput(
                "no device to add has a KeyPackage".into(),
            ));
        }
        let devices: Vec<DeviceRef> = key_packages.iter().map(|(d, _)| d.clone()).collect();
        // Join the fan-out list before the commit so nothing sent in the new
        // epoch is missed; the Welcome lets the new devices catch up.
        self.inner
            .transport
            .add_group_members(&session.token, group_id, &devices)
            .await?;
        let added = self
            .commit(&session, group_id, CommitOp::Add(key_packages))
            .await
            .map(drop);
        if added.is_err() && !self.has_pending_commit(group_id).await? {
            // The commit definitely failed. Best effort: the original error
            // is what matters.
            let _ = self
                .inner
                .transport
                .remove_group_members(&session.token, group_id, &devices)
                .await;
        }
        added
    }

    /// Removes every device of `users` from the group.
    pub async fn remove_members(&self, group_id: &GroupId, users: &[UserId]) -> Result<()> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        let devices: Vec<DeviceRef> = self
            .chat_devices(group_id)
            .await?
            .into_iter()
            .filter(|d| users.contains(&d.user_id) && *d != session.device)
            .collect();
        if devices.is_empty() {
            return Err(ClientError::InvalidInput("no member to remove".into()));
        }
        // The removed devices leave the fan-out list after the commit, so
        // they still receive it.
        let op = CommitOp::Remove {
            devices,
            fan_out: true,
        };
        self.commit(&session, group_id, op).await?;
        Ok(())
    }

    /// Leaves the group: drops this device from the fan-out list and the
    /// local MLS group, and keeps the chat history as `Left` with the own
    /// user's `Left` membership event.
    ///
    /// The other members' MLS trees still contain this device until one of
    /// them removes it.
    pub async fn leave(&self, group_id: &GroupId) -> Result<()> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        self.inner
            .transport
            .remove_group_members(
                &session.token,
                group_id,
                std::slice::from_ref(&session.device),
            )
            .await?;
        let (gid, base) = (group_id.clone(), BaseClient::new(session.device.clone()));
        let changes = self
            .run(move |store, engine| base.leave_chat(store, engine, &gid, now_ms()))
            .await?;
        self.emit(&changes);
        Ok(())
    }

    /// Queues `content` and runs an outbox pass (see
    /// [`Client::flush_outbox`]); a failed post leaves the entry to the
    /// outbox sender. The returned id is also the `client_id`.
    pub async fn send(&self, group_id: &GroupId, content: Content) -> Result<MessageId> {
        self.send_with_reply(group_id, content, None).await
    }

    /// Generates and uploads [`KEY_PACKAGE_BATCH`] one-time KeyPackages.
    pub async fn replenish_key_packages(&self) -> Result<()> {
        let session = self.require_session()?;
        self.upload_key_packages(&session).await
    }

    async fn create_chat(
        &self,
        kind: ChatKind,
        name: Option<String>,
        users: &[UserId],
    ) -> Result<GroupId> {
        let session = self.require_session()?;
        let (group_id, added) = self.create_chat_locked(&session, kind, name, users).await?;
        if added && kind == ChatKind::Group {
            self.share_group_info(&group_id).await?;
        }
        self.resolve_users(&session, users.iter().cloned().collect())
            .await;
        Ok(group_id)
    }

    /// Returns the group id and whether members were added.
    async fn create_chat_locked(
        &self,
        session: &Session,
        kind: ChatKind,
        name: Option<String>,
        users: &[UserId],
    ) -> Result<(GroupId, bool)> {
        let session = session.clone();
        let _guard = self.inner.group_lock.lock().await;
        let devices = self.devices_of(&session, users, &[]).await?;
        let key_packages = self.claim_key_packages(&session, devices).await?;
        let devices: Vec<DeviceRef> = key_packages.iter().map(|(d, _)| d.clone()).collect();
        let group_id = self
            .inner
            .transport
            .create_group(&session.token, kind, &devices)
            .await?;
        let (gid, base) = (group_id.clone(), BaseClient::new(session.device.clone()));
        let changes = self
            .run(move |store, engine| base.create_chat(store, engine, &gid, kind, name, now_ms()))
            .await?;
        self.emit(&changes);
        let added = !key_packages.is_empty();
        if added {
            self.commit(&session, &group_id, CommitOp::Add(key_packages))
                .await?;
        }
        Ok((group_id, added))
    }

    /// Sends the group chat's current name and avatar as a group info
    /// message, if it has either. Direct chats have none to share.
    async fn share_group_info(&self, group_id: &GroupId) -> Result<()> {
        let gid = group_id.clone();
        let chat = self.run(move |store, _| Ok(store.chat(&gid)?)).await?;
        let Some(chat) = chat.filter(|c| c.kind == ChatKind::Group) else {
            return Ok(());
        };
        if chat.name.is_none() && chat.avatar.is_none() {
            return Ok(());
        }
        let content = Content::GroupInfo {
            name: chat.name,
            avatar: chat.avatar,
        };
        self.send(group_id, content).await.map(drop)
    }

    /// Fetches the directory profiles of `users` not cached yet, caches
    /// them and updates the member names of their chats (broadcast as chat
    /// changes, so the chat list and timelines show the names). Best
    /// effort: failures are logged and the lookups retried next time;
    /// users the directory does not know are not looked up again.
    pub(crate) async fn resolve_users(&self, session: &Session, users: BTreeSet<UserId>) {
        if let Err(err) = self.try_resolve_users(session, users).await {
            tracing::debug!(error = %err, "cannot resolve user profiles");
        }
    }

    async fn try_resolve_users(&self, session: &Session, users: BTreeSet<UserId>) -> Result<()> {
        let resolved = |users: &mut dyn Iterator<Item = UserId>| {
            self.inner
                .resolved_users
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(users);
        };
        let users: Vec<UserId> = {
            let known = self
                .inner
                .resolved_users
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            users
                .into_iter()
                .filter(|u| *u != session.device.user_id && !known.contains(u))
                .collect()
        };
        if users.is_empty() {
            return Ok(());
        }
        let (cached, missing): (Vec<UserId>, Vec<UserId>) = self
            .run(move |store, _| {
                let mut split = (Vec::new(), Vec::new());
                for user_id in users {
                    match store.user(&user_id)? {
                        Some(_) => split.0.push(user_id),
                        None => split.1.push(user_id),
                    }
                }
                Ok(split)
            })
            .await?;
        resolved(&mut cached.into_iter());
        let mut found = Vec::new();
        let mut failed = None;
        for user_id in missing {
            match self.inner.transport.user(&session.token, &user_id).await {
                Ok(Some(user)) => found.push(user),
                Ok(None) => resolved(&mut std::iter::once(user_id)),
                Err(err) => {
                    failed = Some(err);
                    break;
                }
            }
        }
        if !found.is_empty() {
            let found_ids: Vec<UserId> = found.iter().map(|u| u.user_id.clone()).collect();
            let changes = self
                .run(move |store, _| {
                    store.transaction(|txn| {
                        for user in &found {
                            txn.upsert_user(user)?;
                        }
                        let mut changes = Vec::new();
                        for mut chat in txn.chats()? {
                            let mut renamed = false;
                            for member in &mut chat.members {
                                let Some(user) =
                                    found.iter().find(|u| u.user_id == member.device.user_id)
                                else {
                                    continue;
                                };
                                if member.display_name.as_ref() != Some(&user.display_name) {
                                    member.display_name = Some(user.display_name.clone());
                                    renamed = true;
                                }
                            }
                            if renamed {
                                txn.upsert_chat(&chat)?;
                                changes.push(StateChange::ChatUpserted(chat));
                            }
                        }
                        Ok(changes)
                    })
                })
                .await?;
            self.emit(&changes);
            resolved(&mut found_ids.into_iter());
        }
        failed.map_or(Ok(()), |err| Err(err.into()))
    }

    /// Creates a commit, posts it and merges it once accepted, then does
    /// what follows it (Welcome, fan-out removal). On an epoch conflict the
    /// commit is dropped, the competing commit synced, and the commit
    /// recreated, up to [`MAX_COMMIT_RETRIES`] times. Returns `false` if
    /// there was nothing to commit (devices to remove already gone).
    ///
    /// If the outcome stays unknown (network errors), the commit is kept
    /// pending and re-posted with the same `client_id` before the next
    /// sync, commit or send of the group.
    async fn commit(&self, session: &Session, group_id: &GroupId, op: CommitOp) -> Result<bool> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            self.resolve_pending_commit(session, group_id).await?;
            let (gid, op) = (group_id.clone(), op.clone());
            // The commit record is persisted with the MLS pending commit, so
            // a restart re-posts the very same commit.
            let created = self
                .run(move |store, engine| {
                    store.transaction(|txn| {
                        let (output, then) = match op {
                            CommitOp::Add(key_packages) => {
                                let (recipients, key_packages): (Vec<_>, Vec<_>) =
                                    key_packages.into_iter().unzip();
                                let output = engine.add_members(&*txn, &gid, &key_packages)?;
                                let then = AfterCommit::Welcome(PendingWelcome {
                                    client_id: new_client_id()?,
                                    epoch: output.epoch + 1,
                                    payload: output
                                        .welcome
                                        .clone()
                                        .expect("an add commit has a Welcome"),
                                    recipients,
                                });
                                (output, then)
                            }
                            CommitOp::Remove { devices, fan_out } => {
                                let members = engine.group_members(&*txn, &gid)?;
                                let devices: Vec<DeviceRef> = devices
                                    .into_iter()
                                    .filter(|d| members.contains(d))
                                    .collect();
                                if devices.is_empty() {
                                    return Ok(false);
                                }
                                let output = engine.remove_members(&*txn, &gid, &devices)?;
                                let then = if fan_out {
                                    AfterCommit::RemoveFromFanOut(devices)
                                } else {
                                    AfterCommit::Nothing
                                };
                                (output, then)
                            }
                        };
                        txn.upsert_pending_commit(&PendingCommit {
                            group_id: gid,
                            client_id: new_client_id()?,
                            epoch: output.epoch,
                            payload: output.commit,
                            merged: false,
                            then,
                        })?;
                        Ok(true)
                    })
                })
                .await?;
            if !created {
                return Ok(false);
            }
            match self.resolve_pending_commit(session, group_id).await? {
                Resolved::Accepted | Resolved::None => return Ok(true),
                Resolved::Conflict if attempt <= MAX_COMMIT_RETRIES => {
                    self.sync_locked(session).await?;
                }
                Resolved::Conflict => return Err(ClientError::CommitConflict(attempt)),
            }
        }
    }

    /// Settles the group's pending commit, if any: posts it (again, same
    /// `client_id`), merges it once accepted and does what follows it.
    /// Unknown outcomes keep it pending and return the error; a conflict
    /// or a definitive rejection drops it.
    async fn resolve_pending_commit(
        &self,
        session: &Session,
        group_id: &GroupId,
    ) -> Result<Resolved> {
        let gid = group_id.clone();
        let Some(pending) = self
            .run(move |store, _| Ok(store.pending_commit(&gid)?))
            .await?
        else {
            return Ok(Resolved::None);
        };
        if !pending.merged {
            let message = OutgoingMessage {
                client_id: pending.client_id,
                epoch: pending.epoch,
                kind: MessageKind::Commit,
                payload: pending.payload,
                recipients: vec![],
            };
            match self.post_until_known(session, group_id, message).await {
                Ok(seq) => {
                    let (gid, base) = (group_id.clone(), BaseClient::new(session.device.clone()));
                    let changes = self
                        .run(move |store, engine| base.merge_own_commit(store, engine, &gid, seq))
                        .await?;
                    self.emit(&changes);
                }
                Err(PostError::Transport(err)) if outcome_unknown(&err) => return Err(err.into()),
                Err(err) => {
                    let gid = group_id.clone();
                    self.run(move |store, engine| {
                        store.transaction(|txn| {
                            engine.clear_pending_commit(&*txn, &gid)?;
                            Ok(txn.remove_pending_commit(&gid)?)
                        })
                    })
                    .await?;
                    return match err {
                        PostError::EpochConflict { .. } => Ok(Resolved::Conflict),
                        PostError::Transport(err) => Err(err.into()),
                    };
                }
            }
        }
        let followed = match pending.then {
            AfterCommit::Nothing => Ok(None),
            AfterCommit::Welcome(welcome) => {
                let message = OutgoingMessage {
                    client_id: welcome.client_id,
                    epoch: welcome.epoch,
                    kind: MessageKind::Welcome,
                    payload: welcome.payload,
                    recipients: welcome.recipients,
                };
                self.post_until_known(session, group_id, message)
                    .await
                    .map(Some)
                    .map_err(Into::into)
            }
            AfterCommit::RemoveFromFanOut(devices) => self
                .inner
                .transport
                .remove_group_members(&session.token, group_id, &devices)
                .await
                .map(|()| None)
                .map_err(Into::into),
        };
        match followed {
            Err(ClientError::Transport(err)) if outcome_unknown(&err) => Err(err.into()),
            followed => {
                // Done, or definitively rejected: nothing left to retry.
                let gid = group_id.clone();
                let welcome_seq = followed.as_ref().ok().copied().flatten();
                self.run(move |store, _| {
                    store.transaction(|txn| {
                        if let Some(seq) = welcome_seq {
                            // Own messages never come back through the stream.
                            let mut cursor = txn.group_cursor(&gid)?;
                            cursor.insert(seq);
                            txn.set_group_cursor(&gid, &cursor)?;
                        }
                        Ok(txn.remove_pending_commit(&gid)?)
                    })
                })
                .await?;
                followed.map(|_| Resolved::Accepted)
            }
        }
    }

    /// Settles every pending commit; stops at the first error.
    pub(crate) async fn resolve_pending_commits(&self, session: &Session) -> Result<()> {
        let pending = self.run(|store, _| Ok(store.pending_commits()?)).await?;
        for commit in pending {
            self.resolve_pending_commit(session, &commit.group_id)
                .await?;
        }
        Ok(())
    }

    /// Posts `message`, re-posting it while the outcome is unknown, up to
    /// [`COMMIT_POST_ATTEMPTS`] times. Safe because the server is idempotent
    /// on `client_id`.
    async fn post_until_known(
        &self,
        session: &Session,
        group_id: &GroupId,
        message: OutgoingMessage,
    ) -> Result<u64, PostError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self
                .inner
                .transport
                .post_message(&session.token, group_id, message.clone())
                .await
            {
                Err(PostError::Transport(err))
                    if outcome_unknown(&err) && attempt < COMMIT_POST_ATTEMPTS =>
                {
                    tokio::time::sleep(COMMIT_REPOST_DELAY * attempt).await;
                }
                posted => return posted,
            }
        }
    }

    pub(crate) async fn settle_commit(&self, session: &Session, group_id: &GroupId) -> Result<()> {
        self.resolve_pending_commit(session, group_id)
            .await
            .map(drop)
    }

    pub(crate) async fn has_pending_commit(&self, group_id: &GroupId) -> Result<bool> {
        let gid = group_id.clone();
        self.run(move |store, _| Ok(store.pending_commit(&gid)?.is_some()))
            .await
    }

    /// Commits the MLS removal of devices that left a group by themselves
    /// (dropped from the fan-out list but still in the tree). Only the
    /// remaining member with the lowest leaf index does it, so members do
    /// not race each other; the others keep the candidates until the
    /// removal commit reaches them. Candidates no longer in the tree, or of
    /// groups this device is not in, are dropped.
    pub(crate) async fn remove_departed(&self, session: &Session) -> Result<()> {
        let own = session.device.clone();
        let to_remove = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    let mut departed: BTreeMap<GroupId, BTreeSet<DeviceRef>> = BTreeMap::new();
                    let mut members: BTreeMap<GroupId, Vec<DeviceRef>> = BTreeMap::new();
                    for candidate in txn.departed_members()? {
                        let gid = &candidate.group_id;
                        if !members.contains_key(gid) {
                            let joined = txn
                                .chat(gid)?
                                .is_some_and(|c| c.membership == Membership::Joined);
                            // Leaf index order.
                            let tree = if joined && engine.has_group(&*txn, gid)? {
                                engine.group_members(&*txn, gid)?
                            } else {
                                vec![]
                            };
                            members.insert(gid.clone(), tree);
                        }
                        if members[gid].contains(&candidate.device) {
                            departed
                                .entry(candidate.group_id)
                                .or_default()
                                .insert(candidate.device);
                        } else {
                            txn.remove_departed_member(&candidate)?;
                        }
                    }
                    Ok(departed
                        .into_iter()
                        .filter(|(gid, devices)| {
                            members[gid].iter().find(|m| !devices.contains(m)) == Some(&own)
                        })
                        .map(|(gid, devices)| (gid, devices.into_iter().collect::<Vec<_>>()))
                        .collect::<Vec<_>>())
                })
            })
            .await?;
        for (group_id, devices) in to_remove {
            let op = CommitOp::Remove {
                devices: devices.clone(),
                fan_out: false,
            };
            // Merging the removal drops the candidates (gim-base).
            if let Err(err) = self.commit(session, &group_id, op).await {
                if !matches!(&err, ClientError::Transport(e) if outcome_unknown(e)) {
                    // Not retried: a definitive failure would repeat on
                    // every sync.
                    self.run(move |store, _| {
                        store.transaction(|txn| {
                            for device in devices {
                                txn.remove_departed_member(&DepartedMember {
                                    group_id: group_id.clone(),
                                    device,
                                })?;
                            }
                            Ok(())
                        })
                    })
                    .await?;
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// Chats joined from a Welcome start as `Group`; takes the kind from the
    /// server.
    pub(crate) async fn sync_chat_kind(
        &self,
        session: &Session,
        group_id: GroupId,
    ) -> Result<Vec<StateChange>> {
        let gid = group_id.clone();
        let chat = self.run(move |store, _| Ok(store.chat(&gid)?)).await?;
        let Some(mut chat) = chat else {
            return Ok(vec![]);
        };
        if chat.membership != Membership::Joined {
            return Ok(vec![]);
        }
        let info = self
            .inner
            .transport
            .group_info(&session.token, &group_id)
            .await?;
        if info.kind == chat.kind {
            return Ok(vec![]);
        }
        chat.kind = info.kind;
        self.run(move |store, _| {
            store.transaction(|txn| {
                txn.upsert_chat(&chat)?;
                Ok(vec![StateChange::ChatUpserted(chat)])
            })
        })
        .await
    }

    pub(crate) async fn upload_key_packages(&self, session: &Session) -> Result<()> {
        let key_packages = self
            .run(|store, engine| {
                store.transaction(|txn| Ok(engine.generate_key_packages(&*txn, KEY_PACKAGE_BATCH)?))
            })
            .await?;
        self.inner
            .transport
            .upload_key_packages(&session.token, key_packages, None)
            .await?;
        Ok(())
    }

    /// Devices of `users` plus this user's other devices, except this
    /// device and `exclude`.
    async fn devices_of(
        &self,
        session: &Session,
        users: &[UserId],
        exclude: &[DeviceRef],
    ) -> Result<Vec<DeviceRef>> {
        let users: BTreeSet<&UserId> = users.iter().chain([&session.device.user_id]).collect();
        let mut devices = Vec::new();
        for user_id in users {
            let listed = self
                .inner
                .transport
                .list_devices(&session.token, user_id)
                .await?;
            devices.extend(
                listed
                    .into_iter()
                    .filter(|d| *d != session.device && !exclude.contains(d)),
            );
        }
        Ok(devices)
    }

    /// Claims one KeyPackage per device; devices without any are skipped.
    async fn claim_key_packages(
        &self,
        session: &Session,
        devices: Vec<DeviceRef>,
    ) -> Result<Vec<(DeviceRef, Vec<u8>)>> {
        let mut claimed = Vec::new();
        for device in devices {
            match self
                .inner
                .transport
                .claim_key_package(&session.token, &device)
                .await
            {
                Ok(key_package) => claimed.push((device, key_package)),
                Err(TransportError::NotFound(_)) => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(claimed)
    }

    async fn chat_devices(&self, group_id: &GroupId) -> Result<Vec<DeviceRef>> {
        let gid = group_id.clone();
        let chat = self
            .run(move |store, _| {
                store
                    .chat(&gid)?
                    .ok_or_else(|| BaseError::NotFound(format!("chat {gid}")))
            })
            .await?;
        if chat.membership != Membership::Joined {
            return Err(ClientError::InvalidInput(format!("left chat {group_id}")));
        }
        Ok(chat.members.into_iter().map(|m| m.device).collect())
    }

    /// Records an own message's seq as applied: own messages never come
    /// back through the event stream.
    pub(crate) async fn mark_applied(&self, group_id: &GroupId, seq: u64) -> Result<()> {
        let gid = group_id.clone();
        self.run(move |store, _| {
            store.transaction(|txn| {
                let mut cursor = txn.group_cursor(&gid)?;
                cursor.insert(seq);
                Ok(txn.set_group_cursor(&gid, &cursor)?)
            })
        })
        .await
    }

    /// Runs blocking store and MLS work off the async runtime.
    pub(crate) async fn run<R, F>(&self, f: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&S, &MlsEngine) -> Result<R, BaseError> + Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || f(&inner.store, &inner.engine))
            .await
            .map_err(|e| ClientError::Task(e.to_string()))?
            .map_err(Into::into)
    }

    pub(crate) fn emit(&self, changes: &[StateChange]) {
        for change in changes {
            // No subscriber is fine.
            let _ = self.inner.changes.send(change.clone());
        }
    }

    pub(crate) fn require_session(&self) -> Result<Session> {
        self.session().ok_or(ClientError::NotLoggedIn)
    }

    fn set_session(&self, session: Session) {
        *self
            .inner
            .session
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(session);
    }
}

pub(crate) fn new_client_id() -> Result<ClientId, BaseError> {
    Ok(ClientId::new(new_message_id()?.as_str()).expect("message ids are client ids"))
}
