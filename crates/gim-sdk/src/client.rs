//! The async client of one device.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::task::JoinHandle;

use gim_base::model::{
    ChatKind, DepartedMember, Membership, PendingCommit, PendingWelcome, StateChange,
};
use gim_base::{
    new_message_id, BaseClient, BaseError, StateReader, StateStore, StoreError, StoreTxn,
};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{CryptoError, CryptoStore, DeviceListCache, MlsEngine};
use gim_identity::SignedDeviceList;
use gim_proto::envelope::Content;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex, Notify};

use crate::identity::merge_directory_user;
use crate::send::TypingState;
use crate::stream::ConnectionState;
use crate::sync::SyncSettings;
use crate::transport::{
    AccessToken, ClaimedKeyPackage, CommitAccepted, OutgoingCommit, PostError, Transport,
    TransportError,
};
use crate::{ClientError, Result, SecretStorage, SecretStorageError};

/// One-time KeyPackages uploaded at registration and per replenish.
pub const KEY_PACKAGE_BATCH: u32 = 100;
/// Retries of a commit rejected because another commit won the epoch.
pub const MAX_COMMIT_RETRIES: u32 = 3;
/// Posts of the same commit (same `client_id`) while its outcome is
/// unknown, before the call gives up and keeps it pending.
pub const COMMIT_POST_ATTEMPTS: u32 = 3;
/// Leave proposals created for one leave (counted again from each
/// [`Client::restore_session`]): one per epoch that ended without removing
/// this device. Then the chat stays leaving until the next start.
pub const MAX_LEAVE_PROPOSALS: u32 = 5;
/// [`SecretStorage`] key of the serialized [`Session`].
pub const SESSION_SECRET_KEY: &str = "gim.session";
/// [`SecretStorage`] key of the user's root key (32-byte Ed25519 seed).
pub const ROOT_KEY_SECRET_KEY: &str = "gim.root_key.v1";
/// [`SecretStorage`] key of this device's signing key (32-byte Ed25519
/// seed).
pub const DEVICE_KEY_SECRET_KEY: &str = "gim.device_key.v1";

/// See [`ClientBuilder::DB_KEY_LEN`].
const DATABASE_KEY_LEN: usize = 32;
/// Buffered [`StateChange`]s per subscriber before it lags.
const CHANGES_CAPACITY: usize = 1024;
/// Buffered [`ConnectionState`]s per subscriber before it lags.
const CONNECTION_CAPACITY: usize = 64;
/// Delay before re-posting a commit after an unknown outcome, times the
/// attempt number.
const COMMIT_REPOST_DELAY: Duration = Duration::from_millis(100);

/// A signed-in device: who it is and its session token. Persisted in
/// [`SecretStorage`] next to the root and device keys; the MLS identity
/// lives in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub device: DeviceRef,
    pub token: AccessToken,
    /// Unix milliseconds; the device signs in again before this.
    #[serde(default)]
    pub expires_at_ms: u64,
    /// The hub signed in to; later challenges must come from it.
    #[serde(default)]
    pub hub_id: String,
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

    /// A client without a session; call [`Client::create_identity`] or
    /// [`Client::restore_session`] next. Loads the stored DeviceLists.
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
        let device_lists = Arc::new(DeviceListCache::new());
        for (user_id, bytes) in self.store.device_lists().map_err(BaseError::from)? {
            let loaded = SignedDeviceList::from_bytes(&bytes)
                .and_then(|list| device_lists.insert(&user_id, &list));
            if let Err(err) = loaded {
                tracing::warn!(%user_id, error = %err, "dropping a stored device list");
            }
        }
        Ok(Client {
            inner: Arc::new(Inner {
                store: self.store,
                transport: self.transport,
                secrets: self.secrets,
                engine: MlsEngine::with_device_list_lookup(device_lists.clone()),
                device_lists,
                session: RwLock::new(None),
                auth_lock: Mutex::new(()),
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
                link_pending: AtomicBool::new(false),
                proposal_timers: Default::default(),
                hosting_lock: Mutex::new(()),
                hosting_wake: Notify::new(),
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
    pub(crate) secrets: Arc<dyn SecretStorage>,
    engine: MlsEngine,
    /// Latest verified DeviceList per user, persisted in the store; the
    /// engine validates credentials and revocations against it.
    pub(crate) device_lists: Arc<DeviceListCache>,
    session: RwLock<Option<Session>>,
    /// Serializes sign-ins.
    pub(crate) auth_lock: Mutex<()>,
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
    /// Users found in the user directory cache or unknown to the hub's
    /// directory; not looked up again.
    pub(crate) resolved_users: std::sync::Mutex<HashSet<UserId>>,
    /// A linked identity waits for [`Client::confirm_link`].
    pub(crate) link_pending: AtomicBool,
    /// (group, epoch) whose pending Proposals this device commits after a
    /// delay unless another member did.
    proposal_timers: std::sync::Mutex<HashSet<(GroupId, u64)>>,
    /// Serializes hosting record publications.
    pub(crate) hosting_lock: Mutex<()>,
    /// Cuts the hosting record renewal wait short.
    pub(crate) hosting_wake: Notify,
}

#[derive(Clone)]
pub(crate) enum CommitOp {
    Add(Vec<ClaimedKeyPackage>),
    Remove(Vec<DeviceRef>),
    /// The Proposals pending in the group, by reference.
    Proposals,
}

enum Resolved {
    /// No pending commit for the group.
    None,
    Accepted,
    /// Another commit won the epoch; the pending commit was dropped.
    Conflict,
}

/// Whether the hub may have accepted a request that failed this way.
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

    /// Restores the session persisted by [`Client::create_identity`];
    /// `false` if there is none, or if the store lost the device identity
    /// (database reset or deleted) or the device key is gone, in which case
    /// the stale session secret is deleted. Signs in again from the stored
    /// device key if the token expired (failures are retried on the next
    /// call). Reconciles MLS pending commits with their records, then
    /// removes file copies under [`Client::outgoing_dir`] that no queued
    /// upload needs, and re-submits commits whose outcome was unknown when
    /// the previous run stopped.
    pub async fn restore_session(&self) -> Result<bool> {
        let Some(encoded) = self.inner.secrets.get(SESSION_SECRET_KEY)? else {
            return Ok(false);
        };
        let session: Session = serde_json::from_slice(&encoded)
            .map_err(|e| ClientError::InvalidSession(e.to_string()))?;
        if self.inner.secrets.get(DEVICE_KEY_SECRET_KEY)?.is_none() {
            tracing::warn!("stored session has no device key; signing out");
            self.inner.secrets.delete(SESSION_SECRET_KEY)?;
            return Ok(false);
        }
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
        self.set_session(session.clone());
        match self.valid_token().await {
            // `renew_token` signed out.
            Err(TransportError::DeviceNotActive(reason)) => {
                return Err(ClientError::DeviceNotActive(reason))
            }
            Err(err) => tracing::warn!(error = %err, "cannot sign in; retrying later"),
            Ok(_) => {}
        }
        self.clean_outgoing().await?;
        // Finish what the previous run left: re-submit its pending commits
        // (same bytes) and remove departed members. Best effort: the same
        // work is retried before the next sync, commit or send of each
        // group.
        let _guard = self.inner.group_lock.lock().await;
        let resumed = match self.resolve_pending_commits(&session).await {
            Ok(()) => match self.remove_departed(&session).await {
                Ok(()) => self.commit_pending_proposals(&session).await,
                err => err,
            },
            err => err,
        };
        if let Err(err) = resumed {
            tracing::warn!(%err, "resuming unfinished group changes failed");
        }
        // A new start allows new leave proposals.
        self.run(|store, _| {
            store.transaction(|txn| {
                for mut leave in txn.pending_leaves()? {
                    leave.attempts = 0;
                    txn.upsert_pending_leave(&leave)?;
                }
                Ok(())
            })
        })
        .await?;
        self.resume_leaves(&session).await;
        Ok(true)
    }

    /// Creates a direct chat with every device of `user_id` (and this user's
    /// other devices), and announces the own display name in it.
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
    /// the group name and avatar and the own display name with them (group
    /// info and profile messages: earlier ones are not readable for new
    /// members).
    pub async fn add_members(&self, group_id: &GroupId, users: &[UserId]) -> Result<()> {
        self.add_members_locked(group_id, users).await?;
        self.share_group_info(group_id).await?;
        self.announce_profile(group_id).await;
        let session = self.require_session()?;
        self.resolve_users(&session, users.iter().cloned().collect())
            .await;
        Ok(())
    }

    async fn add_members_locked(&self, group_id: &GroupId, users: &[UserId]) -> Result<()> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        let members = self.chat_devices(group_id).await?;
        let key_packages = self.claim_key_packages(&session, users, &members).await?;
        if key_packages.is_empty() {
            return Err(ClientError::InvalidInput(
                "no device to add has a KeyPackage".into(),
            ));
        }
        self.commit(&session, group_id, CommitOp::Add(key_packages))
            .await
            .map(drop)
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
        self.commit(&session, group_id, CommitOp::Remove(devices))
            .await?;
        Ok(())
    }

    /// Leaves the group: submits a Proposal removing this device and
    /// returns once the hub accepted it, with the chat `Leaving` (nothing
    /// can be sent; see [`gim_base::model::Membership::Leaving`]). Another
    /// member commits the Proposal; applying that commit drops the local MLS
    /// group and keeps the chat history as `Left` with the own user's `Left`
    /// membership event. If an epoch ends without removing this device, a
    /// fresh Proposal is sent (see [`MAX_LEAVE_PROPOSALS`]).
    ///
    /// If the outcome stays unknown (network errors), the chat stays
    /// `Leaving` and the Proposal is re-posted on the next sync or start.
    /// A Proposal the hub refuses for good returns the chat to `Joined`.
    pub async fn leave(&self, group_id: &GroupId) -> Result<()> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        self.resolve_pending_commit(&session, group_id).await?;
        let gid = group_id.clone();
        let chat = self
            .run(move |store, _| {
                store
                    .chat(&gid)?
                    .ok_or_else(|| BaseError::NotFound(format!("chat {gid}")))
            })
            .await?;
        match chat.membership {
            Membership::Left => {
                return Err(ClientError::InvalidInput(format!("left chat {group_id}")))
            }
            Membership::Leaving => {}
            Membership::Joined => {
                let (gid, base) = (group_id.clone(), BaseClient::new(session.device.clone()));
                let (_, changes) = self
                    .run(move |store, engine| {
                        base.start_leave(store, engine, &gid, new_client_id()?, now_ms())
                    })
                    .await?;
                self.emit(&changes);
            }
        }
        self.advance_leave(&session, group_id).await
    }

    /// Posts the group's pending leave until the hub accepted it: again
    /// (same bytes) while its outcome is unknown, renewed for the current
    /// epoch once its epoch ended. Done if the chat is no longer leaving.
    async fn advance_leave(&self, session: &Session, group_id: &GroupId) -> Result<()> {
        let base = BaseClient::new(session.device.clone());
        let mut stale = 0;
        loop {
            let gid = group_id.clone();
            let state = self
                .run(move |store, engine| {
                    store.transaction(|txn| {
                        let Some(leave) = txn.pending_leave(&gid)? else {
                            return Ok(None);
                        };
                        let leaving = txn
                            .chat(&gid)?
                            .is_some_and(|c| c.membership == Membership::Leaving)
                            && engine.has_group(&*txn, &gid)?;
                        if !leaving {
                            txn.remove_pending_leave(&gid)?;
                            return Ok(None);
                        }
                        Ok(Some((leave, engine.group_epoch(&*txn, &gid)?)))
                    })
                })
                .await?;
            let Some((mut leave, epoch)) = state else {
                return Ok(());
            };
            if leave.epoch < epoch {
                if leave.attempts >= MAX_LEAVE_PROPOSALS {
                    return Err(ClientError::CommitConflict(leave.attempts));
                }
                let (gid, b) = (group_id.clone(), base.clone());
                leave = self
                    .run(move |store, engine| b.renew_leave(store, engine, &gid, new_client_id()?))
                    .await?;
            } else if leave.accepted {
                return Ok(());
            }
            let proposal = OutgoingCommit {
                client_id: leave.client_id.clone(),
                mls_message: leave.payload,
                welcome: None,
                welcome_recipients: vec![],
            };
            match self.submit_until_known(group_id, proposal).await {
                Ok(_) => {
                    let (gid, b) = (group_id.clone(), base.clone());
                    let client_id = leave.client_id;
                    return self
                        .run(move |store, _| b.leave_accepted(store, &gid, &client_id))
                        .await;
                }
                // An epoch ended: catch up, then renew the proposal.
                Err(PostError::StaleEpoch { .. }) if stale < MAX_COMMIT_RETRIES => {
                    stale += 1;
                    self.sync_locked(session).await?;
                }
                Err(PostError::StaleEpoch { .. }) => {
                    return Err(ClientError::CommitConflict(stale + 1))
                }
                Err(PostError::Transport(err)) if outcome_unknown(&err) => return Err(err.into()),
                Err(PostError::Transport(err)) => {
                    tracing::warn!(%group_id, error = %err, "leave proposal refused; staying in the group");
                    let (gid, b) = (group_id.clone(), base.clone());
                    let changes = self
                        .run(move |store, engine| b.abort_leave(store, engine, &gid))
                        .await?;
                    self.emit(&changes);
                    return Err(err.into());
                }
            }
        }
    }

    /// Advances every pending leave (see [`Client::leave`]); failures are
    /// logged and retried on the next sync or start. Caller holds the group
    /// lock.
    pub(crate) async fn resume_leaves(&self, session: &Session) {
        let leaves = match self.run(|store, _| Ok(store.pending_leaves()?)).await {
            Ok(leaves) => leaves,
            Err(err) => {
                tracing::warn!(%err, "cannot read the pending leaves");
                return;
            }
        };
        for leave in leaves {
            if let Err(err) = self.advance_leave(session, &leave.group_id).await {
                tracing::warn!(group_id = %leave.group_id, %err, "leave proposal not delivered; retrying later");
            }
        }
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
        if added {
            self.announce_profile(&group_id).await;
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
        let key_packages = self.claim_key_packages(&session, users, &[]).await?;
        let group_id = self
            .authed(|t| async move { self.inner.transport.create_group(&t, kind).await })
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
    pub(crate) async fn share_group_info(&self, group_id: &GroupId) -> Result<()> {
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
            let looked_up = self
                .authed(|t| {
                    let user_id = user_id.clone();
                    async move { self.inner.transport.user(Some(&t), &user_id).await }
                })
                .await;
            match looked_up {
                Ok(Some(record)) => found.push(self.accept_user(record).await?),
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
                        let mut merged = Vec::with_capacity(found.len());
                        for user in found {
                            let user =
                                merge_directory_user(txn.user(&user.user_id)?.as_ref(), user);
                            txn.upsert_user(&user)?;
                            merged.push(user);
                        }
                        let found = merged;
                        let mut changes = Vec::new();
                        for mut chat in txn.chats()? {
                            let mut renamed = false;
                            for member in &mut chat.members {
                                let Some(user) = found.iter().find(|u| {
                                    u.user_id == member.device.user_id && !u.display_name.is_empty()
                                }) else {
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

    /// Creates a commit, submits it with its Welcome and merges it once
    /// accepted. On a stale epoch the commit is dropped, the competing
    /// commit synced, and the commit recreated, up to [`MAX_COMMIT_RETRIES`]
    /// times. Returns `false` if there was nothing to commit (devices to
    /// remove already gone).
    ///
    /// If the outcome stays unknown (network errors), the commit is kept
    /// pending and re-submitted (same bytes, which the hub recognizes)
    /// before the next sync, commit or send of the group.
    pub(crate) async fn commit(
        &self,
        session: &Session,
        group_id: &GroupId,
        op: CommitOp,
    ) -> Result<bool> {
        if let CommitOp::Add(key_packages) = &op {
            // Credentials are checked against the users' current lists.
            let devices = key_packages.iter().map(|k| k.device.clone());
            let revoked = self.fetch_device_lists(devices).await?;
            self.record_revoked(session, revoked).await?;
        }
        let mut attempt = 1;
        let mut lists_retried = false;
        loop {
            self.resolve_pending_commit(session, group_id).await?;
            let (gid, op) = (group_id.clone(), op.clone());
            // The commit record is persisted with the MLS pending commit, so
            // a restart re-submits the very same commit.
            let created = self
                .run(move |store, engine| {
                    store.transaction(|txn| {
                        let (output, welcome) = match op {
                            CommitOp::Add(key_packages) => {
                                let (claimed, key_packages): (Vec<_>, Vec<_>) = key_packages
                                    .into_iter()
                                    .map(|k| (k.device, k.key_package))
                                    .unzip();
                                let output = engine.add_members(&*txn, &gid, &key_packages)?;
                                if output.added != claimed {
                                    // Rolled back with the transaction.
                                    return Err(CryptoError::InvalidCredential {
                                        reason: "a KeyPackage is not the claimed device's".into(),
                                    }
                                    .into());
                                }
                                let welcome = PendingWelcome {
                                    payload: output
                                        .welcome
                                        .clone()
                                        .expect("an add commit has a Welcome"),
                                    recipients: output.added.clone(),
                                };
                                (output, Some(welcome))
                            }
                            CommitOp::Proposals => {
                                let Some(output) = engine.commit_pending_proposals(&*txn, &gid)?
                                else {
                                    return Ok(false);
                                };
                                let welcome =
                                    output.welcome.clone().map(|payload| PendingWelcome {
                                        payload,
                                        recipients: output.added.clone(),
                                    });
                                (output, welcome)
                            }
                            CommitOp::Remove(devices) => {
                                let members = engine.group_members(&*txn, &gid)?;
                                let devices: Vec<DeviceRef> = devices
                                    .into_iter()
                                    .filter(|d| members.contains(d))
                                    .collect();
                                if devices.is_empty() {
                                    return Ok(false);
                                }
                                (engine.remove_members(&*txn, &gid, &devices)?, None)
                            }
                        };
                        txn.upsert_pending_commit(&PendingCommit {
                            group_id: gid,
                            client_id: new_client_id()?,
                            epoch: output.epoch,
                            payload: output.commit,
                            welcome,
                        })?;
                        Ok(true)
                    })
                })
                .await;
            let created = match created {
                // Safety net behind the pre-fetch: fetch the list, retry once.
                Err(ClientError::Base(BaseError::Crypto(CryptoError::DeviceListUnknown {
                    user_id,
                }))) if !lists_retried => {
                    lists_retried = true;
                    tracing::info!(%user_id, "unknown device list; fetching it and retrying once");
                    let revoked = self.refresh_device_list(&user_id).await?;
                    self.record_revoked(session, revoked).await?;
                    continue;
                }
                created => created?,
            };
            if !created {
                return Ok(false);
            }
            match self.resolve_pending_commit(session, group_id).await? {
                Resolved::Accepted | Resolved::None => return Ok(true),
                Resolved::Conflict if attempt <= MAX_COMMIT_RETRIES => {
                    attempt += 1;
                    self.sync_locked(session).await?;
                }
                Resolved::Conflict => return Err(ClientError::CommitConflict(attempt)),
            }
        }
    }

    /// Settles the group's pending commit, if any: submits it (again, same
    /// bytes; a duplicate counts as accepted) and merges it once accepted.
    /// Unknown outcomes keep it pending and return the error; a stale epoch
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
        let (welcome, welcome_recipients) = match pending.welcome {
            Some(w) => (Some(w.payload), w.recipients),
            None => (None, vec![]),
        };
        let commit = OutgoingCommit {
            client_id: pending.client_id,
            mls_message: pending.payload,
            welcome,
            welcome_recipients,
        };
        match self.submit_until_known(group_id, commit).await {
            Ok(accepted) => {
                let (gid, base) = (group_id.clone(), BaseClient::new(session.device.clone()));
                let changes = self
                    .run(move |store, engine| {
                        base.merge_own_commit(store, engine, &gid, accepted.seq)
                    })
                    .await?;
                self.emit(&changes);
                Ok(Resolved::Accepted)
            }
            Err(PostError::Transport(err)) if outcome_unknown(&err) => Err(err.into()),
            Err(err) => {
                let gid = group_id.clone();
                self.run(move |store, engine| {
                    store.transaction(|txn| {
                        engine.clear_pending_commit(&*txn, &gid)?;
                        Ok(txn.remove_pending_commit(&gid)?)
                    })
                })
                .await?;
                match err {
                    PostError::StaleEpoch { .. } => Ok(Resolved::Conflict),
                    PostError::Transport(err) => Err(err.into()),
                }
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

    /// Submits `commit`, again while the outcome is unknown, up to
    /// [`COMMIT_POST_ATTEMPTS`] times. Safe because the hub recognizes a
    /// resubmitted Commit by its hash (and a Proposal by its `client_id`).
    async fn submit_until_known(
        &self,
        group_id: &GroupId,
        commit: OutgoingCommit,
    ) -> Result<CommitAccepted, PostError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let submitted = self
                .authed(|t| {
                    let commit = commit.clone();
                    async move {
                        self.inner
                            .transport
                            .submit_commit(&t, group_id, commit)
                            .await
                    }
                })
                .await;
            match submitted {
                Err(PostError::Transport(err))
                    if outcome_unknown(&err) && attempt < COMMIT_POST_ATTEMPTS =>
                {
                    tokio::time::sleep(COMMIT_REPOST_DELAY * attempt).await;
                }
                submitted => return submitted,
            }
        }
    }

    pub(crate) async fn settle_commit(&self, session: &Session, group_id: &GroupId) -> Result<()> {
        self.resolve_pending_commit(session, group_id)
            .await
            .map(drop)
    }

    /// Commits the Proposals pending in joined groups (a member leaving,
    /// ...) by reference. One member does it at once: the member device
    /// with the lowest device id among those no Proposal removes. The others
    /// wait a random delay within [`SyncSettings::proposal_commit_delay_min`]
    /// and `_max`, and commit only if the Proposals are still pending in the
    /// same epoch (the chosen member was offline). Caller holds the group
    /// lock.
    pub(crate) async fn commit_pending_proposals(&self, session: &Session) -> Result<()> {
        let own = session.device.clone();
        let pending = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    let mut pending = Vec::new();
                    for chat in txn.chats()? {
                        let gid = chat.group_id;
                        if chat.membership != Membership::Joined
                            || !engine.has_group(&*txn, &gid)?
                        {
                            continue;
                        }
                        let proposals = engine.pending_proposals(&*txn, &gid)?;
                        if proposals.is_empty() {
                            continue;
                        }
                        let removed: BTreeSet<DeviceRef> =
                            proposals.into_iter().filter_map(|p| p.removed).collect();
                        let committer = engine
                            .group_members(&*txn, &gid)?
                            .into_iter()
                            .filter(|m| !removed.contains(m))
                            .min_by(|a, b| {
                                (a.device_id.as_str(), a.user_id.as_str())
                                    .cmp(&(b.device_id.as_str(), b.user_id.as_str()))
                            });
                        let epoch = engine.group_epoch(&*txn, &gid)?;
                        pending.push((gid, epoch, committer.as_ref() == Some(&own)));
                    }
                    Ok(pending)
                })
            })
            .await?;
        for (group_id, epoch, chosen) in pending {
            if chosen {
                self.commit_proposals_now(session, &group_id).await?;
            } else {
                self.schedule_proposal_commit(group_id, epoch);
            }
        }
        Ok(())
    }

    /// Commits the group's pending Proposals. Proposals the hub refuses to
    /// see committed (e.g. no longer pending there) are dropped, so they
    /// are not committed again; unknown outcomes keep the commit pending.
    pub(crate) async fn commit_proposals_now(
        &self,
        session: &Session,
        group_id: &GroupId,
    ) -> Result<()> {
        match self.commit(session, group_id, CommitOp::Proposals).await {
            Ok(_) => Ok(()),
            Err(ClientError::Transport(err)) if outcome_unknown(&err) => Err(err.into()),
            Err(err) => {
                tracing::warn!(%group_id, %err, "cannot commit the pending proposals; dropping them");
                let gid = group_id.clone();
                self.run(move |store, engine| {
                    store.transaction(|txn| {
                        if engine.has_group(&*txn, &gid)? {
                            engine.clear_pending_proposals(&*txn, &gid)?;
                        }
                        Ok(())
                    })
                })
                .await
            }
        }
    }

    /// Commits the group's Proposals of `epoch` after a random delay,
    /// unless another member committed them meanwhile.
    fn schedule_proposal_commit(&self, group_id: GroupId, epoch: u64) {
        let key = (group_id, epoch);
        let timers = || {
            self.inner
                .proposal_timers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
        };
        if !timers().insert(key.clone()) {
            return;
        }
        let settings = self.inner.sync_settings;
        let delay = jittered(
            settings.proposal_commit_delay_min,
            settings.proposal_commit_delay_max,
        );
        tracing::debug!(group_id = %key.0, epoch, ?delay, "another member should commit the pending proposals");
        let client = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            client
                .inner
                .proposal_timers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            let (group_id, epoch) = key;
            if let Err(err) = client.commit_proposals_if_pending(&group_id, epoch).await {
                tracing::debug!(%group_id, %err, "committing the pending proposals failed");
            }
        });
    }

    async fn commit_proposals_if_pending(&self, group_id: &GroupId, epoch: u64) -> Result<()> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        // The chosen member's commit may be waiting on the hub.
        self.sync_locked(&session).await?;
        let gid = group_id.clone();
        let pending = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    Ok(txn
                        .chat(&gid)?
                        .is_some_and(|c| c.membership == Membership::Joined)
                        && engine.has_group(&*txn, &gid)?
                        && engine.group_epoch(&*txn, &gid)? == epoch
                        && !engine.pending_proposals(&*txn, &gid)?.is_empty())
                })
            })
            .await?;
        if !pending {
            return Ok(());
        }
        tracing::info!(%group_id, epoch, "committing pending proposals another member did not commit");
        self.commit_proposals_now(&session, group_id).await
    }

    /// Commits the group's pending Proposals, if any, so that this device
    /// can encrypt again: MLS refuses application messages while Proposals
    /// are pending. Caller holds the group lock.
    pub(crate) async fn commit_proposals_before_send(
        &self,
        session: &Session,
        group_id: &GroupId,
    ) -> Result<()> {
        let gid = group_id.clone();
        let pending = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    Ok(txn
                        .chat(&gid)?
                        .is_some_and(|c| c.membership == Membership::Joined)
                        && engine.has_group(&*txn, &gid)?
                        && !engine.pending_proposals(&*txn, &gid)?.is_empty())
                })
            })
            .await?;
        if pending {
            self.commit_proposals_now(session, group_id).await?;
        }
        Ok(())
    }

    /// Commits the MLS removal of devices that left a group (a revocation,
    /// or a hub-side removal) but are still in the tree. Only the
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
            let op = CommitOp::Remove(devices.clone());
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
    /// hub.
    pub(crate) async fn sync_chat_kind(
        &self,
        _session: &Session,
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
            .authed(|t| {
                let gid = group_id.clone();
                async move { self.inner.transport.group_info(&t, &gid).await }
            })
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

    pub(crate) async fn upload_key_packages(&self, _session: &Session) -> Result<()> {
        let key_packages = self
            .run(|store, engine| {
                store.transaction(|txn| Ok(engine.generate_key_packages(&*txn, KEY_PACKAGE_BATCH)?))
            })
            .await?;
        self.authed(|t| {
            let key_packages = key_packages.clone();
            async move {
                self.inner
                    .transport
                    .upload_key_packages(&t, key_packages, false)
                    .await
            }
        })
        .await?;
        Ok(())
    }

    /// Claims a KeyPackage of every active device of `users` and of this
    /// user's other devices, except this device and `exclude`.
    pub(crate) async fn claim_key_packages(
        &self,
        session: &Session,
        users: &[UserId],
        exclude: &[DeviceRef],
    ) -> Result<Vec<ClaimedKeyPackage>> {
        let users: Vec<UserId> = users
            .iter()
            .chain([&session.device.user_id])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .cloned()
            .collect();
        let claimed = self
            .authed(|t| {
                let users = users.clone();
                async move { self.inner.transport.claim_key_packages(&t, &users).await }
            })
            .await?;
        // Only requested users, one KeyPackage per device: the hub must not
        // pick who joins.
        let mut seen = BTreeSet::new();
        Ok(claimed
            .into_iter()
            .filter(|k| users.contains(&k.device.user_id) && seen.insert(k.device.clone()))
            .filter(|k| k.device != session.device && !exclude.contains(&k.device))
            .collect())
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

    /// Broadcasts `changes`, except those of the self groups.
    pub(crate) fn emit(&self, changes: &[StateChange]) {
        if changes.is_empty() {
            return;
        }
        for change in self.visible(changes.to_vec()) {
            // No subscriber is fine.
            let _ = self.inner.changes.send(change);
        }
    }

    /// `changes` without those of the self groups, which no chat list or
    /// timeline shows.
    pub(crate) fn visible(&self, mut changes: Vec<StateChange>) -> Vec<StateChange> {
        let hidden = match self.inner.store.self_groups() {
            Ok(hidden) => hidden,
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the self groups");
                return changes;
            }
        };
        changes.retain(|change| {
            let group_id = match change {
                StateChange::ChatUpserted(chat) => &chat.group_id,
                StateChange::ChatRemoved(group_id)
                | StateChange::MessageRemoved { group_id, .. }
                | StateChange::Typing { group_id, .. } => group_id,
                StateChange::MessageUpserted(message) => &message.group_id,
                StateChange::MembershipChanged(event) => &event.group_id,
                StateChange::KeyPackagesLow => return true,
            };
            !hidden.contains(group_id)
        });
        changes
    }

    pub(crate) fn require_session(&self) -> Result<Session> {
        self.session().ok_or(ClientError::NotLoggedIn)
    }

    pub(crate) fn set_session(&self, session: Session) {
        *self
            .inner
            .session
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(session);
    }

    /// Signed-out state: forgets the session in memory and in the keystore.
    /// Keys and local data stay.
    pub(crate) fn clear_session(&self) -> Result<()> {
        *self
            .inner
            .session
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        Ok(self.inner.secrets.delete(SESSION_SECRET_KEY)?)
    }
}

/// A random duration in `[min, max]`.
fn jittered(min: Duration, max: Duration) -> Duration {
    let mut bytes = [0u8; 8];
    // A fixed delay is still correct, only less spread out.
    let _ = rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes);
    let span = max.saturating_sub(min).as_millis() as u64;
    min + Duration::from_millis(u64::from_le_bytes(bytes) % (span + 1))
}

pub(crate) fn new_client_id() -> Result<ClientId, BaseError> {
    Ok(ClientId::new(new_message_id()?.as_str()).expect("message ids are client ids"))
}
