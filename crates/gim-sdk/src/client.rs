//! The async client of one device.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::task::JoinHandle;

use gim_base::model::{ChatKind, Membership, MessageKind, StateChange, UserInfo};
use gim_base::{new_message_id, BaseClient, BaseError, StateReader, StateStore, StoreTxn};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::MlsEngine;
use gim_proto::envelope::Content;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex, Notify};

use crate::send::TypingState;
use crate::stream::ConnectionState;
use crate::sync::SyncSettings;
use crate::transport::{AccessToken, OutgoingMessage, PostError, Transport, TransportError};
use crate::{ClientError, Result, SecretStorage};

/// One-time KeyPackages uploaded at registration and per replenish.
pub const KEY_PACKAGE_BATCH: u32 = 100;
/// Retries of a commit rejected because another commit won the epoch.
pub const MAX_COMMIT_RETRIES: u32 = 3;
/// Posts of the same commit (same `client_id`) while its outcome is
/// unknown, before the call gives up and keeps it pending.
pub const COMMIT_POST_ATTEMPTS: u32 = 3;
/// [`SecretStorage`] key of the serialized [`Session`].
pub const SESSION_SECRET_KEY: &str = "gim.session";

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

    /// Timing of the sync loop; see [`SyncSettings`].
    pub fn sync_settings(mut self, settings: SyncSettings) -> Self {
        self.sync_settings = settings;
        self
    }

    /// Directory for temporary media files (encrypted uploads, partial
    /// downloads). Defaults to `gim-sdk` under the system temp directory.
    pub fn data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    /// A client without a session; call [`Client::register`] or
    /// [`Client::restore_session`] next.
    pub fn build(self) -> Client<S> {
        Client {
            inner: Arc::new(Inner {
                store: self.store,
                transport: self.transport,
                secrets: self.secrets,
                engine: MlsEngine::new(),
                session: RwLock::new(None),
                changes: broadcast::channel(CHANGES_CAPACITY).0,
                group_lock: Mutex::new(()),
                data_dir: self
                    .data_dir
                    .unwrap_or_else(|| std::env::temp_dir().join("gim-sdk")),
                flush_lock: Mutex::new(()),
                outbox_wake: Notify::new(),
                force_flush: AtomicBool::new(false),
                pending_commits: Default::default(),
                departed: Default::default(),
                typing: Default::default(),
                sync_settings: self.sync_settings,
                sync_task: Default::default(),
                sync_wake: Notify::new(),
                connection: std::sync::Mutex::new(ConnectionState::Offline),
                connection_changes: broadcast::channel(CONNECTION_CAPACITY).0,
            }),
        }
    }
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
    /// Commits whose outcome is not known yet, by group.
    pending_commits: std::sync::Mutex<HashMap<GroupId, PendingCommit>>,
    /// Devices dropped from a group's fan-out list that may still be in
    /// the MLS tree, by group.
    departed: std::sync::Mutex<BTreeMap<GroupId, BTreeSet<DeviceRef>>>,
    pub(crate) typing: std::sync::Mutex<HashMap<GroupId, TypingState>>,
    pub(crate) sync_settings: SyncSettings,
    pub(crate) sync_task: std::sync::Mutex<Option<JoinHandle<Result<()>>>>,
    /// Cuts the sync loop's reconnect wait short.
    pub(crate) sync_wake: Notify,
    pub(crate) connection: std::sync::Mutex<ConnectionState>,
    pub(crate) connection_changes: broadcast::Sender<ConnectionState>,
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

/// A commit posted (or about to be) whose acceptance is not confirmed, and
/// what has to follow it. Re-posted with the same `client_id` until the
/// server answers definitively.
struct PendingCommit {
    message: OutgoingMessage,
    merged: bool,
    then: AfterCommit,
}

#[derive(Clone)]
enum AfterCommit {
    Nothing,
    Welcome(OutgoingMessage),
    RemoveFromFanOut(Vec<DeviceRef>),
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
    /// there is none.
    pub async fn restore_session(&self) -> Result<bool> {
        let Some(encoded) = self.inner.secrets.get(SESSION_SECRET_KEY)? else {
            return Ok(false);
        };
        let session: Session = serde_json::from_slice(&encoded)
            .map_err(|e| ClientError::InvalidSession(e.to_string()))?;
        let identity = self
            .run(|store, engine| store.transaction(|txn| Ok(engine.identity(&*txn)?)))
            .await?;
        if identity != session.device {
            return Err(ClientError::InvalidSession(format!(
                "store identity {identity} does not match session device {}",
                session.device
            )));
        }
        self.seed_device_directory(&session).await?;
        self.set_session(session);
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
    /// other devices).
    pub async fn create_group_chat(
        &self,
        name: Option<String>,
        users: &[UserId],
    ) -> Result<GroupId> {
        self.create_chat(ChatKind::Group, name, users).await
    }

    /// Adds every device of `users` that is not a member yet.
    pub async fn add_members(&self, group_id: &GroupId, users: &[UserId]) -> Result<()> {
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
        if added.is_err() && !self.has_pending_commit(group_id) {
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
    /// local MLS group, and keeps the chat history as `Left`.
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
        let group_id = group_id.clone();
        let changes = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    if engine.has_group(&*txn, &group_id)? {
                        engine.delete_group(&*txn, &group_id)?;
                    }
                    let Some(mut chat) = txn.chat(&group_id)? else {
                        return Ok(vec![]);
                    };
                    chat.membership = Membership::Left;
                    txn.upsert_chat(&chat)?;
                    Ok(vec![StateChange::ChatUpserted(chat)])
                })
            })
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
        if !key_packages.is_empty() {
            self.commit(&session, &group_id, CommitOp::Add(key_packages))
                .await?;
        }
        Ok(group_id)
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
            let created = self
                .run(move |store, engine| {
                    store.transaction(|txn| match op {
                        CommitOp::Add(key_packages) => {
                            let (recipients, key_packages): (Vec<_>, Vec<_>) =
                                key_packages.into_iter().unzip();
                            let output = engine.add_members(&*txn, &gid, &key_packages)?;
                            let then = AfterCommit::Welcome(OutgoingMessage {
                                client_id: new_client_id()?,
                                epoch: output.epoch + 1,
                                kind: MessageKind::Welcome,
                                payload: output
                                    .welcome
                                    .clone()
                                    .expect("an add commit has a Welcome"),
                                recipients,
                            });
                            Ok(Some((output, then)))
                        }
                        CommitOp::Remove { devices, fan_out } => {
                            let members = engine.group_members(&*txn, &gid)?;
                            let devices: Vec<DeviceRef> = devices
                                .into_iter()
                                .filter(|d| members.contains(d))
                                .collect();
                            if devices.is_empty() {
                                return Ok(None);
                            }
                            let output = engine.remove_members(&*txn, &gid, &devices)?;
                            let then = if fan_out {
                                AfterCommit::RemoveFromFanOut(devices)
                            } else {
                                AfterCommit::Nothing
                            };
                            Ok(Some((output, then)))
                        }
                    })
                })
                .await?;
            let Some((output, then)) = created else {
                return Ok(false);
            };
            let message = OutgoingMessage {
                client_id: new_client_id()?,
                epoch: output.epoch,
                kind: MessageKind::Commit,
                payload: output.commit,
                recipients: vec![],
            };
            self.pending_commits().insert(
                group_id.clone(),
                PendingCommit {
                    message,
                    merged: false,
                    then,
                },
            );
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
        let Some((message, merged, then)) = self
            .pending_commits()
            .get(group_id)
            .map(|p| (p.message.clone(), p.merged, p.then.clone()))
        else {
            return Ok(Resolved::None);
        };
        if !merged {
            match self.post_until_known(session, group_id, message).await {
                Ok(seq) => {
                    let (gid, base) = (group_id.clone(), BaseClient::new(session.device.clone()));
                    let changes = self
                        .run(move |store, engine| base.merge_own_commit(store, engine, &gid, seq))
                        .await?;
                    self.emit(&changes);
                    if let Some(pending) = self.pending_commits().get_mut(group_id) {
                        pending.merged = true;
                    }
                }
                Err(PostError::Transport(err)) if outcome_unknown(&err) => return Err(err.into()),
                Err(err) => {
                    let gid = group_id.clone();
                    self.run(move |store, engine| {
                        store.transaction(|txn| Ok(engine.clear_pending_commit(&*txn, &gid)?))
                    })
                    .await?;
                    self.pending_commits().remove(group_id);
                    return match err {
                        PostError::EpochConflict { .. } => Ok(Resolved::Conflict),
                        PostError::Transport(err) => Err(err.into()),
                    };
                }
            }
        }
        let followed = match then {
            AfterCommit::Nothing => Ok(()),
            AfterCommit::Welcome(welcome) => {
                match self.post_until_known(session, group_id, welcome).await {
                    Ok(seq) => self.mark_applied(group_id, seq).await,
                    Err(err) => Err(err.into()),
                }
            }
            AfterCommit::RemoveFromFanOut(devices) => self
                .inner
                .transport
                .remove_group_members(&session.token, group_id, &devices)
                .await
                .map_err(Into::into),
        };
        match followed {
            Err(ClientError::Transport(err)) if outcome_unknown(&err) => Err(err.into()),
            followed => {
                self.pending_commits().remove(group_id);
                followed.map(|()| Resolved::Accepted)
            }
        }
    }

    /// Settles every pending commit; stops at the first error.
    pub(crate) async fn resolve_pending_commits(&self, session: &Session) -> Result<()> {
        let groups: Vec<GroupId> = self.pending_commits().keys().cloned().collect();
        for group_id in groups {
            self.resolve_pending_commit(session, &group_id).await?;
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

    pub(crate) fn has_pending_commit(&self, group_id: &GroupId) -> bool {
        self.pending_commits().contains_key(group_id)
    }

    fn pending_commits(&self) -> std::sync::MutexGuard<'_, HashMap<GroupId, PendingCommit>> {
        self.inner
            .pending_commits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Commits the MLS removal of devices that left a group by themselves
    /// (dropped from the fan-out list but still in the tree). Only the
    /// remaining member with the lowest leaf index does it, so members do
    /// not race each other.
    pub(crate) async fn remove_departed(&self, session: &Session) -> Result<()> {
        let departed = std::mem::take(&mut *self.departed());
        for (group_id, devices) in departed {
            let (gid, own) = (group_id.clone(), session.device.clone());
            let to_remove = self
                .run(move |store, engine| {
                    let joined = store
                        .chat(&gid)?
                        .is_some_and(|c| c.membership == Membership::Joined);
                    if !joined || !store.transaction(|txn| Ok(engine.has_group(&*txn, &gid)?))? {
                        return Ok(vec![]);
                    }
                    // Leaf index order.
                    let members =
                        store.transaction(|txn| Ok(engine.group_members(&*txn, &gid)?))?;
                    let present: Vec<DeviceRef> = members
                        .iter()
                        .filter(|m| devices.contains(m))
                        .cloned()
                        .collect();
                    let first_remaining = members.iter().find(|m| !devices.contains(m));
                    Ok(if first_remaining == Some(&own) {
                        present
                    } else {
                        vec![]
                    })
                })
                .await?;
            if to_remove.is_empty() {
                continue;
            }
            let op = CommitOp::Remove {
                devices: to_remove.clone(),
                fan_out: false,
            };
            if let Err(err) = self.commit(session, &group_id, op).await {
                if matches!(&err, ClientError::Transport(e) if outcome_unknown(e)) {
                    self.departed()
                        .entry(group_id)
                        .or_default()
                        .extend(to_remove);
                }
                return Err(err);
            }
        }
        Ok(())
    }

    pub(crate) fn departed(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<GroupId, BTreeSet<DeviceRef>>> {
        self.inner
            .departed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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
