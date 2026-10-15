//! The async client of one device.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use gim_base::model::{ChatKind, IncomingEvent, Membership, MessageKind, StateChange, UserInfo};
use gim_base::{new_message_id, BaseClient, BaseError, StateReader, StateStore, StoreTxn};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{CommitOutput, MlsEngine};
use gim_proto::envelope::Content;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};

use crate::transport::{AccessToken, OutgoingMessage, PostError, Transport, TransportError};
use crate::{ClientError, Result, SecretStorage};

/// One-time KeyPackages uploaded at registration and per replenish.
pub const KEY_PACKAGE_BATCH: u32 = 100;
/// Retries of a commit rejected because another commit won the epoch.
pub const MAX_COMMIT_RETRIES: u32 = 3;
/// [`SecretStorage`] key of the serialized [`Session`].
pub const SESSION_SECRET_KEY: &str = "gim.session";

/// Buffered [`StateChange`]s per subscriber before it lags.
const CHANGES_CAPACITY: usize = 1024;

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
        }
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
            }),
        }
    }
}

/// The client of one device. Cheap to clone; clones share all state.
pub struct Client<S> {
    inner: Arc<Inner<S>>,
}

impl<S> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct Inner<S> {
    store: Arc<S>,
    transport: Arc<dyn Transport>,
    secrets: Arc<dyn SecretStorage>,
    engine: MlsEngine,
    session: RwLock<Option<Session>>,
    changes: broadcast::Sender<StateChange>,
    /// Serializes everything that touches MLS group state (sync, commits,
    /// sends): a pending commit must not meet an incoming commit or an
    /// outgoing application message.
    group_lock: Mutex<()>,
}

#[derive(Clone)]
enum CommitOp {
    Add(Vec<Vec<u8>>),
    Remove(Vec<DeviceRef>),
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
        let added = self.add_devices(&session, group_id, key_packages).await;
        if added.is_err() {
            // Best effort: the original error is what matters.
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
        self.commit(&session, group_id, CommitOp::Remove(devices.clone()))
            .await?;
        // After the commit, so the removed devices still receive it.
        self.inner
            .transport
            .remove_group_members(&session.token, group_id, &devices)
            .await?;
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

    /// Queues `content` and makes one attempt to post it. A failed attempt
    /// leaves the entry in the outbox (`Pending` for a retryable error,
    /// `Failed` otherwise); the returned id is also the `client_id`.
    pub async fn send(&self, group_id: &GroupId, content: Content) -> Result<MessageId> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        let base = BaseClient::new(session.device.clone());
        let (gid, b) = (group_id.clone(), base.clone());
        let (message_id, changes) = self
            .run(move |store, _| b.enqueue(store, &gid, content, None, now_ms()))
            .await?;
        self.emit(&changes);
        let (id, b) = (message_id.clone(), base.clone());
        let prepared = self
            .run(move |store, engine| b.prepare(store, engine, &id))
            .await?;
        let message = OutgoingMessage {
            client_id: ClientId::new(message_id.as_str()).expect("message ids are client ids"),
            epoch: prepared.epoch,
            kind: MessageKind::Application,
            payload: prepared.payload,
            recipients: vec![],
        };
        let posted = self
            .inner
            .transport
            .post_message(&session.token, group_id, message)
            .await;
        let id = message_id.clone();
        let changes = match posted {
            Ok(seq) => {
                self.mark_applied(group_id, seq).await?;
                self.run(move |store, _| base.mark_sent(store, &id, seq))
                    .await?
            }
            Err(err) => {
                let retryable = matches!(
                    err,
                    PostError::Transport(TransportError::Network(_) | TransportError::Server(_))
                );
                let error = err.to_string();
                self.run(move |store, _| base.mark_failed(store, &id, &error, retryable, now_ms()))
                    .await?
            }
        };
        self.emit(&changes);
        Ok(message_id)
    }

    /// Fetches the pending events once (no waiting), applies them, persists
    /// the cursor and replenishes KeyPackages if the server asked for it.
    /// Returns the applied changes, which are also broadcast.
    pub async fn sync_once(&self) -> Result<Vec<StateChange>> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        self.sync_locked(&session).await
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
            self.add_devices(&session, &group_id, key_packages).await?;
        }
        Ok(group_id)
    }

    /// Commits adding the devices, then sends them the Welcome. The devices
    /// must already be on the fan-out list.
    async fn add_devices(
        &self,
        session: &Session,
        group_id: &GroupId,
        key_packages: Vec<(DeviceRef, Vec<u8>)>,
    ) -> Result<()> {
        let (recipients, key_packages): (Vec<_>, Vec<_>) = key_packages.into_iter().unzip();
        let output = self
            .commit(session, group_id, CommitOp::Add(key_packages))
            .await?;
        let welcome = OutgoingMessage {
            client_id: new_client_id()?,
            epoch: output.epoch + 1,
            kind: MessageKind::Welcome,
            payload: output.welcome.expect("an add commit has a Welcome"),
            recipients,
        };
        let seq = self
            .inner
            .transport
            .post_message(&session.token, group_id, welcome)
            .await?;
        self.mark_applied(group_id, seq).await
    }

    /// Creates a commit, posts it and merges it once accepted. On an epoch
    /// conflict the commit is dropped, the competing commit synced, and the
    /// commit recreated, up to [`MAX_COMMIT_RETRIES`] times.
    async fn commit(
        &self,
        session: &Session,
        group_id: &GroupId,
        op: CommitOp,
    ) -> Result<CommitOutput> {
        let base = BaseClient::new(session.device.clone());
        let mut attempt = 0;
        loop {
            attempt += 1;
            let (gid, op) = (group_id.clone(), op.clone());
            let output = self
                .run(move |store, engine| {
                    store.transaction(|txn| {
                        Ok(match &op {
                            CommitOp::Add(key_packages) => {
                                engine.add_members(&*txn, &gid, key_packages)?
                            }
                            CommitOp::Remove(devices) => {
                                engine.remove_members(&*txn, &gid, devices)?
                            }
                        })
                    })
                })
                .await?;
            let message = OutgoingMessage {
                client_id: new_client_id()?,
                epoch: output.epoch,
                kind: MessageKind::Commit,
                payload: output.commit.clone(),
                recipients: vec![],
            };
            let posted = self
                .inner
                .transport
                .post_message(&session.token, group_id, message)
                .await;
            let (gid, b) = (group_id.clone(), base.clone());
            let err = match posted {
                Ok(seq) => {
                    let changes = self
                        .run(move |store, engine| b.merge_own_commit(store, engine, &gid, seq))
                        .await?;
                    self.emit(&changes);
                    return Ok(output);
                }
                Err(err) => err,
            };
            // Not accepted (or unknown): the commit must not stay pending.
            // A network error after the server accepted it is not
            // recovered here.
            self.run(move |store, engine| {
                store.transaction(|txn| Ok(engine.clear_pending_commit(&*txn, &gid)?))
            })
            .await?;
            match err {
                PostError::EpochConflict { .. } if attempt <= MAX_COMMIT_RETRIES => {
                    self.sync_locked(session).await?;
                }
                PostError::EpochConflict { .. } => {
                    return Err(ClientError::CommitConflict(attempt))
                }
                PostError::Transport(err) => return Err(err.into()),
            }
        }
    }

    async fn sync_locked(&self, session: &Session) -> Result<Vec<StateChange>> {
        let cursor = self.run(|store, _| Ok(store.global_cursor()?)).await?;
        let batch = self
            .inner
            .transport
            .fetch_events(&session.token, cursor, Duration::ZERO)
            .await?;
        let joined: BTreeSet<GroupId> = batch
            .events
            .iter()
            .filter_map(|event| match event {
                IncomingEvent::Message(m)
                    if m.kind == MessageKind::Welcome && m.sender != session.device =>
                {
                    Some(m.group_id.clone())
                }
                _ => None,
            })
            .collect();
        let base = BaseClient::new(session.device.clone());
        let events = batch.events;
        let mut changes = self
            .run(move |store, engine| {
                let mut changes = Vec::new();
                for event in events {
                    changes.extend(base.apply(store, engine, event)?);
                }
                Ok(changes)
            })
            .await?;
        for group_id in joined {
            changes.extend(self.sync_chat_kind(session, group_id).await?);
        }
        if cursor != Some(batch.next_cursor) {
            let next = batch.next_cursor;
            self.run(move |store, _| store.transaction(|txn| Ok(txn.set_global_cursor(next)?)))
                .await?;
        }
        self.emit(&changes);
        if changes.contains(&StateChange::KeyPackagesLow) {
            self.upload_key_packages(session).await?;
        }
        Ok(changes)
    }

    /// Chats joined from a Welcome start as `Group`; takes the kind from the
    /// server.
    async fn sync_chat_kind(
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

    async fn upload_key_packages(&self, session: &Session) -> Result<()> {
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
    async fn mark_applied(&self, group_id: &GroupId, seq: u64) -> Result<()> {
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
    async fn run<R, F>(&self, f: F) -> Result<R>
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

    fn emit(&self, changes: &[StateChange]) {
        for change in changes {
            // No subscriber is fine.
            let _ = self.inner.changes.send(change.clone());
        }
    }

    fn require_session(&self) -> Result<Session> {
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

fn new_client_id() -> Result<ClientId> {
    Ok(ClientId::new(new_message_id()?.as_str()).expect("message ids are client ids"))
}
