use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use gim_base::model::{ChatKind as BaseChatKind, Membership, MessageContent as BaseContent};
use gim_base::StateReader;
use gim_common::{GroupId, MessageId, UserId};
use gim_sdk::transport::Transport;
use gim_sdk::{Client, ClientBuilder, OutboxSender, SESSION_SECRET_KEY};
use gim_sqlite::{SqliteStore, DATABASE_FILE_NAME};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use url::Url;

use crate::error::parse_id;
use crate::hooks::HookSecrets;
use crate::transport::UnavailableTransport;
use crate::{
    ChatListDiff, ChatListListener, ConnectionState, GimError, PlatformHooks, Session, TaskHandle,
    Timeline, UserProfile,
};

/// Pause between two event fetches while connected.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// First and maximum pause after a failed sync.
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Copies of files passed to `send_media`, under the data directory.
const OUTGOING_DIR: &str = "outgoing";

type Sdk = Client<SqliteStore>;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ClientConfig {
    /// Base URL of gim-server, `http://` or `https://`.
    pub server_url: String,
}

/// Receives connection state changes. The first callback carries the current
/// state.
#[uniffi::export(with_foreign)]
pub trait ConnectionStateListener: Send + Sync {
    fn on_change(&self, state: ConnectionState);
}

/// Receives the users currently typing in one chat (never the signed-in
/// user). The first callback carries the current set, possibly empty.
#[uniffi::export(with_foreign)]
pub trait TypingListener: Send + Sync {
    fn on_update(&self, user_ids: Vec<String>);
}

/// Creates the client. Opens (or creates) local state under
/// `hooks.data_dir()`; it does not touch the network.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_client(
    config: ClientConfig,
    hooks: Arc<dyn PlatformHooks>,
) -> Result<Arc<GimClient>, GimError> {
    // The gim-server HTTP transport does not exist yet.
    GimClient::open(config, hooks, |_| None).await.map(Arc::new)
}

/// Like [`create_client`], over an in-memory fake server shared by every
/// client given a clone of `transport`. Rust only; not exported over FFI.
#[cfg(feature = "testing")]
pub async fn create_client_with_fake_transport(
    config: ClientConfig,
    hooks: Arc<dyn PlatformHooks>,
    transport: gim_sdk::testing::FakeTransport,
) -> Result<Arc<GimClient>, GimError> {
    GimClient::open(config, hooks, move |_| {
        Some(Arc::new(transport) as Arc<dyn Transport>)
    })
    .await
    .map(Arc::new)
}

fn parse_server_url(value: &str) -> Result<Url, GimError> {
    let invalid = |reason: String| GimError::InvalidInput {
        reason: format!("server_url: {reason}"),
    };
    let url = Url::parse(value).map_err(|e| invalid(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid(format!("unsupported scheme '{}'", url.scheme())));
    }
    if url.host().is_none() {
        return Err(invalid("missing host".to_string()));
    }
    Ok(url)
}

/// State shared with the sync task.
struct Shared {
    network_reachable: AtomicBool,
    /// Wakes the sync task early (reachability changed).
    wake: Notify,
    connection: watch::Sender<ConnectionState>,
}

impl Shared {
    fn set_connection(&self, state: ConnectionState) {
        self.connection.send_if_modified(|current| {
            let changed = *current != state;
            *current = state;
            changed
        });
    }

    async fn sleep_or_wake(&self, duration: Duration) {
        tokio::select! {
            () = self.wake.notified() => {}
            () = tokio::time::sleep(duration) => {}
        }
    }
}

/// The running sync loop and outbox sender; both stop when dropped.
struct SyncTasks {
    sync: JoinHandle<()>,
    _outbox: OutboxSender,
}

impl Drop for SyncTasks {
    fn drop(&mut self) {
        self.sync.abort();
    }
}

/// One account on one device. All methods may be called from any thread.
#[derive(uniffi::Object)]
pub struct GimClient {
    sdk: Sdk,
    hooks: Arc<dyn PlatformHooks>,
    data_dir: PathBuf,
    /// Whether `sdk` talks to a real (or fake) server.
    has_transport: bool,
    signed_out: AtomicBool,
    shared: Arc<Shared>,
    sync: Mutex<Option<SyncTasks>>,
}

impl GimClient {
    async fn open(
        config: ClientConfig,
        hooks: Arc<dyn PlatformHooks>,
        transport: impl FnOnce(&Url) -> Option<Arc<dyn Transport>>,
    ) -> Result<Self, GimError> {
        let server_url = parse_server_url(&config.server_url)?;
        let data_dir = PathBuf::from(hooks.data_dir());
        if !data_dir.is_absolute() {
            return Err(GimError::InvalidInput {
                reason: format!("data_dir must be absolute: {}", data_dir.display()),
            });
        }
        let dir = data_dir.clone();
        let store = tokio::task::spawn_blocking(move || SqliteStore::open(dir)).await??;
        let transport = transport(&server_url);
        let has_transport = transport.is_some();
        let sdk = ClientBuilder::new(
            Arc::new(store),
            transport.unwrap_or_else(|| Arc::new(UnavailableTransport)),
            Arc::new(HookSecrets(hooks.clone())),
        )
        .data_dir(&data_dir)
        .build()?;
        sdk.restore_session().await?;
        let shared = Arc::new(Shared {
            network_reachable: AtomicBool::new(hooks.is_network_reachable()),
            wake: Notify::new(),
            connection: watch::channel(ConnectionState::Offline).0,
        });
        Ok(Self {
            sdk,
            hooks,
            data_dir,
            has_transport,
            signed_out: AtomicBool::new(false),
            shared,
            sync: Mutex::new(None),
        })
    }

    /// The SDK client, unless signed out.
    fn sdk(&self) -> Result<&Sdk, GimError> {
        if self.signed_out.load(Ordering::SeqCst) {
            return Err(GimError::NotRegistered);
        }
        Ok(&self.sdk)
    }

    /// The SDK client for a call that needs the server.
    fn network(&self) -> Result<&Sdk, GimError> {
        let sdk = self.sdk()?;
        if !self.has_transport {
            return Err(GimError::NotImplemented);
        }
        Ok(sdk)
    }

    /// Runs a store read off the async runtime.
    async fn read<R, F>(&self, f: F) -> Result<R, GimError>
    where
        R: Send + 'static,
        F: FnOnce(&SqliteStore) -> Result<R, GimError> + Send + 'static,
    {
        let store = self.sdk()?.store().clone();
        tokio::task::spawn_blocking(move || f(&store)).await?
    }

    fn own_user(&self) -> Result<UserId, GimError> {
        Ok(self
            .sdk()?
            .session()
            .ok_or(GimError::NotRegistered)?
            .device
            .user_id)
    }

    fn stop_sync_tasks(&self) {
        drop(self.sync.lock().unwrap_or_else(|e| e.into_inner()).take());
        self.shared.set_connection(ConnectionState::Offline);
    }
}

/// Fetches events until stopped: `Connecting` until the first successful
/// fetch, `Syncing` while catching up, then `Connected`; `Offline` while the
/// platform reports no network. Failures back off exponentially; a
/// reachability change retries at once.
async fn run_sync(sdk: Sdk, shared: Arc<Shared>) {
    let mut backoff = MIN_BACKOFF;
    loop {
        if !shared.network_reachable.load(Ordering::SeqCst) {
            shared.set_connection(ConnectionState::Offline);
            shared.wake.notified().await;
            continue;
        }
        let connected = *shared.connection.borrow() == ConnectionState::Connected;
        if !connected && *shared.connection.borrow() != ConnectionState::Syncing {
            shared.set_connection(ConnectionState::Connecting);
        }
        match sdk.sync_once().await {
            Ok(changes) => {
                backoff = MIN_BACKOFF;
                if changes.is_empty() {
                    shared.set_connection(ConnectionState::Connected);
                    shared.sleep_or_wake(POLL_INTERVAL).await;
                } else if !connected {
                    shared.set_connection(ConnectionState::Syncing);
                }
            }
            Err(_) => {
                shared.set_connection(ConnectionState::Connecting);
                shared.sleep_or_wake(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Profiles of the chat members, one per user in member order.
fn member_profiles(store: &SqliteStore, group_id: &GroupId) -> Result<Vec<UserProfile>, GimError> {
    let chat = store.chat(group_id)?.ok_or_else(|| GimError::NotFound {
        reason: format!("chat {group_id}"),
    })?;
    let mut seen = BTreeSet::new();
    let mut profiles = Vec::new();
    for member in chat.members {
        let user_id = member.device.user_id;
        if !seen.insert(user_id.clone()) {
            continue;
        }
        profiles.push(match store.user(&user_id)? {
            Some(user) => user.into(),
            None => UserProfile {
                user_id: user_id.to_string(),
                handle: user_id.to_string(),
                display_name: member.display_name.unwrap_or_else(|| user_id.to_string()),
            },
        });
    }
    Ok(profiles)
}

/// The joined direct chat whose only other user is `user_id`.
fn find_direct_chat(
    store: &SqliteStore,
    own: &UserId,
    user_id: &UserId,
) -> Result<Option<GroupId>, GimError> {
    Ok(store
        .chats()?
        .into_iter()
        .find(|chat| {
            let others: BTreeSet<&UserId> = chat
                .members
                .iter()
                .map(|m| &m.device.user_id)
                .filter(|u| *u != own)
                .collect();
            chat.kind == BaseChatKind::Direct
                && chat.membership == Membership::Joined
                && others.len() == 1
                && others.contains(user_id)
        })
        .map(|chat| chat.group_id))
}

/// Copies `source` to a fresh directory under `outgoing`, keeping its file
/// name (sent as the attachment name).
fn copy_outgoing(data_dir: &Path, source: &Path) -> Result<PathBuf, GimError> {
    let file_name = source.file_name().ok_or_else(|| GimError::InvalidInput {
        reason: format!("not a file path: {}", source.display()),
    })?;
    let dir = data_dir
        .join(OUTGOING_DIR)
        .join(gim_base::new_message_id()?.as_str());
    std::fs::create_dir_all(&dir)?;
    let copy = dir.join(file_name);
    std::fs::copy(source, &copy).map_err(|e| GimError::InvalidInput {
        reason: format!("cannot read {}: {e}", source.display()),
    })?;
    Ok(copy)
}

fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    let removed = if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match removed {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        removed => removed,
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GimClient {
    /// The persisted session, or `None` before `register`.
    pub async fn session(&self) -> Result<Option<Session>, GimError> {
        let Some(session) = self.sdk()?.session() else {
            return Ok(None);
        };
        let user_id = session.device.user_id.clone();
        let user = self.read(move |store| Ok(store.user(&user_id)?)).await?;
        let user_id = session.device.user_id.to_string();
        let (handle, display_name) = match user {
            Some(user) => (user.handle, user.display_name),
            None => (user_id.clone(), user_id.clone()),
        };
        Ok(Some(Session {
            user_id,
            device_id: session.device.device_id.to_string(),
            handle,
            display_name,
        }))
    }

    /// Creates the account and this device on the server and persists the
    /// session.
    pub async fn register(
        &self,
        handle: String,
        display_name: String,
    ) -> Result<Session, GimError> {
        let session = self.network()?.register(&handle, &display_name).await?;
        Ok(Session {
            user_id: session.device.user_id.to_string(),
            device_id: session.device.device_id.to_string(),
            handle,
            display_name,
        })
    }

    /// Stops sync and deletes the session, local data and keystore secrets.
    pub async fn sign_out(&self) -> Result<(), GimError> {
        self.sdk()?;
        self.stop_sync_tasks();
        self.signed_out.store(true, Ordering::SeqCst);
        self.hooks
            .secure_store_delete(SESSION_SECRET_KEY.to_string());
        let data_dir = self.data_dir.clone();
        tokio::task::spawn_blocking(move || {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                remove_if_exists(&data_dir.join(format!("{DATABASE_FILE_NAME}{suffix}")))?;
            }
            remove_if_exists(&data_dir.join("tmp"))?;
            remove_if_exists(&data_dir.join(OUTGOING_DIR))
        })
        .await??;
        Ok(())
    }

    /// Starts the background sync loop and outbox sender.
    pub async fn start_sync(&self) -> Result<(), GimError> {
        let sdk = self.network()?;
        if sdk.session().is_none() {
            return Err(GimError::NotRegistered);
        }
        let mut sync = self.sync.lock().unwrap_or_else(|e| e.into_inner());
        if sync.is_none() {
            *sync = Some(SyncTasks {
                sync: tokio::spawn(run_sync(sdk.clone(), self.shared.clone())),
                _outbox: sdk.start_outbox_sender(),
            });
        }
        Ok(())
    }

    /// Stops the background sync loop and outbox sender.
    pub async fn stop_sync(&self) -> Result<(), GimError> {
        self.sdk()?;
        self.stop_sync_tasks();
        Ok(())
    }

    /// Reports a reachability change from the platform network monitor.
    pub fn set_network_reachable(&self, reachable: bool) {
        let was = self
            .shared
            .network_reachable
            .swap(reachable, Ordering::SeqCst);
        if reachable && !was {
            self.sdk.network_reachable();
        }
        if reachable != was {
            self.shared.wake.notify_one();
        }
    }

    /// Looks up a user by handle; `None` if no such user exists.
    pub async fn find_user(&self, handle: String) -> Result<Option<UserProfile>, GimError> {
        let user = self.network()?.find_user(&handle).await?;
        Ok(user.map(Into::into))
    }

    /// Returns the chat id of the direct chat with `user_id`, creating it if
    /// needed.
    pub async fn create_direct_chat(&self, user_id: String) -> Result<String, GimError> {
        let sdk = self.network()?;
        let user_id: UserId = parse_id("user_id", user_id)?;
        let own = self.own_user()?;
        let other = user_id.clone();
        if let Some(existing) = self
            .read(move |store| find_direct_chat(store, &own, &other))
            .await?
        {
            return Ok(existing.into());
        }
        Ok(sdk.create_direct_chat(&user_id).await?.into())
    }

    /// Creates a group chat and returns its chat id.
    pub async fn create_group_chat(
        &self,
        name: String,
        member_user_ids: Vec<String>,
    ) -> Result<String, GimError> {
        let sdk = self.network()?;
        let users = member_user_ids
            .into_iter()
            .map(|id| parse_id("member_user_ids", id))
            .collect::<Result<Vec<UserId>, _>>()?;
        let name = Some(name).filter(|n| !n.is_empty());
        Ok(sdk.create_group_chat(name, &users).await?.into())
    }

    pub async fn add_members(
        &self,
        chat_id: String,
        user_ids: Vec<String>,
    ) -> Result<(), GimError> {
        let sdk = self.network()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let users = user_ids
            .into_iter()
            .map(|id| parse_id("user_ids", id))
            .collect::<Result<Vec<UserId>, _>>()?;
        Ok(sdk.add_members(&group_id, &users).await?)
    }

    pub async fn remove_member(&self, chat_id: String, user_id: String) -> Result<(), GimError> {
        let sdk = self.network()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let user_id: UserId = parse_id("user_id", user_id)?;
        Ok(sdk.remove_members(&group_id, &[user_id]).await?)
    }

    /// Current members of the chat, one entry per user (not per device),
    /// including the signed-in user.
    pub async fn chat_members(&self, chat_id: String) -> Result<Vec<UserProfile>, GimError> {
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        self.read(move |store| member_profiles(store, &group_id))
            .await
    }

    pub async fn leave_chat(&self, chat_id: String) -> Result<(), GimError> {
        let sdk = self.network()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        Ok(sdk.leave(&group_id).await?)
    }

    /// Updates the group name and/or avatar; `None` leaves a field unchanged.
    pub async fn set_group_info(
        &self,
        chat_id: String,
        name: Option<String>,
        avatar_file_path: Option<String>,
    ) -> Result<(), GimError> {
        // gim-sdk cannot share group info yet.
        let _ = (chat_id, name, avatar_file_path);
        Err(GimError::NotImplemented)
    }

    /// Queues a text message and returns its message id (the client id).
    pub async fn send_text(
        &self,
        chat_id: String,
        body: String,
        reply_to: Option<String>,
    ) -> Result<String, GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let reply_to: Option<MessageId> =
            reply_to.map(|id| parse_id("reply_to", id)).transpose()?;
        Ok(sdk.send_text(&group_id, body, reply_to).await?.into())
    }

    /// Encrypts, uploads and sends a file; returns its message id. The file
    /// at `file_path` is copied before this returns.
    pub async fn send_media(
        &self,
        chat_id: String,
        file_path: String,
        mime: String,
        caption: Option<String>,
        reply_to: Option<String>,
    ) -> Result<String, GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let reply_to: Option<MessageId> =
            reply_to.map(|id| parse_id("reply_to", id)).transpose()?;
        let data_dir = self.data_dir.clone();
        let copy =
            tokio::task::spawn_blocking(move || copy_outgoing(&data_dir, Path::new(&file_path)))
                .await??;
        Ok(sdk
            .send_media(&group_id, copy, mime, caption, reply_to)
            .await?
            .into())
    }

    pub async fn edit_message(
        &self,
        chat_id: String,
        message_id: String,
        new_body: String,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let target: MessageId = parse_id("message_id", message_id)?;
        sdk.edit(&group_id, &target, new_body).await?;
        Ok(())
    }

    pub async fn delete_message(
        &self,
        chat_id: String,
        message_id: String,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let target: MessageId = parse_id("message_id", message_id)?;
        sdk.delete(&group_id, &target).await?;
        Ok(())
    }

    pub async fn react(
        &self,
        chat_id: String,
        message_id: String,
        emoji: String,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let target: MessageId = parse_id("message_id", message_id)?;
        sdk.react(&group_id, &target, emoji).await?;
        Ok(())
    }

    pub async fn unreact(
        &self,
        chat_id: String,
        message_id: String,
        emoji: String,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let target: MessageId = parse_id("message_id", message_id)?;
        sdk.unreact(&group_id, &target, emoji).await?;
        Ok(())
    }

    /// Re-queues a message in `SendState::Failed`.
    pub async fn retry_send(&self, chat_id: String, message_id: String) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let _: GroupId = parse_id("chat_id", chat_id)?;
        let message_id: MessageId = parse_id("message_id", message_id)?;
        Ok(sdk.retry_send(&message_id).await?)
    }

    /// Removes an unsent message from the outbox and the timeline.
    pub async fn cancel_send(&self, chat_id: String, message_id: String) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let _: GroupId = parse_id("chat_id", chat_id)?;
        let message_id: MessageId = parse_id("message_id", message_id)?;
        Ok(sdk.cancel_send(&message_id).await?)
    }

    /// Marks everything up to and including `up_to_message_id` as read and
    /// sends a read receipt.
    pub async fn mark_read(
        &self,
        chat_id: String,
        up_to_message_id: String,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        // gim-sdk marks the whole chat read.
        let _: MessageId = parse_id("up_to_message_id", up_to_message_id)?;
        Ok(sdk.mark_read(&group_id).await?)
    }

    pub async fn set_typing(&self, chat_id: String, active: bool) -> Result<(), GimError> {
        let sdk = self.network()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        Ok(sdk.set_typing(&group_id, active).await?)
    }

    /// Downloads and decrypts an attachment to `dest_path` and returns the
    /// path of the decrypted file.
    pub async fn fetch_media(
        &self,
        chat_id: String,
        message_id: String,
        dest_path: String,
    ) -> Result<String, GimError> {
        let sdk = self.network()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let message_id: MessageId = parse_id("message_id", message_id)?;
        sdk.fetch_media(&group_id, &message_id, &dest_path).await?;
        Ok(dest_path)
    }

    /// Like `fetch_media` for the thumbnail; `None` if there is none.
    pub async fn fetch_thumbnail(
        &self,
        chat_id: String,
        message_id: String,
        dest_path: String,
    ) -> Result<Option<String>, GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let message_id: MessageId = parse_id("message_id", message_id)?;
        let (gid, mid) = (group_id.clone(), message_id.clone());
        let has_thumbnail = self
            .read(move |store| {
                let message = store
                    .message(&mid)?
                    .filter(|m| m.group_id == gid)
                    .ok_or_else(|| GimError::NotFound {
                        reason: format!("message {mid} in chat {gid}"),
                    })?;
                match message.content {
                    BaseContent::Media { media, .. } => Ok(media.thumbnail.is_some()),
                    _ => Err(GimError::InvalidInput {
                        reason: format!("{mid} has no media"),
                    }),
                }
            })
            .await?;
        if !has_thumbnail {
            return Ok(None);
        }
        sdk.fetch_thumbnail(&group_id, &message_id, &dest_path)
            .await?;
        Ok(Some(dest_path))
    }

    /// Subscribes to the chat list; the first callback is a `Reset`.
    pub async fn chat_list(
        &self,
        listener: Arc<dyn ChatListListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        let service = gim_ui::ChatListService::new(self.sdk()?).await?;
        let (values, stream) = service.entries();
        Ok(Arc::new(TaskHandle::spawn(async move {
            // Keeps the list following the client.
            let _service = service;
            listener.on_update(vec![ChatListDiff::Reset {
                values: values.into_iter().map(Into::into).collect(),
            }]);
            let mut stream = std::pin::pin!(stream);
            while let Some(diffs) = stream.next().await {
                listener.on_update(diffs.into_iter().map(Into::into).collect());
            }
        })))
    }

    /// The timeline of one chat. Cheap; listeners are added on the result.
    pub async fn timeline(&self, chat_id: String) -> Result<Arc<Timeline>, GimError> {
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let inner = gim_ui::Timeline::new(self.sdk()?, group_id).await?;
        Ok(Arc::new(Timeline::new(inner)))
    }

    /// Subscribes to connection state changes.
    pub async fn connection_state(
        &self,
        listener: Arc<dyn ConnectionStateListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        let mut states = self.shared.connection.subscribe();
        Ok(Arc::new(TaskHandle::spawn(async move {
            let state = *states.borrow_and_update();
            listener.on_change(state);
            while states.changed().await.is_ok() {
                let state = *states.borrow_and_update();
                listener.on_change(state);
            }
        })))
    }

    /// Subscribes to typing notifications of one chat.
    pub async fn typing(
        &self,
        chat_id: String,
        listener: Arc<dyn TypingListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let typing = gim_ui::TypingNotifications::new(self.sdk()?, group_id)?;
        let (current, stream) = typing.subscribe();
        let to_strings = |users: Vec<UserId>| users.into_iter().map(String::from).collect();
        Ok(Arc::new(TaskHandle::spawn(async move {
            let _typing = typing;
            listener.on_update(to_strings(current));
            let mut stream = std::pin::pin!(stream);
            while let Some(users) = stream.next().await {
                listener.on_update(to_strings(users));
            }
        })))
    }
}
