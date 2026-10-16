use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures_util::StreamExt;
use gim_base::model::{ChatKind as BaseChatKind, Membership, MessageContent as BaseContent};
use gim_base::{BaseError, StateReader};
use gim_common::{DeviceId, GroupId, MessageId, UserId};
use gim_sdk::transport::Transport;
use gim_sdk::{
    Client, ClientBuilder, HttpTransport, OutboxSender, RecoveryCode, StoreLock,
    DEFAULT_STORE_LOCK_TIMEOUT, DEVICE_KEY_SECRET_KEY, OUTGOING_DIR, PUSH_REGISTRATION_SECRET_KEY,
    ROOT_KEY_SECRET_KEY, SESSION_SECRET_KEY,
};
use gim_sqlite::{DbKey, SqliteStore, DATABASE_FILE_NAME};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use url::Url;

use crate::callbacks::{on_callback_thread, Callbacks, Foreign, DRAIN_TIMEOUT};
use crate::convert::hub_infos;
use crate::error::parse_id;
use crate::hooks::HookSecrets;
use crate::timeline::PlatformTimeZone;
use crate::{
    ChatListDiff, ChatListListener, ChatState, ConnectionState, DeviceInfo, GimError, HubInfo,
    LinkSession, LocalTimeZone, NotificationContent, PendingApproval, PlatformHooks,
    PushRegistration, Session, TaskHandle, Timeline, UserProfile,
};

type Sdk = Client<SqliteStore>;

/// How long `sign_out` waits for the hubs to drop the push registration.
const SIGN_OUT_PUSH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ClientConfig {
    /// Base URL of the hub, `http://` or `https://`.
    pub server_url: String,
    /// The process kind; `None` is `ClientMode::App`.
    #[uniffi(default)]
    pub mode: Option<ClientMode>,
}

/// What the process creating the client is. See `docs/API.md`, *App
/// extensions*.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Enum)]
pub enum ClientMode {
    /// The app.
    #[default]
    App,
    /// An app extension (the iOS Notification Service Extension) on the
    /// app's data directory: no sync loop (`start_sync` fails), no
    /// KeyPackage uploads, hub refreshes or other maintenance, a small
    /// database cache, and a local database that cannot be opened (missing
    /// key, incompatible schema) fails `create_client` instead of being
    /// reset.
    Extension,
}

impl From<ClientMode> for gim_sdk::ClientMode {
    fn from(mode: ClientMode) -> Self {
        match mode {
            ClientMode::App => Self::App,
            ClientMode::Extension => Self::Extension,
        }
    }
}

/// Receives connection state changes. The first callback carries the current
/// state. Called on gim-core's callback thread.
#[uniffi::export(with_foreign)]
pub trait ConnectionStateListener: Send + Sync {
    fn on_change(&self, state: ConnectionState);
}

/// Receives the users currently typing in one chat (never the signed-in
/// user). The first callback carries the current set, possibly empty. Called
/// on gim-core's callback thread.
#[uniffi::export(with_foreign)]
pub trait TypingListener: Send + Sync {
    fn on_update(&self, user_ids: Vec<String>);
}

/// Receives the user's hubs (see `GimClient::hubs`) whenever they may have
/// changed: added, removed, verified, reprioritized, or a URL shared by
/// another own device. The first callback carries the current list. Called
/// on gim-core's callback thread.
#[uniffi::export(with_foreign)]
pub trait HubListListener: Send + Sync {
    fn on_update(&self, hubs: Vec<HubInfo>);
}

/// Creates the client. Opens (or creates) local state under
/// `hooks.data_dir()`; it does not touch the network.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_client(
    config: ClientConfig,
    hooks: Arc<dyn PlatformHooks>,
) -> Result<Arc<GimClient>, GimError> {
    GimClient::open(config, hooks, |url| {
        Ok(Arc::new(HttpTransport::new(url.clone())?) as Arc<dyn Transport>)
    })
    .await
    .map(Arc::new)
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
        Ok(Arc::new(transport) as Arc<dyn Transport>)
    })
    .await
    .map(Arc::new)
}

fn parse_server_url(value: &str) -> Result<Url, GimError> {
    parse_hub_url("server_url", value)
}

/// A hub's client API base URL: `http://` or `https://` with a host.
fn parse_hub_url(what: &str, value: &str) -> Result<Url, GimError> {
    let invalid = |reason: String| GimError::InvalidInput {
        reason: format!("{what}: {reason}"),
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

/// State shared with the connection state forwarder.
struct Shared {
    network_reachable: AtomicBool,
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
}

fn connection_state(state: gim_sdk::ConnectionState) -> ConnectionState {
    match state {
        gim_sdk::ConnectionState::Offline => ConnectionState::Offline,
        gim_sdk::ConnectionState::Connecting => ConnectionState::Connecting,
        gim_sdk::ConnectionState::Syncing => ConnectionState::Syncing,
        gim_sdk::ConnectionState::Connected => ConnectionState::Connected,
    }
}

/// The running gim-sdk sync loop, the task forwarding its connection states
/// and the outbox sender; all stop when dropped.
struct SyncTasks {
    sdk: Sdk,
    forward: JoinHandle<()>,
    _outbox: OutboxSender,
}

impl SyncTasks {
    fn start(sdk: &Sdk, shared: Arc<Shared>) -> Result<Self, GimError> {
        let mut states = sdk.subscribe_connection_state();
        sdk.start_sync()?;
        let source = sdk.clone();
        let forward = tokio::spawn(async move {
            loop {
                let state = match states.recv().await {
                    Ok(state) => state,
                    Err(broadcast::error::RecvError::Lagged(_)) => source.connection_state(),
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                shared.set_connection(connection_state(state));
            }
        });
        Ok(Self {
            sdk: sdk.clone(),
            forward,
            _outbox: sdk.start_outbox_sender(),
        })
    }
}

impl Drop for SyncTasks {
    fn drop(&mut self) {
        self.forward.abort();
        // Stopped on purpose: why the loop may have ended does not matter.
        let _ = self.sdk.stop_sync();
    }
}

/// One account on one device. All methods may be called from any thread.
#[derive(uniffi::Object)]
pub struct GimClient {
    sdk: Sdk,
    hooks: Arc<Foreign<dyn PlatformHooks>>,
    data_dir: PathBuf,
    local_state_reset: bool,
    signed_out: AtomicBool,
    shared: Arc<Shared>,
    sync: Mutex<Option<SyncTasks>>,
    local_time: Mutex<LocalTime>,
    callbacks: Arc<Callbacks>,
}

/// The local time zone and the open timelines that follow it.
#[derive(Default)]
struct LocalTime {
    /// `None` is UTC.
    zone: Option<Arc<dyn gim_ui::TimeZone>>,
    timelines: Vec<Weak<gim_ui::Timeline>>,
}

impl LocalTime {
    fn zone(&self) -> Arc<dyn gim_ui::TimeZone> {
        self.zone
            .clone()
            .unwrap_or_else(|| Arc::new(gim_ui::FixedOffset(0)))
    }
}

impl GimClient {
    async fn open(
        config: ClientConfig,
        hooks: Arc<dyn PlatformHooks>,
        transport: impl FnOnce(&Url) -> Result<Arc<dyn Transport>, GimError>,
    ) -> Result<Self, GimError> {
        let hooks = Arc::new(Foreign::new(hooks));
        let server_url = parse_server_url(&config.server_url)?;
        let data_dir = PathBuf::from(hooks.call(|hooks| hooks.data_dir()));
        if !data_dir.is_absolute() {
            return Err(GimError::InvalidInput {
                reason: format!("data_dir must be absolute: {}", data_dir.display()),
            });
        }
        let transport = transport(&server_url)?;
        let callbacks = Arc::new(Callbacks::default());
        let secrets = Arc::new(HookSecrets {
            hooks: hooks.clone(),
            callbacks: callbacks.clone(),
        });
        let dir = data_dir.clone();
        let mode = config.mode.unwrap_or_default();
        let (builder, local_state_reset) = tokio::task::spawn_blocking(move || {
            // Migrations and resets only under the store lock, so that the
            // other process never sees a half-migrated database.
            let mut dirs = std::fs::DirBuilder::new();
            dirs.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut dirs, 0o700);
            dirs.create(&dir).map_err(gim_sdk::ClientError::from)?;
            let lock = StoreLock::open(&dir, DEFAULT_STORE_LOCK_TIMEOUT)?;
            let _held = lock.acquire()?;
            if mode == ClientMode::Extension {
                let builder = ClientBuilder::open_extension(transport, secrets, |key| {
                    SqliteStore::open_for_extension(&dir, &DbKey::new(*key))
                        .map_err(BaseError::from)
                })?;
                return Ok::<_, GimError>((builder, false));
            }
            let mut reset = false;
            let builder = ClientBuilder::open(transport, secrets, |key, new_key| {
                let opened = SqliteStore::open_or_reset(&dir, &DbKey::new(*key), new_key)
                    .map_err(BaseError::from)?;
                reset = opened.1;
                Ok::<_, BaseError>(opened)
            })?;
            Ok::<_, GimError>((builder, reset))
        })
        .await??;
        let sdk = builder.data_dir(&data_dir).build()?;
        sdk.restore_session().await?;
        let shared = Arc::new(Shared {
            network_reachable: AtomicBool::new(hooks.call(|hooks| hooks.is_network_reachable())),
            connection: watch::channel(ConnectionState::Offline).0,
        });
        Ok(Self {
            sdk,
            hooks,
            data_dir,
            local_state_reset,
            signed_out: AtomicBool::new(false),
            shared,
            sync: Mutex::new(None),
            local_time: Mutex::default(),
            callbacks,
        })
    }

    /// The SDK client, unless signed out.
    fn sdk(&self) -> Result<&Sdk, GimError> {
        if self.signed_out.load(Ordering::SeqCst) {
            return Err(GimError::NotRegistered);
        }
        Ok(&self.sdk)
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

    /// `ChatNotActive` if this device is leaving or has left the chat.
    async fn check_active(&self, group_id: &GroupId) -> Result<(), GimError> {
        let gid = group_id.clone();
        let membership = self
            .read(move |store| Ok(store.chat(&gid)?.map(|chat| chat.membership)))
            .await?;
        match membership {
            Some(membership @ (Membership::Leaving | Membership::Left)) => {
                Err(GimError::ChatNotActive {
                    chat_id: group_id.to_string(),
                    state: gim_ui::ChatState::from(membership).into(),
                })
            }
            _ => Ok(()),
        }
    }

    /// Runs a call that sends to the chat: `ChatNotActive` instead of it if
    /// the chat is leaving or left, also when that is why it failed with
    /// `InvalidInput`.
    async fn in_active_chat<T>(
        &self,
        group_id: &GroupId,
        call: impl Future<Output = Result<T, GimError>>,
    ) -> Result<T, GimError> {
        self.check_active(group_id).await?;
        match call.await {
            Err(err @ GimError::InvalidInput { .. }) => {
                self.check_active(group_id).await?;
                Err(err)
            }
            result => result,
        }
    }

    fn stop_sync_tasks(&self) {
        drop(self.sync.lock().unwrap_or_else(|e| e.into_inner()).take());
        self.shared.set_connection(ConnectionState::Offline);
    }
}

impl Drop for GimClient {
    /// Like `sign_out` without deleting anything: stops the listeners and
    /// sync and waits (bounded) for the callbacks in flight.
    fn drop(&mut self) {
        self.callbacks.close();
        self.stop_sync_tasks();
        // Never block a runtime thread or the callback thread (the client
        // may be released from a task or a callback): a callback in flight
        // may need it.
        if tokio::runtime::Handle::try_current().is_err() && !on_callback_thread() {
            self.callbacks.drain(DRAIN_TIMEOUT);
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
/// name (sent as the attachment name). gim-sdk deletes the copy once
/// uploaded or cancelled, and orphaned copies on start.
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

/// MIME type of an avatar image, from its file extension.
fn image_mime(path: &Path) -> String {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        _ => "application/octet-stream",
    }
    .to_string()
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
    /// The persisted session, or `None` before an identity exists on this
    /// device (`create_identity`, `restore_from_recovery` or a device link).
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

    /// Creates a new identity with this device as its first one: uploads
    /// its signed DeviceList, recovery backup and KeyPackages to the hub,
    /// signs in and persists the session. Returns the recovery code, which
    /// is not stored and must be shown to the user once.
    ///
    /// On failure nothing of the attempt is kept: call it again (it creates
    /// a new user), also after the app restarted. `InvalidInput` once an
    /// identity exists.
    pub async fn create_identity(&self, display_name: String) -> Result<String, GimError> {
        let code = self.sdk()?.create_identity(&display_name).await?;
        Ok(code.to_string())
    }

    /// Restores the user on this (fresh) device from its recovery code
    /// after losing every device: becomes a new device of `user_id`, signed
    /// in, with a new self group. Chats are not rejoined automatically.
    ///
    /// Reads the user's current DeviceList from the hub (no session
    /// needed) and publishes the next one with this device added. With
    /// `revoke_others` every previously listed device is revoked; without
    /// it they all stay active. Fails with `NotFound` if the hub has no
    /// DeviceList of the user, and with `RetryLater` while the hub keeps
    /// throttling the read.
    ///
    /// On failure nothing of the attempt is kept: call it again, also after
    /// the app restarted. If the failed attempt's device was published, the
    /// retry revokes it.
    pub async fn restore_from_recovery(
        &self,
        user_id: String,
        recovery_code: String,
        revoke_others: bool,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let user_id: UserId = parse_id("user_id", user_id)?;
        let code: RecoveryCode = recovery_code.parse().map_err(|e| GimError::InvalidInput {
            reason: format!("recovery_code: {e}"),
        })?;
        Ok(sdk
            .restore_from_recovery(&user_id, &code, revoke_others)
            .await?)
    }

    /// New device: starts a link. Show `LinkSession.qr_string()` as a QR
    /// code and call `wait_link`. `hubs` are the hub URLs the old device
    /// may post the bundle to.
    pub fn start_link(&self, hubs: Vec<String>) -> Result<Arc<LinkSession>, GimError> {
        let link = self.sdk()?.start_link(hubs)?;
        Ok(Arc::new(LinkSession(link)))
    }

    /// New device: waits (up to 10 minutes) for the old device to approve
    /// the link, then signs in as a new device of that user. Returns the
    /// SAS to compare with the one the old device shows; finish with
    /// `confirm_link`.
    ///
    /// If no bundle arrived (network error, timeout), call it again with
    /// the same `link`. A failure after the bundle arrived keeps nothing of
    /// the attempt and uses `link` up: start a new link and approve it on
    /// the old device again (rejecting the first approval there revokes the
    /// failed attempt's device).
    pub async fn wait_link(&self, link: Arc<LinkSession>) -> Result<String, GimError> {
        let linked = self.sdk()?.wait_link(&link.0).await?;
        Ok(linked.sas.to_string())
    }

    /// New device: the user compared the SAS. `false` (mismatch) deletes
    /// the linked identity, the local database and the keystore secrets
    /// like `sign_out`; create a new client afterwards.
    pub async fn confirm_link(&self, accepted: bool) -> Result<(), GimError> {
        self.sdk()?.confirm_link(accepted).await?;
        if !accepted {
            self.sign_out().await?;
        }
        Ok(())
    }

    /// Old device: approves the link offer scanned from the new device's QR
    /// code. Certifies the new device and sends it the user's keys; returns
    /// the pending approval carrying the SAS to compare.
    pub async fn approve_link(&self, qr_string: String) -> Result<Arc<PendingApproval>, GimError> {
        let approval = self.sdk()?.approve_link(&qr_string).await?;
        Ok(Arc::new(PendingApproval(approval)))
    }

    /// Old device: the user compared the SAS. `true` adds the new device to
    /// the user's devices and to every joined chat (the new device must
    /// have finished `wait_link`); `false` revokes it.
    pub async fn confirm_approval(
        &self,
        approval: Arc<PendingApproval>,
        accepted: bool,
    ) -> Result<(), GimError> {
        Ok(self.sdk()?.confirm_approval(&approval.0, accepted).await?)
    }

    /// The devices of the signed-in user.
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, GimError> {
        let devices = self.sdk()?.devices().await?;
        Ok(devices.into_iter().map(Into::into).collect())
    }

    /// The devices of any user, from the user's current DeviceList; empty
    /// for an unknown user.
    pub async fn user_devices(&self, user_id: String) -> Result<Vec<DeviceInfo>, GimError> {
        let user_id: UserId = parse_id("user_id", user_id)?;
        let devices = self.sdk()?.user_devices(&user_id).await?;
        Ok(devices.into_iter().map(Into::into).collect())
    }

    /// Revokes another device of the signed-in user and removes it from
    /// every chat. `InvalidInput` for the current device.
    pub async fn revoke_device(&self, device_id: String) -> Result<(), GimError> {
        let device_id: DeviceId = parse_id("device_id", device_id)?;
        Ok(self.sdk()?.revoke_device(&device_id).await?)
    }

    /// The hubs of the user's hosting record known to this device, primary
    /// first (by priority, then hub id), including removed ones. With a
    /// single hub: the home hub.
    pub async fn hubs(&self) -> Result<Vec<HubInfo>, GimError> {
        Ok(hub_infos(self.sdk()?.hubs().await?))
    }

    /// Adds the hub at `url` (entered by the user) to the hosting record:
    /// checks that it is a gim hub, signs in there, lists it last
    /// (least preferred), uploads this device's KeyPackages there, follows
    /// its events and shares its URL with the own other devices. Adding a
    /// listed hub again only records `url` for it on this device. Returns
    /// the hub.
    pub async fn add_hub(&self, url: String) -> Result<HubInfo, GimError> {
        parse_hub_url("url", &url)?;
        let sdk = self.sdk()?;
        let added = sdk.add_hub(&url).await?;
        hub_infos(sdk.hubs().await?)
            .into_iter()
            .find(|h| h.hub_id == added.hub.hub_id)
            .ok_or_else(|| GimError::Internal {
                reason: format!("hub {} not listed after adding it", added.hub.hub_id),
            })
    }

    /// Removes a hub from the hosting record. `HomeHub` for the hub this
    /// client was created for, `LastHub` for the only listed hub,
    /// `HubOwnsGroups` (with the number of chats) unless
    /// `confirm_owned_groups` if the hub owns chats of this user,
    /// `HubNotDrained` while something sent through it is not settled.
    pub async fn remove_hub(
        &self,
        hub_id: String,
        confirm_owned_groups: bool,
    ) -> Result<(), GimError> {
        Ok(self
            .sdk()?
            .remove_hub(&hub_id, confirm_owned_groups)
            .await?)
    }

    /// Makes a listed hub the primary hub (priority 0, the others follow
    /// in their order). Every hub whose priority changes must be reachable
    /// from this device (`HubInfo.signed_in`), else `InvalidInput`.
    pub async fn set_primary_hub(&self, hub_id: String) -> Result<(), GimError> {
        Ok(self.sdk()?.set_primary_hub(&hub_id).await?)
    }

    /// The signed-in user's id; `None` without a session.
    pub fn user_id(&self) -> Option<String> {
        let session = self.sdk().ok()?.session()?;
        Some(session.device.user_id.into())
    }

    /// Whether opening this client discarded an existing local database
    /// (undecryptable, e.g. its key was lost, or incompatible). The session
    /// is gone with it: show onboarding and tell the user that local
    /// history was lost.
    pub fn local_state_reset(&self) -> bool {
        self.local_state_reset
    }

    /// Sets the signed-in user's display name; synced to the user's other
    /// devices and announced to every joined chat.
    pub async fn set_display_name(&self, name: String) -> Result<(), GimError> {
        Ok(self.sdk()?.set_display_name(&name).await?)
    }

    /// Claims `handle` in the hub directory, so others find the user with
    /// `find_user`; `Server(409)` if it is taken.
    pub async fn claim_handle(&self, handle: String) -> Result<(), GimError> {
        Ok(self.sdk()?.claim_handle(&handle).await?)
    }

    /// Releases the handle claimed with `claim_handle`; `InvalidInput` if
    /// there is none.
    pub async fn release_handle(&self) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let own = self.own_user()?;
        let handle = self
            .read(move |store| Ok(store.user(&own)?.map(|u| u.handle)))
            .await?
            .filter(|h| !h.is_empty())
            .ok_or_else(|| GimError::InvalidInput {
                reason: "no handle claimed".to_string(),
            })?;
        Ok(sdk.release_handle(&handle).await?)
    }

    /// Stops sync and the listeners and deletes the session, local data and
    /// keystore secrets. No callback runs once it returned. The deletion
    /// waits (up to 5 s, then goes ahead) for a change of the local state
    /// in an app extension; the extension's client then fails with
    /// `Storage`. `InvalidInput` in `ClientMode::Extension`: only the app
    /// signs out.
    pub async fn sign_out(&self) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        if sdk.mode() == gim_sdk::ClientMode::Extension {
            return Err(GimError::InvalidInput {
                reason: "an app extension cannot sign out".to_string(),
            });
        }
        // Best effort (gim-sdk logs failures), while the keystore hooks
        // still run: the hubs stop pushing to this device.
        let _ = tokio::time::timeout(SIGN_OUT_PUSH_TIMEOUT, sdk.unregister_push()).await;
        self.callbacks.close();
        self.stop_sync_tasks();
        self.signed_out.store(true, Ordering::SeqCst);
        let sdk = sdk.clone();
        let callbacks = self.callbacks.clone();
        let hooks = self.hooks.clone();
        let data_dir = self.data_dir.clone();
        // On a blocking-pool thread: the wait must not hold a runtime thread
        // a callback in flight may need.
        tokio::task::spawn_blocking(move || {
            // Bounded: a callback that never returns does not hang sign-out.
            callbacks.drain(DRAIN_TIMEOUT);
            // Under the store lock, so that an extension never writes to a
            // database being deleted; gim.lock itself stays.
            sdk.wipe_store(|| {
                for key in [
                    SESSION_SECRET_KEY,
                    DEVICE_KEY_SECRET_KEY,
                    ROOT_KEY_SECRET_KEY,
                    PUSH_REGISTRATION_SECRET_KEY,
                    ClientBuilder::<SqliteStore>::DB_KEY_SECRET_KEY,
                ] {
                    hooks.call(move |hooks| hooks.secure_store_delete(key.to_string()));
                }
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    remove_if_exists(&data_dir.join(format!("{DATABASE_FILE_NAME}{suffix}")))?;
                }
                remove_if_exists(&data_dir.join("tmp"))?;
                Ok(remove_if_exists(&data_dir.join(OUTGOING_DIR))?)
            })
        })
        .await??;
        Ok(())
    }

    /// Registers this device for push on every hub of the user (`PUT
    /// /v2/push/registration`) and keeps the registration on this device:
    /// hubs that cannot be reached now, hubs added later and hubs this
    /// device signs in to again get it from the sync loop. Call it with
    /// every new platform token; before onboarding it is only stored.
    /// `InvalidInput` for a malformed registration (see `PushRegistration`).
    pub async fn register_push(&self, registration: PushRegistration) -> Result<(), GimError> {
        Ok(self.sdk()?.register_push(registration.into()).await?)
    }

    /// Removes the push registration from every hub and from this device.
    /// The local copy is removed even if a hub could not be reached (then
    /// the error is returned). `sign_out` does this too.
    pub async fn unregister_push(&self) -> Result<(), GimError> {
        Ok(self.sdk()?.unregister_push().await?)
    }

    /// Turns a received push into notification content; for a Notification
    /// Service Extension or a background push handler. `payload` is the
    /// push server's payload object as JSON (`push.md` §3). Does one
    /// bounded unit of work (at most 15 s): applies the pushed message
    /// like sync does (the stream does not apply it again), joins a pushed
    /// invite, or reads one page of events. `InvalidInput` only if
    /// `payload` is not a JSON object; when the content cannot be read
    /// (not decryptable, offline, out of time) it returns `Generic` content
    /// with the body "New message" and `should_display` set: show that,
    /// never drop the notification. Show nothing when `should_display` is
    /// false.
    pub async fn process_push(&self, payload: String) -> Result<NotificationContent, GimError> {
        Ok(self.sdk()?.process_push(&payload).await?.into())
    }

    /// Starts the background sync loop (WebSocket stream with a long-poll
    /// fallback, reconnecting with backoff) and the outbox sender.
    pub async fn start_sync(&self) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        if sdk.session().is_none() {
            return Err(GimError::NotRegistered);
        }
        // What an app extension wrote while the app was in the background.
        // Best effort: the next store change picks it up as well.
        let _ = sdk.reload_external_changes().await;
        let mut sync = self.sync.lock().unwrap_or_else(|e| e.into_inner());
        if sync.is_none() {
            *sync = Some(SyncTasks::start(sdk, self.shared.clone())?);
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
        // Retries pending sends and reconnects the sync loop at once.
        if reachable && !was {
            self.sdk.network_reachable();
        }
    }

    /// Sets the local time zone that timeline date separators split
    /// calendar days in; `None` (the default) is UTC. Call it again when
    /// the system time zone changes: open timelines move their date
    /// separators through their listeners.
    pub fn set_local_time_zone(&self, zone: Option<Arc<dyn LocalTimeZone>>) {
        let mut local = self.local_time.lock().unwrap_or_else(|e| e.into_inner());
        local.zone = zone.map(|zone| {
            Arc::new(PlatformTimeZone {
                zone: Foreign::new(zone),
                callbacks: self.callbacks.clone(),
            }) as Arc<dyn gim_ui::TimeZone>
        });
        let zone = local.zone();
        local.timelines.retain(|timeline| match timeline.upgrade() {
            Some(timeline) => {
                timeline.set_time_zone(zone.clone());
                true
            }
            None => false,
        });
    }

    /// Looks up a user by handle; `None` if no such user exists.
    pub async fn find_user(&self, handle: String) -> Result<Option<UserProfile>, GimError> {
        let user = self.sdk()?.find_user(&handle).await?;
        Ok(user.map(Into::into))
    }

    /// Returns the chat id of the direct chat with `user_id`, creating it if
    /// needed.
    pub async fn create_direct_chat(&self, user_id: String) -> Result<String, GimError> {
        let sdk = self.sdk()?;
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
        let sdk = self.sdk()?;
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
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let users = user_ids
            .into_iter()
            .map(|id| parse_id("user_ids", id))
            .collect::<Result<Vec<UserId>, _>>()?;
        self.in_active_chat(&group_id, async {
            Ok(sdk.add_members(&group_id, &users).await?)
        })
        .await
    }

    pub async fn remove_member(&self, chat_id: String, user_id: String) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let user_id: UserId = parse_id("user_id", user_id)?;
        self.in_active_chat(&group_id, async {
            Ok(sdk.remove_members(&group_id, &[user_id]).await?)
        })
        .await
    }

    /// Current members of the chat, one entry per user (not per device),
    /// including the signed-in user.
    pub async fn chat_members(&self, chat_id: String) -> Result<Vec<UserProfile>, GimError> {
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        self.read(move |store| member_profiles(store, &group_id))
            .await
    }

    /// Starts leaving the chat; returns once the hub accepted the request,
    /// with the chat `ChatState::Leaving` (see `ChatState`). Calling it again
    /// while leaving re-sends the request. `ChatNotActive` once left.
    pub async fn leave_chat(&self, chat_id: String) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        match sdk.leave(&group_id).await {
            Err(err) => {
                let err = GimError::from(err);
                if matches!(err, GimError::InvalidInput { .. }) {
                    self.check_active(&group_id).await?;
                }
                Err(err)
            }
            Ok(()) => Ok(()),
        }
    }

    /// Where this device stands in the chat, from local state (no network
    /// call, so it is available right after a restart).
    pub async fn chat_state(&self, chat_id: String) -> Result<ChatState, GimError> {
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let membership = self
            .read(move |store| {
                store
                    .chat(&group_id)?
                    .map(|chat| chat.membership)
                    .ok_or_else(|| GimError::NotFound {
                        reason: format!("chat {group_id}"),
                    })
            })
            .await?;
        Ok(gim_ui::ChatState::from(membership).into())
    }

    /// Updates the group name and/or avatar and shares them with the
    /// members; `None` leaves a field unchanged. The avatar file is
    /// encrypted and uploaded before this returns.
    pub async fn set_group_info(
        &self,
        chat_id: String,
        name: Option<String>,
        avatar_file_path: Option<String>,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let avatar = avatar_file_path.map(|path| {
            let mime = image_mime(Path::new(&path));
            (PathBuf::from(path), mime)
        });
        self.in_active_chat(&group_id, async {
            sdk.set_group_info(&group_id, name, avatar).await?;
            Ok(())
        })
        .await
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
        self.in_active_chat(&group_id, async {
            Ok(sdk.send_text(&group_id, body, reply_to).await?.into())
        })
        .await
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
        self.in_active_chat(&group_id, async {
            let copy = tokio::task::spawn_blocking(move || {
                copy_outgoing(&data_dir, Path::new(&file_path))
            })
            .await??;
            Ok(sdk
                .send_media(&group_id, copy, mime, caption, reply_to)
                .await?
                .into())
        })
        .await
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
        self.in_active_chat(&group_id, async {
            sdk.edit(&group_id, &target, new_body).await?;
            Ok(())
        })
        .await
    }

    pub async fn delete_message(
        &self,
        chat_id: String,
        message_id: String,
    ) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let target: MessageId = parse_id("message_id", message_id)?;
        self.in_active_chat(&group_id, async {
            sdk.delete(&group_id, &target).await?;
            Ok(())
        })
        .await
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
        self.in_active_chat(&group_id, async {
            sdk.react(&group_id, &target, emoji).await?;
            Ok(())
        })
        .await
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
        self.in_active_chat(&group_id, async {
            sdk.unreact(&group_id, &target, emoji).await?;
            Ok(())
        })
        .await
    }

    /// Re-queues a message in `SendState::Failed`.
    pub async fn retry_send(&self, chat_id: String, message_id: String) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let message_id: MessageId = parse_id("message_id", message_id)?;
        self.in_active_chat(&group_id, async { Ok(sdk.retry_send(&message_id).await?) })
            .await
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

    /// Reports whether the user is typing. Call it with `true` on every
    /// keystroke (notifications are rate-limited) and with `false` when
    /// typing stops; see `stop_typing`.
    pub async fn set_typing(&self, chat_id: String, active: bool) -> Result<(), GimError> {
        let sdk = self.sdk()?;
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        Ok(sdk.set_typing(&group_id, active).await?)
    }

    /// Tells the chat the user stopped typing (the input was cleared, the
    /// message sent or the chat closed); same as `set_typing(chat_id,
    /// false)`. Does nothing unless typing was reported.
    pub async fn stop_typing(&self, chat_id: String) -> Result<(), GimError> {
        self.set_typing(chat_id, false).await
    }

    /// Downloads and decrypts an attachment to `dest_path` and returns the
    /// path of the decrypted file.
    pub async fn fetch_media(
        &self,
        chat_id: String,
        message_id: String,
        dest_path: String,
    ) -> Result<String, GimError> {
        let sdk = self.sdk()?;
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
        let listener = Foreign::new(listener);
        let service = gim_ui::ChatListService::new(self.sdk()?).await?;
        let (values, stream) = service.entries();
        let callbacks = self.callbacks.clone();
        Ok(Arc::new(TaskHandle::spawn(&self.callbacks, async move {
            // Keeps the list following the client.
            let _service = service;
            let reset = vec![ChatListDiff::Reset {
                values: values.into_iter().map(Into::into).collect(),
            }];
            if callbacks
                .call(|| listener.call(move |l| l.on_update(reset)))
                .is_none()
            {
                return;
            }
            let mut stream = std::pin::pin!(stream);
            while let Some(diffs) = stream.next().await {
                let diffs = diffs.into_iter().map(Into::into).collect();
                if callbacks
                    .call(|| listener.call(move |l| l.on_update(diffs)))
                    .is_none()
                {
                    return;
                }
            }
        })))
    }

    /// The timeline of one chat. Cheap; listeners are added on the result.
    pub async fn timeline(&self, chat_id: String) -> Result<Arc<Timeline>, GimError> {
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let zone = self
            .local_time
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .zone
            .clone();
        let options = gim_ui::TimelineOptions {
            time_zone: zone.clone(),
            ..gim_ui::TimelineOptions::default()
        };
        let inner = Arc::new(gim_ui::Timeline::with_options(self.sdk()?, group_id, options).await?);
        let mut local = self.local_time.lock().unwrap_or_else(|e| e.into_inner());
        // The zone may have changed while the timeline opened.
        let same = match (&zone, &local.zone) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        };
        if !same {
            inner.set_time_zone(local.zone());
        }
        local
            .timelines
            .retain(|timeline| timeline.strong_count() > 0);
        local.timelines.push(Arc::downgrade(&inner));
        Ok(Arc::new(Timeline::new(inner, self.callbacks.clone())))
    }

    /// Subscribes to connection state changes.
    pub async fn connection_state(
        &self,
        listener: Arc<dyn ConnectionStateListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        let listener = Foreign::new(listener);
        let mut states = self.shared.connection.subscribe();
        let callbacks = self.callbacks.clone();
        Ok(Arc::new(TaskHandle::spawn(&self.callbacks, async move {
            let state = *states.borrow_and_update();
            if callbacks
                .call(|| listener.call(move |l| l.on_change(state)))
                .is_none()
            {
                return;
            }
            while states.changed().await.is_ok() {
                let state = *states.borrow_and_update();
                if callbacks
                    .call(|| listener.call(move |l| l.on_change(state)))
                    .is_none()
                {
                    return;
                }
            }
        })))
    }

    /// Subscribes to the user's hubs; the first callback carries the
    /// current list.
    pub async fn hub_list(
        &self,
        listener: Arc<dyn HubListListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        let listener = Foreign::new(listener);
        let sdk = self.sdk()?.clone();
        let mut changes = sdk.subscribe_hub_changes();
        let current = hub_infos(sdk.hubs().await?);
        let callbacks = self.callbacks.clone();
        Ok(Arc::new(TaskHandle::spawn(&self.callbacks, async move {
            if callbacks
                .call(|| listener.call(move |l| l.on_update(current)))
                .is_none()
            {
                return;
            }
            loop {
                match changes.recv().await {
                    Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
                // A failed read is retried on the next change.
                let Ok(hubs) = sdk.hubs().await.map(hub_infos) else {
                    continue;
                };
                if callbacks
                    .call(|| listener.call(move |l| l.on_update(hubs)))
                    .is_none()
                {
                    return;
                }
            }
        })))
    }

    /// Subscribes to typing notifications of one chat.
    pub async fn typing(
        &self,
        chat_id: String,
        listener: Arc<dyn TypingListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        let listener = Foreign::new(listener);
        let group_id: GroupId = parse_id("chat_id", chat_id)?;
        let typing = gim_ui::TypingNotifications::new(self.sdk()?, group_id)?;
        let (current, stream) = typing.subscribe();
        let to_strings = |users: Vec<UserId>| users.into_iter().map(String::from).collect();
        let callbacks = self.callbacks.clone();
        Ok(Arc::new(TaskHandle::spawn(&self.callbacks, async move {
            let _typing = typing;
            if callbacks
                .call(|| {
                    let users = to_strings(current);
                    listener.call(move |l| l.on_update(users))
                })
                .is_none()
            {
                return;
            }
            let mut stream = std::pin::pin!(stream);
            while let Some(users) = stream.next().await {
                if callbacks
                    .call(|| {
                        let users = to_strings(users);
                        listener.call(move |l| l.on_update(users))
                    })
                    .is_none()
                {
                    return;
                }
            }
        })))
    }
}
