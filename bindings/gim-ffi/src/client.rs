use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use url::Url;

use crate::{
    ChatListListener, ConnectionState, GimError, PlatformHooks, Session, TaskHandle, Timeline,
    UserProfile,
};

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
    let server_url = parse_server_url(&config.server_url)?;
    Ok(Arc::new(GimClient {
        inner: ClientInner::new(server_url, hooks),
    }))
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

/// State behind [`GimClient`]. The FFI surface only maps arguments and
/// results; the backend (gim-ui / gim-sdk) is wired in here.
struct ClientInner {
    #[allow(dead_code)]
    server_url: Url,
    #[allow(dead_code)]
    hooks: Arc<dyn PlatformHooks>,
    network_reachable: AtomicBool,
}

impl ClientInner {
    fn new(server_url: Url, hooks: Arc<dyn PlatformHooks>) -> Self {
        let network_reachable = AtomicBool::new(hooks.is_network_reachable());
        Self {
            server_url,
            hooks,
            network_reachable,
        }
    }
}

/// One account on one device. All methods may be called from any thread.
#[derive(uniffi::Object)]
pub struct GimClient {
    inner: ClientInner,
}

#[uniffi::export(async_runtime = "tokio")]
impl GimClient {
    /// The persisted session, or `None` before `register`.
    pub async fn session(&self) -> Result<Option<Session>, GimError> {
        Err(GimError::NotImplemented)
    }

    /// Creates the account and this device on the server and persists the
    /// session.
    pub async fn register(
        &self,
        handle: String,
        display_name: String,
    ) -> Result<Session, GimError> {
        let _ = (handle, display_name);
        Err(GimError::NotImplemented)
    }

    /// Stops sync and deletes the session, local data and keystore secrets.
    pub async fn sign_out(&self) -> Result<(), GimError> {
        Err(GimError::NotImplemented)
    }

    /// Starts the background sync loop and outbox sender.
    pub async fn start_sync(&self) -> Result<(), GimError> {
        Err(GimError::NotImplemented)
    }

    /// Stops the background sync loop and outbox sender.
    pub async fn stop_sync(&self) -> Result<(), GimError> {
        Err(GimError::NotImplemented)
    }

    /// Reports a reachability change from the platform network monitor.
    pub fn set_network_reachable(&self, reachable: bool) {
        self.inner
            .network_reachable
            .store(reachable, Ordering::Relaxed);
    }

    /// Looks up a user by handle; `None` if no such user exists.
    pub async fn find_user(&self, handle: String) -> Result<Option<UserProfile>, GimError> {
        let _ = handle;
        Err(GimError::NotImplemented)
    }

    /// Returns the chat id of the direct chat with `user_id`, creating it if
    /// needed.
    pub async fn create_direct_chat(&self, user_id: String) -> Result<String, GimError> {
        let _ = user_id;
        Err(GimError::NotImplemented)
    }

    /// Creates a group chat and returns its chat id.
    pub async fn create_group_chat(
        &self,
        name: String,
        member_user_ids: Vec<String>,
    ) -> Result<String, GimError> {
        let _ = (name, member_user_ids);
        Err(GimError::NotImplemented)
    }

    pub async fn add_members(
        &self,
        chat_id: String,
        user_ids: Vec<String>,
    ) -> Result<(), GimError> {
        let _ = (chat_id, user_ids);
        Err(GimError::NotImplemented)
    }

    pub async fn remove_member(&self, chat_id: String, user_id: String) -> Result<(), GimError> {
        let _ = (chat_id, user_id);
        Err(GimError::NotImplemented)
    }

    pub async fn leave_chat(&self, chat_id: String) -> Result<(), GimError> {
        let _ = chat_id;
        Err(GimError::NotImplemented)
    }

    /// Updates the group name and/or avatar; `None` leaves a field unchanged.
    pub async fn set_group_info(
        &self,
        chat_id: String,
        name: Option<String>,
        avatar_file_path: Option<String>,
    ) -> Result<(), GimError> {
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
        let _ = (chat_id, body, reply_to);
        Err(GimError::NotImplemented)
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
        let _ = (chat_id, file_path, mime, caption, reply_to);
        Err(GimError::NotImplemented)
    }

    pub async fn edit_message(
        &self,
        chat_id: String,
        message_id: String,
        new_body: String,
    ) -> Result<(), GimError> {
        let _ = (chat_id, message_id, new_body);
        Err(GimError::NotImplemented)
    }

    pub async fn delete_message(
        &self,
        chat_id: String,
        message_id: String,
    ) -> Result<(), GimError> {
        let _ = (chat_id, message_id);
        Err(GimError::NotImplemented)
    }

    pub async fn react(
        &self,
        chat_id: String,
        message_id: String,
        emoji: String,
    ) -> Result<(), GimError> {
        let _ = (chat_id, message_id, emoji);
        Err(GimError::NotImplemented)
    }

    pub async fn unreact(
        &self,
        chat_id: String,
        message_id: String,
        emoji: String,
    ) -> Result<(), GimError> {
        let _ = (chat_id, message_id, emoji);
        Err(GimError::NotImplemented)
    }

    /// Re-queues a message in `SendState::Failed`.
    pub async fn retry_send(&self, chat_id: String, message_id: String) -> Result<(), GimError> {
        let _ = (chat_id, message_id);
        Err(GimError::NotImplemented)
    }

    /// Removes an unsent message from the outbox and the timeline.
    pub async fn cancel_send(&self, chat_id: String, message_id: String) -> Result<(), GimError> {
        let _ = (chat_id, message_id);
        Err(GimError::NotImplemented)
    }

    /// Marks everything up to and including `up_to_message_id` as read and
    /// sends a read receipt.
    pub async fn mark_read(
        &self,
        chat_id: String,
        up_to_message_id: String,
    ) -> Result<(), GimError> {
        let _ = (chat_id, up_to_message_id);
        Err(GimError::NotImplemented)
    }

    pub async fn set_typing(&self, chat_id: String, active: bool) -> Result<(), GimError> {
        let _ = (chat_id, active);
        Err(GimError::NotImplemented)
    }

    /// Downloads and decrypts an attachment to `dest_path` and returns the
    /// path of the decrypted file.
    pub async fn fetch_media(
        &self,
        chat_id: String,
        message_id: String,
        dest_path: String,
    ) -> Result<String, GimError> {
        let _ = (chat_id, message_id, dest_path);
        Err(GimError::NotImplemented)
    }

    /// Like `fetch_media` for the thumbnail; `None` if there is none.
    pub async fn fetch_thumbnail(
        &self,
        chat_id: String,
        message_id: String,
        dest_path: String,
    ) -> Result<Option<String>, GimError> {
        let _ = (chat_id, message_id, dest_path);
        Err(GimError::NotImplemented)
    }

    /// Subscribes to the chat list; the first callback is a `Reset`.
    pub async fn chat_list(
        &self,
        listener: Arc<dyn ChatListListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        Ok(Arc::new(TaskHandle::idle(listener)))
    }

    /// The timeline of one chat. Cheap; listeners are added on the result.
    pub async fn timeline(&self, chat_id: String) -> Result<Arc<Timeline>, GimError> {
        Ok(Arc::new(Timeline::new(chat_id)))
    }

    /// Subscribes to connection state changes.
    pub async fn connection_state(
        &self,
        listener: Arc<dyn ConnectionStateListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        Ok(Arc::new(TaskHandle::idle(listener)))
    }

    /// Subscribes to typing notifications of one chat.
    pub async fn typing(
        &self,
        chat_id: String,
        listener: Arc<dyn TypingListener>,
    ) -> Result<Arc<TaskHandle>, GimError> {
        let _ = chat_id;
        Ok(Arc::new(TaskHandle::idle(listener)))
    }
}
