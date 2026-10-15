//! Tests against a real gim-server container.
//!
//! Helpers for driving gim-ffi `GimClient`s against the server named by
//! `GIM_SERVER_URL` (see `scripts/integration-test.sh`). Without it every test
//! prints a notice and passes, so the default `cargo test` stays offline.
//! Modelled on matrix-rust-sdk
//! `testing/matrix-sdk-integration-testing/src/helpers.rs` (Apache-2.0).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gim_core::{
    create_client, ChatListDiff, ChatListListener, ChatSummary, ClientConfig, ConnectionState,
    ConnectionStateListener, GimClient, GimError, MessageContent, MessageItem, PlatformHooks,
    TaskHandle, TimelineDiff, TimelineItem, TimelineListener, TypingListener,
};
use tempfile::TempDir;

/// How long `wait` helpers poll before failing the test.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The server under test, or `None` (after printing a notice) when
/// `GIM_SERVER_URL` is unset and the test should pass without running.
pub fn server_url(test: &str) -> Option<String> {
    match std::env::var("GIM_SERVER_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipping {test}: GIM_SERVER_URL is not set");
            None
        }
    }
}

/// A handle unique to this run: the server keeps users across tests and
/// registering an existing handle adds a device to that user.
pub fn unique_handle(prefix: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{prefix}_{:x}_{:x}_{n}",
        nanos % (1 << 40),
        std::process::id()
    )
}

/// In-memory keystore and a temporary data directory.
pub struct MemoryHooks {
    dir: TempDir,
    secrets: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryHooks {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            dir: tempfile::tempdir().unwrap(),
            secrets: Mutex::default(),
        })
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

impl PlatformHooks for MemoryHooks {
    fn secure_store_get(&self, key: String) -> Option<Vec<u8>> {
        self.secrets.lock().unwrap().get(&key).cloned()
    }
    fn secure_store_set(&self, key: String, value: Vec<u8>) -> Result<(), GimError> {
        self.secrets.lock().unwrap().insert(key, value);
        Ok(())
    }
    fn secure_store_delete(&self, key: String) {
        self.secrets.lock().unwrap().remove(&key);
    }
    fn data_dir(&self) -> String {
        self.dir.path().to_str().unwrap().to_string()
    }
    fn is_network_reachable(&self) -> bool {
        true
    }
}

/// Polls `check` until it returns `Some` or [`WAIT_TIMEOUT`] passes.
pub async fn wait_for<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + WAIT_TIMEOUT;
    loop {
        if let Some(value) = check() {
            return value;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// A native-side copy of a list, kept up to date by applying the diffs.
pub struct Mirror<T>(Mutex<Vec<T>>);

impl<T: Clone> Mirror<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Vec::new())))
    }

    pub fn get(&self) -> Vec<T> {
        self.0.lock().unwrap().clone()
    }

    /// Waits until `check` holds for the list and returns it.
    pub async fn wait(&self, what: &str, check: impl Fn(&[T]) -> bool) -> Vec<T> {
        wait_for(what, || Some(self.get()).filter(|items| check(items))).await
    }
}

macro_rules! apply_diffs {
    ($items:expr, $diffs:expr, $ty:ident) => {
        for diff in $diffs {
            match diff {
                $ty::Append { values } => $items.extend(values),
                $ty::Clear => $items.clear(),
                $ty::PushFront { value } => $items.insert(0, value),
                $ty::PushBack { value } => $items.push(value),
                $ty::PopFront => {
                    $items.remove(0);
                }
                $ty::PopBack => {
                    $items.pop();
                }
                $ty::Insert { index, value } => $items.insert(index as usize, value),
                $ty::Set { index, value } => $items[index as usize] = value,
                $ty::Remove { index } => {
                    $items.remove(index as usize);
                }
                $ty::Truncate { length } => $items.truncate(length as usize),
                $ty::Reset { values } => *$items = values,
            }
        }
    };
}

impl ChatListListener for Mirror<ChatSummary> {
    fn on_update(&self, diffs: Vec<ChatListDiff>) {
        let items = &mut *self.0.lock().unwrap();
        apply_diffs!(items, diffs, ChatListDiff);
    }
}

impl TimelineListener for Mirror<TimelineItem> {
    fn on_update(&self, diffs: Vec<TimelineDiff>) {
        let items = &mut *self.0.lock().unwrap();
        apply_diffs!(items, diffs, TimelineDiff);
    }
}

/// Records every value it is given.
pub struct Recorder<T>(Mutex<Vec<T>>);

impl<T: Clone> Recorder<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Vec::new())))
    }

    /// Waits until the latest value satisfies `check`.
    pub async fn wait(&self, what: &str, check: impl Fn(&T) -> bool) {
        wait_for(what, || {
            self.0.lock().unwrap().last().filter(|v| check(v)).map(drop)
        })
        .await
    }
}

impl ConnectionStateListener for Recorder<ConnectionState> {
    fn on_change(&self, state: ConnectionState) {
        self.0.lock().unwrap().push(state);
    }
}

impl TypingListener for Recorder<Vec<String>> {
    fn on_update(&self, user_ids: Vec<String>) {
        self.0.lock().unwrap().push(user_ids);
    }
}

/// Opens a client on `hooks`' data directory.
pub async fn open(server_url: &str, hooks: &Arc<MemoryHooks>) -> Arc<GimClient> {
    let config = ClientConfig {
        server_url: server_url.to_string(),
    };
    create_client(config, hooks.clone()).await.unwrap()
}

/// One registered account on one device.
pub struct TestUser {
    pub client: Arc<GimClient>,
    pub hooks: Arc<MemoryHooks>,
    pub handle: String,
    pub user_id: String,
}

impl TestUser {
    /// Registers a fresh account (handle `<prefix>_<unique>`) and starts sync.
    pub async fn register(server_url: &str, prefix: &str, display_name: &str) -> Self {
        let hooks = MemoryHooks::new();
        let client = open(server_url, &hooks).await;
        assert_eq!(client.session().await.unwrap(), None);
        // The FFI does not claim handles yet: `handle` is not on the hub.
        let handle = unique_handle(prefix);
        client
            .create_identity(display_name.to_string())
            .await
            .unwrap();
        let session = client.session().await.unwrap().unwrap();
        client.start_sync().await.unwrap();
        Self {
            client,
            hooks,
            handle,
            user_id: session.user_id,
        }
    }

    pub async fn timeline(&self, chat_id: &str) -> (Arc<Mirror<TimelineItem>>, Arc<TaskHandle>) {
        timeline(&self.client, chat_id).await
    }

    pub async fn chat_list(&self) -> (Arc<Mirror<ChatSummary>>, Arc<TaskHandle>) {
        let mirror = Mirror::new();
        let handle = self.client.chat_list(mirror.clone()).await.unwrap();
        (mirror, handle)
    }
}

/// Subscribes a [`Mirror`] to the timeline of `chat_id`.
pub async fn timeline(
    client: &GimClient,
    chat_id: &str,
) -> (Arc<Mirror<TimelineItem>>, Arc<TaskHandle>) {
    let mirror = Mirror::new();
    let handle = client
        .timeline(chat_id.to_string())
        .await
        .unwrap()
        .add_listener(mirror.clone())
        .await;
    (mirror, handle)
}

/// The message items of a timeline, in order.
pub fn messages(items: &[TimelineItem]) -> Vec<MessageItem> {
    items
        .iter()
        .filter_map(|item| match item {
            TimelineItem::Message { item } => Some(item.clone()),
            _ => None,
        })
        .collect()
}

pub fn message(items: &[TimelineItem], id: &str) -> Option<MessageItem> {
    messages(items).into_iter().find(|m| m.message_id == id)
}

/// The body of a text message; `None` for other content.
pub fn text(item: &MessageItem) -> Option<&str> {
    match &item.content {
        MessageContent::Text { body } => Some(body),
        _ => None,
    }
}
