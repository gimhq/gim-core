//! Tests against a real gim-hub container.
//!
//! Helpers for driving gim-ffi `GimClient`s (and, for fault injection,
//! gim-sdk clients, see [`sdk`]) against the hub named by `GIM_HUB_URL` (see
//! `scripts/integration-test.sh`). The tests are `#[ignore]`d, and without
//! `GIM_HUB_URL` every test prints a notice and passes, so the default
//! `cargo test` stays offline.
//! Modelled on matrix-rust-sdk
//! `testing/matrix-sdk-integration-testing/src/helpers.rs` (Apache-2.0).

#![forbid(unsafe_code)]

pub mod federation;
pub mod push;
pub mod sdk;

use std::collections::{BTreeSet, HashMap};
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

/// The hub under test, or `None` (after printing a notice) when
/// `GIM_HUB_URL` is unset and the test should pass without running.
pub fn server_url(test: &str) -> Option<String> {
    match std::env::var("GIM_HUB_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipping {test}: GIM_HUB_URL is not set");
            None
        }
    }
}

/// A handle unique to this run: the hub keeps handles across tests.
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
    fn secure_store_get(&self, key: String) -> Result<Option<Vec<u8>>, GimError> {
        Ok(self.secrets.lock().unwrap().get(&key).cloned())
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

/// Like [`wait_for`] for an async check.
pub async fn eventually<T, F, Fut>(what: &str, check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    eventually_within(what, WAIT_TIMEOUT, check).await
}

/// Like [`eventually`] with another timeout.
pub async fn eventually_within<T, F, Fut>(what: &str, timeout: Duration, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The user ids of the chat's members.
pub async fn member_ids(client: &GimClient, chat_id: &str) -> BTreeSet<String> {
    client
        .chat_members(chat_id.to_string())
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.user_id)
        .collect()
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
        mode: None,
    };
    create_client(config, hooks.clone()).await.unwrap()
}

/// One identity on one device.
pub struct TestUser {
    pub client: Arc<GimClient>,
    pub hooks: Arc<MemoryHooks>,
    pub handle: String,
    pub user_id: String,
    pub device_id: String,
    pub recovery_code: String,
}

impl TestUser {
    /// Creates a fresh identity, claims the handle `<prefix>_<unique>` and
    /// starts sync.
    pub async fn register(server_url: &str, prefix: &str, display_name: &str) -> Self {
        let hooks = MemoryHooks::new();
        let client = open(server_url, &hooks).await;
        assert_eq!(client.session().await.unwrap(), None);
        let recovery_code = client
            .create_identity(display_name.to_string())
            .await
            .unwrap();
        let handle = unique_handle(prefix);
        client.claim_handle(handle.clone()).await.unwrap();
        let session = client.session().await.unwrap().unwrap();
        client.start_sync().await.unwrap();
        Self {
            client,
            hooks,
            handle,
            user_id: session.user_id,
            device_id: session.device_id,
            recovery_code,
        }
    }

    /// A second device of this user on a fresh data directory, linked with
    /// the SAS flow (both sides accept) and syncing. Returns it with the SAS
    /// both devices showed.
    pub async fn link_device(&self, server_url: &str) -> (Self, String) {
        let hooks = MemoryHooks::new();
        let client = open(server_url, &hooks).await;
        let link = client.start_link(vec![server_url.to_string()]).unwrap();
        let waiting = {
            let (client, link) = (client.clone(), link.clone());
            tokio::spawn(async move { client.wait_link(link).await })
        };
        let approval = self.client.approve_link(link.qr_string()).await.unwrap();
        let new_sas = waiting.await.unwrap().unwrap();
        assert_eq!(approval.sas(), new_sas, "both devices show the same SAS");
        client.confirm_link(true).await.unwrap();
        self.client
            .confirm_approval(approval.clone(), true)
            .await
            .unwrap();
        let session = client.session().await.unwrap().unwrap();
        assert_eq!(session.user_id, self.user_id);
        assert_eq!(session.device_id, approval.device_id());
        client.start_sync().await.unwrap();
        let device = Self {
            client,
            hooks,
            handle: self.handle.clone(),
            user_id: session.user_id,
            device_id: session.device_id,
            recovery_code: self.recovery_code.clone(),
        };
        (device, new_sas)
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
