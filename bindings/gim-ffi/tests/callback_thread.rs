//! Every foreign callback, and the release of every platform object, runs on
//! gim-core's callback thread, outside any tokio task or future poll, through
//! the whole client lifecycle.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gim_core::{
    create_client_with_fake_transport, ChatListDiff, ChatListListener, ClientConfig,
    ConnectionState, ConnectionStateListener, GimClient, GimError, LocalTimeZone, PlatformHooks,
    TimelineDiff, TimelineListener, TypingListener,
};
use gim_sdk::testing::FakeTransport;
use tempfile::TempDir;

/// Shared by every platform object of one test; they only hold an `Arc` of
/// it, so the test never holds the last reference to one of them.
#[derive(Default)]
struct Check {
    calls: AtomicUsize,
    released: AtomicUsize,
    violations: Mutex<Vec<String>>,
}

impl Check {
    fn record(&self, what: &str) {
        let thread = std::thread::current();
        if thread.name() != Some("gim-callbacks") {
            self.violations
                .lock()
                .unwrap()
                .push(format!("{what} on thread {:?}", thread.name()));
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            self.violations
                .lock()
                .unwrap()
                .push(format!("{what} inside the tokio runtime"));
        }
    }

    fn called(&self, what: &str) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.record(what);
    }

    fn release(&self, what: &str) {
        self.released.fetch_add(1, Ordering::SeqCst);
        self.record(what);
    }

    /// Waits for `count` releases, then asserts no violation.
    async fn assert_clean(&self, released: usize) {
        for _ in 0..200 {
            if self.released.load(Ordering::SeqCst) >= released {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(self.calls.load(Ordering::SeqCst) > 0);
        assert_eq!(self.released.load(Ordering::SeqCst), released);
        assert_eq!(*self.violations.lock().unwrap(), Vec::<String>::new());
    }
}

struct Hooks {
    check: Arc<Check>,
    dir: Arc<TempDir>,
    secrets: Mutex<HashMap<String, Vec<u8>>>,
}

impl PlatformHooks for Hooks {
    fn secure_store_get(&self, key: String) -> Result<Option<Vec<u8>>, GimError> {
        self.check.called("secure_store_get");
        Ok(self.secrets.lock().unwrap().get(&key).cloned())
    }
    fn secure_store_set(&self, key: String, value: Vec<u8>) -> Result<(), GimError> {
        self.check.called("secure_store_set");
        self.secrets.lock().unwrap().insert(key, value);
        Ok(())
    }
    fn secure_store_delete(&self, key: String) {
        self.check.called("secure_store_delete");
        self.secrets.lock().unwrap().remove(&key);
    }
    fn data_dir(&self) -> String {
        self.check.called("data_dir");
        self.dir.path().to_str().unwrap().to_string()
    }
    fn is_network_reachable(&self) -> bool {
        self.check.called("is_network_reachable");
        true
    }
}

impl Drop for Hooks {
    fn drop(&mut self) {
        self.check.release("PlatformHooks release");
    }
}

/// Every listener interface and the time zone, in one type.
struct Platform(Arc<Check>);

impl ChatListListener for Platform {
    fn on_update(&self, _diffs: Vec<ChatListDiff>) {
        self.0.called("ChatListListener");
    }
}

impl TimelineListener for Platform {
    fn on_update(&self, _diffs: Vec<TimelineDiff>) {
        self.0.called("TimelineListener");
    }
}

impl ConnectionStateListener for Platform {
    fn on_change(&self, _state: ConnectionState) {
        self.0.called("ConnectionStateListener");
    }
}

impl TypingListener for Platform {
    fn on_update(&self, _user_ids: Vec<String>) {
        self.0.called("TypingListener");
    }
}

impl LocalTimeZone for Platform {
    fn utc_offset_secs(&self, _at_ms: i64) -> i32 {
        self.0.called("LocalTimeZone");
        3600
    }
}

impl Drop for Platform {
    fn drop(&mut self) {
        self.0.release("listener release");
    }
}

async fn open(transport: &FakeTransport, check: &Arc<Check>, dir: &Arc<TempDir>) -> Arc<GimClient> {
    let hooks = Arc::new(Hooks {
        check: check.clone(),
        dir: dir.clone(),
        secrets: Mutex::default(),
    });
    let config = ClientConfig {
        server_url: "https://gim.example.org".to_string(),
    };
    create_client_with_fake_transport(config, hooks, transport.clone())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_callback_runs_on_the_callback_thread() {
    let transport = FakeTransport::new();
    let check = Arc::new(Check::default());
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let platform = || Arc::new(Platform(check.clone()));

    let client = open(&transport, &check, &dir).await;
    client.set_local_time_zone(Some(platform()));
    client.create_identity("Alice".to_string()).await.unwrap();
    client.start_sync().await.unwrap();
    let chats = client.chat_list(platform()).await.unwrap();
    let states = client.connection_state(platform()).await.unwrap();
    let chat = client
        .create_group_chat("Crew".to_string(), Vec::new())
        .await
        .unwrap();
    let typing = client.typing(chat.clone(), platform()).await.unwrap();
    client
        .send_text(chat.clone(), "hi".to_string(), None)
        .await
        .unwrap();
    let timeline = client.timeline(chat).await.unwrap();
    let items = timeline.add_listener(platform()).await;
    // Another zone while the timeline is open re-buckets it.
    client.set_local_time_zone(Some(platform()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.sign_out().await.unwrap();
    // sign_out aborts the listener tasks and guarantees no callback runs
    // afterwards; a task only reports finished once a runtime worker has
    // processed the abort, which may lag under load.
    for (name, handle) in [
        ("chat list", chats),
        ("connection state", states),
        ("typing", typing),
        ("timeline", items),
    ] {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{name} listener task still running 5 s after sign_out"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    drop(timeline);
    drop(client);
    // Hooks, two zones and four listeners.
    check.assert_clean(7).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_sign_out_cycles_stay_on_the_callback_thread() {
    let transport = FakeTransport::new();
    let check = Arc::new(Check::default());
    for _ in 0..20 {
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let client = open(&transport, &check, &dir).await;
        let _states = client
            .connection_state(Arc::new(Platform(check.clone())))
            .await
            .unwrap();
        client.sign_out().await.unwrap();
    }
    check.assert_clean(40).await;
}
