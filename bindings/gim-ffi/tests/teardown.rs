//! Teardown ordering: `sign_out` and dropping the client wait for slow
//! foreign callbacks in flight, and no callback runs afterwards.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gim_core::{
    create_client_with_fake_transport, ClientConfig, ConnectionState, ConnectionStateListener,
    GimClient, GimError, LocalTimeZone, PlatformHooks, TimelineDiff, TimelineListener,
};
use gim_sdk::testing::FakeTransport;
use tempfile::TempDir;

const SLOW: Duration = Duration::from_millis(300);

/// Records callback invocations; the first armed one sleeps for [`SLOW`].
/// Any invocation running after [`Probe::finish`] counts as late.
#[derive(Default)]
struct Probe {
    armed: AtomicBool,
    entered: AtomicUsize,
    finished: AtomicBool,
    late: AtomicUsize,
}

impl Probe {
    fn run(&self) {
        if self.finished.load(Ordering::SeqCst) {
            self.late.fetch_add(1, Ordering::SeqCst);
        }
        let first = self.entered.fetch_add(1, Ordering::SeqCst) == 0;
        if first && self.armed.load(Ordering::SeqCst) {
            std::thread::sleep(SLOW);
        }
        if self.finished.load(Ordering::SeqCst) {
            self.late.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn wait_entered(&self) {
        for _ in 0..500 {
            if self.entered.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("callback never invoked");
    }

    /// Teardown returned: nothing may still run or start. Waits long
    /// enough for a slow callback that outlived teardown to be caught.
    async fn finish(&self) {
        self.finished.store(true, Ordering::SeqCst);
        tokio::time::sleep(SLOW + Duration::from_millis(100)).await;
        assert_eq!(
            self.late.load(Ordering::SeqCst),
            0,
            "callback after teardown"
        );
    }
}

/// In-memory keystore whose reads of `slow_key` go through a [`Probe`].
struct Hooks {
    dir: TempDir,
    secrets: Mutex<HashMap<String, Vec<u8>>>,
    slow_key: &'static str,
    probe: Probe,
}

impl Hooks {
    fn new(slow_key: &'static str) -> Arc<Self> {
        Arc::new(Self {
            dir: tempfile::tempdir().unwrap(),
            secrets: Mutex::default(),
            slow_key,
            probe: Probe::default(),
        })
    }
}

impl PlatformHooks for Hooks {
    fn secure_store_get(&self, key: String) -> Result<Option<Vec<u8>>, GimError> {
        if key == self.slow_key && self.probe.armed.load(Ordering::SeqCst) {
            self.probe.run();
        }
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

impl ConnectionStateListener for Probe {
    fn on_change(&self, _state: ConnectionState) {
        self.run();
    }
}

impl TimelineListener for Probe {
    fn on_update(&self, _diffs: Vec<TimelineDiff>) {
        self.run();
    }
}

impl LocalTimeZone for Probe {
    fn utc_offset_secs(&self, _at_ms: i64) -> i32 {
        self.run();
        3600
    }
}

fn armed() -> Arc<Probe> {
    let probe = Arc::new(Probe::default());
    probe.armed.store(true, Ordering::SeqCst);
    probe
}

async fn open(transport: &FakeTransport, hooks: &Arc<Hooks>) -> Arc<GimClient> {
    let config = ClientConfig {
        server_url: "https://gim.example.org".to_string(),
    };
    create_client_with_fake_transport(config, hooks.clone(), transport.clone())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_waits_for_a_slow_listener() {
    let client = open(&FakeTransport::new(), &Hooks::new("")).await;
    let probe = armed();
    let _handle = client.connection_state(probe.clone()).await.unwrap();
    probe.wait_entered().await;
    client.sign_out().await.unwrap();
    assert_eq!(probe.entered.load(Ordering::SeqCst), 1);
    probe.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_waits_for_a_slow_time_zone() {
    let transport = FakeTransport::new();
    let hooks = Hooks::new("");
    let client = open(&transport, &hooks).await;
    client.create_identity("Alice".to_string()).await.unwrap();
    let chat = client
        .create_group_chat("Crew".to_string(), Vec::new())
        .await
        .unwrap();
    client
        .send_text(chat.clone(), "hi".to_string(), None)
        .await
        .unwrap();
    let listener = Arc::new(Probe::default());
    let timeline = client.timeline(chat).await.unwrap();
    let _handle = timeline.add_listener(listener.clone()).await;
    listener.wait_entered().await;

    // The new zone re-buckets the timeline on the calling thread.
    let zone = armed();
    let setter = std::thread::spawn({
        let client = client.clone();
        let zone = zone.clone();
        move || client.set_local_time_zone(Some(zone))
    });
    zone.wait_entered().await;
    client.sign_out().await.unwrap();
    zone.finish().await;
    listener.finish().await;
    tokio::task::spawn_blocking(move || setter.join().unwrap())
        .await
        .unwrap();
    // Asked after sign-out (here: paginating), the zone is not called.
    let _ = timeline.paginate_backwards(10).await;
    zone.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_waits_for_a_slow_keystore_hook() {
    let transport = FakeTransport::new();
    // Read first by `create_identity`, through the gated gim-sdk storage.
    let hooks = Hooks::new(gim_sdk::ENROLLMENT_SECRET_KEY);
    let client = open(&transport, &hooks).await;
    hooks.probe.armed.store(true, Ordering::SeqCst);
    let creating = tokio::spawn({
        let client = client.clone();
        async move { client.create_identity("Alice".to_string()).await }
    });
    hooks.probe.wait_entered().await;
    client.sign_out().await.unwrap();
    hooks.probe.finish().await;
    // Whatever the outcome, it no longer reaches the keystore.
    let _ = creating.await.unwrap();
    hooks.probe.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_waits_for_a_slow_listener() {
    let client = open(&FakeTransport::new(), &Hooks::new("")).await;
    let probe = armed();
    let _handle = client.connection_state(probe.clone()).await.unwrap();
    probe.wait_entered().await;
    // Released by the platform: on a thread outside the runtime.
    tokio::task::spawn_blocking(move || std::thread::spawn(move || drop(client)).join())
        .await
        .unwrap()
        .unwrap();
    probe.finish().await;
}

#[test]
fn drop_on_a_runtime_thread_does_not_block() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let client = open(&FakeTransport::new(), &Hooks::new("")).await;
        let probe = Arc::new(Probe::default());
        let _handle = client.connection_state(probe.clone()).await.unwrap();
        probe.wait_entered().await;
        // Inside the runtime: no wait, the listener stops all the same.
        drop(client);
        probe.finish().await;
    });
}
