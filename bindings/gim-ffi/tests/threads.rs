//! Repeated create / subscribe / sign-out cycles do not leak threads. Alone
//! in its binary so no other test adds threads to the process.

use std::sync::Arc;

use gim_core::{
    create_client_with_fake_transport, ClientConfig, ConnectionState, ConnectionStateListener,
    GimError, PlatformHooks,
};
use gim_sdk::testing::FakeTransport;
use tempfile::TempDir;

struct Hooks(TempDir);

impl PlatformHooks for Hooks {
    fn secure_store_get(&self, _key: String) -> Result<Option<Vec<u8>>, GimError> {
        Ok(None)
    }
    fn secure_store_set(&self, _key: String, _value: Vec<u8>) -> Result<(), GimError> {
        Ok(())
    }
    fn secure_store_delete(&self, _key: String) {}
    fn data_dir(&self) -> String {
        self.0.path().to_str().unwrap().to_string()
    }
    fn is_network_reachable(&self) -> bool {
        true
    }
}

struct Ignore;

impl ConnectionStateListener for Ignore {
    fn on_change(&self, _state: ConnectionState) {}
}

fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

async fn cycle(transport: &FakeTransport) {
    let config = ClientConfig {
        server_url: "https://gim.example.org".to_string(),
        mode: None,
    };
    let hooks = Arc::new(Hooks(tempfile::tempdir().unwrap()));
    let client = create_client_with_fake_transport(config, hooks, transport.clone())
        .await
        .unwrap();
    let _handle = client.connection_state(Arc::new(Ignore)).await.unwrap();
    client.sign_out().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_sign_out_cycles_do_not_leak_threads() {
    let transport = FakeTransport::new();
    cycle(&transport).await;
    let before = thread_count();
    for _ in 0..50 {
        cycle(&transport).await;
    }
    let after = thread_count();
    // Idle blocking-pool threads linger for a while; a leak grows per cycle.
    assert!(after <= before + 4, "threads: {before} -> {after}");
}
