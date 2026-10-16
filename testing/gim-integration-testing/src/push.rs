//! Push against real hubs: devices register with the hub's test provider
//! `log`, and the test reads what the hub pushed from its test-only push
//! log (`GET /v2/debug/push-log`, contract `push.md` §5; the harness starts
//! every hub with `GIM_HUB_PUSH_LOG_ENDPOINT=true`). The payloads are fed
//! to `process_push` of an extension-mode client on the app's data
//! directory, as an iOS Notification Service Extension would.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use gim_core::{
    create_client, ClientConfig, ClientMode, GimClient, NotificationContent, PushRegistration,
};
use serde_json::Value;

use crate::{unique_handle, MemoryHooks};

/// A registration with the hub's test provider and a unique token.
pub fn log_registration() -> PushRegistration {
    PushRegistration {
        provider: "log".into(),
        token: unique_handle("token"),
        app_id: Some("im.g.apps".into()),
        sandbox: None,
        p256dh: None,
        auth: None,
    }
}

/// The payloads the hub at `hub_url` pushed to `device_id` with the log
/// provider, oldest first (the hub keeps the last 256 pushes in memory).
/// Empty if the hub cannot be reached.
pub fn push_log(hub_url: &str, device_id: &str) -> Vec<Value> {
    let url = format!("{hub_url}/v2/debug/push-log?device_id={device_id}");
    let out = Command::new("curl")
        .args(["-sf", "--max-time", "5", &url])
        .output()
        .expect("curl runs");
    if !out.status.success() {
        return Vec::new();
    }
    let log: Value = serde_json::from_slice(&out.stdout).expect("the push log is JSON");
    log["notifications"]
        .as_array()
        .expect("the push log lists notifications")
        .iter()
        .inspect(|n| assert_eq!(n["device_id"], device_id))
        .map(|n| n["payload"].clone())
        .collect()
}

/// The payloads of `push_log` of type `kind` for the group `gid`.
pub fn pushes(hub_url: &str, device_id: &str, kind: &str, gid: &str) -> Vec<Value> {
    push_log(hub_url, device_id)
        .into_iter()
        .filter(|p| p["type"] == kind && p["gid"] == gid)
        .collect()
}

/// Waits up to `timeout` for a payload in the hub's push log for
/// `device_id` that `matches`, and returns the newest such one. On timeout
/// it panics with the log.
pub async fn wait_push(
    what: &str,
    hub_url: &str,
    device_id: &str,
    timeout: Duration,
    matches: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let log = push_log(hub_url, device_id);
        if let Some(found) = log.iter().rev().find(|p| matches(p)) {
            return found.clone();
        }
        if tokio::time::Instant::now() >= deadline {
            let log: Vec<String> = log.iter().map(Value::to_string).collect();
            panic!("timed out waiting for {what}; pushed:\n{}", log.join("\n"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The pushed seq of a payload.
pub fn seq(payload: &Value) -> u64 {
    payload["seq"].as_u64().expect("the payload has a seq")
}

/// Checks the shape of a `message` payload (`push.md` §3).
pub fn assert_message_payload(payload: &Value, gid: &str) {
    assert_eq!(payload["v"], 1, "{payload}");
    assert_eq!(payload["type"], "message", "{payload}");
    assert_eq!(payload["gid"], gid, "{payload}");
    assert!(payload["seq"].is_u64(), "{payload}");
    let message_id = payload["message_id"].as_str().expect("a message_id");
    assert!(!message_id.is_empty(), "{payload}");
    assert_eq!(payload["collapse_id"], message_id, "{payload}");
}

/// An app extension (`ClientMode::Extension`) on the data directory and
/// keystore of `hooks`, next to the app's client.
pub async fn open_extension(server_url: &str, hooks: &Arc<MemoryHooks>) -> Arc<GimClient> {
    let config = ClientConfig {
        server_url: server_url.to_string(),
        mode: Some(ClientMode::Extension),
    };
    create_client(config, hooks.clone()).await.unwrap()
}

/// Feeds `payload` to `process_push` of a fresh extension on `hooks`, as a
/// Notification Service Extension does with the payload it was woken with.
pub async fn process_in_extension(
    server_url: &str,
    hooks: &Arc<MemoryHooks>,
    payload: &Value,
) -> NotificationContent {
    let extension = open_extension(server_url, hooks).await;
    assert!(extension.session().await.unwrap().is_some());
    extension.process_push(payload.to_string()).await.unwrap()
}

/// Every payload in turn, each in a fresh extension (one wake-up per
/// push).
pub async fn process_all(
    server_url: &str,
    hooks: &Arc<MemoryHooks>,
    payloads: &[Value],
) -> Vec<NotificationContent> {
    let mut shown = Vec::with_capacity(payloads.len());
    for payload in payloads {
        shown.push(process_in_extension(server_url, hooks, payload).await);
    }
    shown
}

/// The displayed ones of `shown`.
pub fn displayed(shown: &[NotificationContent]) -> Vec<&NotificationContent> {
    shown.iter().filter(|c| c.should_display).collect()
}

/// The pushes to `device_id` after the first `skip` entries of the hub's
/// log, once `ready` holds for them and a second passed without another
/// one. The hub keeps one pending push per device, so a push may replace
/// another one (`push.md` §4). Panics with the log after `timeout`.
pub async fn new_pushes(
    hub_url: &str,
    device_id: &str,
    skip: usize,
    timeout: Duration,
    ready: impl Fn(&[Value]) -> bool,
) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut seen: Option<usize> = None;
    loop {
        let pushed: Vec<Value> = push_log(hub_url, device_id)
            .into_iter()
            .skip(skip)
            .collect();
        if ready(&pushed) {
            if seen == Some(pushed.len()) {
                return pushed;
            }
            seen = Some(pushed.len());
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        if tokio::time::Instant::now() >= deadline {
            let log: Vec<String> = pushed.iter().map(Value::to_string).collect();
            panic!("timed out waiting for pushes; pushed:\n{}", log.join("\n"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
