#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use futures_core::Stream;
use futures_util::StreamExt;
use gim_base::model::{Message, MessageContent, StateChange};
use gim_base::{MemoryStore, StateStore, StoreTxn};
use gim_common::{DeviceRef, GroupId, MessageId, UserId};
use gim_proto::envelope::Content;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::{Client, ClientBuilder, SecretStorage};
use gim_ui::{Vector, VectorDiff};
use tempfile::TempDir;

pub struct Device {
    pub client: Client<MemoryStore>,
    pub store: Arc<MemoryStore>,
    pub data_dir: TempDir,
}

impl Device {
    pub async fn register(transport: &FakeTransport, handle: &str, display_name: &str) -> Self {
        let store = Arc::new(MemoryStore::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = ClientBuilder::new(
            store.clone(),
            Arc::new(transport.clone()),
            Arc::new(MemorySecretStorage::new()) as Arc<dyn SecretStorage>,
        )
        .data_dir(data_dir.path())
        .build()
        .unwrap();
        client.register(handle, display_name).await.unwrap();
        Self {
            client,
            store,
            data_dir,
        }
    }

    pub fn device(&self) -> DeviceRef {
        self.client.session().unwrap().device
    }

    pub fn user_id(&self) -> UserId {
        self.device().user_id
    }

    pub async fn sync(&self) -> Vec<StateChange> {
        self.client.sync_once().await.unwrap()
    }

    pub async fn send(&self, group_id: &GroupId, content: Content) -> MessageId {
        self.client.send(group_id, content).await.unwrap()
    }

    pub async fn send_text(&self, group_id: &GroupId, body: &str) -> MessageId {
        self.send(
            group_id,
            Content::Text {
                body: body.to_string(),
            },
        )
        .await
    }
}

/// Writes a received text message straight into the store.
pub fn seed(
    store: &MemoryStore,
    group_id: &GroupId,
    sender: &DeviceRef,
    seq: u64,
    sent_at_ms: u64,
    body: &str,
) -> MessageId {
    let message_id = MessageId::new(format!("seed-{group_id}-{seq}")).unwrap();
    let message = Message {
        message_id: message_id.clone(),
        group_id: group_id.clone(),
        seq: Some(seq),
        sender: sender.clone(),
        sent_at_ms,
        content: MessageContent::Text {
            body: body.to_string(),
        },
        reply_to: None,
        edited: false,
        deleted: false,
        reactions: Default::default(),
        send_state: None,
        receipts: Default::default(),
    };
    store
        .transaction(|txn| Ok(txn.upsert_message(&message)?))
        .unwrap();
    message_id
}

pub async fn next<T>(stream: &mut (impl Stream<Item = T> + Unpin)) -> T {
    tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await
        .expect("timed out waiting for the stream")
        .expect("stream ended")
}

/// Applies diffs until `done` holds for the items.
pub async fn wait_until<T: Clone>(
    stream: &mut (impl Stream<Item = Vec<VectorDiff<T>>> + Unpin),
    items: &mut Vector<T>,
    done: impl Fn(&Vector<T>) -> bool,
) {
    while !done(items) {
        for diff in next(stream).await {
            diff.apply(items);
        }
    }
}

pub fn apply<T: Clone>(items: &mut Vector<T>, diffs: Vec<VectorDiff<T>>) {
    for diff in diffs {
        diff.apply(items);
    }
}

/// 2026-01-01T00:00:00Z.
pub const JAN_1_MS: u64 = 1_767_225_600_000;
pub const HOUR_MS: u64 = 3_600_000;
pub const DAY_MS: u64 = 24 * HOUR_MS;

pub fn day_start(ms: u64) -> u64 {
    ms - ms % DAY_MS
}
