//! Shared test helpers: a [`FakeTransport`] wrapper that injects network
//! faults, and a registered test device.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, Message, MessageKind, StateChange, UserInfo};
use gim_base::{MemoryStore, StateReader};
use gim_common::{DeviceRef, GroupId, MessageId, UserId};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{
    AccessToken, EventBatch, GroupInfo, OutgoingMessage, PostError, Registration, Transport,
    TransportError, TransportResult,
};
use gim_sdk::{Client, ClientBuilder, SecretStorage};
use tempfile::TempDir;

/// A post fault, applied to the next post of `kind`.
#[derive(Debug, Clone, Copy)]
pub struct PostFault {
    pub kind: MessageKind,
    /// The server accepts the post but the reply is lost; otherwise the
    /// post never reaches the server.
    pub lose_reply: bool,
}

#[derive(Debug, Default)]
pub struct Faults {
    pub posts: Mutex<VecDeque<PostFault>>,
    /// Ranged downloads allowed before they fail; `None`: unlimited.
    pub downloads_left: Mutex<Option<u32>>,
    /// Flips a byte of every downloaded range past the blob header.
    pub tamper: AtomicBool,
    pub downloaded_bytes: AtomicU64,
}

impl Faults {
    pub fn fail_posts(&self, kind: MessageKind, lose_reply: bool, count: usize) {
        let mut posts = self.posts.lock().unwrap();
        for _ in 0..count {
            posts.push_back(PostFault { kind, lose_reply });
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlakyTransport {
    pub inner: FakeTransport,
    pub faults: Arc<Faults>,
}

impl FlakyTransport {
    pub fn new() -> Self {
        Self {
            inner: FakeTransport::new(),
            faults: Arc::default(),
        }
    }

    fn network() -> TransportError {
        TransportError::Network("injected".into())
    }
}

#[async_trait]
impl Transport for FlakyTransport {
    async fn register_device(&self, handle: &str, name: &str) -> TransportResult<Registration> {
        self.inner.register_device(handle, name).await
    }

    async fn find_user(&self, t: &AccessToken, handle: &str) -> TransportResult<Option<UserInfo>> {
        self.inner.find_user(t, handle).await
    }

    async fn list_devices(&self, t: &AccessToken, u: &UserId) -> TransportResult<Vec<DeviceRef>> {
        self.inner.list_devices(t, u).await
    }

    async fn upload_key_packages(
        &self,
        t: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: Option<Vec<u8>>,
    ) -> TransportResult<()> {
        self.inner
            .upload_key_packages(t, key_packages, last_resort)
            .await
    }

    async fn claim_key_package(&self, t: &AccessToken, d: &DeviceRef) -> TransportResult<Vec<u8>> {
        self.inner.claim_key_package(t, d).await
    }

    async fn create_group(
        &self,
        t: &AccessToken,
        kind: ChatKind,
        members: &[DeviceRef],
    ) -> TransportResult<GroupId> {
        self.inner.create_group(t, kind, members).await
    }

    async fn group_info(&self, t: &AccessToken, g: &GroupId) -> TransportResult<GroupInfo> {
        self.inner.group_info(t, g).await
    }

    async fn add_group_members(
        &self,
        t: &AccessToken,
        g: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()> {
        self.inner.add_group_members(t, g, devices).await
    }

    async fn remove_group_members(
        &self,
        t: &AccessToken,
        g: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()> {
        self.inner.remove_group_members(t, g, devices).await
    }

    async fn post_message(
        &self,
        t: &AccessToken,
        g: &GroupId,
        message: OutgoingMessage,
    ) -> Result<u64, PostError> {
        let fault = {
            let mut posts = self.faults.posts.lock().unwrap();
            match posts.front() {
                Some(f) if f.kind == message.kind => posts.pop_front(),
                _ => None,
            }
        };
        match fault {
            None => self.inner.post_message(t, g, message).await,
            Some(PostFault {
                lose_reply: true, ..
            }) => {
                self.inner.post_message(t, g, message).await?;
                Err(Self::network().into())
            }
            Some(_) => Err(Self::network().into()),
        }
    }

    async fn fetch_events(
        &self,
        t: &AccessToken,
        cursor: Option<u64>,
        wait: Duration,
    ) -> TransportResult<EventBatch> {
        self.inner.fetch_events(t, cursor, wait).await
    }

    async fn group_messages(
        &self,
        t: &AccessToken,
        g: &GroupId,
        after_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        self.inner.group_messages(t, g, after_seq, limit).await
    }

    async fn upload_blob(&self, t: &AccessToken, data: Vec<u8>) -> TransportResult<String> {
        self.inner.upload_blob(t, data).await
    }

    async fn download_blob(
        &self,
        t: &AccessToken,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>> {
        {
            let mut left = self.faults.downloads_left.lock().unwrap();
            match left.as_mut() {
                Some(0) => return Err(Self::network()),
                Some(n) => *n -= 1,
                None => {}
            }
        }
        let start = range.as_ref().map_or(0, |r| r.start);
        let mut bytes = self.inner.download_blob(t, blob_id, range).await?;
        self.faults
            .downloaded_bytes
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        if self.faults.tamper.load(Ordering::SeqCst) && start >= 16 && !bytes.is_empty() {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }
}

pub struct Device {
    pub client: Client<MemoryStore>,
    pub store: Arc<MemoryStore>,
    pub data_dir: TempDir,
}

impl Device {
    pub async fn register(transport: &FlakyTransport, handle: &str) -> Self {
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
        client.register(handle, handle).await.unwrap();
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

    pub fn message(&self, id: &MessageId) -> Message {
        self.store.message(id).unwrap().unwrap()
    }

    pub fn messages(&self, group_id: &GroupId) -> Vec<Message> {
        self.store.messages(group_id, None, usize::MAX).unwrap()
    }
}

/// Application messages `sender` posted to the group, as the server holds
/// them.
pub fn server_messages(
    transport: &FlakyTransport,
    group_id: &GroupId,
    sender: &DeviceRef,
) -> Vec<gim_test::Delivered> {
    transport
        .inner
        .service()
        .messages(group_id, 0, usize::MAX)
        .unwrap()
        .into_iter()
        .filter(|m| &m.sender == sender && m.kind == gim_test::MessageKind::Application)
        .collect()
}
