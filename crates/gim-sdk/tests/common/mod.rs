//! Shared test helpers: a [`FakeTransport`] wrapper that injects network
//! faults, and a registered test device.

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, Message, MessageKind, StateChange};
use gim_base::{MemoryStore, StateReader};
use gim_common::{ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{
    AccessToken, Challenge, ClaimedKeyPackage, CommitAccepted, EventBatch, GroupInfo,
    KeyPackageCount, OutgoingCommit, PostError, SessionError, SessionToken, Transport,
    TransportError, TransportResult, UserRecord,
};
use gim_sdk::{Client, ClientBuilder, SecretStorage, SyncSettings};
use tempfile::TempDir;

/// A post fault, applied to the next commit submission (`Commit`) or
/// application message post (`Application`).
#[derive(Debug, Clone, Copy)]
pub struct PostFault {
    pub kind: MessageKind,
    /// The hub accepts the post but the reply is lost; otherwise the post
    /// never reaches the hub.
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
    /// Errors returned by the next `create_session` calls, in order.
    pub sessions: Mutex<VecDeque<SessionError>>,
    /// `device_list` calls for the user still answered "unknown".
    pub hidden_lists: Mutex<HashMap<UserId, usize>>,
    /// Users whose DeviceList was requested, in order.
    pub list_requests: Mutex<Vec<UserId>>,
    /// DeviceLists that land on the hub right before the next
    /// `put_device_list` calls, one per call (a concurrent upload).
    pub concurrent_lists: Mutex<VecDeque<(UserId, Vec<u8>)>>,
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

    /// Takes the next post fault if it is for `kind`.
    fn fault(&self, kind: MessageKind) -> Option<PostFault> {
        let mut posts = self.faults.posts.lock().unwrap();
        match posts.front() {
            Some(f) if f.kind == kind => posts.pop_front(),
            _ => None,
        }
    }
}

#[async_trait]
impl Transport for FlakyTransport {
    async fn put_device_list(&self, u: &UserId, list: Vec<u8>) -> TransportResult<()> {
        let concurrent = self.faults.concurrent_lists.lock().unwrap().pop_front();
        if let Some((user_id, concurrent)) = concurrent {
            self.inner.put_device_list(&user_id, concurrent).await?;
        }
        self.inner.put_device_list(u, list).await
    }

    async fn auth_challenge(&self, d: &DeviceRef) -> TransportResult<Challenge> {
        self.inner.auth_challenge(d).await
    }

    async fn create_session(&self, response: Vec<u8>) -> Result<SessionToken, SessionError> {
        let injected = self.faults.sessions.lock().unwrap().pop_front();
        match injected {
            Some(err) => Err(err),
            None => self.inner.create_session(response).await,
        }
    }

    async fn put_recovery_backup(
        &self,
        t: &AccessToken,
        u: &UserId,
        backup: Vec<u8>,
    ) -> TransportResult<()> {
        self.inner.put_recovery_backup(t, u, backup).await
    }

    async fn recovery_backup(&self, u: &UserId) -> TransportResult<Option<Vec<u8>>> {
        self.inner.recovery_backup(u).await
    }

    async fn post_link_bundle(
        &self,
        t: &AccessToken,
        link_id: &str,
        sealed_bundle: Vec<u8>,
        expires_in: Duration,
    ) -> TransportResult<()> {
        self.inner
            .post_link_bundle(t, link_id, sealed_bundle, expires_in)
            .await
    }

    async fn fetch_link_bundle(
        &self,
        link_id: &str,
        wait: Duration,
    ) -> TransportResult<Option<Vec<u8>>> {
        self.inner.fetch_link_bundle(link_id, wait).await
    }

    async fn device_list(
        &self,
        t: Option<&AccessToken>,
        u: &UserId,
    ) -> TransportResult<Option<Vec<u8>>> {
        self.faults.list_requests.lock().unwrap().push(u.clone());
        if let Some(left @ 1..) = self.faults.hidden_lists.lock().unwrap().get_mut(u) {
            *left -= 1;
            return Ok(None);
        }
        self.inner.device_list(t, u).await
    }

    async fn user(
        &self,
        t: Option<&AccessToken>,
        u: &UserId,
    ) -> TransportResult<Option<UserRecord>> {
        self.inner.user(t, u).await
    }

    async fn find_handle(&self, t: &AccessToken, handle: &str) -> TransportResult<Option<UserId>> {
        self.inner.find_handle(t, handle).await
    }

    async fn claim_handle(&self, t: &AccessToken, handle: &str) -> TransportResult<()> {
        self.inner.claim_handle(t, handle).await
    }

    async fn release_handle(&self, t: &AccessToken, handle: &str) -> TransportResult<()> {
        self.inner.release_handle(t, handle).await
    }

    async fn publish_display_name(&self, t: &AccessToken, name: &str) -> TransportResult<()> {
        self.inner.publish_display_name(t, name).await
    }

    async fn upload_key_packages(
        &self,
        t: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: bool,
    ) -> TransportResult<()> {
        self.inner
            .upload_key_packages(t, key_packages, last_resort)
            .await
    }

    async fn key_package_count(&self, t: &AccessToken) -> TransportResult<KeyPackageCount> {
        self.inner.key_package_count(t).await
    }

    async fn claim_key_packages(
        &self,
        t: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<Vec<ClaimedKeyPackage>> {
        self.inner.claim_key_packages(t, users).await
    }

    async fn create_group(&self, t: &AccessToken, kind: ChatKind) -> TransportResult<GroupId> {
        self.inner.create_group(t, kind).await
    }

    async fn group_info(&self, t: &AccessToken, g: &GroupId) -> TransportResult<GroupInfo> {
        self.inner.group_info(t, g).await
    }

    async fn list_groups(&self, t: &AccessToken) -> TransportResult<Vec<GroupInfo>> {
        self.inner.list_groups(t).await
    }

    async fn submit_commit(
        &self,
        t: &AccessToken,
        g: &GroupId,
        commit: OutgoingCommit,
    ) -> Result<CommitAccepted, PostError> {
        match self.fault(MessageKind::Commit) {
            None => self.inner.submit_commit(t, g, commit).await,
            Some(PostFault {
                lose_reply: true, ..
            }) => {
                self.inner.submit_commit(t, g, commit).await?;
                Err(Self::network().into())
            }
            Some(_) => Err(Self::network().into()),
        }
    }

    async fn post_message(
        &self,
        t: &AccessToken,
        g: &GroupId,
        client_id: ClientId,
        mls_message: Vec<u8>,
    ) -> Result<u64, PostError> {
        match self.fault(MessageKind::Application) {
            None => self.inner.post_message(t, g, client_id, mls_message).await,
            Some(PostFault {
                lose_reply: true, ..
            }) => {
                self.inner
                    .post_message(t, g, client_id, mls_message)
                    .await?;
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

    async fn pending_welcomes(
        &self,
        t: &AccessToken,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        self.inner.pending_welcomes(t, limit).await
    }

    async fn ack_welcome(&self, t: &AccessToken, g: &GroupId) -> TransportResult<()> {
        self.inner.ack_welcome(t, g).await
    }

    async fn group_messages(
        &self,
        t: &AccessToken,
        g: &GroupId,
        from_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        self.inner.group_messages(t, g, from_seq, limit).await
    }

    async fn upload_blob(&self, t: &AccessToken, file: &Path) -> TransportResult<String> {
        self.inner.upload_blob(t, file).await
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

/// Default timing, but members not chosen to commit a pending Proposal
/// wait only 300-600 ms.
pub fn quick_proposals() -> SyncSettings {
    SyncSettings {
        proposal_commit_delay_min: Duration::from_millis(300),
        proposal_commit_delay_max: Duration::from_millis(600),
        ..SyncSettings::default()
    }
}

impl Device {
    pub async fn register(transport: &FlakyTransport, handle: &str) -> Self {
        Self::register_with(transport, handle, SyncSettings::default()).await
    }

    pub async fn register_with(
        transport: &FlakyTransport,
        handle: &str,
        settings: SyncSettings,
    ) -> Self {
        let store = Arc::new(MemoryStore::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = ClientBuilder::new(
            store.clone(),
            Arc::new(transport.clone()),
            Arc::new(MemorySecretStorage::new()) as Arc<dyn SecretStorage>,
        )
        .data_dir(data_dir.path())
        .sync_settings(settings)
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

/// The device the SDK picks to commit pending Proposals at once: the
/// lowest device id.
pub fn lowest(devices: [&Device; 2]) -> (&Device, &Device) {
    let [a, b] = devices;
    if a.device().device_id.as_str() < b.device().device_id.as_str() {
        (a, b)
    } else {
        (b, a)
    }
}

/// Commits (and standalone Proposals) the hub sequenced in the group.
pub fn server_handshakes(transport: &FlakyTransport, group_id: &GroupId) -> usize {
    transport
        .inner
        .service()
        .messages(group_id, 0, usize::MAX)
        .unwrap()
        .into_iter()
        .filter(|m| m.kind == gim_test::MessageKind::Commit)
        .count()
}

/// Application messages `sender` posted to the group, as the hub holds
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
