//! gim-sdk clients over the real hub, with faults injected at the transport
//! boundary for the cases the hub cannot be made to produce on demand: a
//! lost reply to an accepted post (the client re-posts and the hub answers
//! with its idempotent result), and an expired event cursor (410; the hub's
//! event retention is at least one day). With multi-homing, every other hub
//! a device opens goes through a [`FaultyHub`] too (see [`SdkDevice::hub`]),
//! so a test sees which hub got each request.

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, Message, MessageContent};
use gim_base::{MemoryStore, StateReader};
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use gim_sdk::testing::MemorySecretStorage;
use gim_sdk::transport::{
    AccessToken, Challenge, ClaimedKeyPackage, CommitAccepted, EventBatch, EventStream, GroupInfo,
    HostingEntryGrant, HubEvent, HubIdentity, KeyPackageClaim, KeyPackageCount, OutgoingCommit,
    PostError, SessionError, SessionToken, StoredHostingRecord, Transport, TransportError,
    TransportResult, UserRecord,
};
use gim_sdk::{
    Client, ClientBuilder, HttpTransport, HubConnector, RecoveryCode, SecretStorage, SyncSettings,
};
use tempfile::TempDir;
use url::Url;

/// Faults armed on a [`FaultyHub`]; each fires once.
#[derive(Debug, Default)]
pub struct Faults {
    /// Accepts the next Commit on the hub but answers with a network error.
    pub lose_commit_reply: AtomicBool,
    /// Accepts the next application message on the hub but answers with a
    /// network error.
    pub lose_message_reply: AtomicBool,
    /// Answers the next event fetch with 410 at the hub's head cursor, as
    /// if the events after the device's cursor had been pruned.
    pub expire_cursor: AtomicBool,
    /// The group and error of every commit the hub refused, in order.
    pub commit_errors: Mutex<Vec<(GroupId, String)>>,
    /// Every commit result the hub returned, in order.
    pub commit_results: Mutex<Vec<CommitAccepted>>,
    /// Every application message post the hub accepted: its `client_id`
    /// and the `seq` the hub returned, in order.
    pub message_posts: Mutex<Vec<(ClientId, u64)>>,
    /// The MLS message of the last application message post the hub
    /// accepted.
    pub last_message: Mutex<Option<Vec<u8>>>,
    /// Commits the hub answered with 409 `stale_epoch`.
    pub stale_commits: AtomicU32,
    /// Every 502/503 peer hub failure of a commit or message post, in
    /// order.
    pub peer_failures: Mutex<Vec<TransportError>>,
    /// The users of every federated KeyPackage claim sent to the hub, in
    /// order.
    pub claim_requests: Mutex<Vec<Vec<UserId>>>,
    /// Every user a KeyPackage claim reported `unavailable`, in order.
    pub unavailable_claims: Mutex<Vec<UserId>>,
    /// Every KeyPackage the hub handed out to claims, in order.
    pub claimed: Mutex<Vec<ClaimedKeyPackage>>,
    /// The `(group, seq)` of every group message the hub delivered in the
    /// device's events, in order.
    pub delivered: Mutex<Vec<(GroupId, u64)>>,
    /// Sign-in challenges the device asked the hub for.
    pub sign_ins: AtomicU32,
}

impl Faults {
    fn record<T>(&self, result: &Result<T, PostError>) {
        match result {
            Err(PostError::StaleEpoch { .. }) => {
                self.stale_commits.fetch_add(1, Ordering::SeqCst);
            }
            Err(PostError::Transport(err)) if err.is_peer_failure() => {
                self.peer_failures.lock().unwrap().push(err.clone());
            }
            _ => {}
        }
    }
}

fn lost_reply() -> TransportError {
    TransportError::Network("injected: reply lost".into())
}

/// The hub's HTTP transport with [`Faults`]. The live stream is disabled,
/// so the SDK long-polls `GET /v2/events` and every event passes through
/// [`Transport::fetch_events`].
#[derive(Clone)]
pub struct FaultyHub {
    inner: Arc<HttpTransport>,
    pub faults: Arc<Faults>,
}

impl FaultyHub {
    pub fn new(server_url: &str) -> Self {
        let url = Url::parse(server_url).unwrap();
        Self {
            inner: Arc::new(HttpTransport::new(url).unwrap()),
            faults: Arc::default(),
        }
    }

    /// The device's head cursor: drains the events after `cursor` without
    /// applying them.
    async fn head(&self, t: &AccessToken, mut cursor: Option<u64>) -> TransportResult<u64> {
        loop {
            let batch = self.inner.fetch_events(t, cursor, Duration::ZERO).await?;
            if batch.events.is_empty() {
                return Ok(batch.next_cursor);
            }
            cursor = Some(batch.next_cursor);
        }
    }
}

#[async_trait]
impl Transport for FaultyHub {
    fn base_url(&self) -> Option<String> {
        self.inner.base_url()
    }

    async fn hub_info(&self, nonce: Option<&[u8; 32]>) -> TransportResult<HubIdentity> {
        self.inner.hub_info(nonce).await
    }

    async fn put_device_list(&self, u: &UserId, list: Vec<u8>) -> TransportResult<()> {
        self.inner.put_device_list(u, list).await
    }

    async fn auth_challenge(&self, d: &DeviceRef) -> TransportResult<Challenge> {
        self.faults.sign_ins.fetch_add(1, Ordering::SeqCst);
        self.inner.auth_challenge(d).await
    }

    async fn create_session(&self, response: Vec<u8>) -> Result<SessionToken, SessionError> {
        self.inner.create_session(response).await
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
        let claimed = self.inner.claim_key_packages(t, users).await?;
        self.faults
            .claimed
            .lock()
            .unwrap()
            .extend(claimed.iter().cloned());
        Ok(claimed)
    }

    async fn claim_key_packages_federated(
        &self,
        t: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<KeyPackageClaim> {
        self.faults
            .claim_requests
            .lock()
            .unwrap()
            .push(users.to_vec());
        let claim = self.inner.claim_key_packages_federated(t, users).await?;
        self.faults
            .unavailable_claims
            .lock()
            .unwrap()
            .extend(claim.unavailable.iter().cloned());
        self.faults
            .claimed
            .lock()
            .unwrap()
            .extend(claim.key_packages.iter().cloned());
        Ok(claim)
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
        let result = self.inner.submit_commit(t, g, commit).await;
        self.faults.record(&result);
        if let Err(err) = &result {
            let error = (g.clone(), err.to_string());
            self.faults.commit_errors.lock().unwrap().push(error);
        }
        let accepted = result?;
        self.faults.commit_results.lock().unwrap().push(accepted);
        if self.faults.lose_commit_reply.swap(false, Ordering::SeqCst) {
            return Err(lost_reply().into());
        }
        Ok(accepted)
    }

    async fn post_message(
        &self,
        t: &AccessToken,
        g: &GroupId,
        client_id: ClientId,
        mls_message: Vec<u8>,
    ) -> Result<u64, PostError> {
        let result = self
            .inner
            .post_message(t, g, client_id.clone(), mls_message.clone())
            .await;
        self.faults.record(&result);
        let seq = result?;
        *self.faults.last_message.lock().unwrap() = Some(mls_message);
        self.faults
            .message_posts
            .lock()
            .unwrap()
            .push((client_id, seq));
        if self.faults.lose_message_reply.swap(false, Ordering::SeqCst) {
            return Err(lost_reply().into());
        }
        Ok(seq)
    }

    async fn fetch_events(
        &self,
        t: &AccessToken,
        cursor: Option<u64>,
        wait: Duration,
    ) -> TransportResult<EventBatch> {
        if self.faults.expire_cursor.swap(false, Ordering::SeqCst) {
            let head = self.head(t, cursor).await?;
            return Err(TransportError::Gone { cursor: head });
        }
        let batch = self.inner.fetch_events(t, cursor, wait).await?;
        self.faults
            .delivered
            .lock()
            .unwrap()
            .extend(batch.events.iter().filter_map(|event| match event {
                HubEvent::Group(IncomingEvent::Message(m)) => Some((m.group_id.clone(), m.seq)),
                _ => None,
            }));
        Ok(batch)
    }

    async fn open_stream(
        &self,
        _t: &AccessToken,
        _cursor: Option<u64>,
    ) -> TransportResult<Option<Box<dyn EventStream>>> {
        Ok(None)
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

    async fn create_hosting_entry(
        &self,
        t: &AccessToken,
        u: &UserId,
        priority: u8,
    ) -> TransportResult<HostingEntryGrant> {
        self.inner.create_hosting_entry(t, u, priority).await
    }

    async fn put_hosting_record(
        &self,
        u: &UserId,
        record: Vec<u8>,
    ) -> TransportResult<StoredHostingRecord> {
        self.inner.put_hosting_record(u, record).await
    }

    async fn hosting_record(&self, u: &UserId) -> TransportResult<Option<StoredHostingRecord>> {
        self.inner.hosting_record(u).await
    }

    async fn download_blob(
        &self,
        t: &AccessToken,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>> {
        self.inner.download_blob(t, blob_id, range).await
    }
}

/// The [`FaultyHub`]s a device opened for other hubs, by URL.
pub type HubTransports = Arc<Mutex<HashMap<String, FaultyHub>>>;

/// A gim-sdk client with an in-memory store on its own [`FaultyHub`],
/// driven by explicit [`Self::sync`] calls (no sync loop). Pending invites
/// are due again after one second (see [`Client::retry_pending_invites`]).
/// Other hubs are opened as [`FaultyHub`]s too (see [`Self::hub`]).
pub struct SdkDevice {
    pub client: Client<MemoryStore>,
    pub store: Arc<MemoryStore>,
    pub hub: FaultyHub,
    /// The hubs other than `hub` the client opened, by URL.
    pub hubs: HubTransports,
    pub recovery_code: Option<RecoveryCode>,
    _data_dir: TempDir,
}

impl SdkDevice {
    /// Creates a fresh identity on this device.
    pub async fn create(server_url: &str, display_name: &str) -> Self {
        let mut device = Self::open(server_url);
        let code = device.client.create_identity(display_name).await.unwrap();
        device.recovery_code = Some(code);
        device
    }

    /// A client on `server_url` without an identity yet.
    pub fn open(server_url: &str) -> Self {
        let hub = FaultyHub::new(server_url);
        let hubs = HubTransports::default();
        let opened = hubs.clone();
        let connector: HubConnector = Arc::new(move |url: &str| {
            let hub = opened
                .lock()
                .unwrap()
                .entry(url.to_string())
                .or_insert_with(|| FaultyHub::new(url))
                .clone();
            Ok(Arc::new(hub) as Arc<dyn Transport>)
        });
        let store = Arc::new(MemoryStore::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = ClientBuilder::new(
            store.clone(),
            Arc::new(hub.clone()),
            Arc::new(MemorySecretStorage::new()) as Arc<dyn SecretStorage>,
        )
        .data_dir(data_dir.path())
        .hub_connector(connector)
        .sync_settings(SyncSettings {
            invite_retry: Duration::from_secs(1),
            ..SyncSettings::default()
        })
        .build()
        .unwrap();
        Self {
            client,
            store,
            hub,
            hubs,
            recovery_code: None,
            _data_dir: data_dir,
        }
    }

    /// A second device of this user on a fresh client at `server_url` (this
    /// device's hub, which relays the bundle), linked with both sides
    /// accepting the SAS.
    pub async fn link(&self, server_url: &str) -> Self {
        let device = Self::open(server_url);
        let link = device
            .client
            .start_link(vec![server_url.to_string()])
            .unwrap();
        let (waited, approval) = tokio::join!(device.client.wait_link(&link), async {
            self.client.approve_link(&link.qr_string).await.unwrap()
        });
        assert_eq!(waited.unwrap().sas, approval.sas);
        device.client.confirm_link(true).await.unwrap();
        self.client.confirm_approval(&approval, true).await.unwrap();
        assert_eq!(device.user_id(), self.user_id());
        device
    }

    /// The transport the device uses for the hub at `url`: [`Self::hub`]
    /// for its own hub, else the one it opened (panics if it did not).
    pub fn hub(&self, url: &str) -> FaultyHub {
        if self.hub.base_url().as_deref() == Some(url) {
            return self.hub.clone();
        }
        self.hubs
            .lock()
            .unwrap()
            .get(url)
            .unwrap_or_else(|| panic!("the device did not open {url}"))
            .clone()
    }

    pub fn user_id(&self) -> UserId {
        self.client.session().unwrap().device.user_id
    }

    /// Fetches and applies the pending events once.
    pub async fn sync(&self) {
        self.client.sync_once().await.unwrap();
    }

    pub fn messages(&self, group_id: &GroupId) -> Vec<Message> {
        self.store.messages(group_id, None, usize::MAX).unwrap()
    }

    /// The text bodies of the group's messages, in timeline order.
    pub fn texts(&self, group_id: &GroupId) -> Vec<String> {
        self.messages(group_id)
            .into_iter()
            .filter_map(|m| match m.content {
                MessageContent::Text { body } if !m.deleted => Some(body),
                _ => None,
            })
            .collect()
    }

    /// The hub's view of the group (epoch, members).
    pub async fn hub_group(&self, group_id: &GroupId) -> GroupInfo {
        let token = self.client.session().unwrap().token;
        self.hub.group_info(&token, group_id).await.unwrap()
    }
}
