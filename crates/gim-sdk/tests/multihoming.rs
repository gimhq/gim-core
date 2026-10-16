//! Submission and KeyPackages across two listed hubs (contract
//! `multihoming.md` §5.1, §5.4, §6.1): Commits and messages go to the
//! primary hub and, when it cannot be reached, identically to the next one;
//! peer failures and definite rejections never switch hubs; every hub gets
//! its own disjoint KeyPackages; an Add is claimed and committed through
//! one hub.
//!
//! Hub management (§4.1, §7.1): adding a hub, removing one (with the
//! warning for the groups it owns and the drain check), changing the
//! primary hub, the hub map after a restore, and reads that fall back to
//! the other hub while the home hub is down.
//!
//! Hub A owns the groups (hub B with [`Options::owner_b`]). Hub B is a
//! co-host: it keeps its own users, sessions and KeyPackages, claims the
//! packages of users it does not host from the owner, enforces the claim
//! ledger for Adds (`kp_not_claimed`) and forwards group requests to the
//! owner, which dedups them as an owner does.

mod common;

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use common::{server_handshakes, server_messages, Device, FlakyTransport};
use gim_base::model::{ChatKind, GroupMessage, KeyPackageRecord, SendState, StateChange};
use gim_base::{MemoryStore, StateReader};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, UserId};
use gim_identity::{HostingEntry, RootKey, SignedHostingRecord, UserHostingRecord};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{
    AccessToken, Challenge, ClaimedKeyPackage, CommitAccepted, EventBatch, GroupInfo,
    HostingEntryGrant, HubIdentity, KeyPackageClaim, KeyPackageCount, OutgoingCommit, PostError,
    SessionError, SessionToken, StoredHostingRecord, Transport, TransportError, TransportResult,
    UserRecord,
};
use gim_sdk::{
    Client, ClientBuilder, ClientError, HubConnector, HubStatus, RecoveryCode, SecretStorage,
    HOSTING_RECORD_LIFETIME, KEY_PACKAGE_BATCH, ROOT_KEY_SECRET_KEY,
};
use tempfile::TempDir;

const SEED_B: [u8; 32] = [0x62; 32];
const HUB_B_URL: &str = "https://hub-b.test";

/// A request a hub received, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Commit(Vec<u8>),
    Post(ClientId, Vec<u8>),
    Claim(Vec<UserId>),
    Upload(Vec<Vec<u8>>, bool),
    Fetch,
    /// A DeviceList (`"device_list"`) or directory (`"user"`) read.
    Read(&'static str, UserId),
}

/// What a hub does with the next request of a kind.
enum Fault {
    /// Answers with the error without applying the request.
    Fail(TransportError),
    /// Applies the request, then the response is lost.
    LoseResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Commit,
    Post,
    Upload,
}

#[derive(Default)]
struct HubState {
    /// Every request fails as if the hub were unreachable.
    down: AtomicBool,
    /// Commit submissions fail as if the hub were unreachable.
    commits_down: AtomicBool,
    /// Adds need their devices' KeyPackages claimed through this hub.
    enforce_claims: AtomicBool,
    claimed: Mutex<HashSet<DeviceRef>>,
    faults: Mutex<VecDeque<(Op, Fault)>>,
    calls: Mutex<Vec<Call>>,
}

/// A hub for one client: identity, sessions and KeyPackages from `own`,
/// groups on `owner` (the same fake hub for hub A).
#[derive(Clone)]
struct Hub {
    own: FakeTransport,
    owner: FakeTransport,
    state: Arc<HubState>,
    /// The client API base URL the transport reports.
    url: Option<String>,
}

impl Hub {
    fn new(own: &FakeTransport, owner: &FakeTransport) -> Self {
        Self {
            own: own.clone(),
            owner: owner.clone(),
            state: Arc::default(),
            url: None,
        }
    }

    fn fetches(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| matches!(c, Call::Fetch))
            .count()
    }

    fn reads(&self) -> Vec<(&'static str, UserId)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Read(what, user_id) => Some((what, user_id)),
                _ => None,
            })
            .collect()
    }

    fn calls(&self) -> Vec<Call> {
        self.state.calls.lock().unwrap().clone()
    }

    fn commits(&self) -> Vec<Vec<u8>> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Commit(bytes) => Some(bytes),
                _ => None,
            })
            .collect()
    }

    fn posts(&self) -> Vec<(ClientId, Vec<u8>)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Post(client_id, bytes) => Some((client_id, bytes)),
                _ => None,
            })
            .collect()
    }

    fn claims(&self) -> Vec<Vec<UserId>> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Claim(users) => Some(users),
                _ => None,
            })
            .collect()
    }

    fn uploads(&self) -> Vec<(Vec<Vec<u8>>, bool)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Upload(kps, last_resort) => Some((kps, last_resort)),
                _ => None,
            })
            .collect()
    }

    fn inject(&self, op: Op, fault: Fault) {
        self.state.faults.lock().unwrap().push_back((op, fault));
    }

    fn fault(&self, op: Op) -> Option<Fault> {
        let mut faults = self.state.faults.lock().unwrap();
        match faults.front() {
            Some((o, _)) if *o == op => faults.pop_front().map(|(_, f)| f),
            _ => None,
        }
    }

    fn up(&self) -> TransportResult<()> {
        if self.state.down.load(Ordering::SeqCst) {
            return Err(TransportError::Network("hub down".into()));
        }
        Ok(())
    }

    fn log(&self, call: Call) {
        self.state.calls.lock().unwrap().push(call);
    }

    /// A token on the owning hub for the device signed in here.
    fn owner_token(&self, token: &AccessToken) -> TransportResult<AccessToken> {
        let device = self
            .own
            .service()
            .authenticate(token.as_str())
            .map_err(|_| TransportError::Unauthorized)?;
        let owner = self
            .owner
            .service()
            .create_session(&device)
            .map_err(|e| TransportError::Server(e.to_string()))?;
        Ok(AccessToken::new(owner))
    }
}

#[async_trait]
impl Transport for Hub {
    fn base_url(&self) -> Option<String> {
        self.url.clone().or_else(|| self.own.base_url())
    }

    async fn hub_info(&self, nonce: Option<&[u8; 32]>) -> TransportResult<HubIdentity> {
        self.up()?;
        self.own.hub_info(nonce).await
    }

    /// The owning hub learns the list too (federation), so that this
    /// hub's users can sign in there.
    async fn put_device_list(&self, u: &UserId, list: Vec<u8>) -> TransportResult<()> {
        self.up()?;
        if self.own.service().hub_id() != self.owner.service().hub_id() {
            self.owner.put_device_list(u, list.clone()).await?;
        }
        self.own.put_device_list(u, list).await
    }

    async fn auth_challenge(&self, d: &DeviceRef) -> TransportResult<Challenge> {
        self.up()?;
        self.own.auth_challenge(d).await
    }

    async fn create_session(&self, response: Vec<u8>) -> Result<SessionToken, SessionError> {
        self.up()?;
        self.own.create_session(response).await
    }

    async fn put_recovery_backup(
        &self,
        t: &AccessToken,
        u: &UserId,
        backup: Vec<u8>,
    ) -> TransportResult<()> {
        self.up()?;
        self.own.put_recovery_backup(t, u, backup).await
    }

    async fn recovery_backup(&self, u: &UserId) -> TransportResult<Option<Vec<u8>>> {
        self.up()?;
        self.own.recovery_backup(u).await
    }

    async fn post_link_bundle(
        &self,
        t: &AccessToken,
        link_id: &str,
        sealed: Vec<u8>,
        expires_in: Duration,
    ) -> TransportResult<()> {
        self.up()?;
        self.own
            .post_link_bundle(t, link_id, sealed, expires_in)
            .await
    }

    async fn fetch_link_bundle(
        &self,
        link_id: &str,
        wait: Duration,
    ) -> TransportResult<Option<Vec<u8>>> {
        self.up()?;
        self.own.fetch_link_bundle(link_id, wait).await
    }

    async fn device_list(
        &self,
        t: Option<&AccessToken>,
        u: &UserId,
    ) -> TransportResult<Option<Vec<u8>>> {
        self.up()?;
        self.log(Call::Read("device_list", u.clone()));
        self.owner.device_list(t, u).await
    }

    async fn user(
        &self,
        t: Option<&AccessToken>,
        u: &UserId,
    ) -> TransportResult<Option<UserRecord>> {
        self.up()?;
        self.log(Call::Read("user", u.clone()));
        self.owner.user(t, u).await
    }

    async fn find_handle(&self, t: &AccessToken, handle: &str) -> TransportResult<Option<UserId>> {
        self.up()?;
        self.own.find_handle(t, handle).await
    }

    async fn claim_handle(&self, t: &AccessToken, handle: &str) -> TransportResult<()> {
        self.up()?;
        self.own.claim_handle(t, handle).await
    }

    async fn release_handle(&self, t: &AccessToken, handle: &str) -> TransportResult<()> {
        self.up()?;
        self.own.release_handle(t, handle).await
    }

    async fn publish_display_name(&self, t: &AccessToken, name: &str) -> TransportResult<()> {
        self.up()?;
        self.own.publish_display_name(t, name).await
    }

    async fn upload_key_packages(
        &self,
        t: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: bool,
    ) -> TransportResult<()> {
        self.up()?;
        self.log(Call::Upload(key_packages.clone(), last_resort));
        if let Some(Fault::Fail(err)) = self.fault(Op::Upload) {
            return Err(err);
        }
        self.own
            .upload_key_packages(t, key_packages, last_resort)
            .await
    }

    async fn key_package_count(&self, t: &AccessToken) -> TransportResult<KeyPackageCount> {
        self.up()?;
        self.own.key_package_count(t).await
    }

    async fn claim_key_packages(
        &self,
        t: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<Vec<ClaimedKeyPackage>> {
        Ok(self
            .claim_key_packages_federated(t, users)
            .await?
            .key_packages)
    }

    /// Claims from this hub's users first, then from the owning hub for
    /// users without a package here (claim routing).
    async fn claim_key_packages_federated(
        &self,
        t: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<KeyPackageClaim> {
        self.up()?;
        self.log(Call::Claim(users.to_vec()));
        let mut claimed = self.own.claim_key_packages(t, users).await?;
        let missing: Vec<UserId> = users
            .iter()
            .filter(|u| !claimed.iter().any(|k| &k.device.user_id == *u))
            .cloned()
            .collect();
        if !missing.is_empty() && self.own.service().hub_id() != self.owner.service().hub_id() {
            let owner = self.owner_token(t)?;
            claimed.extend(self.owner.claim_key_packages(&owner, &missing).await?);
        }
        self.state
            .claimed
            .lock()
            .unwrap()
            .extend(claimed.iter().map(|k| k.device.clone()));
        Ok(KeyPackageClaim {
            key_packages: claimed,
            unavailable: vec![],
        })
    }

    async fn create_group(&self, t: &AccessToken, kind: ChatKind) -> TransportResult<GroupId> {
        self.up()?;
        self.owner.create_group(&self.owner_token(t)?, kind).await
    }

    async fn group_info(&self, t: &AccessToken, g: &GroupId) -> TransportResult<GroupInfo> {
        self.up()?;
        self.owner.group_info(&self.owner_token(t)?, g).await
    }

    async fn list_groups(&self, t: &AccessToken) -> TransportResult<Vec<GroupInfo>> {
        self.up()?;
        self.owner.list_groups(&self.owner_token(t)?).await
    }

    async fn submit_commit(
        &self,
        t: &AccessToken,
        g: &GroupId,
        commit: OutgoingCommit,
    ) -> Result<CommitAccepted, PostError> {
        self.up()?;
        self.log(Call::Commit(commit.mls_message.clone()));
        if self.state.commits_down.load(Ordering::SeqCst) {
            return Err(TransportError::Network("hub down".into()).into());
        }
        let lose = match self.fault(Op::Commit) {
            Some(Fault::Fail(err)) => return Err(err.into()),
            Some(Fault::LoseResponse) => true,
            None => false,
        };
        if self.state.enforce_claims.load(Ordering::SeqCst) {
            let claimed = self.state.claimed.lock().unwrap();
            if !commit
                .welcome_recipients
                .iter()
                .all(|d| claimed.contains(d))
            {
                return Err(TransportError::Rejected {
                    status: 400,
                    code: "validation_failed".into(),
                    message: "key package not claimed through this hub (kp_not_claimed)".into(),
                }
                .into());
            }
        }
        let accepted = self
            .owner
            .submit_commit(&self.owner_token(t)?, g, commit)
            .await?;
        if lose {
            return Err(TransportError::Network("response lost".into()).into());
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
        self.up()?;
        self.log(Call::Post(client_id.clone(), mls_message.clone()));
        let lose = match self.fault(Op::Post) {
            Some(Fault::Fail(err)) => return Err(err.into()),
            Some(Fault::LoseResponse) => true,
            None => false,
        };
        let seq = self
            .owner
            .post_message(&self.owner_token(t)?, g, client_id, mls_message)
            .await?;
        if lose {
            return Err(TransportError::Network("response lost".into()).into());
        }
        Ok(seq)
    }

    async fn fetch_events(
        &self,
        t: &AccessToken,
        cursor: Option<u64>,
        wait: Duration,
    ) -> TransportResult<EventBatch> {
        self.up()?;
        self.log(Call::Fetch);
        // A co-host's own events (`keypackages.low`); the owner's for A.
        self.own.fetch_events(t, cursor, wait).await
    }

    async fn pending_welcomes(
        &self,
        t: &AccessToken,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        self.up()?;
        self.owner
            .pending_welcomes(&self.owner_token(t)?, limit)
            .await
    }

    async fn ack_welcome(&self, t: &AccessToken, g: &GroupId) -> TransportResult<()> {
        self.up()?;
        self.owner.ack_welcome(&self.owner_token(t)?, g).await
    }

    async fn group_messages(
        &self,
        t: &AccessToken,
        g: &GroupId,
        from_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        self.up()?;
        self.owner
            .group_messages(&self.owner_token(t)?, g, from_seq, limit)
            .await
    }

    async fn create_hosting_entry(
        &self,
        t: &AccessToken,
        u: &UserId,
        priority: u8,
    ) -> TransportResult<HostingEntryGrant> {
        self.up()?;
        self.own.create_hosting_entry(t, u, priority).await
    }

    async fn put_hosting_record(
        &self,
        u: &UserId,
        record: Vec<u8>,
    ) -> TransportResult<StoredHostingRecord> {
        self.up()?;
        self.own.put_hosting_record(u, record).await
    }

    async fn hosting_record(&self, u: &UserId) -> TransportResult<Option<StoredHostingRecord>> {
        self.up()?;
        self.own.hosting_record(u).await
    }

    async fn upload_blob(&self, t: &AccessToken, file: &Path) -> TransportResult<String> {
        self.up()?;
        self.own.upload_blob(t, file).await
    }

    async fn download_blob(
        &self,
        t: &AccessToken,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>> {
        self.up()?;
        self.own.download_blob(t, blob_id, range).await
    }
}

/// How [`Setup`] is built.
#[derive(Debug, Clone, Copy, Default)]
struct Options {
    /// Hub B owns the groups (and bob is on B).
    owner_b: bool,
    /// Alice's record lists hub A only.
    unlisted_b: bool,
}

/// Alice, listing hub A (primary, her home hub) and hub B, with bob (and
/// carol) on the owning hub only.
struct Setup {
    fake_a: FakeTransport,
    fake_b: FakeTransport,
    /// Alice's view of each hub.
    hub_a: Hub,
    hub_b: Hub,
    connector: HubConnector,
    alice: Client<MemoryStore>,
    store: Arc<MemoryStore>,
    secrets: Arc<MemorySecretStorage>,
    recovery_code: RecoveryCode,
    bob: Device,
    _data_dir: TempDir,
}

/// Another device of alice's user.
struct OwnDevice {
    client: Client<MemoryStore>,
    _data_dir: TempDir,
}

impl Setup {
    async fn new() -> Self {
        Self::build(Options::default()).await
    }

    async fn build(options: Options) -> Self {
        let fake_a = FakeTransport::new();
        let fake_b = FakeTransport::with_hub_seed(SEED_B).with_public_url(HUB_B_URL);
        let owner = if options.owner_b { &fake_b } else { &fake_a };
        let hub_a = Hub::new(&fake_a, owner);
        let hub_b = Hub::new(&fake_b, owner);
        let connected = hub_b.clone();
        let connector: HubConnector = Arc::new(move |url: &str| {
            assert_eq!(url, HUB_B_URL);
            Ok(Arc::new(connected.clone()) as Arc<dyn Transport>)
        });
        let store = Arc::new(MemoryStore::new());
        let secrets = Arc::new(MemorySecretStorage::new());
        let data_dir = tempfile::tempdir().unwrap();
        let alice = ClientBuilder::new(
            store.clone(),
            Arc::new(hub_a.clone()),
            secrets.clone() as Arc<dyn SecretStorage>,
        )
        .data_dir(data_dir.path())
        .hub_connector(connector.clone())
        .build()
        .unwrap();
        let recovery_code = alice.register("alice", "Alice").await.unwrap();
        let bob = Device::register(&FlakyTransport::over(owner.clone()), "bob").await;
        let s = Self {
            fake_a,
            fake_b,
            hub_a,
            hub_b,
            connector,
            alice,
            store,
            secrets,
            recovery_code,
            bob,
            _data_dir: data_dir,
        };
        if !options.unlisted_b {
            // The add-hub procedure: the DeviceList and a record listing B.
            let user_id = s.user_id();
            let list = s.fake_a.service().device_list(&user_id).unwrap();
            s.fake_b.put_device_list(&user_id, list).await.unwrap();
            let record = s.record(2, &[(&s.fake_a, 0), (&s.fake_b, 1)]);
            s.fake_a.set_hosting_record(&user_id, Some(record));
            s.alice.refresh_hubs().await.unwrap();
            s.alice
                .set_hub_url(s.fake_b.service().hub_id(), HUB_B_URL)
                .await
                .unwrap();
        }
        s
    }

    fn user_id(&self) -> UserId {
        self.device().user_id
    }

    /// A record of alice listing `hubs` (hub, priority).
    fn record(&self, seq: u64, hubs: &[(&FakeTransport, u8)]) -> Vec<u8> {
        let seed = self.secrets.get(ROOT_KEY_SECRET_KEY).unwrap().unwrap();
        let root = RootKey::from_seed(&seed.try_into().unwrap());
        let entries = hubs
            .iter()
            .map(|(hub, priority)| {
                HostingEntry::sign(hub.hub_root_key(), &self.user_id(), *priority)
            })
            .collect();
        let expires_at = now_ms() + HOSTING_RECORD_LIFETIME.as_millis() as u64;
        UserHostingRecord::new(root.public(), seq, expires_at, entries)
            .and_then(|record| record.sign(&root))
            .unwrap()
            .to_bytes()
    }

    /// The record `fake` stores for alice: its seq and its hubs (hub id,
    /// priority) in canonical order.
    fn stored_record(&self, fake: &FakeTransport) -> (u64, Vec<(String, u8)>) {
        let bytes = fake.stored_hosting_record(&self.user_id()).unwrap();
        let record = SignedHostingRecord::from_bytes(&bytes)
            .and_then(|signed| signed.verify(now_ms()))
            .unwrap();
        let hubs = record
            .hubs()
            .iter()
            .map(|e| (e.hub_id(), e.priority()))
            .collect();
        (record.seq(), hubs)
    }

    /// A client of a new device over `transport`, with alice's connector.
    fn client(&self, transport: Hub) -> OwnDevice {
        let data_dir = tempfile::tempdir().unwrap();
        let client = ClientBuilder::new(
            Arc::new(MemoryStore::new()),
            Arc::new(transport),
            Arc::new(MemorySecretStorage::new()) as Arc<dyn SecretStorage>,
        )
        .data_dir(data_dir.path())
        .hub_connector(self.connector.clone())
        .build()
        .unwrap();
        OwnDevice {
            client,
            _data_dir: data_dir,
        }
    }

    /// A tablet linked to alice over hub A, in the self group.
    async fn link_tablet(&self) -> OwnDevice {
        let tablet = self.client(self.hub_a.clone());
        let session = tablet.client.start_link(vec!["hub-a.test".into()]).unwrap();
        let approval = self.alice.approve_link(&session.qr_string).await.unwrap();
        let linked = tablet.client.wait_link(&session).await.unwrap();
        assert_eq!(linked.sas, approval.sas);
        tablet.client.confirm_link(true).await.unwrap();
        self.alice.confirm_approval(&approval, true).await.unwrap();
        tablet.client.sync_once().await.unwrap();
        tablet
    }

    fn status(&self, hubs: &[HubStatus], fake: &FakeTransport) -> HubStatus {
        let hub_id = Self::hub_id(fake);
        hubs.iter()
            .find(|h| h.hub.hub_id == hub_id)
            .unwrap_or_else(|| panic!("{hub_id} not in {hubs:?}"))
            .clone()
    }

    fn device(&self) -> DeviceRef {
        self.alice.session().unwrap().device
    }

    fn hub_id(fake: &FakeTransport) -> String {
        fake.service().hub_id().to_string()
    }

    fn ledger(&self, fake: &FakeTransport) -> Vec<KeyPackageRecord> {
        let hub_id = Self::hub_id(fake);
        self.store
            .key_package_records()
            .unwrap()
            .into_iter()
            .filter(|r| r.hub_id == hub_id)
            .collect()
    }

    async fn direct_chat(&self) -> GroupId {
        self.alice
            .create_direct_chat(&self.bob.user_id())
            .await
            .unwrap()
    }

    fn members(&self, group_id: &GroupId) -> BTreeSet<DeviceRef> {
        self.fake_a
            .service()
            .group(group_id)
            .unwrap()
            .members
            .into_iter()
            .collect()
    }
}

fn rejected(status: u16, code: &str) -> TransportError {
    TransportError::Rejected {
        status,
        code: code.into(),
        message: "injected".into(),
    }
}

/// Every one-time KeyPackage of `device` on the hub, claimed.
fn drain(hub: &FakeTransport, device: &DeviceRef) -> BTreeSet<Vec<u8>> {
    let count = hub.service().key_package_count(device);
    (0..count)
        .map(|_| {
            let (claimed, _) = hub
                .service()
                .claim_key_packages(std::slice::from_ref(&device.user_id));
            claimed
                .into_iter()
                .find(|c| &c.device == device)
                .unwrap()
                .key_package
        })
        .collect()
}

#[tokio::test]
async fn each_hub_gets_disjoint_key_packages_and_its_own_last_resort() {
    let s = Setup::new().await;
    let device = s.device();
    let batch = KEY_PACKAGE_BATCH as usize;
    for hub in [&s.fake_a, &s.fake_b] {
        assert_eq!(hub.service().key_package_count(&device), batch);
        assert!(hub.service().has_last_resort_key_package(&device));
        let ledger = s.ledger(hub);
        assert_eq!(ledger.len(), batch + 1, "{}", Setup::hub_id(hub));
        assert_eq!(ledger.iter().filter(|r| r.last_resort).count(), 1);
    }
    let on_a = drain(&s.fake_a, &device);
    let on_b = drain(&s.fake_b, &device);
    assert_eq!((on_a.len(), on_b.len()), (batch, batch));
    assert!(on_a.is_disjoint(&on_b));
    // Each hub's last resort is its own.
    let last_resort = |hub: &FakeTransport| {
        let (claimed, _) = hub
            .service()
            .claim_key_packages(std::slice::from_ref(&device.user_id));
        claimed.into_iter().next().unwrap().key_package
    };
    assert_ne!(last_resort(&s.fake_a), last_resort(&s.fake_b));
    // Uploads went to the hub their ledger names, each package once.
    let uploaded = |hub: &Hub| -> Vec<Vec<u8>> {
        hub.uploads().into_iter().flat_map(|(kps, _)| kps).collect()
    };
    let (up_a, up_b) = (uploaded(&s.hub_a), uploaded(&s.hub_b));
    assert_eq!(up_b.len(), batch + 1);
    assert!(up_a.iter().all(|k| !up_b.contains(k)));
}

#[tokio::test]
async fn low_on_one_hub_replenishes_that_hub_only() {
    let s = Setup::new().await;
    let device = s.device();
    let batch = KEY_PACKAGE_BATCH as usize;
    for _ in 0..30 {
        s.fake_b
            .service()
            .claim_key_packages(std::slice::from_ref(&device.user_id));
    }
    let uploads_a = s.hub_a.uploads().len();
    s.alice
        .replenish_hub_key_packages(&Setup::hub_id(&s.fake_b))
        .await
        .unwrap();
    assert_eq!(
        s.fake_b.service().key_package_count(&device),
        batch - 30 + batch
    );
    assert_eq!(s.fake_a.service().key_package_count(&device), batch);
    assert_eq!(s.hub_a.uploads().len(), uploads_a);
    assert_eq!(s.ledger(&s.fake_b).len(), 2 * batch + 1);
    assert_eq!(s.ledger(&s.fake_a).len(), batch + 1);
}

#[tokio::test]
async fn key_packages_low_event_on_a_listed_hub_replenishes_that_hub_only() {
    let s = Setup::new().await;
    let device = s.device();
    let batch = KEY_PACKAGE_BATCH as usize;
    // Claims on B leave few packages there: B sends `keypackages.low`.
    let claimed = batch - 3;
    for _ in 0..claimed {
        s.fake_b
            .service()
            .claim_key_packages(std::slice::from_ref(&device.user_id));
    }
    let uploads_a = s.hub_a.uploads().len();
    let changes = s.alice.sync_once().await.unwrap();
    assert!(
        changes.contains(&StateChange::KeyPackagesLow),
        "{changes:?}"
    );
    assert_eq!(
        s.fake_b.service().key_package_count(&device),
        batch - claimed + batch
    );
    assert_eq!(s.fake_a.service().key_package_count(&device), batch);
    assert_eq!(s.hub_a.uploads().len(), uploads_a);
    assert_eq!(s.ledger(&s.fake_b).len(), 2 * batch + 1);
}

#[tokio::test]
async fn duplicate_key_package_answer_uploads_fresh_ones() {
    let s = Setup::new().await;
    let device = s.device();
    let batch = KEY_PACKAGE_BATCH as usize;
    s.hub_b.inject(
        Op::Upload,
        Fault::Fail(TransportError::Conflict(
            "duplicate_key_package: a KeyPackage was claimed through this hub".into(),
        )),
    );
    let before = s.hub_b.uploads().len();
    s.alice
        .replenish_hub_key_packages(&Setup::hub_id(&s.fake_b))
        .await
        .unwrap();
    let uploads = s.hub_b.uploads()[before..].to_vec();
    assert_eq!(uploads.len(), 2);
    let refused: BTreeSet<_> = uploads[0].0.iter().collect();
    let fresh: BTreeSet<_> = uploads[1].0.iter().collect();
    assert_eq!(fresh.len(), batch);
    assert!(refused.is_disjoint(&fresh));
    assert_eq!(s.fake_b.service().key_package_count(&device), 2 * batch);
    // Both batches stay recorded for B: the refused ones are never sent
    // anywhere again.
    assert_eq!(s.ledger(&s.fake_b).len(), 3 * batch + 1);
}

#[tokio::test]
async fn unreachable_primary_gets_identical_message_and_commit_resubmitted_to_the_next_hub() {
    let s = Setup::new().await;
    let g = s.direct_chat().await;
    let handshakes = server_handshakes(&FlakyTransport::over(s.fake_a.clone()), &g);

    // A applies the message but the response is lost: B gets the same
    // client_id and bytes, and the owner keeps one message.
    s.hub_a.inject(Op::Post, Fault::LoseResponse);
    let id = s.alice.send_text(&g, "fair winds", None).await.unwrap();
    let message = s.store.message(&id).unwrap().unwrap();
    assert_eq!(message.send_state, Some(SendState::Sent));
    let (on_a, on_b) = (s.hub_a.posts(), s.hub_b.posts());
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_a.last(), on_b.last());
    assert_eq!(on_b[0].0.as_str(), id.as_str());
    let delivered = server_messages(&FlakyTransport::over(s.fake_a.clone()), &g, &s.device());
    let copies = delivered
        .iter()
        .filter(|m| m.client_id.as_str() == id.as_str())
        .count();
    assert_eq!(copies, 1);

    // A is down: the next message goes to B directly after A's failure.
    s.hub_a.state.down.store(true, Ordering::SeqCst);
    let id = s.alice.send_text(&g, "reefing", None).await.unwrap();
    assert_eq!(
        s.store.message(&id).unwrap().unwrap().send_state,
        Some(SendState::Sent)
    );
    assert_eq!(s.hub_b.posts().len(), 2);
    s.hub_a.state.down.store(false, Ordering::SeqCst);

    // A sequences the Commit but the response is lost: B gets the same
    // bytes and the owner answers it as a duplicate.
    s.hub_a.inject(Op::Commit, Fault::LoseResponse);
    s.alice
        .remove_members(&g, std::slice::from_ref(&s.bob.user_id()))
        .await
        .unwrap();
    let (on_a, on_b) = (s.hub_a.commits(), s.hub_b.commits());
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_a.last(), on_b.last());
    assert_eq!(
        server_handshakes(&FlakyTransport::over(s.fake_a.clone()), &g),
        handshakes + 1
    );
    assert_eq!(s.members(&g), BTreeSet::from([s.device()]));
}

#[tokio::test]
async fn peer_unavailable_on_primary_is_retried_there_after_retry_after() {
    let s = Setup::new().await;
    let g = s.direct_chat().await;
    let commits_a = s.hub_a.commits().len();
    s.hub_a.inject(
        Op::Commit,
        Fault::Fail(TransportError::PeerUnavailable {
            retry_after_secs: Some(1),
            reason: "peer_unavailable".into(),
        }),
    );
    let started = Instant::now();
    s.alice
        .remove_members(&g, std::slice::from_ref(&s.bob.user_id()))
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(1));
    let on_a = &s.hub_a.commits()[commits_a..];
    assert_eq!(on_a.len(), 2);
    assert_eq!(on_a[0], on_a[1]);
    assert!(s.hub_b.commits().is_empty());
    assert_eq!(s.members(&g), BTreeSet::from([s.device()]));
}

#[tokio::test]
async fn definite_rejection_on_primary_never_fails_over() {
    let s = Setup::new().await;
    let g = s.direct_chat().await;
    s.hub_a
        .inject(Op::Post, Fault::Fail(rejected(403, "forbidden")));
    let id = s.alice.send_text(&g, "rejected", None).await.unwrap();
    assert_eq!(
        s.store.message(&id).unwrap().unwrap().send_state,
        Some(SendState::Failed)
    );
    s.hub_a
        .inject(Op::Commit, Fault::Fail(rejected(403, "forbidden")));
    let removed = s
        .alice
        .remove_members(&g, std::slice::from_ref(&s.bob.user_id()))
        .await;
    assert!(
        matches!(
            removed,
            Err(ClientError::Transport(TransportError::Rejected {
                status: 403,
                ..
            }))
        ),
        "{removed:?}"
    );
    assert!(s.hub_b.posts().is_empty());
    assert!(s.hub_b.commits().is_empty());
}

#[tokio::test]
async fn add_claimed_on_a_is_claimed_again_and_committed_on_b_when_a_goes_down() {
    let s = Setup::new().await;
    let carol = Device::register(&FlakyTransport::over(s.fake_a.clone()), "carol").await;
    let g = s
        .alice
        .create_group_chat(Some("Crew".into()), &[s.bob.user_id()])
        .await
        .unwrap();
    for hub in [&s.hub_a, &s.hub_b] {
        hub.state.enforce_claims.store(true, Ordering::SeqCst);
    }
    // Claims still work on A; then A cannot be reached for the Commit.
    s.hub_a.state.commits_down.store(true, Ordering::SeqCst);
    let (claims_a, claims_b) = (s.hub_a.claims().len(), s.hub_b.claims().len());
    s.alice
        .add_members(&g, std::slice::from_ref(&carol.user_id()))
        .await
        .unwrap();
    assert_eq!(s.hub_a.claims().len(), claims_a + 1);
    let claims_b = &s.hub_b.claims()[claims_b..];
    assert_eq!(claims_b.len(), 1);
    assert!(claims_b[0].contains(&carol.user_id()));
    // The first Commit went to A, then identically to B (refused: not
    // claimed there), on every attempt; the rebuilt one went to B only.
    let (on_a, on_b) = (s.hub_a.commits(), s.hub_b.commits());
    let (rebuilt, first) = on_b.split_last().unwrap();
    assert!(!first.is_empty());
    assert!(first.iter().all(|c| Some(c) == on_a.last()));
    assert_ne!(Some(rebuilt), on_a.last());
    assert!(s.members(&g).contains(&carol.device()));
}

#[tokio::test]
async fn kp_not_claimed_claims_again_and_rebuilds_the_commit() {
    let s = Setup::new().await;
    let carol = Device::register(&FlakyTransport::over(s.fake_a.clone()), "carol").await;
    let g = s
        .alice
        .create_group_chat(None, &[s.bob.user_id()])
        .await
        .unwrap();
    s.hub_b.state.enforce_claims.store(true, Ordering::SeqCst);
    s.hub_a.inject(
        Op::Commit,
        Fault::Fail(TransportError::Rejected {
            status: 400,
            code: "validation_failed".into(),
            message: "key package not claimed through this hub (kp_not_claimed)".into(),
        }),
    );
    let (commits_a, claims_a) = (s.hub_a.commits().len(), s.hub_a.claims().len());
    s.alice
        .add_members(&g, std::slice::from_ref(&carol.user_id()))
        .await
        .unwrap();
    // Claimed twice through A, the rebuilt Commit accepted there.
    assert_eq!(s.hub_a.claims().len(), claims_a + 2);
    let on_a = &s.hub_a.commits()[commits_a..];
    assert_eq!(on_a.len(), 2);
    assert_ne!(on_a[0], on_a[1]);
    assert!(s.members(&g).contains(&carol.device()));
}

/// Polls `done` until it holds, for up to 10 s.
async fn wait_for(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn texts(messages: &[gim_base::model::Message]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|m| match &m.content {
            gim_base::model::MessageContent::Text { body } => Some(body.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn added_hub_is_listed_signed_in_followed_and_shared_with_the_own_devices() {
    let s = Setup::build(Options {
        unlisted_b: true,
        ..Options::default()
    })
    .await;
    let tablet = s.link_tablet().await;
    let (a, b) = (Setup::hub_id(&s.fake_a), Setup::hub_id(&s.fake_b));
    let device = s.device();
    assert_eq!(s.alice.hubs().await.unwrap().len(), 1);

    let added = s.alice.add_hub(HUB_B_URL).await.unwrap();
    assert_eq!(added.hub.hub_id, b);
    assert_eq!(added.hub.url.as_deref(), Some(HUB_B_URL));
    assert_eq!(added.hub.state, gim_base::model::HubState::Verified);
    assert_eq!(added.hub.priority, 1);
    assert!(added.signed_in && !added.home);
    // B co-signed its entry; both hubs store the new record.
    let (seq, hubs) = s.stored_record(&s.fake_a);
    assert_eq!(hubs, [(a.clone(), 0), (b.clone(), 1)]);
    assert_eq!(s.stored_record(&s.fake_b), (seq, hubs));
    // This device's own KeyPackages and the recovery backup went to B.
    let batch = KEY_PACKAGE_BATCH as usize;
    assert_eq!(s.fake_b.service().key_package_count(&device), batch);
    assert!(s.fake_b.service().has_last_resort_key_package(&device));
    assert_eq!(s.ledger(&s.fake_b).len(), batch + 1);
    let backup = s.fake_a.recovery_backup(&device.user_id).await.unwrap();
    assert!(backup.is_some());
    assert_eq!(
        s.fake_b.recovery_backup(&device.user_id).await.unwrap(),
        backup
    );

    // Adding it again changes nothing.
    let uploads = s.hub_b.uploads().len();
    assert_eq!(s.alice.add_hub(HUB_B_URL).await.unwrap(), added);
    assert_eq!(s.stored_record(&s.fake_a).0, seq);
    assert_eq!(s.hub_b.uploads().len(), uploads);

    // The sync loop follows B.
    let fetches = s.hub_b.fetches();
    s.alice.start_sync().unwrap();
    wait_for("a fetch on B", || s.hub_b.fetches() > fetches).await;
    s.alice.stop_sync().unwrap();

    // The tablet learns B's URL through the self group, checks it with the
    // hub proof and uses B: signed in there, with its KeyPackages.
    tablet.client.sync_once().await.unwrap();
    let hubs = tablet.client.hubs().await.unwrap();
    let on_tablet = s.status(&hubs, &s.fake_b);
    assert_eq!(on_tablet.hub.url.as_deref(), Some(HUB_B_URL));
    assert!(on_tablet.hub.url_shared);
    assert_eq!(on_tablet.hub.state, gim_base::model::HubState::Verified);
    assert!(on_tablet.signed_in);
    let tablet_device = tablet.client.session().unwrap().device;
    assert_eq!(s.fake_b.service().key_package_count(&tablet_device), batch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hub_that_does_not_prove_the_entered_url_is_not_added() {
    let s = Setup::build(Options {
        unlisted_b: true,
        ..Options::default()
    })
    .await;
    let device = s.device();
    // B proves another URL than the one entered: a relay or a wrong URL.
    s.fake_b
        .set_public_url(Some("https://elsewhere.example.eu"));
    let result = s.alice.add_hub(HUB_B_URL).await;
    assert!(
        matches!(result, Err(ClientError::InvalidInput(_))),
        "{result:?}"
    );
    assert_eq!(s.alice.hubs().await.unwrap().len(), 1);
    assert_eq!(s.stored_record(&s.fake_a).1.len(), 1);
    // Nothing but the proof reached B: no DeviceList, sign-in or uploads.
    assert!(s.hub_b.uploads().is_empty());
    assert_eq!(s.fake_b.service().key_package_count(&device), 0);
    assert!(s.fake_b.service().device_list(&device.user_id).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_hub_owning_groups_needs_a_confirmation_then_it_is_no_longer_used() {
    let s = Setup::build(Options {
        owner_b: true,
        ..Options::default()
    })
    .await;
    let (a, b) = (Setup::hub_id(&s.fake_a), Setup::hub_id(&s.fake_b));
    let g = s.direct_chat().await;
    assert!(g.as_str().starts_with(&format!("{b}/")));
    let owned = {
        let mut groups: Vec<GroupId> = s
            .store
            .chats()
            .unwrap()
            .into_iter()
            .map(|c| c.group_id)
            .collect();
        groups.extend(s.store.self_groups().unwrap());
        groups
            .iter()
            .filter(|g| g.as_str().starts_with(&format!("{b}/")))
            .count() as u32
    };
    assert!(owned >= 1);
    let ledger = s.ledger(&s.fake_b);
    assert!(!ledger.is_empty());
    s.alice.start_sync().unwrap();
    let fetches = s.hub_b.fetches();
    wait_for("a fetch on B", || s.hub_b.fetches() > fetches).await;

    let refused = s.alice.remove_hub(&b, false).await;
    match refused {
        Err(ClientError::HubOwnsGroups {
            hub_id,
            group_count,
        }) => assert_eq!((hub_id, group_count), (b.clone(), owned)),
        other => panic!("{other:?}"),
    }
    let (seq, _) = s.stored_record(&s.fake_a);

    s.alice.remove_hub(&b, true).await.unwrap();
    let (removed_seq, hubs) = s.stored_record(&s.fake_a);
    assert_eq!((removed_seq, hubs.clone()), (seq + 1, vec![(a.clone(), 0)]));
    // B learns it too, so it stops hosting alice.
    assert_eq!(s.stored_record(&s.fake_b), (removed_seq, hubs));
    let status = s.status(&s.alice.hubs().await.unwrap(), &s.fake_b);
    assert_eq!(status.hub.state, gim_base::model::HubState::Removed);
    assert!(!status.signed_in);
    // B's KeyPackages stay recorded: never uploaded anywhere again.
    assert_eq!(s.ledger(&s.fake_b), ledger);
    // B's loop stopped.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let fetches = s.hub_b.fetches();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(s.hub_b.fetches(), fetches);

    // The group B owns is still reached, through A.
    let posts_b = s.hub_b.posts().len();
    let id = s.alice.send_text(&g, "via A", None).await.unwrap();
    assert_eq!(
        s.store.message(&id).unwrap().unwrap().send_state,
        Some(SendState::Sent)
    );
    assert_eq!(s.hub_b.posts().len(), posts_b);
    assert_eq!(
        s.hub_a.posts().last().map(|(c, _)| c.as_str().to_string()),
        Some(id.as_str().to_string())
    );
    s.alice.stop_sync().unwrap();
    s.bob.sync().await;
    assert_eq!(texts(&s.bob.messages(&g)), ["via A"]);
}

#[tokio::test]
async fn the_home_hub_and_the_only_listed_hub_are_never_removed() {
    let s = Setup::new().await;
    let (a, b) = (Setup::hub_id(&s.fake_a), Setup::hub_id(&s.fake_b));
    let home = s.alice.remove_hub(&a, true).await;
    assert!(
        matches!(&home, Err(ClientError::HomeHub(hub_id)) if *hub_id == a),
        "{home:?}"
    );
    let unknown = s.alice.remove_hub("hnotlisted", true).await;
    assert!(
        matches!(unknown, Err(ClientError::InvalidInput(_))),
        "{unknown:?}"
    );
    assert_eq!(s.stored_record(&s.fake_a).0, 2);

    // Another device dropped A from the record: B is the only hub left.
    let record = s.record(3, &[(&s.fake_b, 0)]);
    s.fake_a.set_hosting_record(&s.user_id(), Some(record));
    s.alice.refresh_hubs().await.unwrap();
    let last = s.alice.remove_hub(&b, true).await;
    assert!(
        matches!(&last, Err(ClientError::LastHub(hub_id)) if *hub_id == b),
        "{last:?}"
    );
    assert_eq!(s.stored_record(&s.fake_a).0, 3);
}

#[tokio::test]
async fn new_primary_hub_gets_the_submissions_first() {
    let s = Setup::new().await;
    let (a, b) = (Setup::hub_id(&s.fake_a), Setup::hub_id(&s.fake_b));
    let g = s.direct_chat().await;

    s.alice.set_primary_hub(&b).await.unwrap();
    let (seq, hubs) = s.stored_record(&s.fake_a);
    assert_eq!(hubs, [(b.clone(), 0), (a.clone(), 1)]);
    let order: Vec<(String, u8)> = s
        .alice
        .hubs()
        .await
        .unwrap()
        .into_iter()
        .map(|h| (h.hub.hub_id, h.hub.priority))
        .collect();
    assert_eq!(order, hubs);

    let (posts_a, posts_b) = (s.hub_a.posts().len(), s.hub_b.posts().len());
    let id = s.alice.send_text(&g, "primary B", None).await.unwrap();
    assert_eq!(
        s.store.message(&id).unwrap().unwrap().send_state,
        Some(SendState::Sent)
    );
    assert_eq!(s.hub_a.posts().len(), posts_a);
    let on_b = &s.hub_b.posts()[posts_b..];
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_b[0].0.as_str(), id.as_str());

    // Already primary: nothing to publish.
    s.alice.set_primary_hub(&b).await.unwrap();
    assert_eq!(s.stored_record(&s.fake_a).0, seq);
    let unknown = s.alice.set_primary_hub("hnotlisted").await;
    assert!(
        matches!(unknown, Err(ClientError::InvalidInput(_))),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn restore_reads_the_hub_list_and_shares_the_hub_map_with_the_devices_linked_next() {
    let s = Setup::new().await;
    let user_id = s.user_id();
    let mut hub_a = s.hub_a.clone();
    hub_a.url = Some("https://hub-a.test".into());
    let restored = s.client(hub_a);
    restored
        .client
        .restore_from_recovery(&user_id, &s.recovery_code, false)
        .await
        .unwrap();

    // The hub list comes from the record, which still lists both hubs.
    let hubs = restored.client.hubs().await.unwrap();
    let a = s.status(&hubs, &s.fake_a);
    assert!(a.home && a.signed_in);
    assert_eq!(a.hub.url.as_deref(), Some("https://hub-a.test"));
    let b = s.status(&hubs, &s.fake_b);
    assert_eq!(b.hub.priority, 1);
    assert_eq!(b.hub.state, gim_base::model::HubState::Unverified);
    assert_eq!(s.stored_record(&s.fake_a).1.len(), 2);

    // B's URL entered on the restored device reaches a device linked from
    // it through the new self group.
    restored
        .client
        .set_hub_url(&Setup::hub_id(&s.fake_b), HUB_B_URL)
        .await
        .unwrap();
    let tablet = s.client(s.hub_a.clone());
    let session = tablet.client.start_link(vec!["hub-a.test".into()]).unwrap();
    let approval = restored
        .client
        .approve_link(&session.qr_string)
        .await
        .unwrap();
    tablet.client.wait_link(&session).await.unwrap();
    tablet.client.confirm_link(true).await.unwrap();
    restored
        .client
        .confirm_approval(&approval, true)
        .await
        .unwrap();
    tablet.client.sync_once().await.unwrap();
    let on_tablet = s.status(&tablet.client.hubs().await.unwrap(), &s.fake_b);
    assert_eq!(on_tablet.hub.url.as_deref(), Some(HUB_B_URL));
    assert!(on_tablet.hub.url_shared);
}

#[tokio::test]
async fn device_lists_and_the_directory_are_read_from_the_other_hub_while_home_is_down() {
    let s = Setup::new().await;
    let carol = Device::register(&FlakyTransport::over(s.fake_a.clone()), "carol").await;
    let g = s
        .alice
        .create_group_chat(Some("Crew".into()), &[s.bob.user_id()])
        .await
        .unwrap();
    // A definite answer of the home hub is final.
    let unknown = RootKey::from_seed(&[9; 32]).public().user_id();
    let reads_b = s.hub_b.reads().len();
    assert!(s.alice.user_devices(&unknown).await.unwrap().is_empty());
    assert_eq!(s.hub_b.reads().len(), reads_b);

    s.hub_a.state.down.store(true, Ordering::SeqCst);
    let devices = s.alice.user_devices(&carol.user_id()).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert!(s.hub_b.reads().contains(&("device_list", carol.user_id())));
    // Adding carol resolves her profile in the directory, through B.
    s.alice
        .add_members(&g, std::slice::from_ref(&carol.user_id()))
        .await
        .unwrap();
    assert!(s.hub_b.reads().contains(&("user", carol.user_id())));
    assert!(s.store.user(&carol.user_id()).unwrap().is_some());
    assert!(s.members(&g).contains(&carol.device()));
}
