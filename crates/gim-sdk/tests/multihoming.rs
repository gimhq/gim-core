//! Submission and KeyPackages across two listed hubs (contract
//! `multihoming.md` §5.1, §5.4, §6.1): Commits and messages go to the
//! primary hub and, when it cannot be reached, identically to the next one;
//! peer failures and definite rejections never switch hubs; every hub gets
//! its own disjoint KeyPackages; an Add is claimed and committed through
//! one hub.
//!
//! Hub A owns the groups. Hub B is a co-host: it keeps its own users,
//! sessions and KeyPackages, claims the packages of users it does not host
//! from A, enforces the claim ledger for Adds (`kp_not_claimed`) and
//! forwards group requests to A, which dedups them as an owner does.

mod common;

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use common::{server_handshakes, server_messages, Device, FlakyTransport};
use gim_base::model::{ChatKind, GroupMessage, KeyPackageRecord, SendState};
use gim_base::{MemoryStore, StateReader};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, UserId};
use gim_identity::{HostingEntry, RootKey, UserHostingRecord};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{
    AccessToken, Challenge, ClaimedKeyPackage, CommitAccepted, EventBatch, GroupInfo,
    HostingEntryGrant, HubIdentity, KeyPackageClaim, KeyPackageCount, OutgoingCommit, PostError,
    SessionError, SessionToken, StoredHostingRecord, Transport, TransportError, TransportResult,
    UserRecord,
};
use gim_sdk::{
    Client, ClientBuilder, ClientError, HubConnector, SecretStorage, HOSTING_RECORD_LIFETIME,
    KEY_PACKAGE_BATCH, ROOT_KEY_SECRET_KEY,
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
}

impl Hub {
    fn new(own: &FakeTransport, owner: &FakeTransport) -> Self {
        Self {
            own: own.clone(),
            owner: owner.clone(),
            state: Arc::default(),
        }
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
    async fn hub_info(&self) -> TransportResult<HubIdentity> {
        self.up()?;
        self.own.hub_info().await
    }

    async fn put_device_list(&self, u: &UserId, list: Vec<u8>) -> TransportResult<()> {
        self.up()?;
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
        self.owner.device_list(t, u).await
    }

    async fn user(
        &self,
        t: Option<&AccessToken>,
        u: &UserId,
    ) -> TransportResult<Option<UserRecord>> {
        self.up()?;
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
        self.owner
            .fetch_events(&self.owner_token(t)?, cursor, wait)
            .await
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

/// Alice, listing hub A (primary, her home hub) and hub B, with bob (and
/// carol) on A only.
struct Setup {
    fake_a: FakeTransport,
    fake_b: FakeTransport,
    /// Alice's view of each hub.
    hub_a: Hub,
    hub_b: Hub,
    alice: Client<MemoryStore>,
    store: Arc<MemoryStore>,
    bob: Device,
    _data_dir: TempDir,
}

impl Setup {
    async fn new() -> Self {
        let fake_a = FakeTransport::new();
        let fake_b = FakeTransport::with_hub_seed(SEED_B);
        let hub_a = Hub::new(&fake_a, &fake_a);
        let hub_b = Hub::new(&fake_b, &fake_a);
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
        .hub_connector(connector)
        .build()
        .unwrap();
        alice.register("alice", "Alice").await.unwrap();
        let user_id = alice.session().unwrap().device.user_id;
        // The add-hub procedure: the DeviceList and a record listing B.
        let list = fake_a.service().device_list(&user_id).unwrap();
        fake_b.put_device_list(&user_id, list).await.unwrap();
        let seed = secrets.get(ROOT_KEY_SECRET_KEY).unwrap().unwrap();
        let root = RootKey::from_seed(&seed.try_into().unwrap());
        let entries = [(&fake_a, 0), (&fake_b, 1)]
            .iter()
            .map(|(hub, priority)| HostingEntry::sign(hub.hub_root_key(), &user_id, *priority))
            .collect();
        let expires_at = now_ms() + HOSTING_RECORD_LIFETIME.as_millis() as u64;
        let record = UserHostingRecord::new(root.public(), 2, expires_at, entries)
            .and_then(|record| record.sign(&root))
            .unwrap()
            .to_bytes();
        fake_a.set_hosting_record(&user_id, Some(record));
        alice.refresh_hubs().await.unwrap();
        alice
            .set_hub_url(fake_b.service().hub_id(), HUB_B_URL)
            .await
            .unwrap();
        let bob = Device::register(&FlakyTransport::over(fake_a.clone()), "bob").await;
        Self {
            fake_a,
            fake_b,
            hub_a,
            hub_b,
            alice,
            store,
            bob,
            _data_dir: data_dir,
        }
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
