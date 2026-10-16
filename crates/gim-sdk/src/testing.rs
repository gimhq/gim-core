//! Test doubles: [`FakeTransport`] over gim-test's in-memory hub, and
//! [`MemorySecretStorage`].

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, MessageKind};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, UserId};
use gim_crypto::{inspect_handshake, private_message_epoch, HandshakeKind, MlsEngine};
use gim_identity::{
    AuthChallenge, AuthResponse, HostingEntry, HubRootKey, IdentityError, SignedDeviceList,
    SignedHostingRecord, UserHostingRecord,
};
use gim_test::{
    Delivered, DeliveryError, Event, FakeDeliveryService, GroupKind, MembershipChange,
    SubmitCommit, Welcome,
};

use crate::transport::{
    AccessToken, Challenge, ClaimedKeyPackage, CommitAccepted, EventBatch, GroupInfo,
    HostingEntryGrant, HubEvent, HubIdentity, KeyPackageCount, OutgoingCommit, PostError,
    SessionError, SessionToken, StoredHostingRecord, Transport, TransportError, TransportResult,
    UserRecord,
};
use crate::{SecretStorage, SecretStorageError};

/// Events returned per [`Transport::fetch_events`] call.
const EVENTS_PER_FETCH: usize = 100;
/// Lifetime of challenges, as on the hub.
const CHALLENGE_LIFETIME_MS: u64 = 5 * 60_000;
/// Lifetime of session tokens: the hub default `GIM_HUB_SESSION_TTL_DAYS`.
const SESSION_LIFETIME_MS: u64 = 30 * 24 * 3_600_000;
/// Largest application message, as on the hub (default).
const MESSAGE_LIMIT_BYTES: usize = 262_144;
/// Accepted hosting record lifetimes (`expires_at - now`), as on the hub.
const HOSTING_RECORD_LIFETIMES_MS: std::ops::RangeInclusive<u64> = 3_600_000..=30 * 24 * 3_600_000;
/// Seed of the fake hub's root key.
const HUB_ROOT_SEED: [u8; 32] = [0x68; 32];

/// A [`Transport`] over a shared [`FakeDeliveryService`]. Cloning shares the
/// service, so several clients can talk to the same fake hub. It verifies
/// DeviceLists and AuthResponses with gim-identity and reads epochs and
/// membership changes from the MLS framing, as the hub does, including
/// those of Proposals a Commit references.
#[derive(Debug, Clone)]
pub struct FakeTransport {
    service: Arc<FakeDeliveryService>,
    challenges: Arc<AtomicU64>,
    /// Validates uploaded KeyPackages against the stored DeviceLists.
    validator: Arc<MlsEngine>,
    proposals: Arc<Mutex<HashMap<GroupId, Proposals>>>,
    hosting: Arc<FakeHosting>,
}

/// Hosting records of the fake hub.
#[derive(Debug)]
struct FakeHosting {
    hub_key: HubRootKey,
    /// Signed records; kept after they expire, as on the hub.
    records: Mutex<HashMap<UserId, Vec<u8>>>,
    reads: AtomicUsize,
    /// Commits and messages need a valid record listing this hub.
    required: AtomicBool,
}

/// The Proposals sequenced in a group's current epoch, by `ProposalRef`.
#[derive(Debug, Default)]
struct Proposals {
    epoch: u64,
    by_ref: HashMap<Vec<u8>, SequencedProposal>,
}

#[derive(Debug, Clone)]
struct SequencedProposal {
    seq: u64,
    added: Vec<DeviceRef>,
    removed_leaves: Vec<u32>,
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTransport {
    pub fn new() -> Self {
        Self::with_hub_seed(HUB_ROOT_SEED)
    }

    /// Another fake hub: its root key comes from `seed` and its `hub_id`
    /// derives from that key.
    pub fn with_hub_seed(seed: [u8; 32]) -> Self {
        let hub_key = HubRootKey::from_seed(&seed);
        let service = Arc::new(FakeDeliveryService::with_hub_id(hub_key.public().hub_id()));
        let lists = service.clone();
        let stored_list = move |user_id: &UserId| {
            let bytes = lists.device_list(user_id)?;
            SignedDeviceList::from_bytes(&bytes)
                .and_then(|signed| signed.verify(user_id))
                .ok()
        };
        Self {
            service,
            challenges: Arc::default(),
            validator: Arc::new(MlsEngine::with_device_list_lookup(Arc::new(stored_list))),
            proposals: Arc::default(),
            hosting: Arc::new(FakeHosting {
                hub_key,
                records: Mutex::default(),
                reads: AtomicUsize::new(0),
                required: AtomicBool::new(false),
            }),
        }
    }

    /// The root key the fake hub signs hosting entries with.
    pub fn hub_root_key(&self) -> &HubRootKey {
        &self.hosting.hub_key
    }

    /// The user's stored hosting record, expired or not.
    pub fn stored_hosting_record(&self, user_id: &UserId) -> Option<Vec<u8>> {
        self.hosting_records().get(user_id).cloned()
    }

    /// Replaces (or with `None` deletes) the user's stored hosting record,
    /// without the hub's checks.
    pub fn set_hosting_record(&self, user_id: &UserId, record: Option<Vec<u8>>) {
        let mut records = self.hosting_records();
        match record {
            Some(record) => records.insert(user_id.clone(), record),
            None => records.remove(user_id),
        };
    }

    /// `GET .../hosting-record` requests served so far.
    pub fn hosting_record_reads(&self) -> usize {
        self.hosting.reads.load(Ordering::SeqCst)
    }

    /// With `required`, commits and application messages fail with 403
    /// `hosting_record_required` unless the sender's user has a valid
    /// hosting record listing this hub, as for federated requests.
    pub fn require_hosting_records(&self, required: bool) {
        self.hosting.required.store(required, Ordering::SeqCst);
    }

    fn hosting_records(&self) -> MutexGuard<'_, HashMap<UserId, Vec<u8>>> {
        self.hosting
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The user's stored record if it is still valid at `now`.
    fn valid_hosting_record(&self, user_id: &UserId, now: u64) -> Option<UserHostingRecord> {
        let bytes = self.stored_hosting_record(user_id)?;
        SignedHostingRecord::from_bytes(&bytes)
            .and_then(|signed| signed.verify(now))
            .ok()
    }

    fn check_hosting_record(&self, user_id: &UserId) -> Result<(), PostError> {
        if !self.hosting.required.load(Ordering::SeqCst) {
            return Ok(());
        }
        let hub = self.hosting.hub_key.public();
        match self.valid_hosting_record(user_id, now_ms()) {
            Some(record)
                if record
                    .hubs()
                    .iter()
                    .any(|e| *e.hub_root_public_key() == hub) =>
            {
                Ok(())
            }
            _ => {
                Err(TransportError::HostingRecordRequired("hosting_record_required".into()).into())
            }
        }
    }

    fn stored(&self, bytes: Vec<u8>, record: &UserHostingRecord) -> StoredHostingRecord {
        let hub = self.hosting.hub_key.public();
        StoredHostingRecord {
            record: bytes,
            seq: record.seq(),
            expires_at_ms: record.expires_at(),
            hosted: record
                .hubs()
                .iter()
                .any(|e| *e.hub_root_public_key() == hub),
        }
    }

    /// The fake hub, for assertions and hub-side actions in tests.
    pub fn service(&self) -> &FakeDeliveryService {
        &self.service
    }

    fn device(&self, token: &AccessToken) -> TransportResult<DeviceRef> {
        Ok(self.service.authenticate(token.as_str())?)
    }

    fn member(&self, token: &AccessToken, group_id: &GroupId) -> TransportResult<DeviceRef> {
        let device = self.device(token)?;
        if !self.service.group(group_id)?.members.contains(&device) {
            return Err(DeliveryError::NotAMember(device).into());
        }
        Ok(device)
    }
}

impl From<DeliveryError> for TransportError {
    fn from(err: DeliveryError) -> Self {
        match err {
            DeliveryError::Unauthorized => Self::Unauthorized,
            DeliveryError::UnknownGroup(_)
            | DeliveryError::UnknownUser(_)
            | DeliveryError::UnknownBlob(_) => Self::NotFound(err.to_string()),
            DeliveryError::StaleEpoch { .. }
            | DeliveryError::StaleDeviceList
            | DeliveryError::HandleTaken(_)
            | DeliveryError::LinkIdTaken(_)
            | DeliveryError::GroupExists(_) => Self::Conflict(err.to_string()),
            DeliveryError::ValidationFailed(_) => rejected(400, "validation_failed", err),
            DeliveryError::NotAMember(_) => rejected(403, "not_member", err),
            DeliveryError::InvalidRange { .. } => rejected(416, "range_not_satisfiable", err),
        }
    }
}

impl From<DeliveryError> for PostError {
    fn from(err: DeliveryError) -> Self {
        match err {
            DeliveryError::StaleEpoch { current_epoch, .. } => Self::StaleEpoch { current_epoch },
            err => Self::Transport(err.into()),
        }
    }
}

/// A definite 4xx, as the HTTP transport maps it.
fn rejected(status: u16, code: &str, message: impl std::fmt::Display) -> TransportError {
    TransportError::Rejected {
        status,
        code: code.into(),
        message: message.to_string(),
    }
}

fn invalid(reason: impl std::fmt::Display) -> TransportError {
    rejected(400, "validation_failed", reason)
}

fn to_group_info(info: gim_test::GroupInfo) -> GroupInfo {
    GroupInfo {
        group_id: info.group_id,
        kind: match info.kind {
            GroupKind::Direct => ChatKind::Direct,
            GroupKind::Group => ChatKind::Group,
        },
        epoch: info.epoch,
        last_seq: info.last_seq,
        members: info.members,
    }
}

fn to_message(delivered: Delivered) -> GroupMessage {
    GroupMessage {
        group_id: delivered.group_id,
        seq: delivered.seq,
        sender: delivered.sender,
        kind: match delivered.kind {
            gim_test::MessageKind::Commit => MessageKind::Commit,
            gim_test::MessageKind::Application => MessageKind::Application,
        },
        payload: delivered.payload,
        client_id: Some(delivered.client_id),
    }
}

/// A Welcome as gim-base takes it: a message at the seq of its Commit.
pub fn welcome_message(welcome: Welcome) -> GroupMessage {
    GroupMessage {
        group_id: welcome.group_id,
        seq: welcome.seq,
        sender: welcome.sender,
        kind: MessageKind::Welcome,
        payload: welcome.welcome,
        client_id: None,
    }
}

fn membership(
    change: MembershipChange,
    event: impl Fn(GroupId, DeviceRef) -> IncomingEvent,
) -> Vec<HubEvent> {
    change
        .device_ids
        .into_iter()
        .map(|device_id| {
            let device = DeviceRef::new(change.user_id.clone(), device_id);
            HubEvent::Group(event(change.group_id.clone(), device))
        })
        .collect()
}

/// The [`HubEvent`]s of a fake hub event.
pub fn hub_events(event: Event) -> Vec<HubEvent> {
    match event {
        Event::Message(delivered) => vec![HubEvent::Group(IncomingEvent::Message(to_message(
            delivered,
        )))],
        Event::MemberAdded(change) => membership(change, |group_id, device| {
            IncomingEvent::MemberAdded { group_id, device }
        }),
        Event::MemberRemoved(change) => membership(change, |group_id, device| {
            IncomingEvent::MemberRemoved { group_id, device }
        }),
        Event::Welcome(welcome) => vec![HubEvent::Group(IncomingEvent::Message(welcome_message(
            welcome,
        )))],
        Event::KeyPackagesLow { .. } => vec![HubEvent::Group(IncomingEvent::KeyPackagesLow)],
        Event::DeviceListUpdated {
            user_id,
            device_list,
        } => vec![HubEvent::DeviceListUpdated {
            user_id,
            device_list,
        }],
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn hub_info(&self) -> TransportResult<HubIdentity> {
        Ok(HubIdentity {
            hub_id: self.service.hub_id().to_string(),
            hub_root_public_key: self.hosting.hub_key.public().as_bytes().to_vec(),
            version: "fake".into(),
        })
    }

    async fn put_device_list(&self, user_id: &UserId, device_list: Vec<u8>) -> TransportResult<()> {
        let list = SignedDeviceList::from_bytes(&device_list)
            .and_then(|signed| signed.verify(user_id))
            .map_err(invalid)?;
        let active = list.certs().map(|c| c.device_id.clone()).collect();
        self.service
            .put_device_list(user_id, list.seq(), device_list, active)?;
        Ok(())
    }

    async fn auth_challenge(&self, device: &DeviceRef) -> TransportResult<Challenge> {
        if !self.service.devices(&device.user_id)?.contains(device) {
            return Err(TransportError::NotFound(format!("{device} is not active")));
        }
        let mut nonce = [0u8; 32];
        let n = self.challenges.fetch_add(1, Ordering::SeqCst);
        nonce[..8].copy_from_slice(&n.to_be_bytes());
        let issued_at = now_ms();
        let challenge = AuthChallenge {
            audience: self.service.hub_id().to_string(),
            nonce,
            issued_at,
            expires_at: issued_at + CHALLENGE_LIFETIME_MS,
        }
        .to_bytes();
        self.service.issue_challenge(challenge.clone(), device);
        Ok(Challenge {
            challenge,
            hub_id: self.service.hub_id().to_string(),
        })
    }

    /// Verifies the response like the hub: each challenge once, for the
    /// device it was issued to, with the hub's error codes.
    async fn create_session(&self, response: Vec<u8>) -> Result<SessionToken, SessionError> {
        let response = AuthResponse::from_bytes(&response).map_err(invalid)?;
        let claimed = DeviceRef::new(response.user_id().clone(), response.device_id().clone());
        if !self
            .service
            .redeem_challenge(response.challenge(), &claimed)
        {
            return Err(SessionError::InvalidChallenge);
        }
        let not_active = || SessionError::Rejected("device_not_active".into());
        let list = self
            .service
            .device_list(response.user_id())
            .and_then(|bytes| SignedDeviceList::from_bytes(&bytes).ok())
            .ok_or_else(not_active)?;
        let device = response
            .verify(self.service.hub_id(), now_ms(), &list)
            .map_err(|err| match err {
                IdentityError::Revoked(_) | IdentityError::UnknownDevice(_) => not_active(),
                IdentityError::BadSignature => SessionError::Rejected("invalid_signature".into()),
                _ => SessionError::InvalidChallenge,
            })?;
        Ok(SessionToken {
            token: AccessToken::new(
                self.service
                    .create_session(&device)
                    .map_err(TransportError::from)?,
            ),
            expires_at_ms: now_ms() + SESSION_LIFETIME_MS,
        })
    }

    async fn put_recovery_backup(
        &self,
        token: &AccessToken,
        user_id: &UserId,
        backup: Vec<u8>,
    ) -> TransportResult<()> {
        let device = self.device(token)?;
        if &device.user_id != user_id {
            return Err(rejected(403, "forbidden", "forbidden"));
        }
        Ok(self.service.put_recovery_backup(user_id, backup)?)
    }

    async fn recovery_backup(&self, user_id: &UserId) -> TransportResult<Option<Vec<u8>>> {
        Ok(self.service.recovery_backup(user_id))
    }

    async fn post_link_bundle(
        &self,
        token: &AccessToken,
        link_id: &str,
        sealed_bundle: Vec<u8>,
        _expires_in: Duration,
    ) -> TransportResult<()> {
        self.device(token)?;
        Ok(self.service.post_link_bundle(link_id, sealed_bundle)?)
    }

    /// Never waits: the fake hub is synchronous.
    async fn fetch_link_bundle(
        &self,
        link_id: &str,
        _wait: Duration,
    ) -> TransportResult<Option<Vec<u8>>> {
        Ok(self.service.take_link_bundle(link_id))
    }

    /// A public read: the token is ignored, as on the hub.
    async fn device_list(
        &self,
        _token: Option<&AccessToken>,
        user_id: &UserId,
    ) -> TransportResult<Option<Vec<u8>>> {
        Ok(self.service.device_list(user_id))
    }

    /// A public read: the token is ignored, as on the hub.
    async fn user(
        &self,
        _token: Option<&AccessToken>,
        user_id: &UserId,
    ) -> TransportResult<Option<UserRecord>> {
        Ok(self.service.user(user_id).map(|user| UserRecord {
            user_id: user.user_id,
            device_list: user.device_list,
            handle: user.handle,
            display_name: user.display_name,
        }))
    }

    async fn find_handle(
        &self,
        token: &AccessToken,
        handle: &str,
    ) -> TransportResult<Option<UserId>> {
        self.device(token)?;
        Ok(self.service.find_handle(handle))
    }

    async fn claim_handle(&self, token: &AccessToken, handle: &str) -> TransportResult<()> {
        let device = self.device(token)?;
        Ok(self.service.claim_handle(&device.user_id, handle)?)
    }

    async fn release_handle(&self, token: &AccessToken, handle: &str) -> TransportResult<()> {
        let device = self.device(token)?;
        self.service.release_handle(&device.user_id, handle);
        Ok(())
    }

    async fn publish_display_name(&self, token: &AccessToken, name: &str) -> TransportResult<()> {
        let device = self.device(token)?;
        Ok(self.service.set_display_name(&device.user_id, name)?)
    }

    async fn upload_key_packages(
        &self,
        token: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: bool,
    ) -> TransportResult<()> {
        let device = self.device(token)?;
        if last_resort && key_packages.len() != 1 {
            return Err(invalid("one last-resort KeyPackage expected"));
        }
        // Each leaf must carry the uploading device's credential (fail
        // closed); one bad package rejects the upload.
        for key_package in &key_packages {
            match self.validator.key_package_device(key_package) {
                Ok(certified) if certified == device => {}
                Ok(_) => return Err(invalid("invalid MLS credential (identity_mismatch)")),
                Err(err) => return Err(invalid(format!("invalid MLS credential ({err})"))),
            }
        }
        self.service
            .upload_key_packages(&device, key_packages, last_resort);
        Ok(())
    }

    async fn key_package_count(&self, token: &AccessToken) -> TransportResult<KeyPackageCount> {
        let device = self.device(token)?;
        Ok(KeyPackageCount {
            available: self.service.key_package_count(&device) as u64,
            has_last_resort: self.service.has_last_resort_key_package(&device),
        })
    }

    async fn claim_key_packages(
        &self,
        token: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<Vec<ClaimedKeyPackage>> {
        self.device(token)?;
        Ok(self
            .service
            .claim_key_packages(users)
            .0
            .into_iter()
            .map(|claimed| ClaimedKeyPackage {
                device: claimed.device,
                key_package: claimed.key_package,
            })
            .collect())
    }

    async fn create_group(&self, token: &AccessToken, kind: ChatKind) -> TransportResult<GroupId> {
        let creator = self.device(token)?;
        let kind = match kind {
            ChatKind::Direct => GroupKind::Direct,
            ChatKind::Group => GroupKind::Group,
        };
        Ok(self.service.create_group_with(kind, &creator)?)
    }

    async fn group_info(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
    ) -> TransportResult<GroupInfo> {
        self.member(token, group_id)?;
        Ok(to_group_info(self.service.group(group_id)?))
    }

    async fn list_groups(&self, token: &AccessToken) -> TransportResult<Vec<GroupInfo>> {
        let device = self.device(token)?;
        Ok(self
            .service
            .groups_of(&device)
            .into_iter()
            .map(to_group_info)
            .collect())
    }

    async fn submit_commit(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        commit: OutgoingCommit,
    ) -> Result<CommitAccepted, PostError> {
        let sender = self.device(token)?;
        self.check_hosting_record(&sender.user_id)?;
        let mut info = inspect_handshake(&commit.mls_message).map_err(invalid)?;
        if info.group_id != group_id.as_str().as_bytes() {
            return Err(invalid("the message is for another group").into());
        }
        let epoch = self.service.epoch(group_id)?;
        let mut proposals = self.proposals.lock().unwrap_or_else(|e| e.into_inner());
        let pending = proposals.entry(group_id.clone()).or_default();
        if pending.epoch != epoch {
            *pending = Proposals {
                epoch,
                by_ref: HashMap::new(),
            };
        }
        let proposal_ref = info.proposal_ref.clone();
        if let Some(sequenced) = proposal_ref.as_ref().and_then(|r| pending.by_ref.get(r)) {
            return Ok(CommitAccepted {
                seq: sequenced.seq,
                epoch,
                duplicate: true,
            });
        }
        // A Commit of the current epoch takes the membership changes of the
        // Proposals it references; others are duplicates or stale.
        if info.kind == HandshakeKind::Commit && info.epoch == epoch {
            for reference in &info.references {
                let Some(sequenced) = pending.by_ref.get(reference) else {
                    return Err(invalid("unknown proposal reference").into());
                };
                info.added.extend(sequenced.added.iter().cloned());
                info.removed_leaves
                    .extend(sequenced.removed_leaves.iter().copied());
            }
        }
        let (added, removed_leaves) = (info.added.clone(), info.removed_leaves.clone());
        let result = self.service.submit_commit(
            group_id,
            &sender,
            SubmitCommit {
                client_id: commit.client_id,
                mls_message: commit.mls_message,
                epoch: info.epoch,
                proposal: info.kind == HandshakeKind::Proposal,
                added: info.added,
                removed_leaves: info.removed_leaves,
                welcome: commit.welcome,
                welcome_recipients: commit.welcome_recipients,
            },
        )?;
        if let (Some(proposal_ref), false) = (proposal_ref, result.duplicate) {
            pending.by_ref.insert(
                proposal_ref,
                SequencedProposal {
                    seq: result.seq,
                    added,
                    removed_leaves,
                },
            );
        }
        Ok(CommitAccepted {
            seq: result.seq,
            epoch: result.epoch,
            duplicate: result.duplicate,
        })
    }

    async fn post_message(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        client_id: ClientId,
        mls_message: Vec<u8>,
    ) -> Result<u64, PostError> {
        let sender = self.device(token)?;
        self.check_hosting_record(&sender.user_id)?;
        if mls_message.len() > MESSAGE_LIMIT_BYTES {
            return Err(TransportError::TooLarge("payload_too_large".into()).into());
        }
        let epoch = private_message_epoch(&mls_message).map_err(invalid)?;
        Ok(self
            .service
            .post_message(group_id, &sender, client_id, epoch, mls_message)?)
    }

    async fn create_hosting_entry(
        &self,
        token: &AccessToken,
        user_id: &UserId,
        priority: u8,
    ) -> TransportResult<HostingEntryGrant> {
        if &self.device(token)?.user_id != user_id {
            return Err(rejected(403, "forbidden", "forbidden"));
        }
        let hub = &self.hosting.hub_key;
        Ok(HostingEntryGrant {
            hub_id: hub.public().hub_id(),
            hub_root_public_key: hub.public().as_bytes().to_vec(),
            priority,
            entry: HostingEntry::sign(hub, user_id, priority).to_bytes(),
        })
    }

    /// Checks the record like the hub: it verifies for `user_id`, its
    /// lifetime is in range, and it supersedes the stored one (409
    /// otherwise; the same record again is a no-op).
    async fn put_hosting_record(
        &self,
        user_id: &UserId,
        bytes: Vec<u8>,
    ) -> TransportResult<StoredHostingRecord> {
        let invalid_record =
            |reason: String| rejected(400, gim_proto::v2::INVALID_HOSTING_RECORD, reason);
        let now = now_ms();
        let record = SignedHostingRecord::from_bytes(&bytes)
            .and_then(|signed| signed.verify(now))
            .map_err(|e| invalid_record(e.to_string()))?;
        if record.user_id() != user_id {
            return Err(invalid_record("user_id_mismatch".into()));
        }
        if !HOSTING_RECORD_LIFETIMES_MS.contains(&(record.expires_at() - now)) {
            return Err(invalid_record("lifetime_out_of_range".into()));
        }
        let mut records = self.hosting_records();
        // Stored records were verified on insert; they may have expired.
        let stored = records.get(user_id).and_then(|stored| {
            SignedHostingRecord::from_bytes(stored)
                .and_then(|signed| signed.verify(0))
                .ok()
                .map(|record| (stored.clone(), record))
        });
        if let Some((stored_bytes, stored)) = stored {
            match record.supersedes(&stored) {
                Ok(true) => {}
                Ok(false) => return Ok(self.stored(stored_bytes, &stored)),
                Err(err) => {
                    return Err(TransportError::Conflict(format!(
                        "stale_hosting_record: {err}"
                    )))
                }
            }
        }
        records.insert(user_id.clone(), bytes.clone());
        Ok(self.stored(bytes, &record))
    }

    async fn hosting_record(
        &self,
        user_id: &UserId,
    ) -> TransportResult<Option<StoredHostingRecord>> {
        self.hosting.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = self.stored_hosting_record(user_id);
        Ok(bytes.and_then(|bytes| {
            let record = self.valid_hosting_record(user_id, now_ms())?;
            Some(self.stored(bytes, &record))
        }))
    }

    /// Never waits: the fake hub is synchronous.
    async fn fetch_events(
        &self,
        token: &AccessToken,
        cursor: Option<u64>,
        _wait: Duration,
    ) -> TransportResult<EventBatch> {
        let device = self.device(token)?;
        let (events, next_cursor) =
            self.service
                .events(&device, cursor.unwrap_or(0), EVENTS_PER_FETCH);
        Ok(EventBatch {
            events: events
                .into_iter()
                .flat_map(|e| hub_events(e.event))
                .collect(),
            next_cursor,
        })
    }

    async fn pending_welcomes(
        &self,
        token: &AccessToken,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        let device = self.device(token)?;
        Ok(self
            .service
            .pending_welcomes(&device, limit as usize)
            .into_iter()
            .map(welcome_message)
            .collect())
    }

    async fn ack_welcome(&self, token: &AccessToken, group_id: &GroupId) -> TransportResult<()> {
        let device = self.device(token)?;
        self.service.ack_welcome(&device, group_id);
        Ok(())
    }

    async fn group_messages(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        from_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        self.member(token, group_id)?;
        Ok(self
            .service
            .messages(group_id, from_seq.saturating_sub(1), limit as usize)?
            .into_iter()
            .map(to_message)
            .collect())
    }

    async fn upload_blob(&self, token: &AccessToken, file: &Path) -> TransportResult<String> {
        self.device(token)?;
        let data = std::fs::read(file).map_err(|e| TransportError::Network(e.to_string()))?;
        Ok(self.service.upload_blob(data))
    }

    async fn download_blob(
        &self,
        token: &AccessToken,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>> {
        self.device(token)?;
        Ok(self.service.download_blob(blob_id, range)?)
    }
}

/// In-memory [`SecretStorage`].
#[derive(Debug, Default)]
pub struct MemorySecretStorage {
    secrets: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemorySecretStorage {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, Vec<u8>>>, SecretStorageError> {
        self.secrets
            .lock()
            .map_err(|_| SecretStorageError::new("poisoned"))
    }
}

impl SecretStorage for MemorySecretStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStorageError> {
        Ok(self.lock()?.get(key).cloned())
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretStorageError> {
        self.lock()?.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), SecretStorageError> {
        self.lock()?.remove(key);
        Ok(())
    }
}
