//! Test doubles: [`FakeTransport`] over gim-test's in-memory hub, and
//! [`MemorySecretStorage`].

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, MessageKind};
use gim_common::{now_ms, ClientId, DeviceRef, GroupId, UserId};
use gim_crypto::{inspect_handshake, message_epoch, HandshakeKind};
use gim_identity::{AuthChallenge, AuthResponse, SignedDeviceList};
use gim_test::{
    Delivered, DeliveryError, Event, FakeDeliveryService, GroupKind, MembershipChange,
    SubmitCommit, Welcome,
};
use zeroize::Zeroizing;

use crate::transport::{
    AccessToken, Challenge, ClaimedKeyPackage, CommitAccepted, EventBatch, GroupInfo, HubEvent,
    KeyPackageCount, OutgoingCommit, PostError, SessionToken, Transport, TransportError,
    TransportResult, UserRecord,
};
use crate::{SecretStorage, SecretStorageError};

/// Events returned per [`Transport::fetch_events`] call.
const EVENTS_PER_FETCH: usize = 100;
/// Lifetime of fake challenges.
const CHALLENGE_LIFETIME_MS: u64 = 60_000;
/// Lifetime of fake session tokens.
const SESSION_LIFETIME_MS: u64 = 3_600_000;

/// Stand-in for device linking, which gim-sdk does not implement yet: the
/// root key seed of each identity registered with a handle through a test
/// transport, so that registering the same handle again adds a device to
/// that user. Never part of a real transport.
#[derive(Debug)]
pub struct TestLinking {
    service: Arc<FakeDeliveryService>,
    roots: Mutex<HashMap<String, Zeroizing<[u8; 32]>>>,
}

impl TestLinking {
    /// Records the root key seed of the user owning `handle`.
    pub fn remember(&self, handle: &str, root_seed: &[u8; 32]) {
        self.roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handle.to_string(), Zeroizing::new(*root_seed));
    }

    /// The root key seed of the user owning `handle`, if registered here.
    pub fn root_seed(&self, handle: &str) -> Option<Zeroizing<[u8; 32]>> {
        self.roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(handle)
            .cloned()
    }

    /// The user's stored signed DeviceList.
    pub fn device_list(&self, user_id: &UserId) -> Option<Vec<u8>> {
        self.service.device_list(user_id)
    }
}

/// A [`Transport`] over a shared [`FakeDeliveryService`]. Cloning shares the
/// service, so several clients can talk to the same fake hub. It verifies
/// DeviceLists and AuthResponses with gim-identity and reads epochs and
/// membership changes from the MLS framing, as the hub does.
#[derive(Debug, Clone)]
pub struct FakeTransport {
    service: Arc<FakeDeliveryService>,
    linking: Arc<TestLinking>,
    challenges: Arc<AtomicU64>,
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTransport {
    pub fn new() -> Self {
        let service = Arc::new(FakeDeliveryService::new());
        Self {
            linking: Arc::new(TestLinking {
                service: service.clone(),
                roots: Mutex::default(),
            }),
            service,
            challenges: Arc::default(),
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
            | DeliveryError::GroupExists(_) => Self::Conflict(err.to_string()),
            DeliveryError::ValidationFailed(_)
            | DeliveryError::NotAMember(_)
            | DeliveryError::InvalidRange { .. } => Self::Server(err.to_string()),
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

fn invalid(reason: impl std::fmt::Display) -> TransportError {
    TransportError::Server(format!("400 validation_failed: {reason}"))
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
        self.service.issue_challenge(challenge.clone());
        Ok(Challenge {
            challenge,
            hub_id: self.service.hub_id().to_string(),
        })
    }

    /// Verifies the response like the hub, except that challenges are not
    /// checked for single use.
    async fn create_session(&self, response: Vec<u8>) -> TransportResult<SessionToken> {
        let response =
            AuthResponse::from_bytes(&response).map_err(|_| TransportError::Unauthorized)?;
        let list = self
            .service
            .device_list(response.user_id())
            .and_then(|bytes| SignedDeviceList::from_bytes(&bytes).ok())
            .ok_or(TransportError::Unauthorized)?;
        let device = response
            .verify(self.service.hub_id(), now_ms(), &list)
            .map_err(|_| TransportError::Unauthorized)?;
        Ok(SessionToken {
            token: AccessToken::new(self.service.create_session(&device)?),
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
            return Err(TransportError::Server("403 forbidden".into()));
        }
        Ok(self.service.put_recovery_backup(user_id, backup)?)
    }

    async fn device_list(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Option<Vec<u8>>> {
        self.device(token)?;
        Ok(self.service.device_list(user_id))
    }

    async fn user(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Option<UserRecord>> {
        self.device(token)?;
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
        let info = inspect_handshake(&commit.mls_message).map_err(invalid)?;
        if info.group_id != group_id.as_str().as_bytes() {
            return Err(invalid("the message is for another group").into());
        }
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
        let epoch = message_epoch(&mls_message).map_err(invalid)?;
        Ok(self
            .service
            .post_message(group_id, &sender, client_id, epoch, mls_message)?)
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

    fn test_linking(&self) -> Option<&TestLinking> {
        Some(&self.linking)
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
