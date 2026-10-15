//! Test doubles: [`FakeTransport`] over gim-test's in-memory delivery
//! service, and [`MemorySecretStorage`].

use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, MessageKind, UserInfo};
use gim_common::{DeviceRef, GroupId, UserId};
use gim_test::{Delivered, DeliveryError, Event, FakeDeliveryService, GroupKind};

use crate::transport::{
    AccessToken, EventBatch, GroupInfo, OutgoingMessage, PostError, Registration, Transport,
    TransportError, TransportResult,
};
use crate::{SecretStorage, SecretStorageError};

/// Events returned per [`Transport::fetch_events`] call.
const EVENTS_PER_FETCH: usize = 100;

/// A [`Transport`] over a shared [`FakeDeliveryService`]. Cloning shares the
/// service, so several clients can talk to the same fake server.
#[derive(Debug, Clone, Default)]
pub struct FakeTransport {
    service: Arc<FakeDeliveryService>,
}

impl FakeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// The fake server, for assertions and server-side actions in tests.
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
            | DeliveryError::NoKeyPackage(_)
            | DeliveryError::UnknownBlob(_) => Self::NotFound(err.to_string()),
            DeliveryError::Conflict409 { .. } | DeliveryError::GroupExists(_) => {
                Self::Conflict(err.to_string())
            }
            DeliveryError::NotAMember(_) | DeliveryError::InvalidRange { .. } => {
                Self::Server(err.to_string())
            }
        }
    }
}

fn to_kind(kind: MessageKind) -> gim_test::MessageKind {
    match kind {
        MessageKind::Commit => gim_test::MessageKind::Commit,
        MessageKind::Welcome => gim_test::MessageKind::Welcome,
        MessageKind::Application => gim_test::MessageKind::Application,
    }
}

fn to_message(delivered: Delivered) -> GroupMessage {
    GroupMessage {
        group_id: delivered.group_id,
        seq: delivered.seq,
        sender: delivered.sender,
        kind: match delivered.kind {
            gim_test::MessageKind::Commit => MessageKind::Commit,
            gim_test::MessageKind::Welcome => MessageKind::Welcome,
            gim_test::MessageKind::Application => MessageKind::Application,
        },
        payload: delivered.payload,
        client_id: Some(delivered.client_id),
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn register_device(
        &self,
        handle: &str,
        display_name: &str,
    ) -> TransportResult<Registration> {
        let registration = self.service.register_device(handle, display_name);
        Ok(Registration {
            device: registration.device,
            token: AccessToken::new(registration.token),
            cursor: registration.cursor,
        })
    }

    async fn find_user(
        &self,
        token: &AccessToken,
        handle: &str,
    ) -> TransportResult<Option<UserInfo>> {
        self.device(token)?;
        Ok(self.service.find_user(handle).map(|user| UserInfo {
            user_id: user.user_id,
            handle: user.handle,
            display_name: user.display_name,
        }))
    }

    async fn list_devices(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Vec<DeviceRef>> {
        self.device(token)?;
        Ok(self.service.devices(user_id)?)
    }

    async fn upload_key_packages(
        &self,
        token: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: Option<Vec<u8>>,
    ) -> TransportResult<()> {
        let device = self.device(token)?;
        self.service
            .upload_key_packages(&device, key_packages, last_resort);
        Ok(())
    }

    async fn claim_key_package(
        &self,
        token: &AccessToken,
        device: &DeviceRef,
    ) -> TransportResult<Vec<u8>> {
        self.device(token)?;
        Ok(self.service.claim_key_package(device)?)
    }

    async fn create_group(
        &self,
        token: &AccessToken,
        kind: ChatKind,
        members: &[DeviceRef],
    ) -> TransportResult<GroupId> {
        let creator = self.device(token)?;
        let kind = match kind {
            ChatKind::Direct => GroupKind::Direct,
            ChatKind::Group => GroupKind::Group,
        };
        Ok(self.service.create_group_with(kind, &creator, members)?)
    }

    async fn group_info(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
    ) -> TransportResult<GroupInfo> {
        self.member(token, group_id)?;
        let info = self.service.group(group_id)?;
        Ok(GroupInfo {
            group_id: info.group_id,
            kind: match info.kind {
                GroupKind::Direct => ChatKind::Direct,
                GroupKind::Group => ChatKind::Group,
            },
            epoch: info.epoch,
            members: info.members,
        })
    }

    async fn add_group_members(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()> {
        self.member(token, group_id)?;
        for device in devices {
            self.service.add_member(group_id, device)?;
        }
        Ok(())
    }

    async fn remove_group_members(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()> {
        self.member(token, group_id)?;
        for device in devices {
            self.service.remove_member(group_id, device)?;
        }
        Ok(())
    }

    async fn post_message(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        message: OutgoingMessage,
    ) -> Result<u64, PostError> {
        let sender = self.device(token)?;
        let message = gim_test::OutgoingMessage {
            client_id: message.client_id,
            epoch: message.epoch,
            kind: to_kind(message.kind),
            payload: message.payload,
            recipients: message.recipients,
        };
        match self.service.post(group_id, &sender, message) {
            Ok(seq) => Ok(seq),
            Err(DeliveryError::Conflict409 { commit_epoch, .. }) => {
                Err(PostError::EpochConflict { commit_epoch })
            }
            Err(err) => Err(TransportError::from(err).into()),
        }
    }

    /// Never waits: the fake server is synchronous.
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
        let events = events
            .into_iter()
            .map(|e| match e.event {
                Event::Message(delivered) => IncomingEvent::Message(to_message(delivered)),
                Event::MemberAdded { group_id, device } => {
                    IncomingEvent::MemberAdded { group_id, device }
                }
                Event::MemberRemoved { group_id, device } => {
                    IncomingEvent::MemberRemoved { group_id, device }
                }
                Event::KeyPackagesLow { .. } => IncomingEvent::KeyPackagesLow,
            })
            .collect();
        Ok(EventBatch {
            events,
            next_cursor,
        })
    }

    async fn group_messages(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        after_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        self.member(token, group_id)?;
        Ok(self
            .service
            .messages(group_id, after_seq, limit as usize)?
            .into_iter()
            .map(to_message)
            .collect())
    }

    async fn upload_blob(&self, token: &AccessToken, data: Vec<u8>) -> TransportResult<String> {
        self.device(token)?;
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
