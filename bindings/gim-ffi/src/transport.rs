//! Stand-in for the gim-server HTTP transport, which is not implemented yet.
//! `GimClient` refuses network calls with `GimError::NotImplemented` when it
//! runs on this transport; local-first calls (sending queues to the outbox)
//! still work and their posts fail as network errors.

use std::ops::Range;
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, UserInfo};
use gim_common::{DeviceRef, GroupId, UserId};
use gim_sdk::transport::{
    AccessToken, EventBatch, GroupInfo, OutgoingMessage, PostError, Registration, Transport,
    TransportError, TransportResult,
};

pub(crate) struct UnavailableTransport;

fn unavailable<T>() -> TransportResult<T> {
    Err(TransportError::Network(
        "no gim-server transport in this build".to_string(),
    ))
}

#[async_trait]
impl Transport for UnavailableTransport {
    async fn register_device(&self, _: &str, _: &str) -> TransportResult<Registration> {
        unavailable()
    }

    async fn find_user(&self, _: &AccessToken, _: &str) -> TransportResult<Option<UserInfo>> {
        unavailable()
    }

    async fn list_devices(&self, _: &AccessToken, _: &UserId) -> TransportResult<Vec<DeviceRef>> {
        unavailable()
    }

    async fn upload_key_packages(
        &self,
        _: &AccessToken,
        _: Vec<Vec<u8>>,
        _: Option<Vec<u8>>,
    ) -> TransportResult<()> {
        unavailable()
    }

    async fn claim_key_package(&self, _: &AccessToken, _: &DeviceRef) -> TransportResult<Vec<u8>> {
        unavailable()
    }

    async fn create_group(
        &self,
        _: &AccessToken,
        _: ChatKind,
        _: &[DeviceRef],
    ) -> TransportResult<GroupId> {
        unavailable()
    }

    async fn group_info(&self, _: &AccessToken, _: &GroupId) -> TransportResult<GroupInfo> {
        unavailable()
    }

    async fn add_group_members(
        &self,
        _: &AccessToken,
        _: &GroupId,
        _: &[DeviceRef],
    ) -> TransportResult<()> {
        unavailable()
    }

    async fn remove_group_members(
        &self,
        _: &AccessToken,
        _: &GroupId,
        _: &[DeviceRef],
    ) -> TransportResult<()> {
        unavailable()
    }

    async fn post_message(
        &self,
        _: &AccessToken,
        _: &GroupId,
        _: OutgoingMessage,
    ) -> Result<u64, PostError> {
        Ok(unavailable()?)
    }

    async fn fetch_events(
        &self,
        _: &AccessToken,
        _: Option<u64>,
        _: Duration,
    ) -> TransportResult<EventBatch> {
        unavailable()
    }

    async fn group_messages(
        &self,
        _: &AccessToken,
        _: &GroupId,
        _: u64,
        _: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        unavailable()
    }

    async fn upload_blob(&self, _: &AccessToken, _: Vec<u8>) -> TransportResult<String> {
        unavailable()
    }

    async fn download_blob(
        &self,
        _: &AccessToken,
        _: &str,
        _: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>> {
        unavailable()
    }
}
