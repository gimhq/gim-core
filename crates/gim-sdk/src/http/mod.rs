//! [`Transport`] over the gim-server REST API: reqwest with rustls (ring
//! provider, webpki roots), bearer auth, JSON bodies and long-poll events.
//!
//! Shape follows matrix-rust-sdk's `http_client` (Apache-2.0): one shared
//! `reqwest::Client`, per-request auth and timeouts, and a single place that
//! maps HTTP statuses to errors. No code is copied.

mod convert;
mod error;

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, UserInfo};
use gim_common::{DeviceId, DeviceRef, GroupId, UserId};
use gim_proto::dto::{self, paths, EventData};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, RANGE};
use reqwest::{Body, Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use tokio_util::io::ReaderStream;

use crate::stream::ws;
use crate::transport::{
    AccessToken, EventBatch, EventStream, GroupInfo, KeyPackageCount, OutgoingMessage, PostError,
    Registration, Transport, TransportError, TransportResult,
};

pub use reqwest::Url;

/// Longest long-poll `wait` gim-server accepts.
pub const MAX_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpConfig {
    pub connect_timeout: Duration,
    /// Total time of a JSON request; a long-poll gets its `wait` on top.
    /// Blob transfers have no total limit but fail when a read stalls for
    /// `request_timeout + MAX_WAIT`.
    pub request_timeout: Duration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// HTTP [`Transport`] for one gim-server, with the `/v1/stream` WebSocket
/// as its live event stream. Clones share the connection pool and the
/// device directory.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    /// Without a trailing `/`; route paths start with one.
    base_url: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    /// Users of the devices seen in responses. Membership events carry
    /// device ids only; this resolves them to [`DeviceRef`]s.
    directory: Arc<Mutex<HashMap<DeviceId, UserId>>>,
}

impl HttpTransport {
    pub fn new(base_url: Url) -> TransportResult<Self> {
        Self::with_config(base_url, HttpConfig::default())
    }

    pub fn with_config(base_url: Url, config: HttpConfig) -> TransportResult<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.request_timeout + MAX_WAIT)
            .build()
            .map_err(error::from_reqwest)?;
        Ok(Self {
            client,
            base_url: base_url.as_str().trim_end_matches('/').to_string(),
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
            directory: Arc::default(),
        })
    }

    /// A request without a total timeout.
    fn request(&self, method: Method, path: &str, token: Option<&AccessToken>) -> RequestBuilder {
        let builder = self
            .client
            .request(method, format!("{}{path}", self.base_url));
        match token {
            Some(token) => builder.bearer_auth(token.as_str()),
            None => builder,
        }
    }

    fn api(&self, method: Method, path: &str, token: Option<&AccessToken>) -> RequestBuilder {
        self.request(method, path, token)
            .timeout(self.request_timeout)
    }

    /// Sends the request; any status is returned as is.
    async fn send(builder: RequestBuilder) -> TransportResult<Response> {
        builder.send().await.map_err(error::from_reqwest)
    }

    /// Sends the request; a non-2xx status becomes an error.
    async fn send_ok(builder: RequestBuilder) -> TransportResult<Response> {
        let response = Self::send(builder).await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Self::status_error(response).await)
        }
    }

    async fn status_error(response: Response) -> TransportError {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        error::from_status(status, &body)
    }

    async fn json<T: DeserializeOwned>(builder: RequestBuilder) -> TransportResult<T> {
        Self::send_ok(builder)
            .await?
            .json()
            .await
            .map_err(error::from_reqwest)
    }

    fn directory(&self) -> MutexGuard<'_, HashMap<DeviceId, UserId>> {
        self.directory.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn remember<'a>(&self, devices: impl IntoIterator<Item = &'a DeviceRef>) {
        let mut directory = self.directory();
        for device in devices {
            directory.insert(device.device_id.clone(), device.user_id.clone());
        }
    }

    fn lookup(&self, device_id: &DeviceId) -> Option<DeviceRef> {
        self.directory()
            .get(device_id)
            .map(|user_id| DeviceRef::new(user_id.clone(), device_id.clone()))
    }

    async fn fetch_group(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
    ) -> TransportResult<GroupInfo> {
        let group = Self::json(self.api(Method::GET, &paths::group(group_id), Some(token))).await?;
        let info = convert::group(group);
        self.remember(&info.members);
        Ok(info)
    }

    /// Fills the directory for the devices of membership events it does not
    /// know yet: from the group's member list, then from `/v1/me` for this
    /// device. Devices that already left the group may stay unresolved.
    async fn resolve_members(
        &self,
        token: &AccessToken,
        events: &[dto::Event],
    ) -> TransportResult<()> {
        let unknown = |events: &[dto::Event]| -> BTreeSet<GroupId> {
            events
                .iter()
                .filter_map(|event| match &event.data {
                    EventData::MemberAdded(change) | EventData::MemberRemoved(change) => {
                        Some(change)
                    }
                    _ => None,
                })
                .filter(|change| change.device_ids.iter().any(|d| self.lookup(d).is_none()))
                .map(|change| change.group_id.clone())
                .collect()
        };
        let groups = unknown(events);
        for group_id in &groups {
            match self.fetch_group(token, group_id).await {
                Ok(_) => {}
                // This device may have been removed: then the group is no
                // longer visible to it.
                Err(TransportError::NotFound(_) | TransportError::Server(_)) => {}
                Err(err) => return Err(err),
            }
        }
        if !groups.is_empty() && !unknown(events).is_empty() {
            let me: dto::Me = Self::json(self.api(Method::GET, paths::ME, Some(token))).await?;
            self.remember(&[DeviceRef::new(me.user_id, me.device_id)]);
        }
        Ok(())
    }

    /// Maps stream events onto [`IncomingEvent`]s, resolving the devices of
    /// membership events; unknown event types are skipped.
    pub(crate) async fn convert_events(
        &self,
        token: &AccessToken,
        events: Vec<dto::Event>,
    ) -> TransportResult<Vec<IncomingEvent>> {
        self.remember(
            &events
                .iter()
                .filter_map(|event| match &event.data {
                    EventData::Message(m) => Some(DeviceRef::new(
                        m.sender_user_id.clone(),
                        m.sender_device_id.clone(),
                    )),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        );
        self.resolve_members(token, &events).await?;
        Ok(events
            .into_iter()
            .flat_map(|event| match event.data {
                EventData::Message(m) => vec![IncomingEvent::Message(convert::message(m))],
                EventData::MemberAdded(change) => self.membership(change, |group_id, device| {
                    IncomingEvent::MemberAdded { group_id, device }
                }),
                EventData::MemberRemoved(change) => self.membership(change, |group_id, device| {
                    IncomingEvent::MemberRemoved { group_id, device }
                }),
                EventData::KeyPackagesLow(_) => vec![IncomingEvent::KeyPackagesLow],
                EventData::Unknown { event_type, .. } => {
                    tracing::debug!(%event_type, cursor = event.cursor, "skipping unknown event");
                    vec![]
                }
            })
            .collect())
    }

    fn membership(
        &self,
        change: dto::MembershipChange,
        event: impl Fn(GroupId, DeviceRef) -> IncomingEvent,
    ) -> Vec<IncomingEvent> {
        change
            .device_ids
            .iter()
            .filter_map(|device_id| match self.lookup(device_id) {
                Some(device) => Some(event(change.group_id.clone(), device)),
                None => {
                    tracing::debug!(%device_id, group_id = %change.group_id, "skipping membership event of an unknown device");
                    None
                }
            })
            .collect()
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn register_device(
        &self,
        handle: &str,
        display_name: &str,
    ) -> TransportResult<Registration> {
        let request = dto::RegisterDeviceRequest {
            handle: handle.to_string(),
            display_name: display_name.to_string(),
        };
        let response: dto::RegisterDeviceResponse =
            Self::json(self.api(Method::POST, paths::DEVICES, None).json(&request)).await?;
        let device = DeviceRef::new(response.user_id, response.device_id);
        self.remember([&device]);
        Ok(Registration {
            device,
            token: AccessToken::new(response.token),
            cursor: response.cursor,
        })
    }

    async fn find_user(
        &self,
        token: &AccessToken,
        handle: &str,
    ) -> TransportResult<Option<UserInfo>> {
        let query = dto::UsersQuery {
            handle: handle.to_string(),
        };
        let request = self
            .api(Method::GET, paths::USERS, Some(token))
            .query(&query);
        match Self::json::<dto::User>(request).await {
            Ok(user) => Ok(Some(UserInfo {
                user_id: user.user_id,
                handle: user.handle,
                display_name: user.display_name,
            })),
            Err(TransportError::NotFound(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn user(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Option<UserInfo>> {
        let request = self.api(Method::GET, &paths::user(user_id), Some(token));
        match Self::json::<dto::User>(request).await {
            Ok(user) => Ok(Some(UserInfo {
                user_id: user.user_id,
                handle: user.handle,
                display_name: user.display_name,
            })),
            Err(TransportError::NotFound(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn list_devices(
        &self,
        token: &AccessToken,
        user_id: &UserId,
    ) -> TransportResult<Vec<DeviceRef>> {
        let list: dto::UserDevices =
            Self::json(self.api(Method::GET, &paths::user_devices(user_id), Some(token))).await?;
        let devices: Vec<_> = list
            .devices
            .into_iter()
            .map(|d| DeviceRef::new(user_id.clone(), d.device_id))
            .collect();
        self.remember(&devices);
        Ok(devices)
    }

    async fn upload_key_packages(
        &self,
        token: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: Option<Vec<u8>>,
    ) -> TransportResult<()> {
        let request = dto::UploadKeyPackagesRequest {
            key_packages,
            last_resort,
        };
        let _: dto::KeyPackageCount = Self::json(
            self.api(Method::POST, paths::KEY_PACKAGES, Some(token))
                .json(&request),
        )
        .await?;
        Ok(())
    }

    async fn key_package_count(&self, token: &AccessToken) -> TransportResult<KeyPackageCount> {
        let count: dto::KeyPackageCount =
            Self::json(self.api(Method::GET, paths::KEY_PACKAGES_COUNT, Some(token))).await?;
        Ok(KeyPackageCount {
            available: count.available,
            has_last_resort: count.has_last_resort,
        })
    }

    async fn claim_key_package(
        &self,
        token: &AccessToken,
        device: &DeviceRef,
    ) -> TransportResult<Vec<u8>> {
        let request = dto::ClaimKeyPackagesRequest {
            device_ids: vec![device.device_id.clone()],
        };
        let response: dto::ClaimKeyPackagesResponse = Self::json(
            self.api(Method::POST, paths::KEY_PACKAGES_CLAIM, Some(token))
                .json(&request),
        )
        .await?;
        response
            .key_packages
            .into_iter()
            .find(|claimed| claimed.device_id == device.device_id)
            .map(|claimed| claimed.key_package)
            .ok_or_else(|| TransportError::NotFound(format!("no key package for {device}")))
    }

    async fn create_group(
        &self,
        token: &AccessToken,
        kind: ChatKind,
        members: &[DeviceRef],
    ) -> TransportResult<GroupId> {
        self.remember(members);
        let request = dto::CreateGroupRequest {
            kind: convert::group_kind(kind),
            member_device_ids: members.iter().map(|d| d.device_id.clone()).collect(),
        };
        let group: dto::Group = Self::json(
            self.api(Method::POST, paths::GROUPS, Some(token))
                .json(&request),
        )
        .await?;
        let info = convert::group(group);
        self.remember(&info.members);
        Ok(info.group_id)
    }

    async fn group_info(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
    ) -> TransportResult<GroupInfo> {
        self.fetch_group(token, group_id).await
    }

    async fn list_groups(&self, token: &AccessToken) -> TransportResult<Vec<GroupInfo>> {
        let list: dto::GroupList =
            Self::json(self.api(Method::GET, paths::GROUPS, Some(token))).await?;
        let groups: Vec<GroupInfo> = list.groups.into_iter().map(convert::group).collect();
        self.remember(groups.iter().flat_map(|g| &g.members));
        Ok(groups)
    }

    async fn add_group_members(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()> {
        self.remember(devices);
        let request = dto::AddMembersRequest {
            device_ids: devices.iter().map(|d| d.device_id.clone()).collect(),
        };
        let _: dto::Group = Self::json(
            self.api(Method::POST, &paths::group_members(group_id), Some(token))
                .json(&request),
        )
        .await?;
        Ok(())
    }

    async fn remove_group_members(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        devices: &[DeviceRef],
    ) -> TransportResult<()> {
        self.remember(devices);
        for device in devices {
            let path = paths::group_member(group_id, &device.device_id);
            let _: dto::Group = Self::json(self.api(Method::DELETE, &path, Some(token))).await?;
        }
        Ok(())
    }

    async fn post_message(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        message: OutgoingMessage,
    ) -> Result<u64, PostError> {
        self.remember(&message.recipients);
        let commit_epoch = message.epoch;
        let request = dto::SendMessageRequest {
            client_id: message.client_id,
            epoch: message.epoch,
            kind: convert::message_kind(message.kind),
            payload: message.payload,
            recipients: (!message.recipients.is_empty()).then(|| {
                message
                    .recipients
                    .into_iter()
                    .map(|d| d.device_id)
                    .collect()
            }),
        };
        let response = Self::send(
            self.api(Method::POST, &paths::group_messages(group_id), Some(token))
                .json(&request),
        )
        .await?;
        if response.status() == StatusCode::CONFLICT {
            let body = response.bytes().await.unwrap_or_default();
            return match serde_json::from_slice::<dto::ErrorResponse>(&body) {
                Ok(e) if e.error.code == dto::STALE_EPOCH => {
                    Err(PostError::EpochConflict { commit_epoch })
                }
                _ => Err(error::from_status(StatusCode::CONFLICT, &body).into()),
            };
        }
        if !response.status().is_success() {
            return Err(Self::status_error(response).await.into());
        }
        let stored: dto::Message = response.json().await.map_err(error::from_reqwest)?;
        Ok(stored.seq)
    }

    async fn fetch_events(
        &self,
        token: &AccessToken,
        cursor: Option<u64>,
        wait: Duration,
    ) -> TransportResult<EventBatch> {
        let wait = wait.min(MAX_WAIT);
        let query = dto::EventsQuery {
            cursor,
            wait: Some(wait.as_secs() as u32),
            limit: None,
        };
        let list: dto::EventList = Self::json(
            self.request(Method::GET, paths::EVENTS, Some(token))
                .timeout(self.request_timeout + wait)
                .query(&query),
        )
        .await?;
        Ok(EventBatch {
            events: self.convert_events(token, list.events).await?,
            next_cursor: list.next_cursor,
        })
    }

    async fn open_stream(
        &self,
        token: &AccessToken,
        cursor: Option<u64>,
    ) -> TransportResult<Option<Box<dyn EventStream>>> {
        let url = ws::stream_url(&self.base_url, cursor)?;
        let timeout = self.connect_timeout + self.request_timeout;
        let stream = ws::WsEventStream::connect(self.clone(), token.clone(), url, timeout).await?;
        Ok(stream.map(|s| Box::new(s) as Box<dyn EventStream>))
    }

    fn seed_device_directory(&self, devices: &[DeviceRef]) {
        self.remember(devices);
    }

    async fn group_messages(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        after_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        let query = dto::MessagesQuery {
            after_seq: Some(after_seq),
            limit: Some(limit),
        };
        let list: dto::MessageList = Self::json(
            self.api(Method::GET, &paths::group_messages(group_id), Some(token))
                .query(&query),
        )
        .await?;
        Ok(list.messages.into_iter().map(convert::message).collect())
    }

    async fn upload_blob(&self, token: &AccessToken, file: &Path) -> TransportResult<String> {
        let local = |e: std::io::Error| {
            TransportError::Network(format!("cannot read {}: {e}", file.display()))
        };
        let file = tokio::fs::File::open(file).await.map_err(local)?;
        let size = file.metadata().await.map_err(local)?.len();
        let created: dto::BlobCreated = Self::json(
            self.request(Method::POST, paths::BLOBS, Some(token))
                .header(CONTENT_TYPE, "application/octet-stream")
                .header(CONTENT_LENGTH, size)
                .body(Body::wrap_stream(ReaderStream::new(file))),
        )
        .await?;
        Ok(created.blob_id)
    }

    async fn download_blob(
        &self,
        token: &AccessToken,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> TransportResult<Vec<u8>> {
        let mut request = self.request(Method::GET, &paths::blob(blob_id), Some(token));
        if let Some(range) = &range {
            if range.is_empty() {
                return Ok(Vec::new());
            }
            request = request.header(RANGE, format!("bytes={}-{}", range.start, range.end - 1));
        }
        let response = Self::send_ok(request).await?;
        let partial = response.status() == StatusCode::PARTIAL_CONTENT;
        let body = response.bytes().await.map_err(error::from_reqwest)?;
        match range {
            // The server ignored the range and sent the whole blob.
            Some(range) if !partial => usize::try_from(range.start)
                .ok()
                .zip(usize::try_from(range.end).ok())
                .and_then(|(start, end)| body.get(start..end))
                .map(<[u8]>::to_vec)
                .ok_or_else(|| {
                    TransportError::Server(format!(
                        "range {range:?} is outside the {}-byte blob",
                        body.len()
                    ))
                }),
            _ => Ok(body.to_vec()),
        }
    }
}
