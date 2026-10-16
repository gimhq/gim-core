//! [`Transport`] over the gim-hub API v2: reqwest with rustls (ring
//! provider, webpki roots), bearer auth, JSON bodies and long-poll events.
//!
//! Shape follows matrix-rust-sdk's `http_client` (Apache-2.0): one shared
//! `reqwest::Client`, per-request auth and timeouts, and a single place that
//! maps HTTP statuses to errors. No code is copied.

mod convert;
mod error;

use std::ops::Range;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use gim_base::model::{ChatKind, GroupMessage};
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use gim_proto::v2::{self, paths};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, RANGE, RETRY_AFTER};
use reqwest::{Body, Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use tokio_util::io::ReaderStream;

use crate::stream::ws;
use crate::transport::{
    AccessToken, Challenge, ClaimedKeyPackage, CommitAccepted, EventBatch, EventStream, GroupInfo,
    HostingEntryGrant, HubEvent, HubIdentity, KeyPackageClaim, KeyPackageCount, OutgoingCommit,
    PostError, SessionError, SessionToken, StoredHostingRecord, Transport, TransportError,
    TransportResult, UserRecord,
};

pub use reqwest::Url;

/// Longest long-poll `wait` the hub accepts.
pub const MAX_WAIT: Duration = Duration::from_secs(30);
/// Retries of a public read answered 429 or 503 with `Retry-After`.
const PUBLIC_READ_RETRIES: u32 = 2;
/// Longest total `Retry-After` wait of one public read or blob download.
const PUBLIC_READ_MAX_DELAY: Duration = Duration::from_secs(60);
/// Attempts of a blob download answered 502 `peer_refused` or 503
/// `peer_unavailable`.
const BLOB_READ_ATTEMPTS: u32 = 3;
/// Delay after a blob download's first 502 `peer_refused` (or 503 without
/// `Retry-After`); doubles.
const BLOB_READ_BACKOFF: Duration = Duration::from_millis(500);

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

/// HTTP [`Transport`] for one gim-hub, with the `/v2/stream` WebSocket as
/// its live event stream. Clones share the connection pool.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    /// Without a trailing `/`; route paths start with one.
    base_url: String,
    connect_timeout: Duration,
    request_timeout: Duration,
}

/// Unix milliseconds from the hub (never negative in practice).
fn millis(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// `Retry-After` in integer seconds, if present.
fn retry_after(response: &Response) -> Option<u64> {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn hosting_record(record: v2::HostingRecord) -> StoredHostingRecord {
    StoredHostingRecord {
        record: record.hosting_record,
        seq: record.seq,
        expires_at_ms: millis(record.expires_at),
        hosted: record.hosted,
    }
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
        let retry_after = retry_after(&response);
        let body = response.bytes().await.unwrap_or_default();
        error::from_status(status, retry_after, &body)
    }

    async fn json<T: DeserializeOwned>(builder: RequestBuilder) -> TransportResult<T> {
        Self::send_ok(builder)
            .await?
            .json()
            .await
            .map_err(error::from_reqwest)
    }

    /// `None` on 404.
    async fn json_opt<T: DeserializeOwned>(builder: RequestBuilder) -> TransportResult<Option<T>> {
        match Self::json(builder).await {
            Ok(value) => Ok(Some(value)),
            Err(TransportError::NotFound(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// GET of a public read (device list, user): `None` on 404. 429 and 503
    /// with `Retry-After` (integer seconds) are retried after that delay, at
    /// most [`PUBLIC_READ_RETRIES`] times and [`PUBLIC_READ_MAX_DELAY`] in
    /// total; past that budget they fail with
    /// [`TransportError::RetryLater`].
    async fn public_read<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&AccessToken>,
    ) -> TransportResult<Option<T>> {
        let mut retries = 0;
        let mut waited = Duration::ZERO;
        loop {
            let response = Self::send(self.api(Method::GET, path, token)).await?;
            let status = response.status();
            if status.is_success() {
                return response.json().await.map(Some).map_err(error::from_reqwest);
            }
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let delay = match status {
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                    retry_after(&response).map(Duration::from_secs)
                }
                _ => None,
            };
            let Some(delay) = delay else {
                return Err(Self::status_error(response).await);
            };
            if retries == PUBLIC_READ_RETRIES || waited + delay > PUBLIC_READ_MAX_DELAY {
                let body = response.bytes().await.unwrap_or_default();
                return Err(error::retry_later(status, delay, &body));
            }
            tracing::debug!(%status, ?delay, path, "public read throttled; retrying");
            tokio::time::sleep(delay).await;
            retries += 1;
            waited += delay;
        }
    }

    /// GET of a blob. The own hub fetches a foreign blob from its origin
    /// hub: 503 `peer_unavailable` is retried after its `Retry-After`, 502
    /// `peer_refused` (transient right after a hosting record change) after
    /// a doubling backoff, at most [`BLOB_READ_ATTEMPTS`] attempts and
    /// [`PUBLIC_READ_MAX_DELAY`] in total. Then 503 fails with
    /// [`TransportError::RetryLater`], 502 with
    /// [`TransportError::PeerRefused`].
    async fn blob_response(
        &self,
        token: &AccessToken,
        path: &str,
        range: Option<&Range<u64>>,
    ) -> TransportResult<Response> {
        let mut attempt = 1;
        let mut backoff = BLOB_READ_BACKOFF;
        let mut waited = Duration::ZERO;
        loop {
            let mut request = self.request(Method::GET, path, Some(token));
            if let Some(range) = range {
                request = request.header(RANGE, format!("bytes={}-{}", range.start, range.end - 1));
            }
            let response = Self::send(request).await?;
            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }
            let retry_after = retry_after(&response);
            let body = response.bytes().await.unwrap_or_default();
            let err = error::from_status(status, retry_after, &body);
            let delay = match &err {
                TransportError::PeerUnavailable { .. } => {
                    retry_after.map_or(backoff, Duration::from_secs)
                }
                TransportError::PeerRefused(_) => backoff,
                _ => return Err(err),
            };
            if attempt == BLOB_READ_ATTEMPTS || waited + delay > PUBLIC_READ_MAX_DELAY {
                return Err(match (err, retry_after) {
                    (TransportError::PeerUnavailable { .. }, Some(_)) => {
                        error::retry_later(status, delay, &body)
                    }
                    (err, _) => err,
                });
            }
            tracing::debug!(%status, ?delay, path, "blob download failed at the origin; retrying");
            tokio::time::sleep(delay).await;
            attempt += 1;
            waited += delay;
            backoff *= 2;
        }
    }

    /// Like [`Self::json`], with a 409 `stale_epoch` as
    /// [`PostError::StaleEpoch`].
    async fn json_post<T: DeserializeOwned>(builder: RequestBuilder) -> Result<T, PostError> {
        let response = Self::send(builder).await?;
        if response.status() == StatusCode::CONFLICT {
            let body = response.bytes().await.unwrap_or_default();
            return match serde_json::from_slice::<v2::StaleEpochError>(&body) {
                Ok(e) if e.error.code == v2::STALE_EPOCH => Err(PostError::StaleEpoch {
                    current_epoch: e.current_epoch,
                }),
                _ => Err(error::from_status(StatusCode::CONFLICT, None, &body).into()),
            };
        }
        if !response.status().is_success() {
            return Err(Self::status_error(response).await.into());
        }
        Ok(response.json().await.map_err(error::from_reqwest)?)
    }

    /// Maps stream events onto [`HubEvent`]s.
    pub(crate) fn convert_events(events: Vec<v2::Event>) -> Vec<HubEvent> {
        events.into_iter().flat_map(convert::event).collect()
    }
}

#[async_trait]
impl Transport for HttpTransport {
    fn base_url(&self) -> Option<String> {
        Some(self.base_url.clone())
    }

    async fn hub_info(&self) -> TransportResult<HubIdentity> {
        let info: v2::HubInfo = Self::json(self.api(Method::GET, paths::HUB, None)).await?;
        Ok(HubIdentity {
            hub_id: info.hub_id,
            hub_root_public_key: info.hub_root_pubkey,
            version: info.version,
        })
    }

    async fn put_device_list(&self, user_id: &UserId, device_list: Vec<u8>) -> TransportResult<()> {
        let request = v2::PutDeviceListRequest { device_list };
        let _: v2::DeviceList = Self::json(
            self.api(
                Method::PUT,
                &paths::user_device_list(user_id.as_str()),
                None,
            )
            .json(&request),
        )
        .await?;
        Ok(())
    }

    async fn auth_challenge(&self, device: &DeviceRef) -> TransportResult<Challenge> {
        let request = v2::AuthChallengeRequest {
            user_id: device.user_id.to_string(),
            device_id: device.device_id.to_string(),
        };
        let challenge: v2::AuthChallenge = Self::json(
            self.api(Method::POST, paths::AUTH_CHALLENGE, None)
                .json(&request),
        )
        .await?;
        Ok(Challenge {
            challenge: challenge.challenge,
            hub_id: challenge.hub_id,
        })
    }

    async fn create_session(&self, response: Vec<u8>) -> Result<SessionToken, SessionError> {
        let request = v2::CreateSessionRequest { response };
        let response = Self::send(
            self.api(Method::POST, paths::AUTH_SESSION, None)
                .json(&request),
        )
        .await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let body = response.bytes().await.unwrap_or_default();
            let code = serde_json::from_slice::<v2::ErrorResponse>(&body)
                .map(|e| e.error.code)
                .unwrap_or_default();
            return Err(match code.as_str() {
                "invalid_challenge" => SessionError::InvalidChallenge,
                "invalid_signature" | "device_not_active" => SessionError::Rejected(code),
                _ => TransportError::Unauthorized.into(),
            });
        }
        if !response.status().is_success() {
            return Err(Self::status_error(response).await.into());
        }
        let session: v2::Session = response.json().await.map_err(error::from_reqwest)?;
        Ok(SessionToken {
            token: AccessToken::new(session.token),
            expires_at_ms: millis(session.expires_at),
        })
    }

    async fn put_recovery_backup(
        &self,
        token: &AccessToken,
        user_id: &UserId,
        backup: Vec<u8>,
    ) -> TransportResult<()> {
        let request = v2::PutRecoveryBackupRequest { backup };
        let path = paths::user_recovery_backup(user_id.as_str());
        let _: v2::RecoveryBackup =
            Self::json(self.api(Method::PUT, &path, Some(token)).json(&request)).await?;
        Ok(())
    }

    async fn recovery_backup(&self, user_id: &UserId) -> TransportResult<Option<Vec<u8>>> {
        let path = paths::user_recovery_backup(user_id.as_str());
        let backup: Option<v2::RecoveryBackup> =
            Self::json_opt(self.api(Method::GET, &path, None)).await?;
        Ok(backup.map(|b| b.backup))
    }

    async fn post_link_bundle(
        &self,
        token: &AccessToken,
        link_id: &str,
        sealed_bundle: Vec<u8>,
        expires_in: Duration,
    ) -> TransportResult<()> {
        let request = v2::CreateLinkBundleRequest {
            link_id: link_id.to_string(),
            sealed_bundle,
            expires_in: expires_in.as_secs().clamp(1, 600) as u32,
        };
        let _: v2::LinkBundleCreated = Self::json(
            self.api(Method::POST, paths::LINK_BUNDLES, Some(token))
                .json(&request),
        )
        .await?;
        Ok(())
    }

    async fn fetch_link_bundle(
        &self,
        link_id: &str,
        wait: Duration,
    ) -> TransportResult<Option<Vec<u8>>> {
        let wait = wait.min(MAX_WAIT);
        let query = v2::LinkBundleQuery {
            wait: Some(wait.as_secs() as u32),
        };
        let bundle: Option<v2::LinkBundle> = Self::json_opt(
            self.request(Method::GET, &paths::link_bundle(link_id), None)
                .timeout(self.request_timeout + wait)
                .query(&query),
        )
        .await?;
        Ok(bundle.map(|b| b.sealed_bundle))
    }

    async fn device_list(
        &self,
        token: Option<&AccessToken>,
        user_id: &UserId,
    ) -> TransportResult<Option<Vec<u8>>> {
        let path = paths::user_device_list(user_id.as_str());
        let list: Option<v2::DeviceList> = self.public_read(&path, token).await?;
        Ok(list.map(|l| l.device_list))
    }

    async fn user(
        &self,
        token: Option<&AccessToken>,
        user_id: &UserId,
    ) -> TransportResult<Option<UserRecord>> {
        let path = paths::user(user_id.as_str());
        let user: Option<v2::User> = self.public_read(&path, token).await?;
        user.map(|user| {
            Ok(UserRecord {
                user_id: convert::user_id(&user.user_id)?,
                device_list: user.device_list,
                handle: user.handle,
                display_name: None,
            })
        })
        .transpose()
    }

    async fn find_handle(
        &self,
        token: &AccessToken,
        handle: &str,
    ) -> TransportResult<Option<UserId>> {
        let found: Option<v2::Handle> =
            Self::json_opt(self.api(Method::GET, &paths::handle(handle), Some(token))).await?;
        found.map(|h| convert::user_id(&h.user_id)).transpose()
    }

    async fn claim_handle(&self, token: &AccessToken, handle: &str) -> TransportResult<()> {
        let _: v2::Handle =
            Self::json(self.api(Method::PUT, &paths::handle(handle), Some(token))).await?;
        Ok(())
    }

    async fn release_handle(&self, token: &AccessToken, handle: &str) -> TransportResult<()> {
        Self::send_ok(self.api(Method::DELETE, &paths::handle(handle), Some(token))).await?;
        Ok(())
    }

    async fn upload_key_packages(
        &self,
        token: &AccessToken,
        key_packages: Vec<Vec<u8>>,
        last_resort: bool,
    ) -> TransportResult<()> {
        let request = v2::UploadKeyPackagesRequest {
            key_packages,
            last_resort,
        };
        let _: v2::KeyPackageCount = Self::json(
            self.api(Method::POST, paths::KEY_PACKAGES, Some(token))
                .json(&request),
        )
        .await?;
        Ok(())
    }

    async fn key_package_count(&self, token: &AccessToken) -> TransportResult<KeyPackageCount> {
        let count: v2::KeyPackageCount =
            Self::json(self.api(Method::GET, paths::KEY_PACKAGES_COUNT, Some(token))).await?;
        Ok(KeyPackageCount {
            available: u64::from(count.available),
            has_last_resort: count.has_last_resort,
        })
    }

    async fn claim_key_packages(
        &self,
        token: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<Vec<ClaimedKeyPackage>> {
        Ok(self
            .claim_key_packages_federated(token, users)
            .await?
            .key_packages)
    }

    async fn claim_key_packages_federated(
        &self,
        token: &AccessToken,
        users: &[UserId],
    ) -> TransportResult<KeyPackageClaim> {
        let request = v2::ClaimKeyPackagesRequest {
            targets: users
                .iter()
                .map(|user_id| v2::ClaimTarget {
                    user_id: user_id.to_string(),
                    device_id: None,
                })
                .collect(),
        };
        let response: v2::ClaimKeyPackagesResponse = Self::json(
            self.api(Method::POST, paths::KEY_PACKAGES_CLAIM, Some(token))
                .json(&request),
        )
        .await?;
        let key_packages = response
            .key_packages
            .into_iter()
            .map(|claimed| {
                Ok(ClaimedKeyPackage {
                    device: convert::device(&claimed.user_id, &claimed.device_id)?,
                    key_package: claimed.key_package,
                })
            })
            .collect::<TransportResult<_>>()?;
        let unavailable = response
            .unavailable
            .iter()
            .map(|target| convert::user_id(&target.user_id))
            .collect::<TransportResult<_>>()?;
        Ok(KeyPackageClaim {
            key_packages,
            unavailable,
        })
    }

    async fn create_group(&self, token: &AccessToken, kind: ChatKind) -> TransportResult<GroupId> {
        let request = v2::CreateGroupRequest {
            kind: convert::group_kind(kind),
        };
        let group: v2::Group = Self::json(
            self.api(Method::POST, paths::GROUPS, Some(token))
                .json(&request),
        )
        .await?;
        convert::group_id(&group.gid)
    }

    async fn group_info(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
    ) -> TransportResult<GroupInfo> {
        let path = paths::group(group_id.as_str());
        convert::group(Self::json(self.api(Method::GET, &path, Some(token))).await?)
    }

    async fn list_groups(&self, token: &AccessToken) -> TransportResult<Vec<GroupInfo>> {
        let list: v2::GroupList =
            Self::json(self.api(Method::GET, paths::GROUPS, Some(token))).await?;
        list.groups.into_iter().map(convert::group).collect()
    }

    async fn submit_commit(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        commit: OutgoingCommit,
    ) -> Result<CommitAccepted, PostError> {
        let request = v2::SubmitCommitRequest {
            client_id: commit.client_id.to_string(),
            mls_message: commit.mls_message,
            welcome_recipients: commit.welcome.is_some().then(|| {
                commit
                    .welcome_recipients
                    .iter()
                    .map(convert::member)
                    .collect()
            }),
            welcome: commit.welcome,
            ratchet_tree: None,
        };
        let path = paths::group_commits(group_id.as_str());
        let result: v2::CommitResult =
            Self::json_post(self.api(Method::POST, &path, Some(token)).json(&request)).await?;
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
        let request = v2::SendMessageRequest {
            client_id: client_id.to_string(),
            mls_message,
        };
        let path = paths::group_messages(group_id.as_str());
        let stored: v2::Message =
            Self::json_post(self.api(Method::POST, &path, Some(token)).json(&request)).await?;
        Ok(stored.seq)
    }

    async fn fetch_events(
        &self,
        token: &AccessToken,
        cursor: Option<u64>,
        wait: Duration,
    ) -> TransportResult<EventBatch> {
        let wait = wait.min(MAX_WAIT);
        let query = v2::EventsQuery {
            cursor,
            wait: Some(wait.as_secs() as u32),
            limit: None,
        };
        let list: v2::EventList = Self::json(
            self.request(Method::GET, paths::EVENTS, Some(token))
                .timeout(self.request_timeout + wait)
                .query(&query),
        )
        .await?;
        Ok(EventBatch {
            events: Self::convert_events(list.events),
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
        let stream = ws::WsEventStream::connect(url, token, timeout).await?;
        Ok(stream.map(|s| Box::new(s) as Box<dyn EventStream>))
    }

    async fn pending_welcomes(
        &self,
        token: &AccessToken,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        let query = v2::PendingWelcomesQuery { limit: Some(limit) };
        let list: v2::PendingWelcomeList = Self::json(
            self.api(Method::GET, paths::WELCOMES_PENDING, Some(token))
                .query(&query),
        )
        .await?;
        list.welcomes
            .into_iter()
            .map(|pending| convert::welcome(pending.welcome))
            .collect()
    }

    async fn ack_welcome(&self, token: &AccessToken, group_id: &GroupId) -> TransportResult<()> {
        let path = paths::welcome_ack(group_id.as_str());
        Self::send_ok(self.api(Method::POST, &path, Some(token))).await?;
        Ok(())
    }

    async fn group_messages(
        &self,
        token: &AccessToken,
        group_id: &GroupId,
        from_seq: u64,
        limit: u32,
    ) -> TransportResult<Vec<GroupMessage>> {
        let path = paths::group_messages(group_id.as_str());
        let mut from_seq = from_seq.max(1);
        loop {
            let query = v2::MessagesQuery {
                from_seq: Some(from_seq),
                limit: Some(limit),
            };
            let list: v2::MessageList =
                Self::json(self.api(Method::GET, &path, Some(token)).query(&query)).await?;
            let next = list.messages.last().map(|m| m.seq + 1);
            let messages = list
                .messages
                .into_iter()
                .filter_map(|m| convert::message(m).transpose())
                .collect::<TransportResult<Vec<_>>>()?;
            // A page of skipped kinds only is not the end of the history.
            match next {
                Some(next) if messages.is_empty() && next > from_seq => from_seq = next,
                _ => return Ok(messages),
            }
        }
    }

    async fn create_hosting_entry(
        &self,
        token: &AccessToken,
        user_id: &UserId,
        priority: u8,
    ) -> TransportResult<HostingEntryGrant> {
        let request = v2::CreateHostingEntryRequest {
            priority: Some(priority),
        };
        let path = paths::user_hosting_entry(user_id.as_str());
        let entry: v2::HostingEntry =
            Self::json(self.api(Method::POST, &path, Some(token)).json(&request)).await?;
        Ok(HostingEntryGrant {
            hub_id: entry.hub_id,
            hub_root_public_key: entry.hub_root_pubkey,
            priority: entry.priority,
            entry: entry.entry,
        })
    }

    async fn put_hosting_record(
        &self,
        user_id: &UserId,
        record: Vec<u8>,
    ) -> TransportResult<StoredHostingRecord> {
        let request = v2::PutHostingRecordRequest {
            hosting_record: record,
        };
        let path = paths::user_hosting_record(user_id.as_str());
        let stored: v2::HostingRecord =
            Self::json(self.api(Method::PUT, &path, None).json(&request)).await?;
        Ok(hosting_record(stored))
    }

    async fn hosting_record(
        &self,
        user_id: &UserId,
    ) -> TransportResult<Option<StoredHostingRecord>> {
        let path = paths::user_hosting_record(user_id.as_str());
        let stored: Option<v2::HostingRecord> = self.public_read(&path, None).await?;
        Ok(stored.map(hosting_record))
    }

    async fn upload_blob(&self, token: &AccessToken, file: &Path) -> TransportResult<String> {
        let local = |e: std::io::Error| {
            TransportError::Network(format!("cannot read {}: {e}", file.display()))
        };
        let file = tokio::fs::File::open(file).await.map_err(local)?;
        let size = file.metadata().await.map_err(local)?.len();
        let created: v2::BlobCreated = Self::json(
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
        if range.as_ref().is_some_and(Range::is_empty) {
            return Ok(Vec::new());
        }
        let response = self
            .blob_response(token, &paths::blob(blob_id), range.as_ref())
            .await?;
        let partial = response.status() == StatusCode::PARTIAL_CONTENT;
        let body = response.bytes().await.map_err(error::from_reqwest)?;
        match range {
            // The hub ignored the range and sent the whole blob.
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
