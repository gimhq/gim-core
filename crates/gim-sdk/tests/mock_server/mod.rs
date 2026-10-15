//! In-process mock hub (API v2) for the sync tests: the routes the SDK
//! uses, over the shared [`FakeDeliveryService`] of a [`FakeTransport`],
//! with fault controls. Other devices of a test talk to the same service
//! through the `FakeTransport` directly.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use gim_base::model::{ChatKind, GroupMessage, MessageContent, StateChange};
use gim_base::{MemoryStore, StateReader};
use gim_common::{ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_proto::envelope::Content;
use gim_proto::v2::{self, EventData};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{AccessToken, OutgoingCommit, PostError, Transport, TransportError};
use gim_sdk::{Client, ClientBuilder, ConnectionState, HttpTransport, SecretStorage, SyncSettings};
use gim_test::{Delivered, Event, StreamEvent};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Server-side polling interval of long-polls and streams.
const TICK: Duration = Duration::from_millis(10);

#[derive(Debug, Default)]
pub struct Controls {
    /// `/v2/stream` answers 404 when unset.
    pub stream_disabled: AtomicBool,
    /// The next stream connection drops (without a close frame) after this
    /// many events.
    pub drop_stream_after: Mutex<Option<usize>>,
    /// Open streams drop now (without a close frame).
    pub kick: AtomicBool,
    /// Message events (group, seq) never delivered as events; they stay in
    /// the group history.
    pub hidden: Mutex<BTreeSet<(GroupId, u64)>>,
    /// `GET /v2/events` with a cursor below this answers 410 (0: off).
    pub events_expired_below: AtomicU64,
    /// The next stream connection with a cursor below this gets a
    /// `cursor_expired` frame and close 4410 (0: off).
    pub stream_expired_below: AtomicU64,
    /// Tokens are rejected (401, or close 4401 on streams), and so are
    /// sign-ins (403).
    pub reject: AtomicBool,
    /// `cursor` of every stream connection.
    pub stream_cursors: Mutex<Vec<Option<u64>>>,
    /// Stream connections whose serving task has taken the per-connection
    /// controls above; the client may report `Connected` before that.
    pub streams_served: AtomicUsize,
    /// `(cursor, wait)` of every `GET /v2/events`.
    pub polls: Mutex<Vec<(Option<u64>, Option<u32>)>>,
    /// `(group, from_seq - 1)` of every history request.
    pub history: Mutex<Vec<(GroupId, Option<u64>)>>,
}

#[derive(Clone)]
struct AppState {
    transport: FakeTransport,
    controls: Arc<Controls>,
}

pub struct MockServer {
    pub url: String,
    pub controls: Arc<Controls>,
    task: JoinHandle<()>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockServer {
    /// Waits until `count` stream connections are being served, so faults
    /// armed next apply to the open connection or the next one.
    pub async fn streams_served(&self, count: usize) {
        let controls = self.controls.clone();
        wait_until("stream connections served", move || {
            controls.streams_served.load(Ordering::SeqCst) >= count
        })
        .await;
    }

    pub async fn start(transport: FakeTransport) -> Self {
        let controls = Arc::new(Controls::default());
        let state = AppState {
            transport,
            controls: controls.clone(),
        };
        let app = Router::new()
            .route(v2::paths::AUTH_CHALLENGE, post(auth_challenge))
            .route(v2::paths::AUTH_SESSION, post(create_session))
            .route(
                "/v2/users/{user_id}/device-list",
                put(put_device_list).get(device_list),
            )
            .route(
                "/v2/users/{user_id}/recovery-backup",
                put(put_recovery_backup),
            )
            .route("/v2/users/{user_id}", get(user))
            .route(
                "/v2/handles/{handle}",
                get(find_handle).put(claim_handle).delete(release_handle),
            )
            .route(v2::paths::KEY_PACKAGES, post(upload_key_packages))
            .route(v2::paths::KEY_PACKAGES_COUNT, get(key_package_count))
            .route(v2::paths::KEY_PACKAGES_CLAIM, post(claim_key_packages))
            .route(v2::paths::GROUPS, get(groups).post(create_group))
            .route("/v2/groups/{gid}", get(group))
            .route("/v2/groups/{gid}/commits", post(submit_commit))
            .route(
                "/v2/groups/{gid}/messages",
                get(messages).post(post_message),
            )
            .route(v2::paths::WELCOMES_PENDING, get(pending_welcomes))
            .route("/v2/welcomes/{gid}/ack", post(ack_welcome))
            .route(v2::paths::EVENTS, get(events))
            .route(v2::paths::STREAM, get(stream))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url,
            controls,
            task,
        }
    }
}

fn error(status: StatusCode, code: &str) -> Response {
    let body = v2::ErrorResponse {
        error: v2::ErrorBody {
            code: code.to_string(),
            message: code.to_string(),
        },
    };
    (status, Json(body)).into_response()
}

fn transport_error(err: TransportError) -> Response {
    match err {
        TransportError::Unauthorized => error(StatusCode::UNAUTHORIZED, "unauthorized"),
        TransportError::NotFound(_) => error(StatusCode::NOT_FOUND, "not_found"),
        TransportError::Conflict(_) => error(StatusCode::CONFLICT, "conflict"),
        _ => error(StatusCode::BAD_REQUEST, "validation_failed"),
    }
}

fn post_error(err: PostError) -> Response {
    match err {
        PostError::StaleEpoch { current_epoch } => {
            let body = v2::StaleEpochError {
                error: v2::ErrorBody {
                    code: v2::STALE_EPOCH.into(),
                    message: "stale".into(),
                },
                current_epoch,
            };
            (StatusCode::CONFLICT, Json(body)).into_response()
        }
        PostError::Transport(err) => transport_error(err),
    }
}

fn reply<T: serde::Serialize>(result: Result<T, TransportError>) -> Response {
    match result {
        Ok(body) => Json(body).into_response(),
        Err(err) => transport_error(err),
    }
}

fn no_content(result: Result<(), TransportError>) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => transport_error(err),
    }
}

fn user_id(text: &str) -> Result<UserId, TransportError> {
    UserId::new(text).map_err(|e| TransportError::Server(e.to_string()))
}

fn group_id(text: &str) -> Result<GroupId, TransportError> {
    GroupId::new(text).map_err(|e| TransportError::Server(e.to_string()))
}

fn member(device: &DeviceRef) -> v2::GroupMember {
    v2::GroupMember {
        user_id: device.user_id.to_string(),
        device_id: device.device_id.to_string(),
    }
}

impl AppState {
    #[allow(clippy::result_large_err)]
    fn token(&self, headers: &HeaderMap) -> Result<AccessToken, TransportError> {
        if self.controls.reject.load(Ordering::SeqCst) {
            return Err(TransportError::Unauthorized);
        }
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(AccessToken::new)
            .ok_or(TransportError::Unauthorized)
    }

    fn authenticate(&self, headers: &HeaderMap) -> Result<DeviceRef, TransportError> {
        let token = self.token(headers)?;
        Ok(self.transport.service().authenticate(token.as_str())?)
    }

    /// Events of `device` after `cursor` minus the hidden ones, and the
    /// cursor after all of them.
    fn visible(&self, device: &DeviceRef, cursor: u64, limit: usize) -> (Vec<v2::Event>, u64) {
        let (events, next) = self.transport.service().events(device, cursor, limit);
        let hidden = self.controls.hidden.lock().unwrap();
        let events = events
            .into_iter()
            .filter(|e| match &e.event {
                Event::Message(m) => !hidden.contains(&(m.group_id.clone(), m.seq)),
                _ => true,
            })
            .map(event_dto)
            .collect();
        (events, next)
    }

    fn head(&self, device: &DeviceRef) -> u64 {
        self.transport.service().events(device, 0, usize::MAX).1
    }
}

fn message_dto(m: Delivered) -> v2::Message {
    v2::Message {
        gid: m.group_id.to_string(),
        seq: m.seq,
        sender_user_id: m.sender.user_id.to_string(),
        sender_device_id: m.sender.device_id.to_string(),
        client_id: m.client_id.to_string(),
        kind: match m.kind {
            gim_test::MessageKind::Commit => v2::MessageKind::Commit,
            gim_test::MessageKind::Application => v2::MessageKind::Application,
        },
        epoch: m.epoch,
        mls_message: m.payload,
        created_at: 0,
    }
}

fn welcome_dto(w: gim_test::Welcome) -> v2::Welcome {
    v2::Welcome {
        gid: w.group_id.to_string(),
        sender_user_id: w.sender.user_id.to_string(),
        sender_device_id: w.sender.device_id.to_string(),
        epoch: w.epoch,
        seq: w.seq,
        welcome: w.welcome,
        ratchet_tree: None,
    }
}

fn group_dto(info: gim_test::GroupInfo) -> v2::Group {
    let creator = info.members.first().map(member).unwrap_or(v2::GroupMember {
        user_id: String::new(),
        device_id: String::new(),
    });
    v2::Group {
        gid: info.group_id.to_string(),
        kind: match info.kind {
            gim_test::GroupKind::Direct => v2::GroupKind::Direct,
            gim_test::GroupKind::Group => v2::GroupKind::Group,
        },
        epoch: info.epoch,
        last_seq: info.last_seq,
        // The fake hub does not track creators: the first member stands in.
        created_by_user_id: creator.user_id,
        created_by_device_id: creator.device_id,
        created_at: 0,
        members: info.members.iter().map(member).collect(),
    }
}

fn event_dto(e: StreamEvent) -> v2::Event {
    let membership = |c: gim_test::MembershipChange| v2::MembershipChange {
        gid: c.group_id.to_string(),
        user_id: c.user_id.to_string(),
        device_ids: c.device_ids.iter().map(ToString::to_string).collect(),
        by_user_id: c.by.user_id.to_string(),
        by_device_id: c.by.device_id.to_string(),
        epoch: c.epoch,
        seq: c.seq,
    };
    let data = match e.event {
        Event::Message(m) => EventData::Message(message_dto(m)),
        Event::MemberAdded(c) => EventData::MemberAdded(membership(c)),
        Event::MemberRemoved(c) => EventData::MemberRemoved(membership(c)),
        Event::Welcome(w) => EventData::Welcome(welcome_dto(w)),
        Event::KeyPackagesLow { available } => EventData::KeyPackagesLow(v2::KeyPackagesLow {
            available: available as u32,
        }),
        Event::DeviceListUpdated {
            user_id,
            device_list,
        } => EventData::DeviceListUpdated(v2::DeviceList {
            user_id: user_id.to_string(),
            device_list,
        }),
    };
    v2::Event {
        cursor: e.cursor,
        created_at: 0,
        data,
    }
}

async fn auth_challenge(
    State(state): State<AppState>,
    Json(request): Json<v2::AuthChallengeRequest>,
) -> Response {
    let result = async {
        let device = DeviceRef::parse(&request.user_id, &request.device_id)
            .map_err(|e| TransportError::Server(e.to_string()))?;
        let challenge = state.transport.auth_challenge(&device).await?;
        Ok(v2::AuthChallenge {
            challenge: challenge.challenge,
            expires_at: 0,
            hub_id: challenge.hub_id,
        })
    }
    .await;
    reply(result)
}

async fn create_session(
    State(state): State<AppState>,
    Json(request): Json<v2::CreateSessionRequest>,
) -> Response {
    if state.controls.reject.load(Ordering::SeqCst) {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    match state.transport.create_session(request.response).await {
        Ok(session) => Json(v2::Session {
            token: session.token.as_str().to_string(),
            expires_at: session.expires_at_ms as i64,
        })
        .into_response(),
        Err(TransportError::Unauthorized) => error(StatusCode::FORBIDDEN, "forbidden"),
        Err(err) => transport_error(err),
    }
}

async fn put_device_list(
    State(state): State<AppState>,
    Path(user): Path<String>,
    Json(request): Json<v2::PutDeviceListRequest>,
) -> Response {
    let result = async {
        let user = user_id(&user)?;
        let list = request.device_list;
        state.transport.put_device_list(&user, list.clone()).await?;
        Ok(v2::DeviceList {
            user_id: user.to_string(),
            device_list: list,
        })
    }
    .await;
    reply(result)
}

async fn device_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
) -> Response {
    let result = async {
        let (token, user) = (state.token(&headers)?, user_id(&user)?);
        let list = state.transport.device_list(&token, &user).await?;
        let list = list.ok_or_else(|| TransportError::NotFound(user.to_string()))?;
        Ok(v2::DeviceList {
            user_id: user.to_string(),
            device_list: list,
        })
    }
    .await;
    reply(result)
}

async fn put_recovery_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
    Json(request): Json<v2::PutRecoveryBackupRequest>,
) -> Response {
    let result = async {
        let (token, user) = (state.token(&headers)?, user_id(&user)?);
        let backup = request.backup;
        state
            .transport
            .put_recovery_backup(&token, &user, backup.clone())
            .await?;
        Ok(v2::RecoveryBackup {
            user_id: user.to_string(),
            backup,
            updated_at: 0,
        })
    }
    .await;
    reply(result)
}

async fn user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
) -> Response {
    let result = async {
        let (token, user) = (state.token(&headers)?, user_id(&user)?);
        let record = state.transport.user(&token, &user).await?;
        let record = record.ok_or_else(|| TransportError::NotFound(user.to_string()))?;
        Ok(v2::User {
            user_id: record.user_id.to_string(),
            device_list: record.device_list,
            handle: record.handle,
        })
    }
    .await;
    reply(result)
}

async fn find_handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        let user = state.transport.find_handle(&token, &handle).await?;
        let user = user.ok_or_else(|| TransportError::NotFound(handle.clone()))?;
        Ok(v2::Handle {
            handle,
            user_id: user.to_string(),
        })
    }
    .await;
    reply(result)
}

async fn claim_handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Response {
    let result = async {
        let device = state.authenticate(&headers)?;
        let token = state.token(&headers)?;
        state.transport.claim_handle(&token, &handle).await?;
        Ok(v2::Handle {
            handle,
            user_id: device.user_id.to_string(),
        })
    }
    .await;
    reply(result)
}

async fn release_handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        state.transport.release_handle(&token, &handle).await
    }
    .await;
    no_content(result)
}

async fn upload_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<v2::UploadKeyPackagesRequest>,
) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        state
            .transport
            .upload_key_packages(&token, request.key_packages, request.last_resort)
            .await?;
        key_package_count_dto(&state, &token).await
    }
    .await;
    reply(result)
}

async fn key_package_count_dto(
    state: &AppState,
    token: &AccessToken,
) -> Result<v2::KeyPackageCount, TransportError> {
    let count = state.transport.key_package_count(token).await?;
    Ok(v2::KeyPackageCount {
        available: count.available as u32,
        has_last_resort: count.has_last_resort,
    })
}

async fn key_package_count(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        key_package_count_dto(&state, &token).await
    }
    .await;
    reply(result)
}

async fn claim_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<v2::ClaimKeyPackagesRequest>,
) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        let users = request
            .targets
            .iter()
            .map(|t| user_id(&t.user_id))
            .collect::<Result<Vec<_>, _>>()?;
        let claimed = state.transport.claim_key_packages(&token, &users).await?;
        let missing = users
            .iter()
            .filter(|u| !claimed.iter().any(|c| &c.device.user_id == *u))
            .map(|u| v2::ClaimTarget {
                user_id: u.to_string(),
                device_id: None,
            })
            .collect();
        Ok(v2::ClaimKeyPackagesResponse {
            key_packages: claimed
                .into_iter()
                .map(|c| v2::ClaimedKeyPackage {
                    user_id: c.device.user_id.to_string(),
                    device_id: c.device.device_id.to_string(),
                    key_package: c.key_package,
                    last_resort: false,
                })
                .collect(),
            missing,
        })
    }
    .await;
    reply(result)
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<v2::CreateGroupRequest>,
) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        let kind = match request.kind {
            v2::GroupKind::Direct => ChatKind::Direct,
            v2::GroupKind::Group => ChatKind::Group,
        };
        let group_id = state.transport.create_group(&token, kind).await?;
        Ok(group_dto(state.transport.service().group(&group_id)?))
    }
    .await;
    match result {
        Ok(group) => (StatusCode::CREATED, Json(group)).into_response(),
        Err(err) => transport_error(err),
    }
}

async fn group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gid): Path<String>,
) -> Response {
    let result = async {
        let (token, group_id) = (state.token(&headers)?, group_id(&gid)?);
        state.transport.group_info(&token, &group_id).await?;
        Ok(group_dto(state.transport.service().group(&group_id)?))
    }
    .await;
    reply(result)
}

async fn groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result = async {
        let device = state.authenticate(&headers)?;
        let groups = state.transport.service().groups_of(&device);
        Ok(v2::GroupList {
            groups: groups.into_iter().map(group_dto).collect(),
        })
    }
    .await;
    reply(result)
}

async fn submit_commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gid): Path<String>,
    Json(request): Json<v2::SubmitCommitRequest>,
) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        let group_id = group_id(&gid)?;
        let client_id =
            ClientId::new(request.client_id).map_err(|e| TransportError::Server(e.to_string()))?;
        let welcome_recipients = request
            .welcome_recipients
            .unwrap_or_default()
            .iter()
            .map(|m| DeviceRef::parse(&m.user_id, &m.device_id))
            .collect::<Result<_, _>>()
            .map_err(|e| TransportError::Server(e.to_string()))?;
        let commit = OutgoingCommit {
            client_id,
            mls_message: request.mls_message,
            welcome: request.welcome,
            welcome_recipients,
        };
        state
            .transport
            .submit_commit(&token, &group_id, commit)
            .await
    }
    .await;
    match result {
        Ok(accepted) => Json(v2::CommitResult {
            seq: accepted.seq,
            epoch: accepted.epoch,
            duplicate: accepted.duplicate,
        })
        .into_response(),
        Err(err) => post_error(err),
    }
}

async fn post_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gid): Path<String>,
    Json(request): Json<v2::SendMessageRequest>,
) -> Response {
    let result = async {
        let device = state.authenticate(&headers)?;
        let token = state.token(&headers)?;
        let group_id = group_id(&gid)?;
        let client_id =
            ClientId::new(request.client_id).map_err(|e| TransportError::Server(e.to_string()))?;
        let seq = state
            .transport
            .post_message(&token, &group_id, client_id.clone(), request.mls_message)
            .await?;
        let stored = state
            .transport
            .service()
            .messages(&group_id, seq - 1, 1)
            .map_err(TransportError::from)?;
        let stored = stored.into_iter().next().filter(|m| m.sender == device);
        Ok::<_, PostError>(message_dto(stored.expect("posted message is stored")))
    }
    .await;
    match result {
        Ok(message) => Json(message).into_response(),
        Err(err) => post_error(err),
    }
}

async fn messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gid): Path<String>,
    Query(query): Query<v2::MessagesQuery>,
) -> Response {
    let result = async {
        let (token, group_id) = (state.token(&headers)?, group_id(&gid)?);
        let after_seq = query.from_seq.map(|s| s.saturating_sub(1));
        state
            .controls
            .history
            .lock()
            .unwrap()
            .push((group_id.clone(), after_seq));
        let limit = query.limit.unwrap_or(100);
        // Membership check of the fake transport.
        let readable: Vec<GroupMessage> = state
            .transport
            .group_messages(&token, &group_id, after_seq.unwrap_or(0) + 1, limit)
            .await?;
        let messages = state.transport.service().messages(
            &group_id,
            after_seq.unwrap_or(0),
            limit as usize,
        )?;
        assert_eq!(readable.len(), messages.len());
        Ok(v2::MessageList {
            messages: messages.into_iter().map(message_dto).collect(),
            has_more: false,
        })
    }
    .await;
    reply(result)
}

async fn pending_welcomes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<v2::PendingWelcomesQuery>,
) -> Response {
    let result = async {
        let device = state.authenticate(&headers)?;
        let limit = query.limit.unwrap_or(50) as usize;
        let welcomes = state.transport.service().pending_welcomes(&device, limit);
        Ok(v2::PendingWelcomeList {
            welcomes: welcomes
                .into_iter()
                .map(|w| v2::PendingWelcome {
                    welcome: welcome_dto(w),
                    created_at: 0,
                })
                .collect(),
        })
    }
    .await;
    reply(result)
}

async fn ack_welcome(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gid): Path<String>,
) -> Response {
    let result = async {
        let (token, group_id) = (state.token(&headers)?, group_id(&gid)?);
        state.transport.ack_welcome(&token, &group_id).await
    }
    .await;
    no_content(result)
}

async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<v2::EventsQuery>,
) -> Response {
    let device = match state.authenticate(&headers) {
        Ok(device) => device,
        Err(err) => return transport_error(err),
    };
    state
        .controls
        .polls
        .lock()
        .unwrap()
        .push((query.cursor, query.wait));
    let cursor = query.cursor.unwrap_or(0);
    if cursor < state.controls.events_expired_below.load(Ordering::SeqCst) {
        let body = v2::CursorExpiredError {
            error: v2::ErrorBody {
                code: v2::CURSOR_EXPIRED.into(),
                message: "expired".into(),
            },
            cursor: state.head(&device),
        };
        return (StatusCode::GONE, Json(body)).into_response();
    }
    let limit = query.limit.unwrap_or(100) as usize;
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(query.wait.unwrap_or(0).into());
    loop {
        let (events, next_cursor) = state.visible(&device, cursor, limit);
        if !events.is_empty() || next_cursor != cursor || tokio::time::Instant::now() >= deadline {
            return Json(v2::EventList {
                events,
                next_cursor,
            })
            .into_response();
        }
        tokio::time::sleep(TICK).await;
    }
}

async fn stream(
    State(state): State<AppState>,
    Query(query): Query<v2::StreamQuery>,
    upgrade: WebSocketUpgrade,
) -> Response {
    if state.controls.stream_disabled.load(Ordering::SeqCst) {
        return error(StatusCode::NOT_FOUND, "not_found");
    }
    state
        .controls
        .stream_cursors
        .lock()
        .unwrap()
        .push(query.cursor);
    let device = query
        .token
        .filter(|_| !state.controls.reject.load(Ordering::SeqCst))
        .and_then(|token| state.transport.service().authenticate(&token).ok());
    upgrade.on_upgrade(move |socket| serve_stream(state, device, query.cursor.unwrap_or(0), socket))
}

async fn close(socket: &mut WebSocket, code: u16) {
    let frame = CloseFrame {
        code,
        reason: "".into(),
    };
    let _ = socket.send(Message::Close(Some(frame))).await;
}

async fn serve_stream(
    state: AppState,
    device: Option<DeviceRef>,
    mut cursor: u64,
    mut socket: WebSocket,
) {
    let controls = &state.controls;
    let Some(device) = device else {
        return close(&mut socket, v2::STREAM_CLOSE_UNAUTHORIZED).await;
    };
    let expired_below = controls.stream_expired_below.swap(0, Ordering::SeqCst);
    if cursor < expired_below {
        let frame = v2::StreamFrame::Error {
            error: v2::ErrorBody {
                code: v2::CURSOR_EXPIRED.into(),
                message: "expired".into(),
            },
            cursor: Some(state.head(&device)),
        };
        let text = serde_json::to_string(&frame).unwrap();
        let _ = socket.send(Message::Text(text.into())).await;
        return close(&mut socket, v2::STREAM_CLOSE_CURSOR_EXPIRED).await;
    }
    let drop_after = controls.drop_stream_after.lock().unwrap().take();
    controls.streams_served.fetch_add(1, Ordering::SeqCst);
    let mut sent = 0;
    loop {
        if controls.reject.load(Ordering::SeqCst) {
            return close(&mut socket, v2::STREAM_CLOSE_UNAUTHORIZED).await;
        }
        if controls.kick.swap(false, Ordering::SeqCst) {
            return;
        }
        let (events, next) = state.visible(&device, cursor, 100);
        for event in events {
            if drop_after.is_some_and(|n| sent >= n) {
                return;
            }
            let frame = v2::StreamFrame::Event { event };
            let text = serde_json::to_string(&frame).unwrap();
            if socket.send(Message::Text(text.into())).await.is_err() {
                return;
            }
            sent += 1;
        }
        cursor = next;
        tokio::time::sleep(TICK).await;
    }
}

/// How long a test waits for a condition.
const PATIENCE: Duration = Duration::from_secs(10);

/// Fast reconnects for tests.
pub fn fast_settings() -> SyncSettings {
    SyncSettings {
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(200),
        long_poll_wait: Duration::from_secs(1),
        stream_retry: Duration::from_secs(60),
    }
}

/// A device of a test: over the fake transport directly, or over HTTP and
/// the stream against a [`MockServer`].
pub struct Peer {
    pub client: Client<MemoryStore>,
    pub store: Arc<MemoryStore>,
    pub data_dir: tempfile::TempDir,
}

impl Peer {
    pub async fn fake(transport: &FakeTransport, handle: &str) -> Self {
        Self::register(Arc::new(transport.clone()), handle, SyncSettings::default()).await
    }

    pub async fn http(server: &MockServer, handle: &str, settings: SyncSettings) -> Self {
        let transport = HttpTransport::new(server.url.parse().unwrap()).unwrap();
        Self::register(Arc::new(transport), handle, settings).await
    }

    async fn register(transport: Arc<dyn Transport>, handle: &str, settings: SyncSettings) -> Self {
        let store = Arc::new(MemoryStore::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = ClientBuilder::new(
            store.clone(),
            transport,
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

    pub async fn send_text(&self, group_id: &GroupId, body: &str) -> MessageId {
        let content = Content::Text {
            body: body.to_string(),
        };
        self.client.send(group_id, content).await.unwrap()
    }

    pub fn texts(&self, group_id: &GroupId) -> Vec<String> {
        self.store
            .messages(group_id, None, usize::MAX)
            .unwrap()
            .into_iter()
            .filter_map(|m| match m.content {
                MessageContent::Text { body } => Some(body),
                _ => None,
            })
            .collect()
    }

    pub fn has_chat(&self, group_id: &GroupId) -> bool {
        self.store.chat(group_id).unwrap().is_some()
    }
}

pub async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The next connection state change.
pub async fn next_state(rx: &mut broadcast::Receiver<ConnectionState>) -> ConnectionState {
    tokio::time::timeout(PATIENCE, rx.recv())
        .await
        .expect("timed out waiting for a connection state")
        .unwrap()
}

/// Skips states until `state` is reached.
pub async fn reach_state(rx: &mut broadcast::Receiver<ConnectionState>, state: ConnectionState) {
    while next_state(rx).await != state {}
}

/// Texts of the next `count` messages upserted in `changes`, in order.
pub async fn recv_texts(
    changes: &mut broadcast::Receiver<StateChange>,
    count: usize,
) -> Vec<String> {
    let mut texts = Vec::new();
    while texts.len() < count {
        let change = tokio::time::timeout(PATIENCE, changes.recv())
            .await
            .expect("timed out waiting for message changes")
            .unwrap();
        if let StateChange::MessageUpserted(m) = change {
            if let MessageContent::Text { body } = m.content {
                texts.push(body);
            }
        }
    }
    texts
}

/// Texts of the messages upserted in `changes` so far, in order.
pub fn upserted_texts(changes: &mut broadcast::Receiver<StateChange>) -> Vec<String> {
    let mut texts = Vec::new();
    while let Ok(change) = changes.try_recv() {
        if let StateChange::MessageUpserted(m) = change {
            if let MessageContent::Text { body } = m.content {
                texts.push(body);
            }
        }
    }
    texts
}
