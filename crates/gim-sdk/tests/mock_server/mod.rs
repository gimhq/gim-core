//! In-process mock gim-server for the sync tests: the event, history,
//! stream and registration routes of openapi.json over the shared
//! [`FakeDeliveryService`] of a [`FakeTransport`], with fault controls.
//! Other devices of a test talk to the same service through the
//! `FakeTransport` directly.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use gim_base::model::{MessageContent, StateChange};
use gim_base::{MemoryStore, StateReader};
use gim_common::{DeviceRef, GroupId, MessageId, UserId};
use gim_proto::dto::{self, EventData};
use gim_proto::envelope::Content;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::Transport;
use gim_sdk::{Client, ClientBuilder, ConnectionState, HttpTransport, SecretStorage, SyncSettings};
use gim_test::{Delivered, Event, StreamEvent};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Server-side polling interval of long-polls and streams.
const TICK: Duration = Duration::from_millis(10);

#[derive(Debug, Default)]
pub struct Controls {
    /// `/v1/stream` answers 404 when unset.
    pub stream_disabled: AtomicBool,
    /// The next stream connection drops (without a close frame) after this
    /// many events.
    pub drop_stream_after: Mutex<Option<usize>>,
    /// Open streams drop now (without a close frame).
    pub kick: AtomicBool,
    /// Message events (group, seq) never delivered as events; they stay in
    /// the group history.
    pub hidden: Mutex<BTreeSet<(GroupId, u64)>>,
    /// `GET /v1/events` with a cursor below this answers 410 (0: off).
    pub events_expired_below: AtomicU64,
    /// The next stream connection with a cursor below this gets a
    /// `cursor_expired` frame and close 4410 (0: off).
    pub stream_expired_below: AtomicU64,
    /// Tokens are rejected: 401, or close 4401 on streams.
    pub reject: AtomicBool,
    /// `cursor` of every stream connection.
    pub stream_cursors: Mutex<Vec<Option<u64>>>,
    /// `(cursor, wait)` of every `GET /v1/events`.
    pub polls: Mutex<Vec<(Option<u64>, Option<u32>)>>,
    /// `(group, after_seq)` of every history request.
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
    pub async fn start(transport: FakeTransport) -> Self {
        let controls = Arc::new(Controls::default());
        let state = AppState {
            transport,
            controls: controls.clone(),
        };
        let app = Router::new()
            .route("/v1/devices", post(register))
            .route("/v1/keypackages", post(upload_key_packages))
            .route("/v1/me", get(me))
            .route("/v1/groups/{group_id}", get(group))
            .route("/v1/groups/{group_id}/messages", get(messages))
            .route("/v1/events", get(events))
            .route("/v1/stream", get(stream))
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
    let body = dto::ErrorResponse {
        error: dto::ErrorBody {
            code: code.to_string(),
            message: code.to_string(),
        },
    };
    (status, Json(body)).into_response()
}

impl AppState {
    fn authenticate(&self, headers: &HeaderMap) -> Result<DeviceRef, Response> {
        let unauthorized = || error(StatusCode::UNAUTHORIZED, "unauthorized");
        if self.controls.reject.load(Ordering::SeqCst) {
            return Err(unauthorized());
        }
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(unauthorized)?;
        self.transport
            .service()
            .authenticate(token)
            .map_err(|_| unauthorized())
    }

    /// Events of `device` after `cursor` minus the hidden ones, and the
    /// cursor after all of them.
    fn visible(&self, device: &DeviceRef, cursor: u64, limit: usize) -> (Vec<dto::Event>, u64) {
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

fn message_dto(m: Delivered) -> dto::Message {
    dto::Message {
        group_id: m.group_id,
        seq: m.seq,
        sender_device_id: m.sender.device_id,
        sender_user_id: m.sender.user_id,
        client_id: m.client_id,
        kind: match m.kind {
            gim_test::MessageKind::Commit => dto::MessageKind::Commit,
            gim_test::MessageKind::Welcome => dto::MessageKind::Welcome,
            gim_test::MessageKind::Application => dto::MessageKind::Application,
        },
        epoch: m.epoch,
        payload: m.payload,
        recipients: (!m.recipients.is_empty())
            .then(|| m.recipients.into_iter().map(|d| d.device_id).collect()),
        created_at: 0,
    }
}

fn event_dto(e: StreamEvent) -> dto::Event {
    let membership = |group_id: GroupId, device: DeviceRef| dto::MembershipChange {
        group_id,
        device_ids: vec![device.device_id.clone()],
        by_device_id: device.device_id,
    };
    let data = match e.event {
        Event::Message(m) => EventData::Message(message_dto(m)),
        Event::MemberAdded { group_id, device } => {
            EventData::MemberAdded(membership(group_id, device))
        }
        Event::MemberRemoved { group_id, device } => {
            EventData::MemberRemoved(membership(group_id, device))
        }
        Event::KeyPackagesLow { available } => EventData::KeyPackagesLow(dto::KeyPackagesLow {
            available: available as u64,
        }),
    };
    dto::Event {
        cursor: e.cursor,
        created_at: 0,
        data,
    }
}

async fn register(
    State(state): State<AppState>,
    Json(request): Json<dto::RegisterDeviceRequest>,
) -> Response {
    let registration = state
        .transport
        .service()
        .register_device(&request.handle, &request.display_name);
    Json(dto::RegisterDeviceResponse {
        user_id: registration.device.user_id,
        device_id: registration.device.device_id,
        token: registration.token,
        cursor: registration.cursor,
    })
    .into_response()
}

async fn upload_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<dto::UploadKeyPackagesRequest>,
) -> Response {
    let device = match state.authenticate(&headers) {
        Ok(device) => device,
        Err(response) => return response,
    };
    let service = state.transport.service();
    service.upload_key_packages(&device, request.key_packages, request.last_resort);
    Json(dto::KeyPackageCount {
        available: service.key_package_count(&device) as u64,
        has_last_resort: true,
    })
    .into_response()
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match state.authenticate(&headers) {
        Ok(device) => Json(dto::Me {
            user_id: device.user_id,
            device_id: device.device_id,
            handle: String::new(),
            display_name: String::new(),
        })
        .into_response(),
        Err(response) => response,
    }
}

async fn group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<GroupId>,
) -> Response {
    let device = match state.authenticate(&headers) {
        Ok(device) => device,
        Err(response) => return response,
    };
    let Ok(info) = state.transport.service().group(&group_id) else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    if !info.members.contains(&device) {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    Json(dto::Group {
        group_id: info.group_id,
        kind: match info.kind {
            gim_test::GroupKind::Direct => dto::GroupKind::Direct,
            gim_test::GroupKind::Group => dto::GroupKind::Group,
        },
        epoch: info.epoch,
        created_by_device_id: device.device_id,
        created_at: 0,
        members: info
            .members
            .into_iter()
            .map(|d| dto::GroupMember {
                device_id: d.device_id,
                user_id: d.user_id,
            })
            .collect(),
    })
    .into_response()
}

/// Group history as this device may see it: Welcomes addressed to other
/// devices are left out, so their seqs look like holes.
async fn messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<GroupId>,
    Query(query): Query<dto::MessagesQuery>,
) -> Response {
    let device = match state.authenticate(&headers) {
        Ok(device) => device,
        Err(response) => return response,
    };
    state
        .controls
        .history
        .lock()
        .unwrap()
        .push((group_id.clone(), query.after_seq));
    let limit = query.limit.unwrap_or(100) as usize;
    let Ok(messages) =
        state
            .transport
            .service()
            .messages(&group_id, query.after_seq.unwrap_or(0), limit)
    else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    let messages = messages
        .into_iter()
        .filter(|m| m.kind != gim_test::MessageKind::Welcome || m.recipients.contains(&device))
        .map(message_dto)
        .collect();
    Json(dto::MessageList {
        messages,
        has_more: false,
    })
    .into_response()
}

async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<dto::EventsQuery>,
) -> Response {
    let device = match state.authenticate(&headers) {
        Ok(device) => device,
        Err(response) => return response,
    };
    state
        .controls
        .polls
        .lock()
        .unwrap()
        .push((query.cursor, query.wait));
    let cursor = query.cursor.unwrap_or(0);
    if cursor < state.controls.events_expired_below.load(Ordering::SeqCst) {
        let body = dto::CursorExpiredError {
            error: dto::ErrorBody {
                code: dto::CURSOR_EXPIRED.into(),
                message: "expired".into(),
            },
            cursor: state.head(&device),
        };
        return (StatusCode::GONE, Json(body)).into_response();
    }
    let limit = query.limit.unwrap_or(100) as usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(query.wait.unwrap_or(0).into());
    loop {
        let (events, next_cursor) = state.visible(&device, cursor, limit);
        if !events.is_empty() || next_cursor != cursor || tokio::time::Instant::now() >= deadline {
            return Json(dto::EventList {
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
    headers: HeaderMap,
    Query(query): Query<dto::StreamQuery>,
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
    let device = state.authenticate(&headers).ok();
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
        return close(&mut socket, dto::STREAM_CLOSE_UNAUTHORIZED).await;
    };
    let expired_below = controls.stream_expired_below.swap(0, Ordering::SeqCst);
    if cursor < expired_below {
        let frame = dto::StreamFrame::Error {
            error: dto::ErrorBody {
                code: dto::CURSOR_EXPIRED.into(),
                message: "expired".into(),
            },
            cursor: Some(state.head(&device)),
        };
        let text = serde_json::to_string(&frame).unwrap();
        let _ = socket.send(Message::Text(text.into())).await;
        return close(&mut socket, dto::STREAM_CLOSE_CURSOR_EXPIRED).await;
    }
    let drop_after = controls.drop_stream_after.lock().unwrap().take();
    let mut sent = 0;
    loop {
        if controls.reject.load(Ordering::SeqCst) {
            return close(&mut socket, dto::STREAM_CLOSE_UNAUTHORIZED).await;
        }
        if controls.kick.swap(false, Ordering::SeqCst) {
            return;
        }
        let (events, next) = state.visible(&device, cursor, 100);
        for event in events {
            if drop_after.is_some_and(|n| sent >= n) {
                return;
            }
            let frame = dto::StreamFrame::Event { event };
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
