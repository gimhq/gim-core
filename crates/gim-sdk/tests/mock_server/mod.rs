//! In-process mock hub (API v2) for the sync tests: the routes the SDK
//! uses, over the shared [`FakeDeliveryService`] of a [`FakeTransport`],
//! with fault controls. Other devices of a test talk to the same service
//! through the `FakeTransport` directly.
//!
//! [`MockServer::replica`] serves a second listed hub of a multi-homed
//! user: its own identity and sessions, and the events, groups, history and
//! pending Welcomes of another hub's service, as the owner fans everything
//! out to every listed hub (contract `multihoming.md` §2.2); Welcome
//! acknowledgements stay on the replica.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, RawQuery, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use gim_base::model::{ChatKind, GroupMessage, MessageContent, StateChange};
use gim_base::{MemoryStore, StateReader};
use gim_common::{ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{inspect_handshake, HandshakeKind};
use gim_proto::envelope::Content;
use gim_proto::v2::{self, EventData};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{
    AccessToken, OutgoingCommit, PostError, SessionError, StoredHostingRecord, Transport,
    TransportError,
};
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
    /// Tokens are rejected (401, or close 4401 on streams), and sign-ins
    /// fail with 401 `device_not_active`.
    pub reject: AtomicBool,
    /// `cursor` of every stream connection.
    pub stream_cursors: Mutex<Vec<Option<u64>>>,
    /// Raw query string and `Authorization` header of every stream
    /// upgrade request.
    pub stream_requests: Mutex<Vec<(Option<String>, Option<String>)>>,
    /// Stream connections whose serving task has taken the per-connection
    /// controls above; the client may report `Connected` before that.
    pub streams_served: AtomicUsize,
    /// `POST /v2/auth/challenge` requests served.
    pub challenges: AtomicUsize,
    /// `(cursor, wait)` of every `GET /v2/events`.
    pub polls: Mutex<Vec<(Option<u64>, Option<u32>)>>,
    /// `(group, from_seq - 1)` of every history request.
    pub history: Mutex<Vec<(GroupId, Option<u64>)>>,
    /// Messages (group, seq) served with this kind instead of their own,
    /// in events and history.
    pub relabeled: Mutex<BTreeMap<(GroupId, u64), v2::MessageKind>>,
    /// The hub is down: every request answers 503 and open streams drop.
    pub down: AtomicBool,
    /// `(device, group)` of every Welcome acknowledgement served.
    pub acked: Mutex<Vec<(DeviceRef, GroupId)>>,
    /// `GET /v2/events` answered 410.
    pub expired_served: AtomicUsize,
    /// `GET /v2/hub` requests served.
    pub hub_infos: AtomicUsize,
    /// `GET /v2/hub?nonce=` answers with the proof for this nonce instead
    /// of the request's (a replayed proof).
    pub replay_nonce: Mutex<Option<[u8; 32]>>,
    /// `GET /v2/hub?nonce=` answers with a corrupted proof.
    pub corrupt_proof: AtomicBool,
    /// Challenges are re-encoded as AuthChallenge v1 (no `audience_url`).
    pub challenge_v1: AtomicBool,
    /// Challenges are re-encoded as v2 for this `audience_url`.
    pub challenge_url: Mutex<Option<String>>,
    /// `POST /v2/auth/session` requests served.
    pub sessions: AtomicUsize,
    /// The user is suspended: tokens are rejected (401, or close 4401 on
    /// streams), and sign-ins fail with 403 `user_suspended`.
    pub suspended: AtomicBool,
    /// The user policy does not admit the user: tokens are rejected (401,
    /// or close 4401 on streams), sign-ins fail with 403
    /// `user_not_admitted` (after `suspended`), and so does the first
    /// DeviceList upload of a user.
    pub not_admitted: AtomicBool,
    /// Commits and messages of these groups answer 403
    /// `not_admitted_by_peer`.
    pub refused_groups: Mutex<BTreeSet<GroupId>>,
    /// Claim targets reported under `not_admitted` (nothing is claimed).
    pub claim_not_admitted: Mutex<BTreeSet<UserId>>,
    /// Every request served.
    pub requests: AtomicUsize,
}

impl Controls {
    pub fn acked(&self, device: &DeviceRef, group_id: &GroupId) -> bool {
        self.acked
            .lock()
            .unwrap()
            .iter()
            .any(|(d, g)| d == device && g == group_id)
    }
}

#[derive(Clone)]
struct AppState {
    /// Identity, sessions, DeviceLists and writes.
    transport: FakeTransport,
    /// Events, groups, history and pending Welcomes: `transport`'s, or
    /// the replicated hub's.
    data: FakeTransport,
    /// `data` is another hub's.
    replica: bool,
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

    /// Serves `transport`, whose public URL becomes this server's URL.
    pub async fn start(transport: FakeTransport) -> Self {
        Self::serve(transport.clone(), transport, false, true).await
    }

    /// A hub with its own identity and sessions (`transport`, whose public
    /// URL becomes this server's URL) serving the events, groups, history
    /// and pending Welcomes of `owner`.
    pub async fn replica(transport: FakeTransport, owner: FakeTransport) -> Self {
        Self::serve(transport, owner, true, true).await
    }

    /// A relay: forwards every request to the hub `transport`, which keeps
    /// its own public URL (that of another server).
    pub async fn relay(transport: FakeTransport) -> Self {
        Self::serve(transport.clone(), transport, false, false).await
    }

    async fn serve(
        transport: FakeTransport,
        data: FakeTransport,
        replica: bool,
        public: bool,
    ) -> Self {
        let controls = Arc::new(Controls::default());
        let state = AppState {
            transport: transport.clone(),
            data,
            replica,
            controls: controls.clone(),
        };
        let app = Router::new()
            .route(v2::paths::HUB, get(hub))
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
            .route(
                "/v2/users/{user_id}/hosting-entry",
                post(create_hosting_entry),
            )
            .route(
                "/v2/users/{user_id}/hosting-record",
                put(put_hosting_record).get(hosting_record),
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
            .route(
                v2::paths::PUSH_REGISTRATION,
                put(put_push_registration).delete(delete_push_registration),
            )
            .route(v2::paths::EVENTS, get(events))
            .route(v2::paths::STREAM, get(stream))
            .layer(middleware::from_fn_with_state(controls.clone(), down))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        if public {
            transport.set_public_url(Some(&url));
        }
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

async fn down(State(controls): State<Arc<Controls>>, request: Request, next: Next) -> Response {
    controls.requests.fetch_add(1, Ordering::SeqCst);
    if controls.down.load(Ordering::SeqCst) {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    next.run(request).await
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
        TransportError::TooLarge(_) => error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
        TransportError::HostingRecordRequired(_) => {
            error(StatusCode::FORBIDDEN, v2::HOSTING_RECORD_REQUIRED)
        }
        TransportError::Rejected { status, code, .. } => {
            error(StatusCode::from_u16(status).expect("a 4xx status"), &code)
        }
        TransportError::PeerRefused(_) => error(StatusCode::BAD_GATEWAY, v2::PEER_REFUSED),
        TransportError::PeerUnavailable { .. } => {
            error(StatusCode::SERVICE_UNAVAILABLE, v2::PEER_UNAVAILABLE)
        }
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
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

/// A malformed request: 400 `validation_failed`, as on the hub.
fn invalid(err: impl std::fmt::Display) -> TransportError {
    TransportError::Rejected {
        status: 400,
        code: "validation_failed".into(),
        message: err.to_string(),
    }
}

fn user_id(text: &str) -> Result<UserId, TransportError> {
    UserId::new(text).map_err(invalid)
}

fn group_id(text: &str) -> Result<GroupId, TransportError> {
    GroupId::new(text).map_err(invalid)
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
        if self.controls.reject.load(Ordering::SeqCst)
            || self.controls.suspended.load(Ordering::SeqCst)
            || self.controls.not_admitted.load(Ordering::SeqCst)
        {
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

    /// 403 `not_admitted_by_peer` for a post to a refused group.
    #[allow(clippy::result_large_err)]
    fn refused(&self, group_id: &GroupId) -> Result<(), TransportError> {
        if self
            .controls
            .refused_groups
            .lock()
            .unwrap()
            .contains(group_id)
        {
            return Err(TransportError::Rejected {
                status: 403,
                code: v2::NOT_ADMITTED_BY_PEER.into(),
                message: "a peer hub does not admit this user".into(),
            });
        }
        Ok(())
    }

    /// The device of the token if it is a member of the group.
    fn member(&self, headers: &HeaderMap, group_id: &GroupId) -> Result<DeviceRef, TransportError> {
        let device = self.authenticate(headers)?;
        let group = self.data.service().group(group_id)?;
        if !group.members.contains(&device) {
            return Err(TransportError::Rejected {
                status: 403,
                code: "not_member".into(),
                message: "not a member".into(),
            });
        }
        Ok(device)
    }

    /// Events of `device` after `cursor` minus the hidden ones, and the
    /// cursor after all of them.
    fn visible(&self, device: &DeviceRef, cursor: u64, limit: usize) -> (Vec<v2::Event>, u64) {
        let (events, next) = self.data.service().events(device, cursor, limit);
        let hidden = self.controls.hidden.lock().unwrap();
        let events = events
            .into_iter()
            .filter(|e| match &e.event {
                Event::Message(m) => !hidden.contains(&(m.group_id.clone(), m.seq)),
                _ => true,
            })
            .map(event_dto)
            .map(|mut e| {
                if let EventData::Message(m) = &mut e.data {
                    self.relabel(m);
                }
                e
            })
            .collect();
        (events, next)
    }

    fn relabel(&self, m: &mut v2::Message) {
        let key = (group_id(&m.gid).unwrap(), m.seq);
        if let Some(kind) = self.controls.relabeled.lock().unwrap().get(&key) {
            m.kind = *kind;
        }
    }

    fn head(&self, device: &DeviceRef) -> u64 {
        self.data.service().events(device, 0, usize::MAX).1
    }
}

fn message_dto(m: Delivered) -> v2::Message {
    v2::Message {
        gid: m.group_id.to_string(),
        seq: m.seq,
        sender_user_id: m.sender.user_id.to_string(),
        sender_device_id: m.sender.device_id.to_string(),
        client_id: m.client_id.to_string(),
        message_id: format!("{}#{}", m.group_id, m.seq),
        kind: match m.kind {
            gim_test::MessageKind::Commit
                if inspect_handshake(&m.payload)
                    .is_ok_and(|info| info.kind == HandshakeKind::Proposal) =>
            {
                v2::MessageKind::Proposal
            }
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

async fn hub(State(state): State<AppState>, Query(query): Query<v2::HubQuery>) -> Response {
    let controls = &state.controls;
    controls.hub_infos.fetch_add(1, Ordering::SeqCst);
    let result = async {
        let nonce = match query.nonce {
            Some(nonce) => Some(<[u8; 32]>::try_from(nonce).map_err(|_| invalid("nonce"))?),
            None => None,
        };
        let nonce = match *controls.replay_nonce.lock().unwrap() {
            Some(old) if nonce.is_some() => Some(old),
            _ => nonce,
        };
        let mut info = state.transport.hub_info(nonce.as_ref()).await?;
        if controls.corrupt_proof.load(Ordering::SeqCst) {
            if let Some(proof) = info.proof.as_mut() {
                proof[0] ^= 1;
            }
        }
        Ok(v2::HubInfo {
            hub_id: info.hub_id,
            hub_root_pubkey: info.hub_root_public_key,
            version: info.version,
            public_url: info.public_url,
            proof: info.proof,
        })
    }
    .await;
    reply(result)
}

async fn auth_challenge(
    State(state): State<AppState>,
    Json(request): Json<v2::AuthChallengeRequest>,
) -> Response {
    state.controls.challenges.fetch_add(1, Ordering::SeqCst);
    if state.controls.suspended.load(Ordering::SeqCst) {
        return error(StatusCode::FORBIDDEN, v2::USER_SUSPENDED);
    }
    if state.controls.not_admitted.load(Ordering::SeqCst) {
        return error(StatusCode::FORBIDDEN, v2::USER_NOT_ADMITTED);
    }
    let result = async {
        let device = DeviceRef::parse(&request.user_id, &request.device_id).map_err(invalid)?;
        let mut challenge = state.transport.auth_challenge(&device).await?;
        let controls = &state.controls;
        let url = controls.challenge_url.lock().unwrap().clone();
        if url.is_some() || controls.challenge_v1.load(Ordering::SeqCst) {
            let mut decoded = gim_identity::AuthChallenge::from_bytes(&challenge.challenge)
                .map_err(|e| TransportError::Server(e.to_string()))?;
            decoded.audience_url = url;
            challenge.challenge = decoded.to_bytes();
        }
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
    state.controls.sessions.fetch_add(1, Ordering::SeqCst);
    if state.controls.reject.load(Ordering::SeqCst) {
        return error(StatusCode::UNAUTHORIZED, "device_not_active");
    }
    if state.controls.suspended.load(Ordering::SeqCst) {
        return error(StatusCode::FORBIDDEN, v2::USER_SUSPENDED);
    }
    if state.controls.not_admitted.load(Ordering::SeqCst) {
        return error(StatusCode::FORBIDDEN, v2::USER_NOT_ADMITTED);
    }
    match state.transport.create_session(request.response).await {
        Ok(session) => Json(v2::Session {
            token: session.token.as_str().to_string(),
            expires_at: session.expires_at_ms as i64,
        })
        .into_response(),
        Err(SessionError::InvalidChallenge) => error(StatusCode::UNAUTHORIZED, "invalid_challenge"),
        Err(SessionError::Rejected(code)) => error(StatusCode::UNAUTHORIZED, &code),
        Err(SessionError::Transport(err)) => transport_error(err),
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
        if state.controls.not_admitted.load(Ordering::SeqCst)
            && state.transport.device_list(None, &user).await?.is_none()
        {
            return Err(TransportError::Rejected {
                status: 403,
                code: v2::USER_NOT_ADMITTED.into(),
                message: "user is not admitted on this hub".into(),
            });
        }
        state.transport.put_device_list(&user, list.clone()).await?;
        Ok(v2::DeviceList {
            user_id: user.to_string(),
            device_list: list,
        })
    }
    .await;
    reply(result)
}

/// A public read: any bearer token is ignored, as on the hub.
async fn device_list(State(state): State<AppState>, Path(user): Path<String>) -> Response {
    let result = async {
        let user = user_id(&user)?;
        let list = state.transport.device_list(None, &user).await?;
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

async fn create_hosting_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
    Json(request): Json<v2::CreateHostingEntryRequest>,
) -> Response {
    let result = async {
        let (token, user) = (state.token(&headers)?, user_id(&user)?);
        let priority = request.priority.unwrap_or(0);
        let grant = state
            .transport
            .create_hosting_entry(&token, &user, priority)
            .await?;
        Ok(v2::HostingEntry {
            hub_id: grant.hub_id,
            hub_root_pubkey: grant.hub_root_public_key,
            priority: grant.priority,
            entry: grant.entry,
        })
    }
    .await;
    reply(result)
}

fn hosting_record_dto(user: &UserId, stored: StoredHostingRecord) -> v2::HostingRecord {
    v2::HostingRecord {
        user_id: user.to_string(),
        hosting_record: stored.record,
        seq: stored.seq,
        expires_at: stored.expires_at_ms as i64,
        hosted: stored.hosted,
    }
}

async fn put_hosting_record(
    State(state): State<AppState>,
    Path(user): Path<String>,
    Json(request): Json<v2::PutHostingRecordRequest>,
) -> Response {
    let result = async {
        let user = user_id(&user)?;
        let stored = state
            .transport
            .put_hosting_record(&user, request.hosting_record)
            .await?;
        Ok(hosting_record_dto(&user, stored))
    }
    .await;
    match result {
        Err(TransportError::Conflict(_)) => error(StatusCode::CONFLICT, v2::STALE_HOSTING_RECORD),
        result => reply(result),
    }
}

/// A public read, as on the hub.
async fn hosting_record(State(state): State<AppState>, Path(user): Path<String>) -> Response {
    let result = async {
        let user = user_id(&user)?;
        let stored = state.transport.hosting_record(&user).await?;
        let stored = stored.ok_or_else(|| TransportError::NotFound(user.to_string()))?;
        Ok(hosting_record_dto(&user, stored))
    }
    .await;
    reply(result)
}

/// A public read: any bearer token is ignored, as on the hub.
async fn user(State(state): State<AppState>, Path(user): Path<String>) -> Response {
    let result = async {
        let user = user_id(&user)?;
        let record = state.transport.user(None, &user).await?;
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
        let refused = state.controls.claim_not_admitted.lock().unwrap().clone();
        let (not_admitted, users): (Vec<UserId>, Vec<UserId>) =
            users.into_iter().partition(|u| refused.contains(u));
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
            unavailable: Vec::new(),
            not_admitted: not_admitted
                .iter()
                .map(|u| v2::ClaimTarget {
                    user_id: u.to_string(),
                    device_id: None,
                })
                .collect(),
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
        let group_id = group_id(&gid)?;
        if state.replica {
            state.member(&headers, &group_id)?;
        } else {
            let token = state.token(&headers)?;
            state.transport.group_info(&token, &group_id).await?;
        }
        Ok(group_dto(state.data.service().group(&group_id)?))
    }
    .await;
    reply(result)
}

async fn groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result = async {
        let device = state.authenticate(&headers)?;
        let groups = state.data.service().groups_of(&device);
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
        state.refused(&group_id)?;
        let client_id = ClientId::new(request.client_id).map_err(invalid)?;
        let welcome_recipients = request
            .welcome_recipients
            .unwrap_or_default()
            .iter()
            .map(|m| DeviceRef::parse(&m.user_id, &m.device_id))
            .collect::<Result<_, _>>()
            .map_err(invalid)?;
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
        state.refused(&group_id)?;
        let client_id = ClientId::new(request.client_id).map_err(invalid)?;
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
        let messages =
            state
                .data
                .service()
                .messages(&group_id, after_seq.unwrap_or(0), limit as usize)?;
        if state.replica {
            state.member(&headers, &group_id)?;
        } else {
            // Membership check of the fake transport.
            let readable: Vec<GroupMessage> = state
                .transport
                .group_messages(&token, &group_id, after_seq.unwrap_or(0) + 1, limit)
                .await?;
            assert_eq!(readable.len(), messages.len());
        }
        Ok(v2::MessageList {
            messages: messages
                .into_iter()
                .map(message_dto)
                .map(|mut m| {
                    state.relabel(&mut m);
                    m
                })
                .collect(),
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
        let welcomes = if state.replica {
            // Acknowledgements are per hub.
            let acked = state.controls.acked.lock().unwrap().clone();
            state
                .data
                .service()
                .pending_welcomes(&device, usize::MAX)
                .into_iter()
                .filter(|w| !acked.contains(&(device.clone(), w.group_id.clone())))
                .take(limit)
                .collect()
        } else {
            state.transport.service().pending_welcomes(&device, limit)
        };
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

async fn put_push_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<v2::PushRegistration>,
) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        let registration = gim_sdk::PushRegistration {
            provider: body.provider,
            token: body.token,
            app_id: body.app_id,
            sandbox: body.sandbox,
            p256dh: body.p256dh,
            auth: body.auth,
        };
        state
            .transport
            .put_push_registration(&token, &registration)
            .await
    }
    .await;
    no_content(result)
}

async fn delete_push_registration(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result = async {
        let token = state.token(&headers)?;
        state.transport.delete_push_registration(&token).await
    }
    .await;
    no_content(result)
}

async fn ack_welcome(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gid): Path<String>,
) -> Response {
    let result = async {
        let (token, group_id) = (state.token(&headers)?, group_id(&gid)?);
        let device = state.authenticate(&headers)?;
        if !state.replica {
            state.transport.ack_welcome(&token, &group_id).await?;
        }
        state
            .controls
            .acked
            .lock()
            .unwrap()
            .push((device, group_id));
        Ok(())
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
        state.controls.expired_served.fetch_add(1, Ordering::SeqCst);
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
    headers: HeaderMap,
    Query(query): Query<v2::StreamQuery>,
    RawQuery(raw_query): RawQuery,
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
    let authorization = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    state
        .controls
        .stream_requests
        .lock()
        .unwrap()
        .push((raw_query, authorization));
    // Only the Bearer header: the SDK keeps the token out of the URL.
    let token = state.token(&headers).ok().map(|t| t.as_str().to_string());
    let cursor = query.cursor.unwrap_or(0);
    upgrade.on_upgrade(move |socket| serve_stream(state, token, cursor, socket))
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
    token: Option<String>,
    mut cursor: u64,
    mut socket: WebSocket,
) {
    let controls = &state.controls;
    let service = state.transport.service();
    let token = token.unwrap_or_default();
    let Ok(device) = service.authenticate(&token) else {
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
        // The session is re-validated with every batch, like the hub.
        if controls.reject.load(Ordering::SeqCst)
            || controls.suspended.load(Ordering::SeqCst)
            || controls.not_admitted.load(Ordering::SeqCst)
            || service.authenticate(&token).is_err()
        {
            return close(&mut socket, v2::STREAM_CLOSE_UNAUTHORIZED).await;
        }
        if controls.kick.swap(false, Ordering::SeqCst) || controls.down.load(Ordering::SeqCst) {
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
        proposal_commit_delay_min: Duration::from_millis(300),
        proposal_commit_delay_max: Duration::from_millis(600),
        ..SyncSettings::default()
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
