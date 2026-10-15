//! `HttpTransport` against an in-process mock gim-server: request shapes,
//! response mapping and error mapping.

use std::time::Duration;

use gim_base::model::{ChatKind, IncomingEvent, MessageKind};
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use gim_sdk::transport::{AccessToken, OutgoingMessage, PostError, Transport, TransportError};
use gim_sdk::{HttpConfig, HttpTransport};
use serde_json::{json, Value};
use wiremock::matchers::{body_bytes, body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "tok_secret";
const BEARER: &str = "Bearer tok_secret";

fn token() -> AccessToken {
    AccessToken::new(TOKEN)
}

fn transport(server: &MockServer) -> HttpTransport {
    transport_at(&server.uri())
}

fn transport_at(uri: &str) -> HttpTransport {
    HttpTransport::new(uri.parse().unwrap()).unwrap()
}

fn device(user: &str, device: &str) -> DeviceRef {
    DeviceRef::parse(user, device).unwrap()
}

fn gid(id: &str) -> GroupId {
    GroupId::new(id).unwrap()
}

fn error_body(code: &str) -> Value {
    json!({ "error": { "code": code, "message": "nope" } })
}

fn group_json(id: &str, kind: &str, members: &[(&str, &str)]) -> Value {
    json!({
        "group_id": id,
        "kind": kind,
        "epoch": 3,
        "created_by_device_id": "d_a",
        "created_at": 1,
        "members": members
            .iter()
            .map(|(u, d)| json!({ "user_id": u, "device_id": d }))
            .collect::<Vec<_>>(),
    })
}

fn message_json(seq: u64, kind: &str) -> Value {
    json!({
        "group_id": "g_1",
        "seq": seq,
        "sender_device_id": "d_b",
        "sender_user_id": "u_b",
        "client_id": "c1",
        "kind": kind,
        "epoch": 2,
        "payload": "AQID",
        "created_at": 5,
    })
}

async fn mount(server: &MockServer, verb: &str, route: &str, response: ResponseTemplate) {
    Mock::given(method(verb))
        .and(path(route))
        .and(header("authorization", BEARER))
        .respond_with(response)
        .mount(server)
        .await;
}

#[tokio::test]
async fn register_device() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/devices"))
        .and(body_json(
            json!({ "handle": "alice", "display_name": "Alice" }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "user_id": "u_a", "device_id": "d_a", "token": TOKEN, "cursor": 42,
        })))
        .mount(&server)
        .await;
    let registration = transport(&server)
        .register_device("alice", "Alice")
        .await
        .unwrap();
    assert_eq!(registration.device, device("u_a", "d_a"));
    assert_eq!(registration.token, token());
    assert_eq!(registration.cursor, 42);
    let request = &server.received_requests().await.unwrap()[0];
    assert!(request.headers.get("authorization").is_none());
}

#[tokio::test]
async fn find_user() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/users"))
        .and(query_param("handle", "bob"))
        .and(header("authorization", BEARER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "u_b", "handle": "bob", "display_name": "Bob",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/users"))
        .and(query_param("handle", "nobody"))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_body("not_found")))
        .mount(&server)
        .await;
    let http = transport(&server);
    let user = http.find_user(&token(), "bob").await.unwrap().unwrap();
    assert_eq!(user.user_id, UserId::new("u_b").unwrap());
    assert_eq!(user.display_name, "Bob");
    assert_eq!(http.find_user(&token(), "nobody").await, Ok(None));
}

#[tokio::test]
async fn list_devices() {
    let server = MockServer::start().await;
    let body = json!({ "devices": [
        { "device_id": "d_1", "created_at": 1 },
        { "device_id": "d_2", "created_at": 2 },
    ]});
    mount(
        &server,
        "GET",
        "/v1/users/u_b/devices",
        ResponseTemplate::new(200).set_body_json(body),
    )
    .await;
    let devices = transport(&server)
        .list_devices(&token(), &UserId::new("u_b").unwrap())
        .await
        .unwrap();
    assert_eq!(devices, vec![device("u_b", "d_1"), device("u_b", "d_2")]);
}

#[tokio::test]
async fn upload_key_packages() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/keypackages"))
        .and(header("authorization", BEARER))
        .and(body_json(
            json!({ "key_packages": ["AQ==", "Ag=="], "last_resort": "Aw==" }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "available": 2, "has_last_resort": true })),
        )
        .expect(1)
        .mount(&server)
        .await;
    transport(&server)
        .upload_key_packages(&token(), vec![vec![1], vec![2]], Some(vec![3]))
        .await
        .unwrap();
}

#[tokio::test]
async fn claim_key_package() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/keypackages/claim"))
        .and(header("authorization", BEARER))
        .and(body_json(json!({ "device_ids": ["d_b"] })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key_packages": [{ "device_id": "d_b", "key_package": "BAU=", "last_resort": false }],
            "missing": [],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/keypackages/claim"))
        .and(body_json(json!({ "device_ids": ["d_c"] })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "key_packages": [], "missing": ["d_c"] })),
        )
        .mount(&server)
        .await;
    let http = transport(&server);
    let kp = http
        .claim_key_package(&token(), &device("u_b", "d_b"))
        .await
        .unwrap();
    assert_eq!(kp, vec![4, 5]);
    assert!(matches!(
        http.claim_key_package(&token(), &device("u_c", "d_c"))
            .await,
        Err(TransportError::NotFound(_))
    ));
}

#[tokio::test]
async fn create_group_and_group_info() {
    let server = MockServer::start().await;
    let group = group_json("g_1", "direct", &[("u_a", "d_a"), ("u_b", "d_b")]);
    Mock::given(method("POST"))
        .and(path("/v1/groups"))
        .and(header("authorization", BEARER))
        .and(body_json(
            json!({ "kind": "direct", "member_device_ids": ["d_b"] }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(&group))
        .mount(&server)
        .await;
    mount(
        &server,
        "GET",
        "/v1/groups/g_1",
        ResponseTemplate::new(200).set_body_json(&group),
    )
    .await;
    let http = transport(&server);
    let group_id = http
        .create_group(&token(), ChatKind::Direct, &[device("u_b", "d_b")])
        .await
        .unwrap();
    assert_eq!(group_id, gid("g_1"));
    let info = http.group_info(&token(), &group_id).await.unwrap();
    assert_eq!(info.kind, ChatKind::Direct);
    assert_eq!(info.epoch, 3);
    assert_eq!(
        info.members,
        vec![device("u_a", "d_a"), device("u_b", "d_b")]
    );
}

#[tokio::test]
async fn add_and_remove_members() {
    let server = MockServer::start().await;
    let group = group_json("g_1", "group", &[("u_a", "d_a")]);
    Mock::given(method("POST"))
        .and(path("/v1/groups/g_1/members"))
        .and(header("authorization", BEARER))
        .and(body_json(json!({ "device_ids": ["d_b", "d_c"] })))
        .respond_with(ResponseTemplate::new(200).set_body_json(&group))
        .expect(1)
        .mount(&server)
        .await;
    for d in ["d_b", "d_c"] {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/groups/g_1/members/{d}")))
            .and(header("authorization", BEARER))
            .respond_with(ResponseTemplate::new(200).set_body_json(&group))
            .expect(1)
            .mount(&server)
            .await;
    }
    let http = transport(&server);
    let devices = [device("u_b", "d_b"), device("u_c", "d_c")];
    http.add_group_members(&token(), &gid("g_1"), &devices)
        .await
        .unwrap();
    http.remove_group_members(&token(), &gid("g_1"), &devices)
        .await
        .unwrap();
}

fn outgoing(kind: MessageKind, recipients: Vec<DeviceRef>) -> OutgoingMessage {
    OutgoingMessage {
        client_id: ClientId::new("c1").unwrap(),
        epoch: 2,
        kind,
        payload: vec![1, 2, 3],
        recipients,
    }
}

#[tokio::test]
async fn post_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/groups/g_1/messages"))
        .and(header("authorization", BEARER))
        .and(body_json(json!({
            "client_id": "c1", "epoch": 2, "kind": "welcome", "payload": "AQID",
            "recipients": ["d_b"],
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(message_json(7, "welcome")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/groups/g_1/messages"))
        .and(body_json(json!({
            "client_id": "c1", "epoch": 2, "kind": "application", "payload": "AQID",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(message_json(8, "application")))
        .mount(&server)
        .await;
    let http = transport(&server);
    let seq = http
        .post_message(
            &token(),
            &gid("g_1"),
            outgoing(MessageKind::Welcome, vec![device("u_b", "d_b")]),
        )
        .await
        .unwrap();
    assert_eq!(seq, 7);
    let seq = http
        .post_message(
            &token(),
            &gid("g_1"),
            outgoing(MessageKind::Application, vec![]),
        )
        .await
        .unwrap();
    assert_eq!(seq, 8);
}

#[tokio::test]
async fn post_message_conflicts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/groups/g_1/messages"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": { "code": "stale_epoch", "message": "stale" }, "current_epoch": 3,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/groups/g_2/messages"))
        .respond_with(ResponseTemplate::new(409).set_body_json(error_body("conflict")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/groups/g_3/messages"))
        .respond_with(ResponseTemplate::new(403).set_body_json(error_body("forbidden")))
        .mount(&server)
        .await;
    let http = transport(&server);
    let post = |g: &'static str| {
        let http = &http;
        async move {
            http.post_message(&token(), &gid(g), outgoing(MessageKind::Commit, vec![]))
                .await
        }
    };
    assert_eq!(
        post("g_1").await,
        Err(PostError::EpochConflict { commit_epoch: 2 })
    );
    assert!(matches!(
        post("g_2").await,
        Err(PostError::Transport(TransportError::Conflict(_)))
    ));
    assert!(matches!(
        post("g_3").await,
        Err(PostError::Transport(TransportError::Server(_)))
    ));
}

#[tokio::test]
async fn fetch_events_long_poll() {
    let server = MockServer::start().await;
    let body = json!({
        "events": [
            { "cursor": 11, "created_at": 1, "type": "message", "data": message_json(4, "application") },
            { "cursor": 12, "created_at": 1, "type": "group.member_added",
              "data": { "group_id": "g_1", "device_ids": ["d_b"], "by_device_id": "d_a" } },
            { "cursor": 13, "created_at": 1, "type": "keypackages.low", "data": { "available": 1 } },
            { "cursor": 14, "created_at": 1, "type": "future.thing", "data": { "x": 1 } },
        ],
        "next_cursor": 14,
    });
    Mock::given(method("GET"))
        .and(path("/v1/events"))
        .and(header("authorization", BEARER))
        .and(query_param("cursor", "10"))
        .and(query_param("wait", "25"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let batch = transport(&server)
        .fetch_events(&token(), Some(10), Duration::from_secs(25))
        .await
        .unwrap();
    assert_eq!(batch.next_cursor, 14);
    assert_eq!(batch.events.len(), 3);
    let IncomingEvent::Message(message) = &batch.events[0] else {
        panic!("expected a message: {:?}", batch.events[0]);
    };
    assert_eq!(message.seq, 4);
    assert_eq!(message.sender, device("u_b", "d_b"));
    assert_eq!(message.kind, MessageKind::Application);
    assert_eq!(message.payload, vec![1, 2, 3]);
    assert_eq!(message.client_id, Some(ClientId::new("c1").unwrap()));
    // The sender of event 11 resolved the device of event 12.
    assert_eq!(
        batch.events[1],
        IncomingEvent::MemberAdded {
            group_id: gid("g_1"),
            device: device("u_b", "d_b")
        }
    );
    assert_eq!(batch.events[2], IncomingEvent::KeyPackagesLow);
}

#[tokio::test]
async fn fetch_events_without_cursor_clamps_wait() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v1/events",
        ResponseTemplate::new(200).set_body_json(json!({ "events": [], "next_cursor": 0 })),
    )
    .await;
    transport(&server)
        .fetch_events(&token(), None, Duration::from_secs(120))
        .await
        .unwrap();
    let request = &server.received_requests().await.unwrap()[0];
    let query: Vec<_> = request.url.query_pairs().into_owned().collect();
    assert_eq!(query, vec![("wait".to_string(), "30".to_string())]);
}

#[tokio::test]
async fn fetch_events_resolves_removed_devices() {
    let server = MockServer::start().await;
    let body = json!({
        "events": [
            { "cursor": 2, "created_at": 1, "type": "group.member_removed",
              "data": { "group_id": "g_1", "device_ids": ["d_c", "d_a", "d_x"], "by_device_id": "d_b" } },
        ],
        "next_cursor": 2,
    });
    mount(
        &server,
        "GET",
        "/v1/events",
        ResponseTemplate::new(200).set_body_json(body),
    )
    .await;
    // d_c is still listed; d_a (this device) only shows up in /v1/me.
    mount(
        &server,
        "GET",
        "/v1/groups/g_1",
        ResponseTemplate::new(200).set_body_json(group_json("g_1", "group", &[("u_c", "d_c")])),
    )
    .await;
    mount(
        &server,
        "GET",
        "/v1/me",
        ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "u_a", "device_id": "d_a", "handle": "alice", "display_name": "Alice",
        })),
    )
    .await;
    let batch = transport(&server)
        .fetch_events(&token(), Some(1), Duration::ZERO)
        .await
        .unwrap();
    let removed = |u, d| IncomingEvent::MemberRemoved {
        group_id: gid("g_1"),
        device: device(u, d),
    };
    // d_x cannot be resolved and is skipped.
    assert_eq!(
        batch.events,
        vec![removed("u_c", "d_c"), removed("u_a", "d_a")]
    );
}

#[tokio::test]
async fn fetch_events_cursor_expired() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v1/events",
        ResponseTemplate::new(410).set_body_json(json!({
            "error": { "code": "cursor_expired", "message": "pruned" }, "cursor": 99,
        })),
    )
    .await;
    assert_eq!(
        transport(&server)
            .fetch_events(&token(), Some(1), Duration::ZERO)
            .await,
        Err(TransportError::Gone { cursor: 99 })
    );
}

#[tokio::test]
async fn group_messages() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/groups/g_1/messages"))
        .and(header("authorization", BEARER))
        .and(query_param("after_seq", "3"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [message_json(4, "commit"), message_json(5, "application")],
            "has_more": false,
        })))
        .mount(&server)
        .await;
    let messages = transport(&server)
        .group_messages(&token(), &gid("g_1"), 3, 50)
        .await
        .unwrap();
    assert_eq!(
        messages.iter().map(|m| m.seq).collect::<Vec<_>>(),
        vec![4, 5]
    );
    assert_eq!(messages[0].kind, MessageKind::Commit);
}

#[tokio::test]
async fn upload_blob_streams_file() {
    let server = MockServer::start().await;
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    Mock::given(method("POST"))
        .and(path("/v1/blobs"))
        .and(header("authorization", BEARER))
        .and(header("content-type", "application/octet-stream"))
        .and(header("content-length", "200000"))
        .and(body_bytes(data.clone()))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({ "blob_id": "b_1", "size": 200000 })),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blob");
    std::fs::write(&file, &data).unwrap();
    let blob_id = transport(&server)
        .upload_blob(&token(), &file)
        .await
        .unwrap();
    assert_eq!(blob_id, "b_1");
}

#[tokio::test]
async fn download_blob_with_range() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/blobs/b_1"))
        .and(header("authorization", BEARER))
        .and(header("range", "bytes=2-4"))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(vec![2u8, 3, 4]))
        .mount(&server)
        .await;
    mount(
        &server,
        "GET",
        "/v1/blobs/b_1",
        ResponseTemplate::new(200).set_body_bytes(vec![0u8, 1, 2, 3, 4, 5]),
    )
    .await;
    let http = transport(&server);
    assert_eq!(
        http.download_blob(&token(), "b_1", Some(2..5)).await,
        Ok(vec![2, 3, 4])
    );
    assert_eq!(
        http.download_blob(&token(), "b_1", None).await,
        Ok(vec![0, 1, 2, 3, 4, 5])
    );
    let requests = server.received_requests().await.unwrap();
    assert!(requests[1].headers.get("range").is_none());
}

#[tokio::test]
async fn download_blob_range_ignored_by_server() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v1/blobs/b_1",
        ResponseTemplate::new(200).set_body_bytes(vec![0u8, 1, 2, 3, 4, 5]),
    )
    .await;
    let http = transport(&server);
    assert_eq!(
        http.download_blob(&token(), "b_1", Some(1..3)).await,
        Ok(vec![1, 2])
    );
    assert!(matches!(
        http.download_blob(&token(), "b_1", Some(4..9)).await,
        Err(TransportError::Server(_))
    ));
}

#[tokio::test]
async fn status_mapping() {
    let server = MockServer::start().await;
    let cases = [
        (401, "unauthorized"),
        (404, "not_found"),
        (409, "conflict"),
        (410, "gone"),
        (500, "internal"),
        (503, "unavailable"),
        (400, "bad_request"),
    ];
    for (status, code) in cases {
        Mock::given(method("GET"))
            .and(path(format!("/v1/groups/g_{status}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(error_body(code)))
            .mount(&server)
            .await;
    }
    let http = transport(&server);
    let info = |status: u16| {
        let http = &http;
        async move {
            http.group_info(&token(), &gid(&format!("g_{status}")))
                .await
        }
    };
    assert_eq!(info(401).await, Err(TransportError::Unauthorized));
    assert_eq!(
        info(404).await,
        Err(TransportError::NotFound("not_found: nope".into()))
    );
    assert_eq!(
        info(409).await,
        Err(TransportError::Conflict("conflict: nope".into()))
    );
    // A 410 without a head cursor is not a usable `Gone`.
    assert!(matches!(info(410).await, Err(TransportError::Server(_))));
    assert_eq!(
        info(500).await,
        Err(TransportError::Server("internal: nope".into()))
    );
    assert_eq!(
        info(503).await,
        Err(TransportError::Server("unavailable: nope".into()))
    );
    assert!(matches!(info(400).await, Err(TransportError::Server(m)) if m.contains("400")));
}

#[tokio::test]
async fn invalid_json_is_a_server_error() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v1/groups/g_1",
        ResponseTemplate::new(200).set_body_string("not json"),
    )
    .await;
    assert!(matches!(
        transport(&server).group_info(&token(), &gid("g_1")).await,
        Err(TransportError::Server(_))
    ));
}

#[tokio::test]
async fn timeouts_and_connect_failures_are_network_errors() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v1/groups/g_1",
        ResponseTemplate::new(200)
            .set_body_json(group_json("g_1", "group", &[]))
            .set_delay(Duration::from_secs(2)),
    )
    .await;
    let config = HttpConfig {
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_millis(200),
    };
    let http = HttpTransport::with_config(server.uri().parse().unwrap(), config).unwrap();
    assert!(matches!(
        http.group_info(&token(), &gid("g_1")).await,
        Err(TransportError::Network(_))
    ));

    // Nothing listens on a port that was just released.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let http = transport_at(&format!("http://127.0.0.1:{port}"));
    assert!(matches!(
        http.group_info(&token(), &gid("g_1")).await,
        Err(TransportError::Network(_))
    ));
}

#[tokio::test]
async fn base_url_path_prefix_is_kept() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/api/v1/groups/g_1",
        ResponseTemplate::new(200).set_body_json(group_json("g_1", "group", &[])),
    )
    .await;
    let http = transport_at(&format!("{}/api/", server.uri()));
    http.group_info(&token(), &gid("g_1")).await.unwrap();
}
