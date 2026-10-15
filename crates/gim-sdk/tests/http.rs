//! `HttpTransport` against an in-process mock hub (API v2): request shapes,
//! response mapping and error mapping.

use std::time::{Duration, Instant};

use gim_base::model::{ChatKind, IncomingEvent, MessageKind};
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use gim_identity::{DeviceSigningKey, RootKey};
use gim_sdk::transport::{
    AccessToken, ClaimedKeyPackage, CommitAccepted, HostingEntryGrant, HubEvent, OutgoingCommit,
    PostError, SessionError, StoredHostingRecord, Transport, TransportError,
};
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

/// A device id of the gim-identity formats: device `n` of user `n`.
fn device(n: u8) -> DeviceRef {
    let user_id = RootKey::from_seed(&[n; 32]).public().user_id();
    let device_id = DeviceSigningKey::from_seed(&[n + 100; 32])
        .public()
        .device_id();
    DeviceRef::new(user_id, device_id)
}

fn user(n: u8) -> UserId {
    device(n).user_id
}

fn uid(n: u8) -> String {
    user(n).to_string()
}

fn did(n: u8) -> String {
    device(n).device_id.to_string()
}

fn gid(id: &str) -> GroupId {
    GroupId::new(id).unwrap()
}

fn error_body(code: &str) -> Value {
    json!({ "error": { "code": code, "message": "nope" } })
}

fn group_json(id: &str, kind: &str, members: &[u8]) -> Value {
    json!({
        "gid": id,
        "kind": kind,
        "epoch": 3,
        "last_seq": 9,
        "created_by_user_id": uid(1),
        "created_by_device_id": did(1),
        "created_at": 1,
        "members": members
            .iter()
            .map(|n| json!({ "user_id": uid(*n), "device_id": did(*n) }))
            .collect::<Vec<_>>(),
    })
}

fn message_json(seq: u64, kind: &str) -> Value {
    json!({
        "gid": "g/1",
        "seq": seq,
        "sender_user_id": uid(2),
        "sender_device_id": did(2),
        "client_id": "c1",
        "kind": kind,
        "epoch": 2,
        "mls_message": "AQID",
        "created_at": 5,
    })
}

fn welcome_json(seq: u64) -> Value {
    json!({
        "gid": "g/1",
        "sender_user_id": uid(2),
        "sender_device_id": did(2),
        "epoch": 3,
        "seq": seq,
        "welcome": "BAU=",
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
async fn put_device_list_without_token() {
    let server = MockServer::start().await;
    let route = format!("/v2/users/{}/device-list", uid(1));
    Mock::given(method("PUT"))
        .and(path(route.as_str()))
        .and(body_json(json!({ "device_list": "AQI=" })))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({ "user_id": uid(1), "device_list": "AQI=" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    transport(&server)
        .put_device_list(&user(1), vec![1, 2])
        .await
        .unwrap();
    let request = &server.received_requests().await.unwrap()[0];
    assert!(request.headers.get("authorization").is_none());
}

#[tokio::test]
async fn sign_in_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/auth/challenge"))
        .and(body_json(json!({ "user_id": uid(1), "device_id": did(1) })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "challenge": "AQID", "expires_at": 1000, "hub_id": "hub.example",
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/auth/session"))
        .and(body_json(json!({ "response": "BAU=" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "token": TOKEN, "expires_at": 5000 })),
        )
        .mount(&server)
        .await;
    // 401 codes: AQ== invalid_challenge, Ag== invalid_signature, Aw==
    // device_not_active, BA== validation_failed (400).
    for (body, status, code) in [
        ("AQ==", 401, "invalid_challenge"),
        ("Ag==", 401, "invalid_signature"),
        ("Aw==", 401, "device_not_active"),
        ("BA==", 400, "validation_failed"),
    ] {
        Mock::given(method("POST"))
            .and(path("/v2/auth/session"))
            .and(body_json(json!({ "response": body })))
            .respond_with(ResponseTemplate::new(status).set_body_json(error_body(code)))
            .mount(&server)
            .await;
    }
    let http = transport(&server);
    let challenge = http.auth_challenge(&device(1)).await.unwrap();
    assert_eq!(challenge.challenge, vec![1, 2, 3]);
    assert_eq!(challenge.hub_id, "hub.example");
    let session = http.create_session(vec![4, 5]).await.unwrap();
    assert_eq!(session.token, token());
    assert_eq!(session.expires_at_ms, 5000);
    assert_eq!(
        http.create_session(vec![1]).await,
        Err(SessionError::InvalidChallenge)
    );
    assert_eq!(
        http.create_session(vec![2]).await,
        Err(SessionError::Rejected("invalid_signature".into()))
    );
    assert_eq!(
        http.create_session(vec![3]).await,
        Err(SessionError::Rejected("device_not_active".into()))
    );
    assert!(matches!(
        http.create_session(vec![4]).await,
        Err(SessionError::Transport(TransportError::Server(m))) if m.contains("400")
    ));
}

#[tokio::test]
async fn users_and_handles() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        &format!("/v2/users/{}", uid(2)),
        ResponseTemplate::new(200).set_body_json(json!({
            "user_id": uid(2), "device_list": "AQI=", "handle": "bob",
        })),
    )
    .await;
    mount(
        &server,
        "GET",
        &format!("/v2/users/{}", uid(3)),
        ResponseTemplate::new(404).set_body_json(error_body("not_found")),
    )
    .await;
    mount(
        &server,
        "GET",
        "/v2/handles/bob",
        ResponseTemplate::new(200).set_body_json(json!({ "handle": "bob", "user_id": uid(2) })),
    )
    .await;
    mount(
        &server,
        "GET",
        "/v2/handles/nobody",
        ResponseTemplate::new(404).set_body_json(error_body("not_found")),
    )
    .await;
    mount(
        &server,
        "PUT",
        "/v2/handles/al%20ice",
        ResponseTemplate::new(200).set_body_json(json!({ "handle": "al ice", "user_id": uid(1) })),
    )
    .await;
    mount(
        &server,
        "DELETE",
        "/v2/handles/al%20ice",
        ResponseTemplate::new(204),
    )
    .await;
    let http = transport(&server);
    let record = http.user(Some(&token()), &user(2)).await.unwrap().unwrap();
    assert_eq!(record.user_id, user(2));
    assert_eq!(record.device_list, vec![1, 2]);
    assert_eq!(record.handle.as_deref(), Some("bob"));
    assert_eq!(http.user(Some(&token()), &user(3)).await, Ok(None));
    assert_eq!(http.find_handle(&token(), "bob").await, Ok(Some(user(2))));
    assert_eq!(http.find_handle(&token(), "nobody").await, Ok(None));
    http.claim_handle(&token(), "al ice").await.unwrap();
    http.release_handle(&token(), "al ice").await.unwrap();
}

#[tokio::test]
async fn upload_key_packages() {
    let server = MockServer::start().await;
    for (body, last_resort) in [
        (json!({ "key_packages": ["AQ==", "Ag=="] }), false),
        (
            json!({ "key_packages": ["Aw=="], "last_resort": true }),
            true,
        ),
    ] {
        Mock::given(method("POST"))
            .and(path("/v2/keypackages"))
            .and(header("authorization", BEARER))
            .and(body_json(body))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "available": 2, "has_last_resort": last_resort })),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let http = transport(&server);
    http.upload_key_packages(&token(), vec![vec![1], vec![2]], false)
        .await
        .unwrap();
    http.upload_key_packages(&token(), vec![vec![3]], true)
        .await
        .unwrap();
}

#[tokio::test]
async fn claim_key_packages_by_user() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/keypackages/claim"))
        .and(header("authorization", BEARER))
        .and(body_json(json!({
            "targets": [{ "user_id": uid(2) }, { "user_id": uid(3) }],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key_packages": [{
                "user_id": uid(2), "device_id": did(2), "key_package": "BAU=", "last_resort": false,
            }],
            "missing": [{ "user_id": uid(3) }],
            "unavailable": [],
        })))
        .mount(&server)
        .await;
    let claimed = transport(&server)
        .claim_key_packages(&token(), &[user(2), user(3)])
        .await
        .unwrap();
    assert_eq!(
        claimed,
        vec![ClaimedKeyPackage {
            device: device(2),
            key_package: vec![4, 5],
        }]
    );
}

#[tokio::test]
async fn create_group_and_group_info() {
    let server = MockServer::start().await;
    // The hub assigns the gid; '/' is percent-encoded in paths.
    let group = group_json("hub.example/g1", "direct", &[1, 2]);
    Mock::given(method("POST"))
        .and(path("/v2/groups"))
        .and(header("authorization", BEARER))
        .and(body_json(json!({ "kind": "direct" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(&group))
        .mount(&server)
        .await;
    mount(
        &server,
        "GET",
        "/v2/groups/hub.example%2Fg1",
        ResponseTemplate::new(200).set_body_json(&group),
    )
    .await;
    mount(
        &server,
        "GET",
        "/v2/groups",
        ResponseTemplate::new(200).set_body_json(json!({ "groups": [group] })),
    )
    .await;
    let http = transport(&server);
    let group_id = http.create_group(&token(), ChatKind::Direct).await.unwrap();
    assert_eq!(group_id, gid("hub.example/g1"));
    let info = http.group_info(&token(), &group_id).await.unwrap();
    assert_eq!(info.kind, ChatKind::Direct);
    assert_eq!(info.epoch, 3);
    assert_eq!(info.last_seq, 9);
    assert_eq!(info.members, vec![device(1), device(2)]);
    assert_eq!(http.list_groups(&token()).await.unwrap(), vec![info]);
}

#[tokio::test]
async fn submit_commit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g%2F1/commits"))
        .and(header("authorization", BEARER))
        .and(body_json(json!({
            "client_id": "c1", "mls_message": "AQID", "welcome": "BAU=",
            "welcome_recipients": [{ "user_id": uid(2), "device_id": did(2) }],
        })))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({ "seq": 7, "epoch": 3, "duplicate": false })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g%2F1/commits"))
        .and(body_json(
            json!({ "client_id": "c2", "mls_message": "AQID" }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "seq": 8, "epoch": 4, "duplicate": true })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g%2F1/commits"))
        .and(body_json(
            json!({ "client_id": "c3", "mls_message": "AQID" }),
        ))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": { "code": "stale_epoch", "message": "stale" }, "current_epoch": 5,
        })))
        .mount(&server)
        .await;
    let http = transport(&server);
    let commit = |client_id: &str, welcome: bool| OutgoingCommit {
        client_id: ClientId::new(client_id).unwrap(),
        mls_message: vec![1, 2, 3],
        welcome: welcome.then(|| vec![4, 5]),
        welcome_recipients: if welcome { vec![device(2)] } else { vec![] },
    };
    let g = gid("g/1");
    assert_eq!(
        http.submit_commit(&token(), &g, commit("c1", true)).await,
        Ok(CommitAccepted {
            seq: 7,
            epoch: 3,
            duplicate: false
        })
    );
    assert_eq!(
        http.submit_commit(&token(), &g, commit("c2", false)).await,
        Ok(CommitAccepted {
            seq: 8,
            epoch: 4,
            duplicate: true
        })
    );
    assert_eq!(
        http.submit_commit(&token(), &g, commit("c3", false)).await,
        Err(PostError::StaleEpoch { current_epoch: 5 })
    );
}

#[tokio::test]
async fn post_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g%2F1/messages"))
        .and(header("authorization", BEARER))
        .and(body_json(
            json!({ "client_id": "c1", "mls_message": "AQID" }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(message_json(8, "application")))
        .mount(&server)
        .await;
    let seq = transport(&server)
        .post_message(
            &token(),
            &gid("g/1"),
            ClientId::new("c1").unwrap(),
            vec![1, 2, 3],
        )
        .await
        .unwrap();
    assert_eq!(seq, 8);
}

#[tokio::test]
async fn post_message_conflicts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g_1/messages"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": { "code": "stale_epoch", "message": "stale" }, "current_epoch": 3,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g_2/messages"))
        .respond_with(ResponseTemplate::new(409).set_body_json(error_body("conflict")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g_3/messages"))
        .respond_with(ResponseTemplate::new(403).set_body_json(error_body("forbidden")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/groups/g_4/messages"))
        .respond_with(ResponseTemplate::new(413).set_body_json(error_body("payload_too_large")))
        .mount(&server)
        .await;
    let http = transport(&server);
    let post = |g: &'static str| {
        let http = &http;
        async move {
            http.post_message(&token(), &gid(g), ClientId::new("c1").unwrap(), vec![1])
                .await
        }
    };
    assert_eq!(
        post("g_1").await,
        Err(PostError::StaleEpoch { current_epoch: 3 })
    );
    assert!(matches!(
        post("g_2").await,
        Err(PostError::Transport(TransportError::Conflict(_)))
    ));
    assert!(matches!(
        post("g_3").await,
        Err(PostError::Transport(TransportError::Server(_)))
    ));
    assert!(matches!(
        post("g_4").await,
        Err(PostError::Transport(TransportError::TooLarge(_)))
    ));
}

#[tokio::test]
async fn fetch_events_long_poll() {
    let server = MockServer::start().await;
    let membership = json!({
        "gid": "g/1", "user_id": uid(2), "device_ids": [did(2)],
        "by_user_id": uid(1), "by_device_id": did(1), "epoch": 3, "seq": 5,
    });
    let body = json!({
        "events": [
            { "cursor": 11, "created_at": 1, "type": "message", "data": message_json(4, "application") },
            { "cursor": 12, "created_at": 1, "type": "group.member_added", "data": membership },
            { "cursor": 13, "created_at": 1, "type": "keypackages.low", "data": { "available": 1 } },
            { "cursor": 14, "created_at": 1, "type": "future.thing", "data": { "x": 1 } },
            { "cursor": 15, "created_at": 1, "type": "welcome", "data": welcome_json(5) },
            { "cursor": 16, "created_at": 1, "type": "device_list.updated",
              "data": { "user_id": uid(2), "device_list": "AQI=" } },
            // Not a gim-identity user id: skipped.
            { "cursor": 17, "created_at": 1, "type": "device_list.updated",
              "data": { "user_id": "u_b", "device_list": "AQI=" } },
            { "cursor": 18, "created_at": 1, "type": "hosting_record.expiring",
              "data": { "user_id": uid(1), "expires_at": 1_700_000_000_000_i64, "seq": 3 } },
        ],
        "next_cursor": 18,
    });
    Mock::given(method("GET"))
        .and(path("/v2/events"))
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
    assert_eq!(batch.next_cursor, 18);
    assert_eq!(batch.events.len(), 6);
    let HubEvent::Group(IncomingEvent::Message(message)) = &batch.events[0] else {
        panic!("expected a message: {:?}", batch.events[0]);
    };
    assert_eq!(message.group_id, gid("g/1"));
    assert_eq!(message.seq, 4);
    assert_eq!(message.sender, device(2));
    assert_eq!(message.kind, MessageKind::Application);
    assert_eq!(message.payload, vec![1, 2, 3]);
    assert_eq!(message.client_id, Some(ClientId::new("c1").unwrap()));
    assert_eq!(
        batch.events[1],
        HubEvent::Group(IncomingEvent::MemberAdded {
            group_id: gid("g/1"),
            device: device(2)
        })
    );
    assert_eq!(
        batch.events[2],
        HubEvent::Group(IncomingEvent::KeyPackagesLow)
    );
    let HubEvent::Group(IncomingEvent::Message(welcome)) = &batch.events[3] else {
        panic!("expected a welcome: {:?}", batch.events[3]);
    };
    assert_eq!(welcome.kind, MessageKind::Welcome);
    assert_eq!(welcome.seq, 5);
    assert_eq!(welcome.payload, vec![4, 5]);
    assert_eq!(
        batch.events[4],
        HubEvent::DeviceListUpdated {
            user_id: user(2),
            device_list: vec![1, 2]
        }
    );
    assert_eq!(
        batch.events[5],
        HubEvent::HostingRecordExpiring {
            user_id: user(1),
            expires_at_ms: 1_700_000_000_000,
            seq: 3
        }
    );
}

#[tokio::test]
async fn fetch_events_without_cursor_clamps_wait() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v2/events",
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
async fn fetch_events_cursor_expired() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v2/events",
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
async fn pending_welcomes_and_ack() {
    let server = MockServer::start().await;
    let mut pending = welcome_json(5);
    pending["created_at"] = json!(1);
    Mock::given(method("GET"))
        .and(path("/v2/welcomes/pending"))
        .and(header("authorization", BEARER))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "welcomes": [pending] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/welcomes/g%2F1/ack"))
        .and(header("authorization", BEARER))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let http = transport(&server);
    let welcomes = http.pending_welcomes(&token(), 50).await.unwrap();
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0].group_id, gid("g/1"));
    assert_eq!(welcomes[0].kind, MessageKind::Welcome);
    assert_eq!(welcomes[0].sender, device(2));
    assert_eq!(welcomes[0].seq, 5);
    http.ack_welcome(&token(), &gid("g/1")).await.unwrap();
}

#[tokio::test]
async fn group_messages_from_seq_inclusive() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/groups/g%2F1/messages"))
        .and(header("authorization", BEARER))
        .and(query_param("from_seq", "4"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [message_json(4, "commit"), message_json(5, "application")],
            "has_more": false,
        })))
        .mount(&server)
        .await;
    let messages = transport(&server)
        .group_messages(&token(), &gid("g/1"), 4, 50)
        .await
        .unwrap();
    assert_eq!(
        messages.iter().map(|m| m.seq).collect::<Vec<_>>(),
        vec![4, 5]
    );
    assert_eq!(messages[0].kind, MessageKind::Commit);
}

#[tokio::test]
async fn group_messages_skip_proposal_and_unknown_kinds() {
    let server = MockServer::start().await;
    let page = |from: &str, messages: Vec<Value>| {
        Mock::given(method("GET"))
            .and(path("/v2/groups/g%2F1/messages"))
            .and(query_param("from_seq", from))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "messages": messages,
                "has_more": false,
            })))
    };
    // A page of skipped kinds only is followed by the next one.
    page(
        "4",
        vec![message_json(4, "proposal"), message_json(5, "foo")],
    )
    .mount(&server)
    .await;
    page(
        "6",
        vec![message_json(6, "application"), message_json(7, "proposal")],
    )
    .mount(&server)
    .await;
    page("8", vec![]).mount(&server).await;
    let http = transport(&server);
    let messages = http
        .group_messages(&token(), &gid("g/1"), 4, 2)
        .await
        .unwrap();
    assert_eq!(messages.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![6]);
    let messages = http
        .group_messages(&token(), &gid("g/1"), 8, 2)
        .await
        .unwrap();
    assert!(messages.is_empty());

    // Message events of those kinds are dropped.
    Mock::given(method("GET"))
        .and(path("/v2/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "events": [
                {"cursor": 1, "created_at": 0, "type": "message", "data": message_json(4, "proposal")},
                {"cursor": 2, "created_at": 0, "type": "message", "data": message_json(5, "foo")},
                {"cursor": 3, "created_at": 0, "type": "message", "data": message_json(6, "application")},
            ],
            "next_cursor": 3,
        })))
        .mount(&server)
        .await;
    let batch = http
        .fetch_events(&token(), Some(0), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(batch.next_cursor, 3);
    assert!(matches!(
        batch.events.as_slice(),
        [HubEvent::Group(IncomingEvent::Message(m))] if m.seq == 6
    ));
}

#[tokio::test]
async fn upload_blob_streams_file() {
    let server = MockServer::start().await;
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    Mock::given(method("POST"))
        .and(path("/v2/blobs"))
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
        .and(path("/v2/blobs/b_1"))
        .and(header("authorization", BEARER))
        .and(header("range", "bytes=2-4"))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(vec![2u8, 3, 4]))
        .mount(&server)
        .await;
    mount(
        &server,
        "GET",
        "/v2/blobs/b_1",
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
        "/v2/blobs/b_1",
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
        (403, "hosting_record_required"),
        (402, "forbidden"),
    ];
    for (status, code) in cases {
        Mock::given(method("GET"))
            .and(path(format!("/v2/groups/g_{status}")))
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
    assert_eq!(
        info(403).await,
        Err(TransportError::HostingRecordRequired(
            "hosting_record_required: nope".into()
        ))
    );
    assert!(matches!(info(402).await, Err(TransportError::Server(m)) if m.contains("402")));
}

#[tokio::test]
async fn hosting_entry_and_record() {
    let server = MockServer::start().await;
    let entry_route = format!("/v2/users/{}/hosting-entry", uid(1));
    Mock::given(method("POST"))
        .and(path(entry_route.as_str()))
        .and(header("authorization", BEARER))
        .and(body_json(json!({ "priority": 0 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hub_id": "h1", "hub_root_pubkey": "AQI=", "priority": 0, "entry": "AwQ=",
        })))
        .mount(&server)
        .await;
    let record_route = format!("/v2/users/{}/hosting-record", uid(1));
    let record = |seq: u64| {
        json!({
            "user_id": uid(1), "hosting_record": "BQY=", "seq": seq,
            "expires_at": 1_700_000_000_000_i64, "hosted": true,
        })
    };
    Mock::given(method("PUT"))
        .and(path(record_route.as_str()))
        .and(body_json(json!({ "hosting_record": "BQY=" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(record(2)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(record_route.as_str()))
        .and(body_json(json!({ "hosting_record": "AA==" })))
        .respond_with(ResponseTemplate::new(409).set_body_json(error_body("stale_hosting_record")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(record_route.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(record(2)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v2/users/{}/hosting-record", uid(2))))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_body("not_found")))
        .mount(&server)
        .await;

    let http = transport(&server);
    let grant = http
        .create_hosting_entry(&token(), &user(1), 0)
        .await
        .unwrap();
    assert_eq!(
        grant,
        HostingEntryGrant {
            hub_id: "h1".into(),
            hub_root_public_key: vec![1, 2],
            priority: 0,
            entry: vec![3, 4],
        }
    );
    let stored = StoredHostingRecord {
        record: vec![5, 6],
        seq: 2,
        expires_at_ms: 1_700_000_000_000,
        hosted: true,
    };
    assert_eq!(
        http.put_hosting_record(&user(1), vec![5, 6]).await,
        Ok(stored.clone())
    );
    assert_eq!(
        http.put_hosting_record(&user(1), vec![0]).await,
        Err(TransportError::Conflict(
            "stale_hosting_record: nope".into()
        ))
    );
    assert_eq!(http.hosting_record(&user(1)).await, Ok(Some(stored)));
    assert_eq!(http.hosting_record(&user(2)).await, Ok(None));

    // Record uploads and reads carry no token.
    let requests = server.received_requests().await.unwrap();
    for request in requests.iter().filter(|r| r.url.path() == record_route) {
        assert!(!request.headers.contains_key("authorization"));
    }
}

#[tokio::test]
async fn invalid_json_is_a_server_error() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/v2/groups/g_1",
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
        "/v2/groups/g_1",
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

    // The URL in the error keeps its path but loses its query.
    match http.group_messages(&token(), &gid("g_1"), 7, 10).await {
        Err(TransportError::Network(message)) => {
            assert!(message.contains("/v2/groups/g_1"), "{message}");
            assert!(!message.contains('?'), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn base_url_path_prefix_is_kept() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/api/v2/groups/g_1",
        ResponseTemplate::new(200).set_body_json(group_json("g_1", "group", &[])),
    )
    .await;
    let http = transport_at(&format!("{}/api/", server.uri()));
    http.group_info(&token(), &gid("g_1")).await.unwrap();
}

#[tokio::test]
async fn recovery_backup_put_and_get() {
    let server = MockServer::start().await;
    let route = format!("/v2/users/{}/recovery-backup", uid(1));
    let backup = json!({ "user_id": uid(1), "backup": "AQI=", "updated_at": 7 });
    Mock::given(method("PUT"))
        .and(path(route.as_str()))
        .and(header("authorization", BEARER))
        .and(body_json(json!({ "backup": "AQI=" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(&backup))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(&backup))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v2/users/{}/recovery-backup", uid(2))))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_body("not_found")))
        .mount(&server)
        .await;
    let http = transport(&server);
    http.put_recovery_backup(&token(), &user(1), vec![1, 2])
        .await
        .unwrap();
    assert_eq!(http.recovery_backup(&user(1)).await, Ok(Some(vec![1, 2])));
    assert_eq!(http.recovery_backup(&user(2)).await, Ok(None));
    // The restore path has no session.
    let requests = server.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .filter(|r| r.method.as_str() == "GET")
        .all(|r| r.headers.get("authorization").is_none()));
}

#[tokio::test]
async fn link_bundles_post_and_fetch_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/link-bundles"))
        .and(header("authorization", BEARER))
        .and(body_json(json!({
            "link_id": "00ff",
            "sealed_bundle": "AQID",
            // Clamped to the hub's maximum.
            "expires_in": 600,
        })))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({ "link_id": "00ff", "expires_at": 9 })),
        )
        .expect(1)
        .mount(&server)
        .await;
    // The hub deletes the bundle on the first fetch.
    Mock::given(method("GET"))
        .and(path("/v2/link-bundles/00ff"))
        .and(query_param("wait", "30"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "link_id": "00ff", "sealed_bundle": "AQID" })),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/link-bundles/00ff"))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_body("not_found")))
        .with_priority(2)
        .mount(&server)
        .await;
    let http = transport(&server);
    http.post_link_bundle(&token(), "00ff", vec![1, 2, 3], Duration::from_secs(900))
        .await
        .unwrap();
    // `wait` is clamped to 30 s.
    assert_eq!(
        http.fetch_link_bundle("00ff", Duration::from_secs(45))
            .await,
        Ok(Some(vec![1, 2, 3]))
    );
    assert_eq!(
        http.fetch_link_bundle("00ff", Duration::ZERO).await,
        Ok(None)
    );
    let requests = server.received_requests().await.unwrap();
    let fetches: Vec<_> = requests
        .iter()
        .filter(|r| r.method.as_str() == "GET")
        .collect();
    assert_eq!(fetches.len(), 2);
    assert_eq!(fetches[1].url.query(), Some("wait=0"));
    assert!(fetches
        .iter()
        .all(|r| r.headers.get("authorization").is_none()));
}

#[tokio::test]
async fn get_device_list() {
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        &format!("/v2/users/{}/device-list", uid(2)),
        ResponseTemplate::new(200)
            .set_body_json(json!({ "user_id": uid(2), "device_list": "AQI=" })),
    )
    .await;
    mount(
        &server,
        "GET",
        &format!("/v2/users/{}/device-list", uid(3)),
        ResponseTemplate::new(404).set_body_json(error_body("not_found")),
    )
    .await;
    let http = transport(&server);
    assert_eq!(
        http.device_list(Some(&token()), &user(2)).await,
        Ok(Some(vec![1, 2]))
    );
    assert_eq!(http.device_list(Some(&token()), &user(3)).await, Ok(None));
}

#[tokio::test]
async fn public_reads_send_no_token_when_signed_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v2/users/{}/device-list", uid(2))))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "user_id": uid(2), "device_list": "AQI=" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v2/users/{}", uid(2))))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "user_id": uid(2), "device_list": "AQI=" })),
        )
        .mount(&server)
        .await;
    let http = transport(&server);
    assert_eq!(http.device_list(None, &user(2)).await, Ok(Some(vec![1, 2])));
    let record = http.user(None, &user(2)).await.unwrap().unwrap();
    assert_eq!(record.device_list, vec![1, 2]);
    assert_eq!(record.handle, None);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|r| r.headers.get("authorization").is_none()));
}

/// A 429/503 reply of a public read with `Retry-After: retry_after`.
fn throttled(status: u16, code: &str, retry_after: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("retry-after", retry_after)
        .set_body_json(error_body(code))
}

#[tokio::test]
async fn public_read_waits_for_retry_after() {
    let server = MockServer::start().await;
    let route = format!("/v2/users/{}/device-list", uid(2));
    Mock::given(method("GET"))
        .and(path(route.as_str()))
        .respond_with(throttled(429, "rate_limited", "1"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "user_id": uid(2), "device_list": "AQI=" })),
        )
        .mount(&server)
        .await;
    let http = transport(&server);
    let started = Instant::now();
    assert_eq!(http.device_list(None, &user(2)).await, Ok(Some(vec![1, 2])));
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn public_read_gives_up_after_the_retry_budget() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v2/users/{}/device-list", uid(2))))
        .respond_with(throttled(429, "rate_limited", "1"))
        .mount(&server)
        .await;
    // A delay beyond the total budget is not waited for.
    Mock::given(method("GET"))
        .and(path(format!("/v2/users/{}", uid(3))))
        .respond_with(throttled(503, "peer_unavailable", "61"))
        .mount(&server)
        .await;
    let http = transport(&server);
    let started = Instant::now();
    assert_eq!(
        http.device_list(None, &user(2)).await,
        Err(TransportError::RetryLater {
            status: 429,
            retry_after_secs: 1,
            reason: "rate_limited: nope".into(),
        })
    );
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);

    assert_eq!(
        http.user(None, &user(3)).await,
        Err(TransportError::RetryLater {
            status: 503,
            retry_after_secs: 61,
            reason: "peer_unavailable: nope".into(),
        })
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}
