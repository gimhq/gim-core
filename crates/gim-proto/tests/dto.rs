//! Round-trips every DTO against JSON built from the openapi.json schemas
//! and their examples.

use std::fmt::Debug;

use gim_common::{DeviceId, GroupId, UserId};
use gim_proto::dto::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

const USER: &str = "u_3q2-7wZpQkSx5n1bX0yJ4A";
const DEVICE: &str = "d_V1c9sG0kq4m2T8xYbR7wLg";
const DEVICE_2: &str = "d_Kq7mP2xW9cB4nT6vR1yZ8s";
const GROUP: &str = "g_Zp8nA2vQe5rK1yW6tH3uJw";
const BLOB: &str = "b_Hk4dN7sL2pX9cV0mB5qT1g";
const CLIENT: &str = "9f1c2a7e-0b44-4d0e-9a51-3c8f1e2d6b70";
const TS: i64 = 1_760_479_200_000;

/// Parses `json` into `T`, checks it serializes back to the same JSON, and
/// returns the parsed value.
fn round_trip<T: Serialize + DeserializeOwned + Debug>(json: Value) -> T {
    let value: T = serde_json::from_value(json.clone()).expect("deserialize");
    assert_eq!(serde_json::to_value(&value).expect("serialize"), json);
    value
}

fn message_json(kind: &str, recipients: Option<Value>) -> Value {
    let mut message = json!({
        "group_id": GROUP,
        "seq": 7,
        "sender_device_id": DEVICE,
        "sender_user_id": USER,
        "client_id": CLIENT,
        "kind": kind,
        "epoch": 3,
        "payload": "AAEC",
        "created_at": TS,
    });
    if let Some(recipients) = recipients {
        message["recipients"] = recipients;
    }
    message
}

#[test]
fn health() {
    let health: Health = round_trip(json!({"status": "ok"}));
    assert_eq!(health.status, HealthStatus::Ok);
}

#[test]
fn devices_and_directory() {
    let req: RegisterDeviceRequest =
        round_trip(json!({"handle": "alice", "display_name": "Alice"}));
    assert_eq!(req.handle, "alice");

    let resp: RegisterDeviceResponse = round_trip(json!({
        "user_id": USER, "device_id": DEVICE, "token": "tok", "cursor": 42
    }));
    assert_eq!(resp.user_id.as_str(), USER);
    assert_eq!(resp.cursor, 42);

    let me: Me = round_trip(json!({
        "user_id": USER, "device_id": DEVICE, "handle": "alice", "display_name": "Alice"
    }));
    assert_eq!(me.device_id.as_str(), DEVICE);

    let user: User =
        round_trip(json!({"user_id": USER, "handle": "alice", "display_name": "Alice"}));
    assert_eq!(user.display_name, "Alice");

    let devices: UserDevices = round_trip(json!({
        "devices": [{"device_id": DEVICE, "created_at": TS}]
    }));
    assert_eq!(devices.devices[0].created_at, TS);

    round_trip::<UsersQuery>(json!({"handle": "alice"}));
}

#[test]
fn key_packages() {
    let upload: UploadKeyPackagesRequest =
        round_trip(json!({"key_packages": ["AAEC", "AQID"], "last_resort": "/w=="}));
    assert_eq!(upload.key_packages, vec![vec![0, 1, 2], vec![1, 2, 3]]);
    assert_eq!(upload.last_resort, Some(vec![0xff]));

    let upload: UploadKeyPackagesRequest = round_trip(json!({"key_packages": []}));
    assert_eq!(upload.last_resort, None);

    let count: KeyPackageCount = round_trip(json!({"available": 5, "has_last_resort": true}));
    assert!(count.has_last_resort);

    round_trip::<ClaimKeyPackagesRequest>(json!({"device_ids": [DEVICE, DEVICE_2]}));

    let claimed: ClaimKeyPackagesResponse = round_trip(json!({
        "key_packages": [{"device_id": DEVICE, "key_package": "AAEC", "last_resort": false}],
        "missing": [DEVICE_2]
    }));
    assert_eq!(claimed.key_packages[0].key_package, vec![0, 1, 2]);
    assert_eq!(claimed.missing[0].as_str(), DEVICE_2);
}

#[test]
fn invalid_base64_is_rejected() {
    let err = serde_json::from_value::<ClaimedKeyPackage>(json!({
        "device_id": DEVICE, "key_package": "not base64!", "last_resort": false
    }));
    assert!(err.is_err());
}

#[test]
fn groups() {
    let group_json = json!({
        "group_id": GROUP,
        "kind": "group",
        "epoch": 2,
        "created_by_device_id": DEVICE,
        "created_at": TS,
        "members": [{"device_id": DEVICE, "user_id": USER}]
    });
    let group: Group = round_trip(group_json.clone());
    assert_eq!(group.kind, GroupKind::Group);
    assert_eq!(group.members[0].user_id.as_str(), USER);

    let list: GroupList = round_trip(json!({"groups": [group_json]}));
    assert_eq!(list.groups, vec![group]);

    let create: CreateGroupRequest =
        round_trip(json!({"kind": "direct", "member_device_ids": [DEVICE_2]}));
    assert_eq!(create.kind, GroupKind::Direct);

    round_trip::<AddMembersRequest>(json!({"device_ids": [DEVICE_2]}));
}

#[test]
fn messages() {
    let send: SendMessageRequest = round_trip(json!({
        "client_id": CLIENT, "epoch": 0, "kind": "welcome", "payload": "AQID",
        "recipients": [DEVICE_2]
    }));
    assert_eq!(send.kind, MessageKind::Welcome);
    assert_eq!(send.payload, vec![1, 2, 3]);
    assert_eq!(send.recipients.unwrap()[0].as_str(), DEVICE_2);

    let send: SendMessageRequest = round_trip(json!({
        "client_id": CLIENT, "epoch": 3, "kind": "application", "payload": ""
    }));
    assert_eq!(send.recipients, None);
    assert!(send.payload.is_empty());

    let message: Message = round_trip(message_json("commit", None));
    assert_eq!(message.seq, 7);
    assert_eq!(message.kind, MessageKind::Commit);
    assert_eq!(message.payload, vec![0, 1, 2]);

    let list: MessageList = round_trip(json!({
        "messages": [message_json("welcome", Some(json!([DEVICE_2])))],
        "has_more": true
    }));
    assert!(list.has_more);

    round_trip::<MessagesQuery>(json!({"after_seq": 7, "limit": 50}));
    round_trip::<MessagesQuery>(json!({}));
}

#[test]
fn error_bodies() {
    let error: ErrorResponse =
        round_trip(json!({"error": {"code": "not_found", "message": "no such group"}}));
    assert_eq!(error.error.code, "not_found");

    let stale: StaleEpochError = round_trip(json!({
        "error": {"code": STALE_EPOCH, "message": "stale epoch"}, "current_epoch": 4
    }));
    assert_eq!(stale.current_epoch, 4);

    let expired: CursorExpiredError = round_trip(json!({
        "error": {"code": CURSOR_EXPIRED, "message": "cursor expired"}, "cursor": 900
    }));
    assert_eq!(expired.cursor, 900);

    // The 409/410 bodies are also plain `Error` bodies.
    let generic: ErrorResponse = serde_json::from_value(json!({
        "error": {"code": STALE_EPOCH, "message": "stale epoch"}, "current_epoch": 4
    }))
    .unwrap();
    assert_eq!(generic.error.code, STALE_EPOCH);
}

#[test]
fn blobs() {
    let blob: BlobCreated = round_trip(json!({"blob_id": BLOB, "size": 1024}));
    assert_eq!(blob.size, 1024);
}

#[test]
fn known_events() {
    let membership = json!({"group_id": GROUP, "device_ids": [DEVICE_2], "by_device_id": DEVICE});
    let list: EventList = round_trip(json!({
        "events": [
            {"cursor": 1, "created_at": TS, "type": "message", "data": message_json("application", None)},
            {"cursor": 2, "created_at": TS, "type": "group.member_added", "data": membership},
            {"cursor": 3, "created_at": TS, "type": "group.member_removed", "data": membership},
            {"cursor": 4, "created_at": TS, "type": "keypackages.low", "data": {"available": 2}}
        ],
        "next_cursor": 4
    }));
    assert_eq!(list.next_cursor, 4);

    let events = list.events;
    assert!(matches!(&events[0].data, EventData::Message(m) if m.kind == MessageKind::Application));
    let change = MembershipChange {
        group_id: GroupId::new(GROUP).unwrap(),
        device_ids: vec![DeviceId::new(DEVICE_2).unwrap()],
        by_device_id: DeviceId::new(DEVICE).unwrap(),
    };
    assert_eq!(events[1].data, EventData::MemberAdded(change.clone()));
    assert_eq!(events[2].data, EventData::MemberRemoved(change));
    assert_eq!(
        events[3].data,
        EventData::KeyPackagesLow(KeyPackagesLow { available: 2 })
    );
    assert_eq!(events[3].cursor, 4);
    assert_eq!(events[3].data.event_type(), "keypackages.low");
}

#[test]
fn unknown_event_type_does_not_fail_the_list() {
    let list: EventList = round_trip(json!({
        "events": [
            {"cursor": 5, "created_at": TS, "type": "group.renamed", "data": {"x": [1, 2]}},
            {"cursor": 6, "created_at": TS, "type": "presence"},
            {"cursor": 7, "created_at": TS, "type": "keypackages.low", "data": {"available": 0}}
        ],
        "next_cursor": 7
    }));
    assert_eq!(
        list.events[0].data,
        EventData::Unknown {
            event_type: "group.renamed".into(),
            data: json!({"x": [1, 2]}),
        }
    );
    assert_eq!(list.events[1].data.event_type(), "presence");
    assert!(matches!(list.events[2].data, EventData::KeyPackagesLow(_)));
}

#[test]
fn malformed_known_event_is_an_error() {
    let err = serde_json::from_value::<Event>(json!({
        "cursor": 1, "created_at": TS, "type": "keypackages.low", "data": {}
    }));
    assert!(err.is_err());
}

#[test]
fn stream_frames() {
    let frame: StreamFrame = round_trip(json!({
        "type": "event",
        "event": {"cursor": 9, "created_at": TS, "type": "keypackages.low", "data": {"available": 1}}
    }));
    assert!(matches!(frame, StreamFrame::Event { event } if event.cursor == 9));

    let frame: StreamFrame = round_trip(json!({
        "type": "error",
        "error": {"code": CURSOR_EXPIRED, "message": "cursor expired"},
        "cursor": 120
    }));
    assert!(
        matches!(frame, StreamFrame::Error { error, cursor: Some(120) } if error.code == CURSOR_EXPIRED)
    );

    let frame: StreamFrame = serde_json::from_value(json!({"type": "ping", "at": TS})).unwrap();
    assert_eq!(frame, StreamFrame::Unknown);

    let frame: StreamFrame = serde_json::from_value(json!({
        "type": "event",
        "event": {"cursor": 10, "created_at": TS, "type": "future.thing", "data": 1}
    }))
    .unwrap();
    assert!(matches!(
        frame,
        StreamFrame::Event { event } if event.data.event_type() == "future.thing"
    ));

    round_trip::<StreamQuery>(json!({"cursor": 3, "token": "tok"}));
    round_trip::<EventsQuery>(json!({"cursor": 3, "wait": 30, "limit": 100}));
}

#[test]
fn paths() {
    let user = UserId::new(USER).unwrap();
    let group = GroupId::new(GROUP).unwrap();
    let device = DeviceId::new(DEVICE).unwrap();

    assert_eq!(paths::HEALTHZ, "/healthz");
    assert_eq!(paths::DEVICES, "/v1/devices");
    assert_eq!(paths::ME, "/v1/me");
    assert_eq!(paths::USERS, "/v1/users");
    assert_eq!(paths::KEY_PACKAGES, "/v1/keypackages");
    assert_eq!(paths::KEY_PACKAGES_COUNT, "/v1/keypackages/count");
    assert_eq!(paths::KEY_PACKAGES_CLAIM, "/v1/keypackages/claim");
    assert_eq!(paths::GROUPS, "/v1/groups");
    assert_eq!(paths::EVENTS, "/v1/events");
    assert_eq!(paths::STREAM, "/v1/stream");
    assert_eq!(paths::BLOBS, "/v1/blobs");
    assert_eq!(paths::user(&user), format!("/v1/users/{USER}"));
    assert_eq!(
        paths::user_devices(&user),
        format!("/v1/users/{USER}/devices")
    );
    assert_eq!(paths::group(&group), format!("/v1/groups/{GROUP}"));
    assert_eq!(
        paths::group_members(&group),
        format!("/v1/groups/{GROUP}/members")
    );
    assert_eq!(
        paths::group_member(&group, &device),
        format!("/v1/groups/{GROUP}/members/{DEVICE}")
    );
    assert_eq!(
        paths::group_messages(&group),
        format!("/v1/groups/{GROUP}/messages")
    );
    assert_eq!(paths::blob(BLOB), format!("/v1/blobs/{BLOB}"));
}

/// Every route in the committed openapi.json is covered by `paths`.
#[test]
fn paths_cover_openapi() {
    let spec: Value =
        serde_json::from_str(include_str!("../openapi.json")).expect("openapi.json parses");
    let mut routes: Vec<&str> = spec["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    routes.sort_unstable();
    // Builders called with the template names reproduce the spec's paths.
    let user = UserId::new("{user_id}").unwrap();
    let group = GroupId::new("{group_id}").unwrap();
    let device = DeviceId::new("{device_id}").unwrap();
    let templated = [
        paths::user(&user),
        paths::user_devices(&user),
        paths::group(&group),
        paths::group_members(&group),
        paths::group_member(&group, &device),
        paths::group_messages(&group),
        paths::blob("{blob_id}"),
    ];
    let mut ours = vec![
        paths::HEALTHZ,
        paths::DEVICES,
        paths::ME,
        paths::USERS,
        paths::KEY_PACKAGES,
        paths::KEY_PACKAGES_COUNT,
        paths::KEY_PACKAGES_CLAIM,
        paths::GROUPS,
        paths::EVENTS,
        paths::STREAM,
        paths::BLOBS,
    ];
    ours.extend(templated.iter().map(String::as_str));
    ours.sort_unstable();
    assert_eq!(routes, ours);

    let schemas = spec["components"]["schemas"].as_object().unwrap().len();
    assert_eq!(schemas, 33, "openapi.json schema set changed; update dto");
}
