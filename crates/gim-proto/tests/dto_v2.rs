//! Checks every `gim_proto::v2` DTO against the vendored hub v2 contract:
//! field names and required-ness of each `components.schemas` entry, enum
//! values, event types, routes and query parameters, plus JSON round-trips.

use std::collections::BTreeSet;
use std::fmt::Debug;

use gim_proto::v2::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

const USER: &str = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa";
const USER_2: &str = "uciqd6m3zbx2mf7kqnqatr2y4j3x5gxkzavpb5lzsvpi4bxbqwpvacaa";
const DEVICE: &str = "d54ta5gvdyzz26janc6rgmbeagy";
const DEVICE_2: &str = "dqk2hvjm4l7xyb3ztc5rwefn6aa";
const HUB: &str = "hciqgrcknldyy6lbu2splf5frcdqeftipgfikjxbzeq6x6y55lggapay";
const GID: &str =
    "hciqgrcknldyy6lbu2splf5frcdqeftipgfikjxbzeq6x6y55lggapay/hf4caruf7nbxzmwh5wvgefz6pa";
const CLIENT: &str = "9f1c2a7e-0b44-4d0e-9a51-3c8f1e2d6b70";
const TS: i64 = 1_760_479_200_000;

/// Federation additions of the contract (hosting records, H3) that
/// `gim_proto::v2` does not model yet; the federation client (C3) adds them.
const DEFERRED_SCHEMAS: [&str; 6] = [
    "CreateHostingEntryRequest",
    "HostingEntry",
    "HostingRecord",
    "HostingRecordExpiring",
    "HostingRecordExpiringEvent",
    "PutHostingRecordRequest",
];
const DEFERRED_EVENTS: [&str; 1] = ["hosting_record.expiring"];
const DEFERRED_ROUTES: [&str; 2] = [
    "/v2/users/{user_id}/hosting-entry",
    "/v2/users/{user_id}/hosting-record",
];

fn spec() -> Value {
    serde_json::from_str(include_str!("../contract/hub-v2/openapi.json"))
        .expect("openapi.json parses")
}

/// Parses `json` into `T`, checks it serializes back to the same JSON, and
/// returns the parsed value.
fn round_trip<T: Serialize + DeserializeOwned + Debug>(json: Value) -> T {
    let value: T = serde_json::from_value(json.clone()).expect("deserialize");
    assert_eq!(serde_json::to_value(&value).expect("serialize"), json);
    value
}

/// Type-erased round trip: deserialize into `T` and serialize back.
fn reencode<T: Serialize + DeserializeOwned>(json: Value) -> Result<Value, String> {
    let value: T = serde_json::from_value(json).map_err(|e| e.to_string())?;
    serde_json::to_value(value).map_err(|e| e.to_string())
}

fn message_json() -> Value {
    json!({
        "gid": GID, "seq": 7, "sender_user_id": USER, "sender_device_id": DEVICE,
        "client_id": CLIENT, "kind": "application", "epoch": 3, "mls_message": "AAEC",
        "created_at": TS,
    })
}

fn membership_json() -> Value {
    json!({
        "gid": GID, "user_id": USER_2, "device_ids": [DEVICE_2], "by_user_id": USER,
        "by_device_id": DEVICE, "epoch": 4, "seq": 9,
    })
}

fn welcome_json(ratchet_tree: bool) -> Value {
    let mut welcome = json!({
        "gid": GID, "sender_user_id": USER, "sender_device_id": DEVICE, "epoch": 4,
        "seq": 9, "welcome": "AQID",
    });
    if ratchet_tree {
        welcome["ratchet_tree"] = json!("/w==");
    }
    welcome
}

fn group_json() -> Value {
    json!({
        "gid": GID, "kind": "group", "epoch": 2, "last_seq": 11,
        "created_by_user_id": USER, "created_by_device_id": DEVICE, "created_at": TS,
        "members": [{"user_id": USER, "device_id": DEVICE}],
    })
}

fn event_json(cursor: u64, event_type: &str, data: Value) -> Value {
    json!({"cursor": cursor, "created_at": TS, "type": event_type, "data": data})
}

fn error_json() -> Value {
    json!({"code": "not_found", "message": "no such group"})
}

/// One `components.schemas` entry: a JSON value with every property, one with
/// only the required properties, and the DTO round trip for both.
struct Case {
    schema: &'static str,
    full: Value,
    min: Value,
    reencode: fn(Value) -> Result<Value, String>,
}

fn case<T: Serialize + DeserializeOwned>(schema: &'static str, full: Value, min: Value) -> Case {
    Case {
        schema,
        full,
        min,
        reencode: reencode::<T>,
    }
}

fn cases() -> Vec<Case> {
    let b = || json!("AAEC");
    vec![
        case::<Health>(
            "Health",
            json!({"status": "ok", "version": "0.1.0"}),
            json!({"status": "ok", "version": "0.1.0"}),
        ),
        case::<AuthChallengeRequest>(
            "AuthChallengeRequest",
            json!({"user_id": USER, "device_id": DEVICE}),
            json!({"user_id": USER, "device_id": DEVICE}),
        ),
        case::<AuthChallenge>(
            "AuthChallenge",
            json!({"challenge": b(), "expires_at": TS, "hub_id": HUB}),
            json!({"challenge": b(), "expires_at": TS, "hub_id": HUB}),
        ),
        case::<CreateSessionRequest>(
            "CreateSessionRequest",
            json!({"response": b()}),
            json!({"response": b()}),
        ),
        case::<Session>(
            "Session",
            json!({"token": "tok", "expires_at": TS}),
            json!({"token": "tok", "expires_at": TS}),
        ),
        case::<Me>(
            "Me",
            json!({"user_id": USER, "device_id": DEVICE, "handle": "alice"}),
            json!({"user_id": USER, "device_id": DEVICE}),
        ),
        case::<User>(
            "User",
            json!({"user_id": USER, "device_list": b(), "handle": "alice"}),
            json!({"user_id": USER, "device_list": b()}),
        ),
        case::<DeviceList>(
            "DeviceList",
            json!({"user_id": USER, "device_list": b()}),
            json!({"user_id": USER, "device_list": b()}),
        ),
        case::<PutDeviceListRequest>(
            "PutDeviceListRequest",
            json!({"device_list": b()}),
            json!({"device_list": b()}),
        ),
        case::<Handle>(
            "Handle",
            json!({"handle": "alice", "user_id": USER}),
            json!({"handle": "alice", "user_id": USER}),
        ),
        case::<PutRecoveryBackupRequest>(
            "PutRecoveryBackupRequest",
            json!({"backup": b()}),
            json!({"backup": b()}),
        ),
        case::<RecoveryBackup>(
            "RecoveryBackup",
            json!({"user_id": USER, "backup": b(), "updated_at": TS}),
            json!({"user_id": USER, "backup": b(), "updated_at": TS}),
        ),
        case::<CreateLinkBundleRequest>(
            "CreateLinkBundleRequest",
            json!({"link_id": "lnk", "sealed_bundle": b(), "expires_in": 300}),
            json!({"link_id": "lnk", "sealed_bundle": b(), "expires_in": 300}),
        ),
        case::<LinkBundleCreated>(
            "LinkBundleCreated",
            json!({"link_id": "lnk", "expires_at": TS}),
            json!({"link_id": "lnk", "expires_at": TS}),
        ),
        case::<LinkBundle>(
            "LinkBundle",
            json!({"link_id": "lnk", "sealed_bundle": b()}),
            json!({"link_id": "lnk", "sealed_bundle": b()}),
        ),
        case::<UploadKeyPackagesRequest>(
            "UploadKeyPackagesRequest",
            json!({"key_packages": ["AAEC"], "last_resort": true}),
            json!({"key_packages": ["AAEC", "AQID"]}),
        ),
        case::<KeyPackageCount>(
            "KeyPackageCount",
            json!({"available": 5, "has_last_resort": true}),
            json!({"available": 5, "has_last_resort": false}),
        ),
        case::<ClaimTarget>(
            "ClaimTarget",
            json!({"user_id": USER, "device_id": DEVICE}),
            json!({"user_id": USER}),
        ),
        case::<ClaimKeyPackagesRequest>(
            "ClaimKeyPackagesRequest",
            json!({"targets": [{"user_id": USER}, {"user_id": USER_2, "device_id": DEVICE_2}]}),
            json!({"targets": []}),
        ),
        case::<ClaimKeyPackagesResponse>(
            "ClaimKeyPackagesResponse",
            json!({
                "key_packages": [{"user_id": USER, "device_id": DEVICE, "key_package": b(), "last_resort": false}],
                "missing": [{"user_id": USER_2}],
                "unavailable": [{"user_id": USER_2, "device_id": DEVICE_2}],
            }),
            json!({"key_packages": [], "missing": [], "unavailable": []}),
        ),
        case::<ClaimedKeyPackage>(
            "ClaimedKeyPackage",
            json!({"user_id": USER, "device_id": DEVICE, "key_package": b(), "last_resort": true}),
            json!({"user_id": USER, "device_id": DEVICE, "key_package": b(), "last_resort": false}),
        ),
        case::<Group>("Group", group_json(), group_json()),
        case::<GroupMember>(
            "GroupMember",
            json!({"user_id": USER, "device_id": DEVICE}),
            json!({"user_id": USER, "device_id": DEVICE}),
        ),
        case::<GroupList>(
            "GroupList",
            json!({"groups": [group_json()]}),
            json!({"groups": []}),
        ),
        case::<CreateGroupRequest>(
            "CreateGroupRequest",
            json!({"kind": "direct"}),
            json!({"kind": "group"}),
        ),
        case::<SubmitCommitRequest>(
            "SubmitCommitRequest",
            json!({
                "client_id": CLIENT, "mls_message": b(), "welcome": "AQID",
                "welcome_recipients": [{"user_id": USER_2, "device_id": DEVICE_2}],
                "ratchet_tree": "/w==",
            }),
            json!({"client_id": CLIENT, "mls_message": b()}),
        ),
        case::<CommitResult>(
            "CommitResult",
            json!({"seq": 12, "epoch": 5, "duplicate": true}),
            json!({"seq": 12, "epoch": 5, "duplicate": false}),
        ),
        case::<Message>("Message", message_json(), message_json()),
        case::<SendMessageRequest>(
            "SendMessageRequest",
            json!({"client_id": CLIENT, "mls_message": b()}),
            json!({"client_id": CLIENT, "mls_message": ""}),
        ),
        case::<MessageList>(
            "MessageList",
            json!({"messages": [message_json()], "has_more": true}),
            json!({"messages": [], "has_more": false}),
        ),
        case::<MembershipChange>("MembershipChange", membership_json(), membership_json()),
        case::<Welcome>("Welcome", welcome_json(true), welcome_json(false)),
        case::<KeyPackagesLow>(
            "KeyPackagesLow",
            json!({"available": 2}),
            json!({"available": 0}),
        ),
        case::<Event>(
            "MessageEvent",
            event_json(1, "message", message_json()),
            event_json(1, "message", message_json()),
        ),
        case::<Event>(
            "MemberAddedEvent",
            event_json(2, "group.member_added", membership_json()),
            event_json(2, "group.member_added", membership_json()),
        ),
        case::<Event>(
            "MemberRemovedEvent",
            event_json(3, "group.member_removed", membership_json()),
            event_json(3, "group.member_removed", membership_json()),
        ),
        case::<Event>(
            "WelcomeEvent",
            event_json(4, "welcome", welcome_json(true)),
            event_json(4, "welcome", welcome_json(false)),
        ),
        case::<Event>(
            "KeyPackagesLowEvent",
            event_json(5, "keypackages.low", json!({"available": 1})),
            event_json(5, "keypackages.low", json!({"available": 1})),
        ),
        case::<Event>(
            "DeviceListUpdatedEvent",
            event_json(
                6,
                "device_list.updated",
                json!({"user_id": USER, "device_list": b()}),
            ),
            event_json(
                6,
                "device_list.updated",
                json!({"user_id": USER, "device_list": b()}),
            ),
        ),
        case::<EventList>(
            "EventList",
            json!({"events": [event_json(5, "keypackages.low", json!({"available": 1}))], "next_cursor": 5}),
            json!({"events": [], "next_cursor": 0}),
        ),
        case::<PendingWelcome>(
            "PendingWelcome",
            {
                let mut v = welcome_json(true);
                v["created_at"] = json!(TS);
                v
            },
            {
                let mut v = welcome_json(false);
                v["created_at"] = json!(TS);
                v
            },
        ),
        case::<PendingWelcomeList>(
            "PendingWelcomeList",
            json!({"welcomes": [{
                "gid": GID, "sender_user_id": USER, "sender_device_id": DEVICE, "epoch": 4,
                "seq": 9, "welcome": "AQID", "created_at": TS,
            }]}),
            json!({"welcomes": []}),
        ),
        case::<PushRegistration>(
            "PushRegistration",
            json!({"provider": "apns", "token": "ab12", "app_id": "im.g.apps", "sandbox": true}),
            json!({"provider": "unifiedpush", "token": "https://push.example/x"}),
        ),
        case::<BlobCreated>(
            "BlobCreated",
            json!({"blob_id": "b1", "size": 1024}),
            json!({"blob_id": "b1", "size": 0}),
        ),
        case::<ErrorResponse>(
            "Error",
            json!({"error": error_json()}),
            json!({"error": error_json()}),
        ),
        case::<ErrorBody>("ErrorBody", error_json(), error_json()),
        case::<StaleEpochError>(
            "StaleEpochError",
            json!({"error": {"code": STALE_EPOCH, "message": "stale"}, "current_epoch": 4}),
            json!({"error": {"code": STALE_EPOCH, "message": "stale"}, "current_epoch": 4}),
        ),
        case::<CursorExpiredError>(
            "CursorExpiredError",
            json!({"error": {"code": CURSOR_EXPIRED, "message": "expired"}, "cursor": 900}),
            json!({"error": {"code": CURSOR_EXPIRED, "message": "expired"}, "cursor": 900}),
        ),
    ]
}

/// String-enum schemas and the serialized values of every variant.
fn enums() -> Vec<(&'static str, Vec<Value>)> {
    fn values<T: Serialize>(variants: &[T]) -> Vec<Value> {
        variants
            .iter()
            .map(|v| serde_json::to_value(v).unwrap())
            .collect()
    }
    vec![
        ("HealthStatus", values(&[HealthStatus::Ok])),
        ("GroupKind", values(&[GroupKind::Direct, GroupKind::Group])),
        (
            "MessageKind",
            values(&[MessageKind::Commit, MessageKind::Application]),
        ),
        (
            "PushProvider",
            values(&[
                PushProvider::Apns,
                PushProvider::Fcm,
                PushProvider::UnifiedPush,
                PushProvider::Log,
            ]),
        ),
    ]
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Properties and required names of an object schema, merging `allOf`.
fn shape(spec: &Value, name: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    fn collect(
        spec: &Value,
        schema: &Value,
        props: &mut BTreeSet<String>,
        req: &mut BTreeSet<String>,
    ) {
        if let Some(target) = schema["$ref"].as_str() {
            let name = target.strip_prefix("#/components/schemas/").unwrap();
            return collect(spec, &spec["components"]["schemas"][name], props, req);
        }
        if let Some(parts) = schema["allOf"].as_array() {
            for part in parts {
                collect(spec, part, props, req);
            }
        }
        if let Some(own) = schema["properties"].as_object() {
            props.extend(own.keys().cloned());
        }
        req.extend(strings(&schema["required"]));
    }
    let (mut props, mut req) = (BTreeSet::new(), BTreeSet::new());
    collect(
        spec,
        &spec["components"]["schemas"][name],
        &mut props,
        &mut req,
    );
    (props, req)
}

#[test]
fn schemas_match_dtos() {
    let spec = spec();
    for case in cases() {
        let name = case.schema;
        let (props, required) = shape(&spec, name);
        assert!(
            !props.is_empty(),
            "{name}: not an object schema in openapi.json"
        );

        assert_eq!(keys(&case.full), props, "{name}: property names");
        assert_eq!(keys(&case.min), required, "{name}: required properties");
        for json in [&case.full, &case.min] {
            assert_eq!(
                (case.reencode)(json.clone()).as_ref(),
                Ok(json),
                "{name}: round trip"
            );
        }
        for field in &required {
            let mut partial = case.min.clone();
            partial.as_object_mut().unwrap().remove(field);
            assert!(
                (case.reencode)(partial).is_err(),
                "{name}: accepted a body without required `{field}`"
            );
        }
    }
}

#[test]
fn every_schema_has_a_dto() {
    let spec = spec();
    let all: BTreeSet<String> = keys(&spec["components"]["schemas"]);
    let mut ours: BTreeSet<String> = cases().iter().map(|c| c.schema.to_owned()).collect();
    ours.extend(enums().iter().map(|(name, _)| (*name).to_owned()));
    ours.insert("Event".to_owned());
    ours.extend(DEFERRED_SCHEMAS.iter().map(|name| (*name).to_owned()));
    assert_eq!(
        all, ours,
        "openapi.json schema set changed; update gim_proto::v2"
    );
}

#[test]
fn enums_match() {
    let spec = spec();
    for (name, values) in enums() {
        assert_eq!(
            spec["components"]["schemas"][name]["enum"],
            Value::Array(values),
            "{name}: enum values"
        );
    }
}

#[test]
fn event_types_match() {
    let spec = spec();
    let event = &spec["components"]["schemas"]["Event"];
    let mapping = &event["discriminator"]["mapping"];
    assert_eq!(event["discriminator"]["propertyName"], "type");
    assert_eq!(
        keys(mapping).len(),
        event["oneOf"].as_array().unwrap().len()
    );
    let ours = [
        (EventData::MESSAGE, "MessageEvent"),
        (EventData::MEMBER_ADDED, "MemberAddedEvent"),
        (EventData::MEMBER_REMOVED, "MemberRemovedEvent"),
        (EventData::WELCOME, "WelcomeEvent"),
        (EventData::KEY_PACKAGES_LOW, "KeyPackagesLowEvent"),
        (EventData::DEVICE_LIST_UPDATED, "DeviceListUpdatedEvent"),
    ];
    assert_eq!(
        keys(mapping),
        ours.iter()
            .map(|(t, _)| *t)
            .chain(DEFERRED_EVENTS)
            .map(str::to_owned)
            .collect()
    );
    for (event_type, schema) in ours {
        assert_eq!(
            mapping[event_type],
            format!("#/components/schemas/{schema}")
        );
        let props = &spec["components"]["schemas"][schema]["properties"];
        assert_eq!(props["type"]["enum"], json!([event_type]), "{schema}: type");
    }
}

/// Every route in openapi.json but [`DEFERRED_ROUTES`] is covered by
/// `paths` (34 operations, 3 of them deferred).
#[test]
fn paths_cover_openapi() {
    let spec = spec();
    let routes = keys(&spec["paths"]);
    let operations: usize = spec["paths"]
        .as_object()
        .unwrap()
        .values()
        .map(|item| item.as_object().unwrap().len())
        .sum();
    assert_eq!(operations, 34);

    // Builders called with the template names reproduce the spec's paths
    // once the escaped braces are restored.
    let templated = [
        paths::user("{user_id}"),
        paths::user_device_list("{user_id}"),
        paths::user_recovery_backup("{user_id}"),
        paths::handle("{handle}"),
        paths::link_bundle("{link_id}"),
        paths::group("{gid}"),
        paths::group_commits("{gid}"),
        paths::group_messages("{gid}"),
        paths::welcome_ack("{gid}"),
        paths::blob("{blob_id}"),
    ];
    let mut ours: BTreeSet<String> = [
        paths::HEALTHZ,
        paths::AUTH_CHALLENGE,
        paths::AUTH_SESSION,
        paths::ME,
        paths::KEY_PACKAGES,
        paths::KEY_PACKAGES_CLAIM,
        paths::KEY_PACKAGES_COUNT,
        paths::LINK_BUNDLES,
        paths::GROUPS,
        paths::EVENTS,
        paths::STREAM,
        paths::WELCOMES_PENDING,
        paths::PUSH_REGISTRATION,
        paths::BLOBS,
    ]
    .iter()
    .map(|path| (*path).to_owned())
    .collect();
    ours.extend(
        templated
            .iter()
            .map(|path| path.replace("%7B", "{").replace("%7D", "}")),
    );
    ours.extend(DEFERRED_ROUTES.iter().map(|route| (*route).to_owned()));
    assert_eq!(routes, ours);
}

#[test]
fn query_parameters_match() {
    let spec = spec();
    let cases = [
        (
            "/v2/events",
            serde_json::to_value(EventsQuery {
                cursor: Some(3),
                wait: Some(30),
                limit: Some(100),
            }),
        ),
        (
            "/v2/stream",
            serde_json::to_value(StreamQuery {
                cursor: Some(3),
                token: Some("tok".into()),
            }),
        ),
        (
            "/v2/groups/{gid}/messages",
            serde_json::to_value(MessagesQuery {
                from_seq: Some(1),
                limit: Some(50),
            }),
        ),
        (
            "/v2/welcomes/pending",
            serde_json::to_value(PendingWelcomesQuery { limit: Some(50) }),
        ),
        (
            "/v2/link-bundles/{link_id}",
            serde_json::to_value(LinkBundleQuery { wait: Some(30) }),
        ),
    ];
    for (path, query) in cases {
        let query = query.unwrap();
        let params: BTreeSet<String> = spec["paths"][path]["get"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["in"] == "query")
            .map(|p| p["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(keys(&query), params, "{path}: query parameters");
    }
    for query in [json!({}), json!({"from_seq": 7})] {
        round_trip::<MessagesQuery>(query);
    }
}

#[test]
fn path_parameters_are_percent_encoded() {
    assert_eq!(
        paths::group(GID),
        format!("/v2/groups/{}", GID.replace('/', "%2F"))
    );
    assert_eq!(paths::group_commits("a/b"), "/v2/groups/a%2Fb/commits");
    assert_eq!(paths::group_messages("a/b"), "/v2/groups/a%2Fb/messages");
    assert_eq!(paths::welcome_ack("a/b"), "/v2/welcomes/a%2Fb/ack");
    assert_eq!(paths::user(USER), format!("/v2/users/{USER}"));
    assert_eq!(paths::handle("a b?#%"), "/v2/handles/a%20b%3F%23%25");
    assert_eq!(paths::blob("x-._~"), "/v2/blobs/x-._~");
    assert_eq!(paths::link_bundle("é"), "/v2/link-bundles/%C3%A9");
}

#[test]
fn binary_fields_decode() {
    let upload: UploadKeyPackagesRequest = round_trip(json!({"key_packages": ["AAEC", "AQID"]}));
    assert_eq!(upload.key_packages, vec![vec![0, 1, 2], vec![1, 2, 3]]);
    assert!(!upload.last_resort);

    let commit: SubmitCommitRequest = round_trip(json!({
        "client_id": CLIENT, "mls_message": "AAEC", "welcome": "AQID",
        "welcome_recipients": [{"user_id": USER_2, "device_id": DEVICE_2}], "ratchet_tree": "/w=="
    }));
    assert_eq!(commit.welcome, Some(vec![1, 2, 3]));
    assert_eq!(commit.ratchet_tree, Some(vec![0xff]));
    assert_eq!(commit.welcome_recipients.unwrap()[0].device_id, DEVICE_2);

    let session: CreateSessionRequest = round_trip(json!({"response": "AAEC"}));
    assert_eq!(session.response, vec![0, 1, 2]);

    let err = serde_json::from_value::<ClaimedKeyPackage>(json!({
        "user_id": USER, "device_id": DEVICE, "key_package": "not base64!", "last_resort": false
    }));
    assert!(err.is_err());
}

#[test]
fn explicit_nulls_are_accepted() {
    let commit: SubmitCommitRequest = serde_json::from_value(json!({
        "client_id": CLIENT, "mls_message": "AAEC", "welcome": null,
        "welcome_recipients": null, "ratchet_tree": null
    }))
    .unwrap();
    assert_eq!(commit.welcome, None);
    assert_eq!(commit.welcome_recipients, None);

    let me: Me =
        serde_json::from_value(json!({"user_id": USER, "device_id": DEVICE, "handle": null}))
            .unwrap();
    assert_eq!(me.handle, None);

    let target: ClaimTarget =
        serde_json::from_value(json!({"user_id": USER, "device_id": null})).unwrap();
    assert_eq!(target.device_id, None);
}

#[test]
fn health_and_session() {
    let health: Health = round_trip(json!({"status": "ok", "version": "0.1.0"}));
    assert_eq!(health.status, HealthStatus::Ok);

    let session: Session = round_trip(json!({"token": "secret-token", "expires_at": TS}));
    let debug = format!("{session:?}");
    assert!(!debug.contains("secret-token"), "{debug}");

    let challenge: AuthChallenge =
        round_trip(json!({"challenge": "AAEC", "expires_at": TS, "hub_id": HUB}));
    assert_eq!(challenge.hub_id, HUB);
}

#[test]
fn known_events() {
    let list: EventList = round_trip(json!({
        "events": [
            event_json(1, "message", message_json()),
            event_json(2, "group.member_added", membership_json()),
            event_json(3, "group.member_removed", membership_json()),
            event_json(4, "welcome", welcome_json(true)),
            event_json(5, "keypackages.low", json!({"available": 2})),
            event_json(6, "device_list.updated", json!({"user_id": USER, "device_list": "AAEC"})),
        ],
        "next_cursor": 6
    }));
    let events = list.events;
    assert!(matches!(&events[0].data, EventData::Message(m) if m.kind == MessageKind::Application));
    let change = MembershipChange {
        gid: GID.into(),
        user_id: USER_2.into(),
        device_ids: vec![DEVICE_2.into()],
        by_user_id: USER.into(),
        by_device_id: DEVICE.into(),
        epoch: 4,
        seq: 9,
    };
    assert_eq!(events[1].data, EventData::MemberAdded(change.clone()));
    assert_eq!(events[2].data, EventData::MemberRemoved(change));
    assert!(matches!(&events[3].data, EventData::Welcome(w) if w.ratchet_tree == Some(vec![0xff])));
    assert_eq!(
        events[4].data,
        EventData::KeyPackagesLow(KeyPackagesLow { available: 2 })
    );
    assert_eq!(
        events[5].data,
        EventData::DeviceListUpdated(DeviceList {
            user_id: USER.into(),
            device_list: vec![0, 1, 2],
        })
    );
    assert_eq!(events[5].data.event_type(), "device_list.updated");
}

#[test]
fn unknown_event_type_does_not_fail_the_list() {
    let list: EventList = round_trip(json!({
        "events": [
            event_json(5, "group.renamed", json!({"x": [1, 2]})),
            {"cursor": 6, "created_at": TS, "type": "presence"},
            event_json(7, "keypackages.low", json!({"available": 0})),
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
fn message_id_is_parsed_and_optional() {
    let mut json = message_json();
    json["message_id"] = json!("m-01HZX3");
    let message = round_trip::<Message>(json);
    assert_eq!(message.message_id.as_deref(), Some("m-01HZX3"));
    // Hubs before f4da007 do not send it.
    assert_eq!(round_trip::<Message>(message_json()).message_id, None);
    // In a message event too.
    let mut proposal = message_json();
    proposal["kind"] = json!("proposal");
    proposal["message_id"] = json!("m-2");
    let event: Event = round_trip(event_json(1, "message", proposal));
    assert!(matches!(
        &event.data,
        EventData::Message(m) if m.message_id.as_deref() == Some("m-2") && m.kind == MessageKind::Proposal
    ));
}

#[test]
fn proposal_commit_result_keeps_the_epoch() {
    // A Proposal is sequenced without an epoch change; a resubmit is a
    // duplicate with the original result.
    let first: CommitResult = round_trip(json!({"seq": 8, "epoch": 3, "duplicate": false}));
    let again: CommitResult = round_trip(json!({"seq": 8, "epoch": 3, "duplicate": true}));
    assert_eq!((first.seq, first.epoch), (again.seq, again.epoch));
    assert!(again.duplicate && !first.duplicate);
}

#[test]
fn message_kind_proposal_and_unknown() {
    let mut proposal = message_json();
    proposal["kind"] = json!("proposal");
    assert_eq!(round_trip::<Message>(proposal).kind, MessageKind::Proposal);

    let mut unknown = message_json();
    unknown["kind"] = json!("membership_hint");
    let message: Message = serde_json::from_value(unknown.clone()).unwrap();
    assert_eq!(message.kind, MessageKind::Unknown);

    // A message event of an unknown kind does not fail the event list.
    let list: EventList = serde_json::from_value(json!({
        "events": [event_json(1, "message", unknown), event_json(2, "message", message_json())],
        "next_cursor": 2
    }))
    .unwrap();
    assert!(
        matches!(&list.events[0].data, EventData::Message(m) if m.kind == MessageKind::Unknown)
    );
    assert!(
        matches!(&list.events[1].data, EventData::Message(m) if m.kind == MessageKind::Application)
    );
}

#[test]
fn malformed_known_event_is_an_error() {
    let err = serde_json::from_value::<Event>(event_json(1, "welcome", json!({"gid": GID})));
    assert!(err.is_err());
}

#[test]
fn pending_welcomes() {
    let mut item = welcome_json(true);
    item["created_at"] = json!(TS);
    let list: PendingWelcomeList = round_trip(json!({"welcomes": [item]}));
    let pending = &list.welcomes[0];
    assert_eq!(pending.created_at, TS);
    assert_eq!(pending.welcome.seq, 9);
    assert_eq!(pending.welcome.welcome, vec![1, 2, 3]);
}

#[test]
fn stream_frames() {
    let frame: StreamFrame = round_trip(json!({
        "type": "event",
        "event": event_json(9, "welcome", welcome_json(false)),
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
    assert_eq!(STREAM_CLOSE_CURSOR_EXPIRED, 4410);
    assert_eq!(STREAM_CLOSE_UNAUTHORIZED, 4401);
}
