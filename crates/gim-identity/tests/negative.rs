//! Shared negative vectors: every case of `tests/vectors/negative.json` must
//! fail with its `expected_error` code (`docs/identity.md`, "Negative
//! vectors"). After an intentional change, regenerate them with
//! `cargo test -p gim-identity --test negative -- --ignored regenerate`.

use ciborium::Value as Cbor;
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signer, SigningKey};
use gim_identity::{
    parse_user_id, AuthChallenge, AuthResponse, DeviceList, DeviceSigningKey, HostingEntry,
    HubRootKey, HubRootPublicKey, HubRuntimePublicKey, IdentityError, RootKey, RootPublicKey,
    SignedDeviceCert, SignedDeviceList, SignedHostingRecord, SignedHubRuntimeCert,
    UserHostingRecord, AUTH_RESPONSE_CONTEXT, DEVICE_CERT_CONTEXT, DEVICE_LIST_CONTEXT,
    HOSTING_ENTRY_CONTEXT, HOSTING_RECORD_CONTEXT, HUB_RUNTIME_CERT_CONTEXT,
};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/negative.json");
const NOW: u64 = 1_760_486_400_000; // 2025-10-15T00:00:00Z
const DAY: u64 = 86_400_000;
const TTL: u64 = 60_000;

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

const ROOT: u8 = 0x00;
const OTHER_ROOT: u8 = 0xe0;
const DEVICE_A: u8 = 0x20;
const DEVICE_B: u8 = 0x40;
const DEVICE_UNLISTED: u8 = 0x90;
const HUB_A: u8 = 0x60;
const HUB_B: u8 = 0x80;
const RUNTIME: u8 = 0xa0;
const NONCE: u8 = 0xc0;

fn root(start: u8) -> RootKey {
    RootKey::from_seed(&seed(start))
}

fn device(start: u8) -> DeviceSigningKey {
    DeviceSigningKey::from_seed(&seed(start))
}

fn hub(start: u8) -> HubRootKey {
    HubRootKey::from_seed(&seed(start))
}

fn hex(bytes: &[u8]) -> String {
    HEXLOWER.encode(bytes)
}

fn unhex(value: &Value) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

fn encode(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn decode(bytes: &[u8]) -> Cbor {
    ciborium::from_reader(bytes).unwrap()
}

/// Ed25519 over `context || 0x00 || tbs` with the key of `seed`.
fn sign(seed: &[u8; 32], context: &[u8], tbs: &[u8]) -> Vec<u8> {
    let mut message = context.to_vec();
    message.push(0);
    message.extend_from_slice(tbs);
    SigningKey::from_bytes(seed)
        .sign(&message)
        .to_bytes()
        .to_vec()
}

fn envelope(tbs: Vec<u8>, sig: Vec<u8>) -> Vec<u8> {
    encode(&Cbor::Array(vec![Cbor::Bytes(tbs), Cbor::Bytes(sig)]))
}

fn tbs_of(signed: &[u8]) -> Vec<u8> {
    let Cbor::Array(items) = decode(signed) else {
        panic!("not a signed form")
    };
    items[0].as_bytes().unwrap().clone()
}

/// The signed form with its body edited and signed again by `seed`.
fn resign(
    signed: &[u8],
    seed: &[u8; 32],
    context: &[u8],
    edit: impl FnOnce(&mut Vec<Cbor>),
) -> Vec<u8> {
    let Cbor::Array(mut body) = decode(&tbs_of(signed)) else {
        panic!("body is not an array")
    };
    edit(&mut body);
    let tbs = encode(&Cbor::Array(body));
    let sig = sign(seed, context, &tbs);
    envelope(tbs, sig)
}

/// `bytes` with the last byte (the last signature byte of every form here)
/// flipped.
fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    bytes
}

/// `tbs` with the one-byte uint at `at` re-encoded with a one-byte argument
/// (`0x18 n`), signed again by `seed`.
fn non_shortest(signed: &[u8], at: usize, seed: &[u8; 32], context: &[u8]) -> Vec<u8> {
    let mut tbs = tbs_of(signed);
    assert!(tbs[at] < 0x18, "not a one-byte uint");
    tbs.insert(at, 0x18);
    let sig = sign(seed, context, &tbs);
    envelope(tbs, sig)
}

fn text(value: impl Into<String>) -> Cbor {
    Cbor::Text(value.into())
}

fn case(name: &str, kind: &str, input: &[u8], context: Value, expected: &str) -> Value {
    json!({
        "name": name,
        "kind": kind,
        "input_hex": hex(input),
        "context": context,
        "expected_error": expected,
    })
}

fn device_cert_cases(cases: &mut Vec<Value>) {
    let root = root(ROOT);
    let cert = SignedDeviceCert::issue(&root, &device(DEVICE_A).public(), NOW, 1).to_bytes();
    let context = json!({ "root_pubkey": hex(root.public().as_bytes()) });
    let resign = |edit: fn(&mut Vec<Cbor>)| resign(&cert, &seed(ROOT), DEVICE_CERT_CONTEXT, edit);
    let mut add = |name: &str, input: Vec<u8>, expected: &str| {
        cases.push(case(name, "device_cert", &input, context.clone(), expected))
    };

    add(
        "device_cert_bad_signature",
        flip_last(&cert),
        "bad_signature",
    );
    let tbs = tbs_of(&cert);
    let sig = sign(&seed(ROOT), DEVICE_LIST_CONTEXT, &tbs);
    add(
        "device_cert_wrong_context",
        envelope(tbs.clone(), sig),
        "bad_signature",
    );
    add(
        "device_cert_trailing_byte",
        [cert.as_slice(), &[0x00]].concat(),
        "non_canonical_cbor",
    );
    // The last body item is seq = 1.
    add(
        "device_cert_non_shortest_int",
        non_shortest(&cert, tbs.len() - 1, &seed(ROOT), DEVICE_CERT_CONTEXT),
        "non_canonical_cbor",
    );
    add(
        "device_cert_unsupported_version",
        resign(|body| body[0] = Cbor::Integer(2.into())),
        "unsupported_version",
    );
    add(
        "device_cert_user_id_mismatch",
        resign(|body| body[1] = text(self::root(OTHER_ROOT).public().user_id().as_str())),
        "user_id_mismatch",
    );
    add(
        "device_cert_device_id_mismatch",
        resign(|body| body[2] = text(device(DEVICE_B).public().device_id().as_str())),
        "device_id_mismatch",
    );
}

/// Seq 1 certifies devices A and B; seq 2 revokes B.
fn device_lists() -> (SignedDeviceList, SignedDeviceList) {
    let root = root(ROOT);
    let certs = [DEVICE_A, DEVICE_B]
        .map(|start| SignedDeviceCert::issue(&root, &device(start).public(), NOW, 1))
        .to_vec();
    let v1 = DeviceList::new(root.public(), 1, certs, vec![]).unwrap();
    let v2 = v1.revoke(&device(DEVICE_B).public().device_id()).unwrap();
    (v1.sign(&root).unwrap(), v2.sign(&root).unwrap())
}

fn device_list_cases(cases: &mut Vec<Value>) {
    let root = root(ROOT);
    let user_id = root.public().user_id();
    let (v1, v2) = device_lists();
    let (v1, v2) = (v1.to_bytes(), v2.to_bytes());
    let context = json!({ "user_id": user_id.as_str() });
    let with_stored = json!({ "user_id": user_id.as_str(), "stored": hex(&v2) });
    let resign = |list: &[u8], edit: fn(&mut Vec<Cbor>)| {
        resign(list, &seed(ROOT), DEVICE_LIST_CONTEXT, edit)
    };
    let mut add = |name: &str, input: Vec<u8>, context: &Value, expected: &str| {
        cases.push(case(name, "device_list", &input, context.clone(), expected))
    };

    add(
        "device_list_bad_signature",
        flip_last(&v2),
        &context,
        "bad_signature",
    );
    let tbs = tbs_of(&v2);
    let sig = sign(&seed(ROOT), DEVICE_CERT_CONTEXT, &tbs);
    add(
        "device_list_wrong_context",
        envelope(tbs, sig),
        &context,
        "bad_signature",
    );
    let mut indefinite = v2.clone();
    assert_eq!(indefinite[0], 0x82);
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    add(
        "device_list_indefinite_length",
        indefinite,
        &context,
        "non_canonical_cbor",
    );
    // Body offset of seq: array head, version, user_id (2 + 56), root key
    // (2 + 32).
    add(
        "device_list_non_shortest_int",
        non_shortest(&v2, 1 + 1 + 58 + 34, &seed(ROOT), DEVICE_LIST_CONTEXT),
        &context,
        "non_canonical_cbor",
    );
    add(
        "device_list_unsupported_version",
        resign(&v2, |body| body[0] = Cbor::Integer(2.into())),
        &context,
        "unsupported_version",
    );
    let other = self::root(OTHER_ROOT);
    let foreign = DeviceList::new(other.public(), 1, vec![], vec![])
        .unwrap()
        .sign(&other)
        .unwrap();
    add(
        "device_list_other_user",
        foreign.to_bytes(),
        &context,
        "user_id_mismatch",
    );
    add(
        "device_list_body_user_id_mismatch",
        resign(&v2, |body| {
            body[1] = text(self::root(OTHER_ROOT).public().user_id().as_str())
        }),
        &context,
        "user_id_mismatch",
    );
    add(
        "device_list_duplicate_device",
        resign(&v1, |body| {
            let Cbor::Array(certs) = &mut body[4] else {
                panic!("certs is not an array")
            };
            certs.push(certs[0].clone());
        }),
        &context,
        "duplicate_device",
    );
    // Seq 2 that revokes A instead of B.
    let (v1_list, _) = device_lists();
    let fork = v1_list
        .verify(&user_id)
        .unwrap()
        .revoke(&device(DEVICE_A).public().device_id())
        .unwrap()
        .sign(&root)
        .unwrap();
    add(
        "device_list_seq_conflict",
        fork.to_bytes(),
        &with_stored,
        "seq_conflict",
    );
    add("device_list_stale_seq", v1, &with_stored, "stale_seq");
}

fn runtime_cert_cases(cases: &mut Vec<Value>) {
    let hub = hub(HUB_A);
    let runtime_public = device(RUNTIME).public();
    let runtime = HubRuntimePublicKey::from_bytes(runtime_public.as_bytes()).unwrap();
    let cert = SignedHubRuntimeCert::issue(&hub, &runtime, NOW, NOW + DAY).to_bytes();
    let context = |hub: &HubRootKey, now: u64| json!({ "hub_root_pubkey": hex(hub.public().as_bytes()), "now": now });
    let resign =
        |edit: fn(&mut Vec<Cbor>)| resign(&cert, &seed(HUB_A), HUB_RUNTIME_CERT_CONTEXT, edit);
    let mut add = |name: &str, input: &[u8], context: Value, expected: &str| {
        cases.push(case(name, "runtime_cert", input, context, expected))
    };

    add(
        "runtime_cert_bad_signature",
        &flip_last(&cert),
        context(&hub, NOW),
        "bad_signature",
    );
    add(
        "runtime_cert_other_hub",
        &cert,
        context(&self::hub(HUB_B), NOW),
        "bad_signature",
    );
    add(
        "runtime_cert_hub_key_mismatch",
        &resign(|body| body[1] = Cbor::Bytes(self::hub(HUB_B).public().as_bytes().to_vec())),
        context(&hub, NOW),
        "hub_key_mismatch",
    );
    add(
        "runtime_cert_unsupported_version",
        &resign(|body| body[0] = Cbor::Integer(2.into())),
        context(&hub, NOW),
        "unsupported_version",
    );
    add(
        "runtime_cert_expired",
        &cert,
        context(&hub, NOW + DAY),
        "expired",
    );
    add(
        "runtime_cert_not_yet_valid",
        &cert,
        context(&hub, NOW - 1),
        "not_yet_valid",
    );
}

/// A record of the root user hosted on `hubs` as `(seed, priority)`.
fn record(seq: u64, hubs: &[(u8, u8)]) -> Vec<u8> {
    let root = root(ROOT);
    let user_id = root.public().user_id();
    let entries = hubs
        .iter()
        .map(|&(start, priority)| HostingEntry::sign(&hub(start), &user_id, priority))
        .collect();
    UserHostingRecord::new(root.public(), seq, NOW + DAY, entries)
        .unwrap()
        .sign(&root)
        .unwrap()
        .to_bytes()
}

fn hosting_record_cases(cases: &mut Vec<Value>) {
    let v1 = record(1, &[(HUB_A, 0), (HUB_B, 10)]);
    let v2 = record(2, &[(HUB_B, 0)]);
    let user_id = root(ROOT).public().user_id();
    let context = json!({ "now": NOW });
    let resign = |edit: fn(&mut Vec<Cbor>)| resign(&v1, &seed(ROOT), HOSTING_RECORD_CONTEXT, edit);
    let mut add = |name: &str, input: &[u8], context: Value, expected: &str| {
        cases.push(case(name, "hosting_record", input, context, expected))
    };

    add(
        "hosting_record_bad_signature",
        &flip_last(&v1),
        context.clone(),
        "bad_signature",
    );
    add(
        "hosting_record_user_id_mismatch",
        &resign(|body| body[1] = text(self::root(OTHER_ROOT).public().user_id().as_str())),
        context.clone(),
        "user_id_mismatch",
    );
    add(
        "hosting_record_other_user",
        &v1,
        json!({ "now": NOW, "user_id": root(OTHER_ROOT).public().user_id().as_str() }),
        "user_id_mismatch",
    );
    add(
        "hosting_record_unsupported_version",
        &resign(|body| body[0] = Cbor::Integer(2.into())),
        context.clone(),
        "unsupported_version",
    );
    add(
        "hosting_record_no_hubs",
        &resign(|body| body[5] = Cbor::Array(vec![])),
        context.clone(),
        "hub_count",
    );
    // The count is checked before the entries are decoded.
    add(
        "hosting_record_too_many_hubs",
        &resign(|body| body[5] = Cbor::Array(vec![Cbor::Null; 17])),
        context.clone(),
        "hub_count",
    );
    add(
        "hosting_record_duplicate_hub",
        &resign(|body| {
            let Cbor::Array(hubs) = &mut body[5] else {
                panic!("hubs is not an array")
            };
            hubs.push(hubs[0].clone());
        }),
        context.clone(),
        "duplicate_hub",
    );
    add(
        "hosting_record_bad_hub_signature",
        &resign(|body| {
            let Cbor::Array(hubs) = &mut body[5] else {
                panic!("hubs is not an array")
            };
            let Cbor::Array(entry) = &mut hubs[0] else {
                panic!("entry is not an array")
            };
            let Cbor::Bytes(hub_sig) = &mut entry[2] else {
                panic!("hub_sig is not a byte string")
            };
            hub_sig[63] ^= 1;
        }),
        context.clone(),
        "bad_hub_signature",
    );
    add(
        "hosting_record_unsorted_hubs",
        &resign(|body| {
            let Cbor::Array(hubs) = &mut body[5] else {
                panic!("hubs is not an array")
            };
            hubs.reverse();
        }),
        context.clone(),
        "unsorted_hubs",
    );
    // A hub entry correctly signed by the user root key acting as a hub.
    add(
        "hosting_record_user_key_is_hub_key",
        &resign(|body| {
            let user_root = self::root(ROOT).public();
            let tbs = encode(&Cbor::Array(vec![
                Cbor::Integer(1.into()),
                text(user_root.user_id().as_str()),
                Cbor::Bytes(user_root.as_bytes().to_vec()),
                Cbor::Integer(0.into()),
            ]));
            body[5] = Cbor::Array(vec![Cbor::Array(vec![
                Cbor::Bytes(user_root.as_bytes().to_vec()),
                Cbor::Integer(0.into()),
                Cbor::Bytes(sign(&seed(ROOT), HOSTING_ENTRY_CONTEXT, &tbs)),
            ])]);
        }),
        context.clone(),
        "user_key_is_hub_key",
    );
    add(
        "hosting_record_expired",
        &v1,
        json!({ "now": NOW + DAY }),
        "expired",
    );
    add(
        "hosting_record_seq_conflict",
        &record(1, &[(HUB_B, 0)]),
        json!({ "now": NOW, "user_id": user_id.as_str(), "stored": hex(&v1) }),
        "seq_conflict",
    );
    add(
        "hosting_record_stale_seq",
        &v1,
        json!({ "now": NOW, "user_id": user_id.as_str(), "stored": hex(&v2) }),
        "stale_seq",
    );
}

fn auth_response_cases(cases: &mut Vec<Value>) {
    let user_id = root(ROOT).public().user_id();
    let audience = hub(HUB_A).public().hub_id();
    let challenge_for = |issued_at: u64, expires_at: u64| {
        AuthChallenge {
            audience: audience.clone(),
            nonce: seed(NONCE),
            issued_at,
            expires_at,
        }
        .to_bytes()
    };
    let challenge = challenge_for(NOW, NOW + TTL);
    let (_, list) = device_lists();
    let context = |audience: &str, now: u64| json!({ "audience": audience, "now": now, "device_list": hex(&list.to_bytes()) });
    let respond_to = |challenge: &[u8], start: u8| {
        AuthResponse::sign(challenge, &device(start), &user_id).to_bytes()
    };
    let respond = |start: u8| respond_to(&challenge, start);
    let mut add = |name: &str, input: &[u8], context: Value, expected: &str| {
        cases.push(case(name, "auth_response", input, context, expected))
    };

    let ok = respond(DEVICE_A);
    add(
        "auth_response_bad_signature",
        &flip_last(&ok),
        context(&audience, NOW),
        "bad_signature",
    );
    let device_id = device(DEVICE_A).public().device_id();
    let tbs = encode(&Cbor::Array(vec![
        Cbor::Bytes(challenge.clone()),
        text(user_id.as_str()),
        text(device_id.as_str()),
    ]));
    let wrong_context = encode(&Cbor::Array(vec![
        Cbor::Integer(1.into()),
        Cbor::Bytes(challenge.clone()),
        text(user_id.as_str()),
        text(device_id.as_str()),
        Cbor::Bytes(sign(&seed(DEVICE_A), DEVICE_CERT_CONTEXT, &tbs)),
    ]));
    // The same body with the right context verifies.
    assert_eq!(
        wrong_context[..wrong_context.len() - 64],
        ok[..ok.len() - 64]
    );
    assert_eq!(
        ok[ok.len() - 64..],
        sign(&seed(DEVICE_A), AUTH_RESPONSE_CONTEXT, &tbs)
    );
    add(
        "auth_response_wrong_context",
        &wrong_context,
        context(&audience, NOW),
        "bad_signature",
    );
    let Cbor::Array(mut body) = decode(&ok) else {
        panic!("response is not an array")
    };
    body[0] = Cbor::Integer(2.into());
    add(
        "auth_response_unsupported_version",
        &encode(&Cbor::Array(body)),
        context(&audience, NOW),
        "unsupported_version",
    );
    add(
        "auth_response_revoked_device",
        &respond(DEVICE_B),
        context(&audience, NOW),
        "device_revoked",
    );
    add(
        "auth_response_unknown_device",
        &respond(DEVICE_UNLISTED),
        context(&audience, NOW),
        "unknown_device",
    );
    add(
        "auth_response_expired_challenge",
        &ok,
        context(&audience, NOW + TTL),
        "expired",
    );
    add(
        "auth_response_challenge_not_yet_valid",
        &ok,
        context(&audience, NOW - 1),
        "not_yet_valid",
    );
    add(
        "auth_response_challenge_empty_window",
        &respond_to(&challenge_for(NOW, NOW), DEVICE_A),
        context(&audience, NOW),
        "invalid_validity_window",
    );
    add(
        "auth_response_challenge_lifetime_too_long",
        &respond_to(&challenge_for(NOW, NOW + 300_001), DEVICE_A),
        context(&audience, NOW),
        "lifetime_too_long",
    );
    add(
        "auth_response_wrong_audience",
        &ok,
        context(&hub(HUB_B).public().hub_id(), NOW),
        "audience_mismatch",
    );
}

fn compute() -> Value {
    let mut cases = Vec::new();
    device_cert_cases(&mut cases);
    device_list_cases(&mut cases);
    runtime_cert_cases(&mut cases);
    hosting_record_cases(&mut cases);
    auth_response_cases(&mut cases);
    json!({
        "description": "gim identity negative test vectors, see docs/identity.md",
        "cases": cases,
    })
}

fn key(value: &Value) -> [u8; 32] {
    unhex(value).try_into().unwrap()
}

fn now(context: &Value) -> u64 {
    context["now"].as_u64().unwrap()
}

/// Runs one case the way a verifier would.
fn run(case: &Value) -> Result<(), IdentityError> {
    let input = unhex(&case["input_hex"]);
    let context = &case["context"];
    match case["kind"].as_str().unwrap() {
        "device_cert" => {
            let root = RootPublicKey::from_bytes(&key(&context["root_pubkey"]))?;
            SignedDeviceCert::from_bytes(&input)?.verify(&root)?;
        }
        "device_list" => {
            let user_id = parse_user_id(context["user_id"].as_str().unwrap())?;
            let list = SignedDeviceList::from_bytes(&input)?.verify(&user_id)?;
            if let Some(stored) = context.get("stored") {
                let stored = SignedDeviceList::from_bytes(&unhex(stored))?.verify(&user_id)?;
                list.supersedes(&stored)?;
            }
        }
        "runtime_cert" => {
            let hub = HubRootPublicKey::from_bytes(&key(&context["hub_root_pubkey"]))?;
            SignedHubRuntimeCert::from_bytes(&input)?.verify(&hub, now(context))?;
        }
        "hosting_record" => {
            let record = SignedHostingRecord::from_bytes(&input)?.verify(now(context))?;
            if let Some(user_id) = context.get("user_id") {
                if record.user_id().as_str() != user_id {
                    return Err(IdentityError::UserIdMismatch);
                }
            }
            if let Some(stored) = context.get("stored") {
                let stored =
                    SignedHostingRecord::from_bytes(&unhex(stored))?.verify(now(context))?;
                record.supersedes(&stored)?;
            }
        }
        "auth_response" => {
            let list = SignedDeviceList::from_bytes(&unhex(&context["device_list"]))?;
            AuthResponse::from_bytes(&input)?.verify(
                context["audience"].as_str().unwrap(),
                now(context),
                &list,
            )?;
        }
        kind => panic!("unknown kind {kind}"),
    }
    Ok(())
}

#[test]
fn every_case_fails_with_its_code() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(file, compute());

    let cases = file["cases"].as_array().unwrap();
    let mut names = std::collections::HashSet::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        assert!(names.insert(name), "duplicate case {name}");
        let error = run(case).expect_err(name);
        assert_eq!(error.code(), case["expected_error"], "{name}: {error}");
    }
}

#[test]
#[ignore = "rewrites tests/vectors/negative.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}
