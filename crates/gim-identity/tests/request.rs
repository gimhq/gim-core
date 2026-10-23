//! Root-signed requests and meta-server storage keys. Asserts
//! `tests/vectors/request.json` (shared with the gim meta server). After an
//! intentional format change, regenerate it with
//! `cargo test -p gim-identity --test request -- --ignored regenerate`.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use gim_identity::storage::StorageKey;
use gim_identity::{
    root_request_tbs, IdentityError, RootKey, RootRequestSignature, ROOT_REQUEST_CONTEXT,
    ROOT_REQUEST_MAX_SKEW_MS,
};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/request.json");
const NOW: u64 = 1_760_486_400_000; // 2025-10-15T00:00:00Z

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

fn compute() -> Value {
    let cases = [
        ("GET", "/api/raw/gim/v1/storage/settings", &b""[..]),
        (
            "PUT",
            "/api/raw/gim/v1/storage/settings",
            &br#"{"version":0,"data":"AAEC"}"#[..],
        ),
        ("DELETE", "/v2/users/u-placeholder?reason=user", &b""[..]),
    ]
    .into_iter()
    .enumerate()
    .map(|(n, (method, path, body))| {
        let root_seed = seed(0x10 * n as u8);
        let root = RootKey::from_seed(&root_seed);
        let timestamp_ms = NOW + n as u64;
        let signed = root.sign_request(method, path, timestamp_ms, body);
        let tbs = root_request_tbs(method, path, timestamp_ms, body);
        let mut message = ROOT_REQUEST_CONTEXT.to_vec();
        message.push(0);
        message.extend_from_slice(&tbs);
        json!({
            "root_seed": HEXLOWER.encode(&root_seed),
            "user_id": root.public().user_id().as_str(),
            "method": method,
            "path": path,
            "body": HEXLOWER.encode(body),
            "timestamp_ms": timestamp_ms,
            "message": HEXLOWER.encode(&message),
            "gim_key": BASE64URL_NOPAD.encode(root.public().as_bytes()),
            "gim_signature": BASE64URL_NOPAD.encode(&signed.signature),
        })
    })
    .collect::<Vec<_>>();
    json!({
        "description": "gim root-signed request vectors, see docs/identity.md \"Root-signed requests\": signature = Ed25519(root key, \"gim/root-request/v1\" || 0x00 || method \"\\n\" path \"\\n\" decimal(timestamp_ms) \"\\n\" hex(SHA-256(body))); `message` is the exact signed input; gim_key and gim_signature are the header values (unpadded base64url).",
        "cases": cases,
    })
}

#[test]
fn request_vectors() {
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(stored, compute());
}

#[test]
#[ignore = "rewrites the vector file"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}

#[test]
fn a_request_verifies_only_as_signed_and_in_time() {
    let root = RootKey::from_seed(&seed(1));
    let user_id = root.public().user_id();
    let signed = root.sign_request("PUT", "/a", NOW, b"body");
    assert_eq!(signed.verify("PUT", "/a", b"body", NOW).unwrap(), user_id);
    let skew = ROOT_REQUEST_MAX_SKEW_MS;
    assert!(signed.verify("PUT", "/a", b"body", NOW + skew).is_ok());
    assert!(signed.verify("PUT", "/a", b"body", NOW - skew).is_ok());
    assert!(matches!(
        signed.verify("PUT", "/a", b"body", NOW + skew + 1),
        Err(IdentityError::Expired)
    ));
    assert!(matches!(
        signed.verify("PUT", "/a", b"body", NOW - skew - 1),
        Err(IdentityError::NotYetValid)
    ));
    for (method, path, body) in [
        ("GET", "/a", &b"body"[..]),
        ("PUT", "/b", b"body"),
        ("PUT", "/a", b"bodx"),
    ] {
        assert!(matches!(
            signed.verify(method, path, body, NOW),
            Err(IdentityError::BadSignature)
        ));
    }
    // Another key cannot claim the signature.
    let forged = RootRequestSignature {
        public_key: RootKey::from_seed(&seed(2)).public(),
        ..signed
    };
    assert!(forged.verify("PUT", "/a", b"body", NOW).is_err());
}

#[test]
fn the_storage_key_belongs_to_the_root_key() {
    let a = StorageKey::derive(&RootKey::from_seed(&seed(1)));
    let b = StorageKey::derive(&RootKey::from_seed(&seed(1)));
    let sealed = a.seal("settings", b"data").unwrap();
    assert_eq!(b.open("settings", &sealed).unwrap().as_slice(), b"data");
}
