//! Asserts `tests/vectors/credential.json` (the gim MLS credential, see
//! `docs/identity.md`). Seeds are those of gim-identity's `identity.json`.
//! After an intentional format change, regenerate it with
//! `cargo test -p gim-crypto --test credential_vectors -- --ignored regenerate`.

use ciborium::Value as Cbor;
use data_encoding::HEXLOWER;
use gim_common::UserId;
use gim_crypto::credential::check;
use gim_crypto::{DeviceListLookup, GimCredential, GIM_CREDENTIAL_TYPE};
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert, SignedDeviceList};
use openmls::prelude::{Credential, CredentialType};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/credential.json");
const IDENTITY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../gim-identity/tests/vectors/identity.json"
);
const CREATED_AT: u64 = 1_760_486_400_000; // 2025-10-15T00:00:00Z
const BASIC_CREDENTIAL_TYPE: u16 = 1;

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

fn hex(bytes: &[u8]) -> String {
    HEXLOWER.encode(bytes)
}

fn unhex(value: &Value) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

fn cbor(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn compute() -> Value {
    let root = RootKey::from_seed(&seed(0x00));
    let other_root = RootKey::from_seed(&seed(0x60));
    let devices: Vec<_> = [0x20u8, 0x40]
        .into_iter()
        .enumerate()
        .map(|(n, start)| {
            let public = DeviceSigningKey::from_seed(&seed(start)).public();
            let cert = SignedDeviceCert::issue(&root, &public, CREATED_AT, n as u64 + 1);
            (public, GimCredential::new(root.public(), cert))
        })
        .collect();
    // seq 1 certifies both devices; seq 2 revokes the second one.
    let list = DeviceList::new(
        root.public(),
        1,
        devices
            .iter()
            .map(|(_, c)| c.signed_cert().clone())
            .collect(),
        vec![],
    )
    .unwrap()
    .revoke(&devices[1].0.device_id())
    .unwrap()
    .sign(&root)
    .unwrap();
    let list_hex = hex(&list.to_bytes());

    let valid = |name: &str, n: usize, with_list: bool| {
        let (public, credential) = &devices[n];
        json!({
            "name": name,
            "content_hex": hex(&credential.encode()),
            "leaf_signature_key": hex(public.as_bytes()),
            "device_list": with_list.then(|| list_hex.clone()),
            "user_id": root.public().user_id().as_str(),
            "device_id": public.device_id().as_str(),
        })
    };
    let invalid = |name: &str,
                   content: Vec<u8>,
                   credential_type: u16,
                   leaf: &[u8],
                   with_list: bool,
                   error: &str| {
        json!({
            "name": name,
            "input_hex": hex(&content),
            "context": {
                "credential_type": credential_type,
                "leaf_signature_key": hex(leaf),
                "device_list": with_list.then(|| list_hex.clone()),
            },
            "expected_error": error,
        })
    };

    let leaf = |n: usize| devices[n].0.as_bytes().as_slice();
    let content = devices[0].1.encode();
    // Certified by the root but absent from the list.
    let unlisted = DeviceSigningKey::from_seed(&seed(0x80)).public();
    let unlisted_content = GimCredential::new(
        root.public(),
        SignedDeviceCert::issue(&root, &unlisted, CREATED_AT, 3),
    )
    .encode();
    let forged = GimCredential::new(
        root.public(),
        SignedDeviceCert::issue(&other_root, &devices[0].0, CREATED_AT, 1),
    )
    .encode();
    let with_version = |version: u64| {
        cbor(&Cbor::Array(vec![
            Cbor::Integer(version.into()),
            Cbor::Bytes(root.public().as_bytes().to_vec()),
            Cbor::Bytes(devices[0].1.signed_cert().to_bytes()),
        ]))
    };
    // The version `1` re-encoded with a one-byte argument (0x18 0x01).
    let mut non_canonical = vec![content[0], 0x18];
    non_canonical.extend_from_slice(&content[1..]);

    let gim = GIM_CREDENTIAL_TYPE;
    json!({
        "description": "gim MLS credential test vectors, see docs/identity.md",
        "credential_type": gim,
        "root_seed": hex(&seed(0x00)),
        "root_pubkey": hex(root.public().as_bytes()),
        "user_id": root.public().user_id().as_str(),
        "device_seeds": [hex(&seed(0x20)), hex(&seed(0x40))],
        "valid": [
            valid("device", 0, true),
        ],
        "invalid": [
            invalid("cert_signed_by_another_root", forged, gim, leaf(0), false, "bad_cert_signature"),
            invalid("leaf_key_mismatch", content.clone(), gim, leaf(1), false, "leaf_key_mismatch"),
            invalid("revoked_device", devices[1].1.encode(), gim, leaf(1), true, "revoked_device"),
            invalid("non_canonical_cbor", non_canonical, gim, leaf(0), false, "non_canonical_cbor"),
            invalid("unsupported_version", with_version(2), gim, leaf(0), false, "unsupported_version"),
            invalid(
                "wrong_credential_type",
                content.clone(),
                BASIC_CREDENTIAL_TYPE,
                leaf(0),
                false,
                "wrong_credential_type",
            ),
            invalid("device_list_unknown", content, gim, leaf(0), false, "device_list_unknown"),
            invalid(
                "device_not_in_list",
                unlisted_content,
                gim,
                unlisted.as_bytes(),
                true,
                "device_not_in_list",
            ),
        ],
    })
}

/// Knows at most one device list, given as hex in the vector.
struct Lookup(Option<DeviceList>);

impl Lookup {
    fn from_vector(value: &Value, user_id: &UserId) -> Self {
        Self(value.as_str().map(|_| {
            SignedDeviceList::from_bytes(&unhex(value))
                .unwrap()
                .verify(user_id)
                .unwrap()
        }))
    }
}

impl DeviceListLookup for Lookup {
    fn device_list(&self, user_id: &UserId) -> Option<DeviceList> {
        self.0.clone().filter(|list| list.user_id() == user_id)
    }
}

#[test]
fn vectors_match() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(file, compute());
    let user_id = RootKey::from_seed(&seed(0x00)).public().user_id();

    // Same identity as gim-identity's vectors.
    let identity: Value =
        serde_json::from_str(&std::fs::read_to_string(IDENTITY_PATH).unwrap()).unwrap();
    assert_eq!(file["root_pubkey"], identity["root_pubkey"]);
    assert_eq!(file["user_id"], identity["user_id"]);
    assert_eq!(
        file["valid"][0]["device_list"],
        identity["device_list"]["signed"]
    );

    // The committed bytes validate on their own.
    for case in file["valid"].as_array().unwrap() {
        let credential = Credential::new(
            CredentialType::Other(GIM_CREDENTIAL_TYPE),
            unhex(&case["content_hex"]),
        );
        let lookup = Lookup::from_vector(&case["device_list"], &user_id);
        let device = check(&credential, &unhex(&case["leaf_signature_key"]), &lookup)
            .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(device.user_id.as_str(), case["user_id"]);
        assert_eq!(device.device_id.as_str(), case["device_id"]);
    }
    for case in file["invalid"].as_array().unwrap() {
        let context = &case["context"];
        let credential_type = context["credential_type"].as_u64().unwrap() as u16;
        let credential = Credential::new(credential_type.into(), unhex(&case["input_hex"]));
        let lookup = Lookup::from_vector(&context["device_list"], &user_id);
        let err = check(&credential, &unhex(&context["leaf_signature_key"]), &lookup)
            .expect_err(case["name"].as_str().unwrap());
        assert_eq!(err.code(), case["expected_error"], "{}", case["name"]);
    }
}

#[test]
#[ignore = "rewrites tests/vectors/credential.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}
