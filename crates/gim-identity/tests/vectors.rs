//! Asserts `tests/vectors/identity.json`. After an intentional format change,
//! regenerate it with
//! `cargo test -p gim-identity --test vectors -- --ignored regenerate`.

use data_encoding::HEXLOWER;
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert, SignedDeviceList};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/identity.json");
const CREATED_AT: u64 = 1_760_486_400_000; // 2025-10-15T00:00:00Z

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

fn compute() -> Value {
    let root_seed = seed(0x00);
    let root = RootKey::from_seed(&root_seed);
    let user_id = root.public().user_id();

    let mut devices = Vec::new();
    let mut certs = Vec::new();
    for (n, start) in [0x20u8, 0x40].into_iter().enumerate() {
        let device_seed = seed(start);
        let public = DeviceSigningKey::from_seed(&device_seed).public();
        let cert_seq = n as u64 + 1;
        let cert = SignedDeviceCert::issue(&root, &public, CREATED_AT, cert_seq);
        devices.push(json!({
            "seed": HEXLOWER.encode(&device_seed),
            "pubkey": HEXLOWER.encode(public.as_bytes()),
            "device_id": public.device_id().as_str(),
            "created_at": CREATED_AT,
            "seq": cert_seq,
            "signed_cert": HEXLOWER.encode(&cert.to_bytes()),
        }));
        certs.push((public, cert));
    }

    // seq 1 certifies both devices; seq 2 revokes the second one.
    let list = DeviceList::new(
        root.public(),
        1,
        certs.iter().map(|(_, cert)| cert.clone()).collect(),
        vec![],
    )
    .unwrap()
    .revoke(&certs[1].0.device_id())
    .unwrap();
    let signed_list = list.sign(&root).unwrap();

    json!({
        "description": "gim identity test vectors, see docs/identity.md",
        "root_seed": HEXLOWER.encode(&root_seed),
        "root_pubkey": HEXLOWER.encode(root.public().as_bytes()),
        "user_id": user_id.as_str(),
        "devices": devices,
        "device_list": {
            "seq": list.seq(),
            "certs": [certs[0].0.device_id().as_str()],
            "revoked": [certs[1].0.device_id().as_str()],
            "signed": HEXLOWER.encode(&signed_list.to_bytes()),
        },
    })
}

#[test]
fn vectors_match() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(file, compute());

    // The committed bytes verify on their own.
    let root = RootKey::from_seed(&seed(0x00)).public();
    for device in file["devices"].as_array().unwrap() {
        let bytes = HEXLOWER
            .decode(device["signed_cert"].as_str().unwrap().as_bytes())
            .unwrap();
        let cert = SignedDeviceCert::from_bytes(&bytes)
            .unwrap()
            .verify(&root)
            .unwrap();
        assert_eq!(cert.device_id.as_str(), device["device_id"]);
    }
    let bytes = HEXLOWER
        .decode(file["device_list"]["signed"].as_str().unwrap().as_bytes())
        .unwrap();
    let list = SignedDeviceList::from_bytes(&bytes)
        .unwrap()
        .verify(&root.user_id())
        .unwrap();
    assert_eq!(list.seq(), 2);
    assert_eq!(list.certs().count(), 1);
    assert_eq!(list.revoked().len(), 1);
}

#[test]
#[ignore = "rewrites tests/vectors/identity.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}
