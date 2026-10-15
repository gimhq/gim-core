//! Device authentication. Asserts `tests/vectors/auth.json`; after an
//! intentional format change, regenerate it with
//! `cargo test -p gim-identity --test auth -- --ignored regenerate`.

use data_encoding::HEXLOWER;
use gim_common::DeviceRef;
use gim_identity::{
    AuthChallenge, AuthResponse, DeviceList, DeviceSigningKey, HubRootKey, IdentityError, RootKey,
    SignedDeviceCert, SignedDeviceList,
};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/auth.json");
const NOW: u64 = 1_760_486_400_000; // 2025-10-15T00:00:00Z
const TTL: u64 = 60_000;

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

fn user_root() -> RootKey {
    RootKey::from_seed(&seed(0x00))
}

fn device(start: u8) -> DeviceSigningKey {
    DeviceSigningKey::from_seed(&seed(start))
}

fn hub_id() -> String {
    HubRootKey::from_seed(&seed(0x60)).public().hub_id()
}

fn challenge() -> AuthChallenge {
    AuthChallenge {
        audience: hub_id(),
        nonce: seed(0xc0),
        issued_at: NOW,
        expires_at: NOW + TTL,
    }
}

/// Seq 1 certifies devices 0x20 and 0x40; seq 2 revokes 0x40.
fn device_lists() -> (SignedDeviceList, SignedDeviceList) {
    let root = user_root();
    let certs = [0x20, 0x40]
        .map(|start| SignedDeviceCert::issue(&root, &device(start).public(), NOW, 1))
        .to_vec();
    let v1 = DeviceList::new(root.public(), 1, certs, vec![]).unwrap();
    let v2 = v1.revoke(&device(0x40).public().device_id()).unwrap();
    (v1.sign(&root).unwrap(), v2.sign(&root).unwrap())
}

fn respond(challenge: &AuthChallenge, device: &DeviceSigningKey) -> AuthResponse {
    AuthResponse::sign(
        &challenge.to_bytes(),
        device,
        &user_root().public().user_id(),
    )
}

#[test]
fn challenge_round_trip() {
    let challenge = challenge();
    assert_eq!(
        AuthChallenge::from_bytes(&challenge.to_bytes()).unwrap(),
        challenge
    );
}

#[test]
fn response_round_trip() {
    let (list, _) = device_lists();
    let response = respond(&challenge(), &device(0x20));
    let parsed = AuthResponse::from_bytes(&response.to_bytes()).unwrap();
    assert_eq!(parsed, response);
    assert_eq!(
        parsed.verify(&hub_id(), NOW, &list).unwrap(),
        DeviceRef::new(
            user_root().public().user_id(),
            device(0x20).public().device_id()
        )
    );
}

#[test]
fn wrong_audience_rejected() {
    let (list, _) = device_lists();
    let response = respond(&challenge(), &device(0x20));
    let other_hub = HubRootKey::from_seed(&seed(0x80)).public().hub_id();
    assert!(matches!(
        response.verify(&other_hub, NOW, &list),
        Err(IdentityError::AudienceMismatch)
    ));
}

#[test]
fn expired_challenge_rejected() {
    let (list, _) = device_lists();
    let response = respond(&challenge(), &device(0x20));
    assert!(response.verify(&hub_id(), NOW + TTL - 1, &list).is_ok());
    assert!(matches!(
        response.verify(&hub_id(), NOW + TTL, &list),
        Err(IdentityError::Expired)
    ));
}

#[test]
fn challenge_validity_window_enforced() {
    let (list, _) = device_lists();
    let at = |issued_at: u64, expires_at: u64| {
        let challenge = AuthChallenge {
            issued_at,
            expires_at,
            ..challenge()
        };
        respond(&challenge, &device(0x20))
    };
    assert!(matches!(
        at(NOW, NOW + TTL).verify(&hub_id(), NOW - 1, &list),
        Err(IdentityError::NotYetValid)
    ));
    assert!(matches!(
        at(NOW, NOW).verify(&hub_id(), NOW, &list),
        Err(IdentityError::InvalidValidityWindow)
    ));
    assert!(matches!(
        at(NOW + 1, NOW).verify(&hub_id(), NOW, &list),
        Err(IdentityError::InvalidValidityWindow)
    ));
    assert!(at(NOW, NOW + 300_000).verify(&hub_id(), NOW, &list).is_ok());
    assert!(matches!(
        at(NOW, NOW + 300_001).verify(&hub_id(), NOW, &list),
        Err(IdentityError::LifetimeTooLong)
    ));
}

#[test]
fn revoked_device_rejected() {
    let (v1, v2) = device_lists();
    let response = respond(&challenge(), &device(0x40));
    assert!(response.verify(&hub_id(), NOW, &v1).is_ok());
    assert!(matches!(
        response.verify(&hub_id(), NOW, &v2),
        Err(IdentityError::Revoked(_))
    ));
}

#[test]
fn device_not_in_list_rejected() {
    let (list, _) = device_lists();
    let response = respond(&challenge(), &device(0x90));
    assert!(matches!(
        response.verify(&hub_id(), NOW, &list),
        Err(IdentityError::UnknownDevice(_))
    ));
}

#[test]
fn list_of_another_user_rejected() {
    let other_root = RootKey::from_seed(&[9; 32]);
    let cert = SignedDeviceCert::issue(&other_root, &device(0x20).public(), NOW, 1);
    let list = DeviceList::new(other_root.public(), 1, vec![cert], vec![])
        .unwrap()
        .sign(&other_root)
        .unwrap();
    let response = respond(&challenge(), &device(0x20));
    assert!(matches!(
        response.verify(&hub_id(), NOW, &list),
        Err(IdentityError::UserIdMismatch)
    ));
}

#[test]
fn signature_from_another_device_rejected() {
    let (list, _) = device_lists();
    // Device 0x40's signature presented as device 0x20.
    let forged = respond(&challenge(), &device(0x40)).to_bytes();
    let honest = respond(&challenge(), &device(0x20)).to_bytes();
    let id_40 = device(0x40).public().device_id();
    let id_20 = device(0x20).public().device_id();
    let pos = forged
        .windows(id_40.as_str().len())
        .position(|w| w == id_40.as_str().as_bytes())
        .unwrap();
    let mut forged = forged;
    forged[pos..pos + id_20.as_str().len()].copy_from_slice(id_20.as_str().as_bytes());
    assert_ne!(forged, honest);
    let response = AuthResponse::from_bytes(&forged).unwrap();
    assert_eq!(response.device_id(), &id_20);
    assert!(matches!(
        response.verify(&hub_id(), NOW, &list),
        Err(IdentityError::BadSignature)
    ));
}

#[test]
fn tampered_challenge_rejected() {
    let (list, _) = device_lists();
    let mut bytes = respond(&challenge(), &device(0x20)).to_bytes();
    // The nonce is the only 32-byte run of 0xc0.. in the response.
    let nonce = seed(0xc0);
    let pos = bytes.windows(32).position(|w| w == nonce).unwrap();
    bytes[pos] ^= 1;
    let response = AuthResponse::from_bytes(&bytes).unwrap();
    assert!(matches!(
        response.verify(&hub_id(), NOW, &list),
        Err(IdentityError::BadSignature)
    ));
}

fn compute() -> Value {
    let (list, _) = device_lists();
    let challenge = challenge();
    let response = respond(&challenge, &device(0x20));
    json!({
        "description": "gim device authentication test vectors, see docs/identity.md",
        "hub_root_seed": HEXLOWER.encode(&seed(0x60)),
        "audience": challenge.audience,
        "user_root_seed": HEXLOWER.encode(&seed(0x00)),
        "user_id": user_root().public().user_id().as_str(),
        "device_seed": HEXLOWER.encode(&seed(0x20)),
        "device_id": device(0x20).public().device_id().as_str(),
        "device_list": HEXLOWER.encode(&list.to_bytes()),
        "challenge": {
            "nonce": HEXLOWER.encode(&challenge.nonce),
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
            "bytes": HEXLOWER.encode(&challenge.to_bytes()),
        },
        "response": HEXLOWER.encode(&response.to_bytes()),
    })
}

fn hex(value: &Value) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

#[test]
fn vectors_match() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(file, compute());

    // The committed bytes verify on their own.
    let list = SignedDeviceList::from_bytes(&hex(&file["device_list"])).unwrap();
    let device = AuthResponse::from_bytes(&hex(&file["response"]))
        .unwrap()
        .verify(file["audience"].as_str().unwrap(), NOW, &list)
        .unwrap();
    assert_eq!(device.user_id.as_str(), file["user_id"]);
    assert_eq!(device.device_id.as_str(), file["device_id"]);
}

#[test]
#[ignore = "rewrites tests/vectors/auth.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}
