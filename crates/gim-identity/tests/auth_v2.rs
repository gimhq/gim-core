//! AuthChallenge v2, bound to the hub's public URL. Asserts
//! `tests/vectors/auth-v2.json` (shared with gim-hub) and the v1/v2
//! version rules on both sides.

use ciborium::Value as Cbor;
use data_encoding::HEXLOWER;
use gim_identity::{
    AuthChallenge, AuthResponse, DeviceSigningKey, HubRootKey, IdentityError, SignedDeviceList,
};
use serde_json::Value;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/auth-v2.json");
const URL: &str = "https://hub-a.example.eu";

fn file() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

fn seed(value: &Value) -> [u8; 32] {
    hex(value).try_into().unwrap()
}

fn cbor(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn vector_challenge(file: &Value) -> AuthChallenge {
    let challenge = &file["challenge"];
    AuthChallenge {
        audience: file["audience"].as_str().unwrap().into(),
        audience_url: Some(file["audience_url"].as_str().unwrap().into()),
        nonce: seed(&challenge["nonce"]),
        issued_at: challenge["issued_at"].as_u64().unwrap(),
        expires_at: challenge["expires_at"].as_u64().unwrap(),
    }
}

#[test]
fn vectors_match() {
    let file = file();
    let hub = HubRootKey::from_seed(&seed(&file["hub_root_seed"])).public();
    assert_eq!(hub.as_bytes().to_vec(), hex(&file["hub_root_pubkey"]));
    assert_eq!(hub.hub_id(), file["audience"].as_str().unwrap());
    let device = DeviceSigningKey::from_seed(&seed(&file["device_seed"]));
    assert_eq!(
        device.public().device_id().as_str(),
        file["device_id"].as_str().unwrap()
    );

    let challenge = vector_challenge(&file);
    let bytes = hex(&file["challenge"]["bytes"]);
    assert_eq!(challenge.to_bytes(), bytes);
    assert_eq!(AuthChallenge::from_bytes(&bytes).unwrap(), challenge);
    assert_eq!(challenge.version(), 2);

    let user_id = gim_identity::parse_user_id(file["user_id"].as_str().unwrap()).unwrap();
    let response = AuthResponse::sign(&bytes, &device, &user_id);
    assert_eq!(response.to_bytes(), hex(&file["response"]));

    let list = SignedDeviceList::from_bytes(&hex(&file["device_list"])).unwrap();
    let parsed = AuthResponse::from_bytes(&hex(&file["response"])).unwrap();
    let now = challenge.issued_at;
    let verified = parsed.verify(&hub.hub_id(), Some(URL), now, &list).unwrap();
    assert_eq!(verified.device_id, device.public().device_id());
}

#[test]
fn hub_side_requires_the_version_and_url_of_the_hub() {
    let file = file();
    let audience = file["audience"].as_str().unwrap();
    let list = SignedDeviceList::from_bytes(&hex(&file["device_list"])).unwrap();
    let device = DeviceSigningKey::from_seed(&seed(&file["device_seed"]));
    let user_id = gim_identity::parse_user_id(file["user_id"].as_str().unwrap()).unwrap();
    let v2 = vector_challenge(&file);
    let now = v2.issued_at;
    let answer = |challenge: &AuthChallenge| {
        AuthResponse::sign(&challenge.to_bytes(), &device, &user_id).verify(
            audience,
            Some(URL),
            now,
            &list,
        )
    };
    assert!(answer(&v2).is_ok());
    // A v1 challenge at a hub with a public URL.
    let v1 = AuthChallenge {
        audience_url: None,
        ..v2.clone()
    };
    assert!(matches!(
        answer(&v1),
        Err(IdentityError::AudienceUrlMismatch)
    ));
    // A v2 challenge for another URL.
    let other = AuthChallenge {
        audience_url: Some("https://relay.example.eu".into()),
        ..v2.clone()
    };
    assert!(matches!(
        answer(&other),
        Err(IdentityError::AudienceUrlMismatch)
    ));
    // A v2 challenge at a hub without a public URL.
    let response = AuthResponse::sign(&v2.to_bytes(), &device, &user_id);
    assert!(matches!(
        response.verify(audience, None, now, &list),
        Err(IdentityError::AudienceUrlMismatch)
    ));
    // The audience is still checked first.
    let foreign = AuthChallenge {
        audience: HubRootKey::from_seed(&[9; 32]).public().hub_id(),
        ..v2
    };
    assert!(matches!(
        answer(&foreign),
        Err(IdentityError::AudienceMismatch)
    ));
}

#[test]
fn device_side_check() {
    let challenge = vector_challenge(&file());
    let audience = challenge.audience.clone();
    assert!(challenge.check_audience(&audience, Some(URL)).is_ok());
    assert!(matches!(
        challenge.check_audience(&audience, Some("https://hub-a.example.eu:8443")),
        Err(IdentityError::AudienceUrlMismatch)
    ));
    assert!(matches!(
        challenge.check_audience(&audience, None),
        Err(IdentityError::AudienceUrlMismatch)
    ));
    assert!(matches!(
        challenge.check_audience("hother", Some(URL)),
        Err(IdentityError::AudienceMismatch)
    ));
    let v1 = AuthChallenge {
        audience_url: None,
        ..challenge
    };
    assert_eq!(v1.version(), 1);
    assert!(v1.check_audience(&audience, None).is_ok());
    assert!(matches!(
        v1.check_audience(&audience, Some(URL)),
        Err(IdentityError::AudienceUrlMismatch)
    ));
}

#[test]
fn versions_decode_with_their_exact_length() {
    let text = |s: &str| Cbor::Text(s.into());
    let int = |n: u64| Cbor::Integer(n.into());
    let nonce = || Cbor::Bytes(vec![7; 32]);
    let decode = |items: Vec<Cbor>| AuthChallenge::from_bytes(&cbor(&Cbor::Array(items)));
    let v1 = vec![int(1), text("h"), nonce(), int(1), int(2)];
    let v2 = vec![int(2), text("h"), text(URL), nonce(), int(1), int(2)];
    assert_eq!(decode(v1.clone()).unwrap().audience_url, None);
    assert_eq!(
        decode(v2.clone()).unwrap().audience_url.as_deref(),
        Some(URL)
    );

    // v1 with 6 items, v2 with 5 or 7.
    let mut long_v1 = v1.clone();
    long_v1.push(int(3));
    let short_v2 = vec![int(2), text("h"), nonce(), int(1), int(2)];
    let mut long_v2 = v2.clone();
    long_v2.push(int(3));
    for items in [long_v1, short_v2, long_v2] {
        let err = decode(items).unwrap_err();
        assert_eq!(err.code(), "decode_error", "{err}");
    }
    // v2 with a non-text URL.
    let bad_url = vec![
        int(2),
        text("h"),
        Cbor::Bytes(vec![1]),
        nonce(),
        int(1),
        int(2),
    ];
    assert_eq!(decode(bad_url).unwrap_err().code(), "decode_error");
    let v3 = vec![int(3), text("h"), text(URL), nonce(), int(1), int(2)];
    assert!(matches!(
        decode(v3),
        Err(IdentityError::UnsupportedVersion(3))
    ));
}
