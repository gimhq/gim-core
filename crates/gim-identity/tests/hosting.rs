//! Hub identity, runtime certificates and hosting records. Asserts
//! `tests/vectors/hosting.json`; after an intentional format change,
//! regenerate it with
//! `cargo test -p gim-identity --test hosting -- --ignored regenerate`.

use ciborium::Value as Cbor;
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signer, SigningKey};
use gim_identity::{
    libp2p_peer_id_bytes, DeviceSigningKey, HostingEntry, HubRootKey, HubRootPublicKey,
    HubRuntimePublicKey, IdentityError, RootKey, SignedHostingRecord, SignedHubRuntimeCert,
    UserHostingRecord, HOSTING_RECORD_CONTEXT,
};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/hosting.json");
const NOW: u64 = 1_760_486_400_000; // 2025-10-15T00:00:00Z
const DAY: u64 = 86_400_000;

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

fn user_root() -> RootKey {
    RootKey::from_seed(&seed(0x00))
}

fn hub(n: u8) -> HubRootKey {
    HubRootKey::from_seed(&seed(0x60 + 0x20 * n))
}

/// The runtime key reuses an Ed25519 key type only to derive a public key.
fn runtime_key() -> HubRuntimePublicKey {
    let public = DeviceSigningKey::from_seed(&seed(0xa0)).public();
    HubRuntimePublicKey::from_bytes(public.as_bytes()).unwrap()
}

fn record(hubs: &[(u8, u8)]) -> UserHostingRecord {
    let root = user_root();
    let user_id = root.public().user_id();
    let entries = hubs
        .iter()
        .map(|&(n, priority)| HostingEntry::sign(&hub(n), &user_id, priority))
        .collect();
    UserHostingRecord::new(root.public(), 1, NOW + 2 * DAY, entries).unwrap()
}

fn cbor(bytes: &[u8]) -> Cbor {
    ciborium::from_reader(bytes).unwrap()
}

fn cbor_bytes(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

/// Splits a signed form into `(tbs, sig)`.
fn split(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let Cbor::Array(items) = cbor(bytes) else {
        panic!("not an array")
    };
    let [Cbor::Bytes(tbs), Cbor::Bytes(sig)] = <[Cbor; 2]>::try_from(items).unwrap() else {
        panic!("not a signed form")
    };
    (tbs, sig)
}

fn join(tbs: Vec<u8>, sig: Vec<u8>) -> Vec<u8> {
    cbor_bytes(&Cbor::Array(vec![Cbor::Bytes(tbs), Cbor::Bytes(sig)]))
}

/// A hosting record over an arbitrary body, correctly signed by the user
/// root key.
fn signed_raw(body: Cbor) -> SignedHostingRecord {
    let tbs = cbor_bytes(&body);
    let mut message = HOSTING_RECORD_CONTEXT.to_vec();
    message.push(0);
    message.extend_from_slice(&tbs);
    let sig = SigningKey::from_bytes(&seed(0x00))
        .sign(&message)
        .to_bytes();
    SignedHostingRecord::from_bytes(&join(tbs, sig.to_vec())).unwrap()
}

/// The body of a valid record with its hub entries replaced by `hubs`.
fn body_with_hubs(hubs: Vec<Cbor>) -> Cbor {
    let (tbs, _) = split(&record(&[(0, 0)]).sign(&user_root()).unwrap().to_bytes());
    let Cbor::Array(mut items) = cbor(&tbs) else {
        panic!("not an array")
    };
    items[5] = Cbor::Array(hubs);
    Cbor::Array(items)
}

/// The CBOR encoding of `entry`, taken from a record of `root`'s user that
/// it is valid for.
fn entry_value(entry: &HostingEntry, root: &RootKey) -> Cbor {
    let record = UserHostingRecord::new(root.public(), 1, NOW + DAY, vec![entry.clone()]).unwrap();
    let (tbs, _) = split(&record.sign(root).unwrap().to_bytes());
    let Cbor::Array(mut items) = cbor(&tbs) else {
        panic!("not an array")
    };
    let Cbor::Array(mut hubs) = items.remove(5) else {
        panic!("not an array")
    };
    hubs.remove(0)
}

#[test]
fn hub_id_format() {
    let hub_id = hub(0).public().hub_id();
    assert!(hub_id.starts_with('h'));
    assert_eq!(hub_id.len(), 56);
    assert_ne!(hub_id, hub(1).public().hub_id());
    let debug = format!("{:?}", hub(0));
    assert!(!debug.contains(&HEXLOWER.encode(&seed(0x60))));
}

#[test]
fn runtime_cert_round_trip() {
    let hub = hub(0);
    let runtime = runtime_key();
    let signed = SignedHubRuntimeCert::issue(&hub, &runtime, NOW, NOW + DAY);
    let parsed = SignedHubRuntimeCert::from_bytes(&signed.to_bytes()).unwrap();
    assert_eq!(parsed, signed);
    let cert = parsed.verify(&hub.public(), NOW).unwrap();
    assert_eq!(cert.hub_root_public_key, hub.public());
    assert_eq!(cert.runtime_public_key, runtime);
    assert_eq!((cert.not_before, cert.not_after), (NOW, NOW + DAY));

    let peer_id = libp2p_peer_id_bytes(&runtime);
    assert_eq!(peer_id[..6], [0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
    assert_eq!(&peer_id[6..], runtime.as_bytes());
}

#[test]
fn runtime_cert_rejections() {
    let hub = hub(0);
    let signed = SignedHubRuntimeCert::issue(&hub, &runtime_key(), NOW, NOW + DAY);
    assert!(matches!(
        signed.verify(&hub.public(), NOW - 1),
        Err(IdentityError::NotYetValid)
    ));
    assert!(matches!(
        signed.verify(&hub.public(), NOW + DAY),
        Err(IdentityError::Expired)
    ));
    assert!(matches!(
        signed.verify(&self::hub(1).public(), NOW),
        Err(IdentityError::BadSignature)
    ));

    let (tbs, sig) = split(&signed.to_bytes());
    let mut bad_tbs = tbs.clone();
    *bad_tbs.last_mut().unwrap() ^= 1; // inside not_after
    let tampered = SignedHubRuntimeCert::from_bytes(&join(bad_tbs, sig.clone())).unwrap();
    assert!(matches!(
        tampered.verify(&hub.public(), NOW),
        Err(IdentityError::BadSignature)
    ));
    let mut bad_sig = sig;
    bad_sig[0] ^= 1;
    let tampered = SignedHubRuntimeCert::from_bytes(&join(tbs, bad_sig)).unwrap();
    assert!(matches!(
        tampered.verify(&hub.public(), NOW),
        Err(IdentityError::BadSignature)
    ));
}

#[test]
fn record_round_trip() {
    let record = record(&[(0, 10), (1, 0)]);
    let signed = record.sign(&user_root()).unwrap();
    let parsed = SignedHostingRecord::from_bytes(&signed.to_bytes()).unwrap();
    assert_eq!(parsed, signed);
    let verified = parsed.verify(NOW).unwrap();
    assert_eq!(verified, record);
    assert_eq!(verified.user_id(), &user_root().public().user_id());
    assert_eq!(verified.hubs().len(), 2);
    assert_eq!(verified.primary().hub_root_public_key(), &hub(1).public());
}

#[test]
fn builder_sorts_hubs_by_priority_then_key() {
    let record = record(&[(1, 5), (0, 9), (2, 5)]);
    let mut expected = [
        (5, hub(1).public()),
        (9, hub(0).public()),
        (5, hub(2).public()),
    ]
    .map(|(priority, key)| (priority, *key.as_bytes()));
    expected.sort();
    let actual = record
        .hubs()
        .iter()
        .map(|entry| (entry.priority(), *entry.hub_root_public_key().as_bytes()))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn user_root_key_as_hub_key_rejected() {
    let root = user_root();
    let as_hub = HostingEntry::sign(
        &HubRootKey::from_seed(&seed(0x00)),
        &root.public().user_id(),
        0,
    );
    assert!(matches!(
        UserHostingRecord::new(root.public(), 1, NOW + DAY, vec![as_hub]),
        Err(IdentityError::UserKeyIsHubKey)
    ));
}

#[test]
fn primary_ties_break_by_hub_id() {
    let record = record(&[(0, 5), (1, 5)]);
    let expected = [hub(0).public().hub_id(), hub(1).public().hub_id()]
        .into_iter()
        .min()
        .unwrap();
    assert_eq!(record.primary().hub_id(), expected);
}

#[test]
fn record_sign_requires_user_root() {
    assert!(matches!(
        record(&[(0, 0)]).sign(&RootKey::from_seed(&[9; 32])),
        Err(IdentityError::RootKeyMismatch)
    ));
}

#[test]
fn record_tampering_rejected() {
    let signed = record(&[(0, 0), (1, 1)]).sign(&user_root()).unwrap();
    let (tbs, sig) = split(&signed.to_bytes());

    // Change seq inside the signed body.
    let Cbor::Array(mut items) = cbor(&tbs) else {
        panic!("not an array")
    };
    items[3] = Cbor::Integer(2.into());
    let tampered =
        SignedHostingRecord::from_bytes(&join(cbor_bytes(&Cbor::Array(items)), sig.clone()))
            .unwrap();
    assert!(matches!(
        tampered.verify(NOW),
        Err(IdentityError::BadSignature)
    ));

    let mut bad_sig = sig;
    bad_sig[63] ^= 1;
    let tampered = SignedHostingRecord::from_bytes(&join(tbs, bad_sig)).unwrap();
    assert!(matches!(
        tampered.verify(NOW),
        Err(IdentityError::BadSignature)
    ));
}

#[test]
fn record_expiry() {
    let signed = record(&[(0, 0)]).sign(&user_root()).unwrap();
    assert!(signed.verify(NOW + 2 * DAY - 1).is_ok());
    assert!(matches!(
        signed.verify(NOW + 2 * DAY),
        Err(IdentityError::Expired)
    ));
}

#[test]
fn hub_entry_for_another_user_rejected() {
    let other_user = RootKey::from_seed(&[9; 32]).public().user_id();
    let foreign = HostingEntry::sign(&hub(0), &other_user, 0);
    assert!(matches!(
        UserHostingRecord::new(user_root().public(), 1, NOW + DAY, vec![foreign.clone()]),
        Err(IdentityError::BadHubSignature(_))
    ));

    // The same entry inside a body the user signed.
    let foreign = entry_value(&foreign, &RootKey::from_seed(&[9; 32]));
    assert!(matches!(
        signed_raw(body_with_hubs(vec![foreign])).verify(NOW),
        Err(IdentityError::BadHubSignature(_))
    ));
}

#[test]
fn hub_count_and_duplicates_rejected() {
    let user_id = user_root().public().user_id();
    let entry = HostingEntry::sign(&hub(0), &user_id, 0);

    assert!(matches!(
        UserHostingRecord::new(user_root().public(), 1, NOW + DAY, vec![]),
        Err(IdentityError::HubCount(0))
    ));
    assert!(matches!(
        UserHostingRecord::new(
            user_root().public(),
            1,
            NOW + DAY,
            vec![entry.clone(), HostingEntry::sign(&hub(0), &user_id, 1)]
        ),
        Err(IdentityError::DuplicateHub(_))
    ));
    let many = (0..17u8)
        .map(|n| HostingEntry::sign(&HubRootKey::from_seed(&[n; 32]), &user_id, n))
        .collect::<Vec<_>>();
    assert!(
        UserHostingRecord::new(user_root().public(), 1, NOW + DAY, many[..16].to_vec()).is_ok()
    );
    assert!(matches!(
        UserHostingRecord::new(user_root().public(), 1, NOW + DAY, many),
        Err(IdentityError::HubCount(17))
    ));

    // The same checks run on received bytes.
    assert!(matches!(
        signed_raw(body_with_hubs(vec![])).verify(NOW),
        Err(IdentityError::HubCount(0))
    ));
    // The count is checked before any entry is decoded.
    assert!(matches!(
        signed_raw(body_with_hubs(vec![Cbor::Null; 17])).verify(NOW),
        Err(IdentityError::HubCount(17))
    ));
    let value = entry_value(&entry, &user_root());
    assert!(matches!(
        signed_raw(body_with_hubs(vec![value.clone(), value])).verify(NOW),
        Err(IdentityError::DuplicateHub(_))
    ));
}

#[test]
fn record_user_id_must_match_root_key() {
    let entry = HostingEntry::sign(&hub(0), &user_root().public().user_id(), 0);
    let Cbor::Array(mut items) = body_with_hubs(vec![entry_value(&entry, &user_root())]) else {
        panic!("not an array")
    };
    items[1] = Cbor::Text(RootKey::from_seed(&[9; 32]).public().user_id().to_string());
    assert!(matches!(
        signed_raw(Cbor::Array(items)).verify(NOW),
        Err(IdentityError::UserIdMismatch)
    ));
}

#[test]
fn supersedes() {
    let root = user_root();
    let user_id = root.public().user_id();
    let a = HostingEntry::sign(&hub(0), &user_id, 0);
    let b = HostingEntry::sign(&hub(1), &user_id, 0);
    let v1 = UserHostingRecord::new(root.public(), 1, NOW + DAY, vec![a.clone()]).unwrap();
    let v2 = UserHostingRecord::new(root.public(), 2, NOW + DAY, vec![b.clone()]).unwrap();
    assert!(v2.supersedes(&v1).unwrap());
    assert!(matches!(
        v1.supersedes(&v2),
        Err(IdentityError::StaleSeq(1))
    ));
    assert!(!v1.supersedes(&v1.clone()).unwrap());

    let fork = UserHostingRecord::new(root.public(), 1, NOW + DAY, vec![b]).unwrap();
    assert!(matches!(
        fork.supersedes(&v1),
        Err(IdentityError::SeqConflict(1))
    ));

    let other_root = RootKey::from_seed(&[9; 32]);
    let other = UserHostingRecord::new(
        other_root.public(),
        5,
        NOW + DAY,
        vec![HostingEntry::sign(
            &hub(0),
            &other_root.public().user_id(),
            0,
        )],
    )
    .unwrap();
    assert!(matches!(
        other.supersedes(&v1),
        Err(IdentityError::UserIdMismatch)
    ));
}

fn compute() -> Value {
    let hubs = [hub(0), hub(1)];
    let runtime = runtime_key();
    let runtime_cert = SignedHubRuntimeCert::issue(&hubs[0], &runtime, NOW, NOW + DAY);
    let record = record(&[(0, 0), (1, 10)]);
    let signed_record = record.sign(&user_root()).unwrap();

    json!({
        "description": "gim hub identity and hosting record test vectors, see docs/identity.md",
        "hubs": hubs.iter().enumerate().map(|(n, hub)| json!({
            "root_seed": HEXLOWER.encode(&seed(0x60 + 0x20 * n as u8)),
            "root_pubkey": HEXLOWER.encode(hub.public().as_bytes()),
            "hub_id": hub.public().hub_id(),
        })).collect::<Vec<_>>(),
        "runtime_cert": {
            "hub": 0,
            "runtime_seed": HEXLOWER.encode(&seed(0xa0)),
            "runtime_pubkey": HEXLOWER.encode(runtime.as_bytes()),
            "peer_id": HEXLOWER.encode(&libp2p_peer_id_bytes(&runtime)),
            "not_before": NOW,
            "not_after": NOW + DAY,
            "signed": HEXLOWER.encode(&runtime_cert.to_bytes()),
        },
        "hosting_record": {
            "user_root_seed": HEXLOWER.encode(&seed(0x00)),
            "user_id": record.user_id().as_str(),
            "seq": record.seq(),
            "expires_at": record.expires_at(),
            "hubs": [{"hub": 0, "priority": 0}, {"hub": 1, "priority": 10}],
            "primary_hub_id": record.primary().hub_id(),
            "signed": HEXLOWER.encode(&signed_record.to_bytes()),
        },
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
    let hub_root =
        HubRootPublicKey::from_bytes(&hex(&file["hubs"][0]["root_pubkey"]).try_into().unwrap())
            .unwrap();
    let cert = SignedHubRuntimeCert::from_bytes(&hex(&file["runtime_cert"]["signed"]))
        .unwrap()
        .verify(&hub_root, NOW)
        .unwrap();
    assert_eq!(
        libp2p_peer_id_bytes(&cert.runtime_public_key).to_vec(),
        hex(&file["runtime_cert"]["peer_id"])
    );
    let record = SignedHostingRecord::from_bytes(&hex(&file["hosting_record"]["signed"]))
        .unwrap()
        .verify(NOW)
        .unwrap();
    assert_eq!(record.user_id().as_str(), file["hosting_record"]["user_id"]);
    assert_eq!(
        record.primary().hub_id(),
        file["hosting_record"]["primary_hub_id"]
    );
}

#[test]
#[ignore = "rewrites tests/vectors/hosting.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}

#[test]
fn entry_bytes_round_trip() {
    let root = user_root();
    let entry = HostingEntry::sign(&hub(0), &root.public().user_id(), 3);
    let bytes = entry.to_bytes();
    assert_eq!(cbor(&bytes), entry_value(&entry, &root));
    assert_eq!(HostingEntry::from_bytes(&bytes).unwrap(), entry);

    let mut tampered = cbor(&bytes);
    let Cbor::Array(items) = &mut tampered else {
        panic!("not an array")
    };
    items[1] = Cbor::Integer(256.into());
    assert!(HostingEntry::from_bytes(&cbor_bytes(&tampered)).is_err());
    assert!(HostingEntry::from_bytes(&bytes[..bytes.len() - 1]).is_err());
}
