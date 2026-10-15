//! Device link round trip, rejection cases and `tests/vectors/link.json`.
//! After an intentional format change, regenerate the vectors with
//! `cargo test -p gim-identity --test link -- --ignored regenerate`.

use data_encoding::HEXLOWER;
use gim_identity::link::{
    open_link_bundle, seal_link_bundle, seal_link_bundle_with, LinkBundle, LinkError, LinkOffer,
};
use gim_identity::{
    DeviceList, DevicePublicKey, DeviceSigningKey, RootKey, SignedDeviceCert, SignedDeviceList,
};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/link.json");
const CREATED_AT: u64 = 1_760_486_400_000; // 2025-10-15T00:00:00Z

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn device(start: u8) -> DevicePublicKey {
    DeviceSigningKey::from_seed(&seed(start)).public()
}

/// The old device's state: root key, a cert for `new_device` and a signed
/// list `[old device, new device]`.
fn issue(root: &RootKey, new_device: &DevicePublicKey) -> (SignedDeviceCert, SignedDeviceList) {
    let old = SignedDeviceCert::issue(root, &device(0x20), CREATED_AT, 1);
    let new = SignedDeviceCert::issue(root, new_device, CREATED_AT, 2);
    let list = DeviceList::new(root.public(), 1, vec![old], vec![])
        .unwrap()
        .add_cert(new.clone())
        .unwrap()
        .sign(root)
        .unwrap();
    (new, list)
}

fn hubs() -> Vec<String> {
    vec!["hub.example.eu".into(), "backup.example.eu".into()]
}

#[test]
fn round_trip() {
    let root = RootKey::from_seed(&seed(0x00));
    let new_device = device(0x40);
    let (offer, secret) = LinkOffer::new(new_device, hubs()).unwrap();
    let scanned = LinkOffer::from_qr_string(&offer.to_qr_string()).unwrap();
    assert_eq!(scanned, offer);
    assert_eq!(LinkOffer::from_bytes(&offer.to_bytes()).unwrap(), offer);

    let (cert, list) = issue(&root, &new_device);
    let bundle = LinkBundle::new(&root, &cert, &list, Some(b"welcome".to_vec()));
    let (sealed, sas) = seal_link_bundle(&scanned, &bundle).unwrap();
    let (opened, opened_sas) = open_link_bundle(&offer, &secret, &sealed).unwrap();

    assert_eq!(sas, opened_sas);
    assert_eq!(sas.to_string().len(), 7);
    assert_eq!(opened.root.public(), root.public());
    assert_eq!(opened.cert.device_public_key, new_device);
    assert_eq!(
        opened.device_list,
        list.verify(&root.public().user_id()).unwrap()
    );
    assert_eq!(opened.self_group_welcome.as_deref(), Some(&b"welcome"[..]));
}

#[test]
fn rejects_wrong_secret_and_tampering() {
    let root = RootKey::from_seed(&seed(0x00));
    let new_device = device(0x40);
    let (offer, secret) = LinkOffer::new(new_device, hubs()).unwrap();
    let (cert, list) = issue(&root, &new_device);
    let bundle = LinkBundle::new(&root, &cert, &list, None);
    let (sealed, _) = seal_link_bundle(&offer, &bundle).unwrap();

    // Another offer's secret.
    let (_, other_secret) = LinkOffer::new(new_device, hubs()).unwrap();
    assert!(matches!(
        open_link_bundle(&offer, &other_secret, &sealed),
        Err(LinkError::Decrypt)
    ));

    // Last ciphertext byte (the GCM tag).
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        open_link_bundle(&offer, &secret, &tampered),
        Err(LinkError::Decrypt)
    ));

    // The same X25519 key and link id, but a different device key: the
    // transcript differs.
    let mut swapped = offer.to_bytes();
    let device_at = swapped.len() - 32 - 1 - hubs().iter().map(|h| h.len() + 1).sum::<usize>();
    swapped[device_at..device_at + 32].copy_from_slice(device(0x60).as_bytes());
    let swapped = LinkOffer::from_bytes(&swapped).unwrap();
    assert_eq!(swapped.eph_pub(), offer.eph_pub());
    assert_eq!(swapped.device_public_key(), &device(0x60));
    assert!(matches!(
        open_link_bundle(&swapped, &secret, &sealed),
        Err(LinkError::Decrypt)
    ));

    // Version 2 envelope.
    let mut v2 = sealed.clone();
    assert_eq!(v2[1], 0x01);
    v2[1] = 0x02;
    assert!(matches!(
        open_link_bundle(&offer, &secret, &v2),
        Err(LinkError::UnsupportedVersion(2))
    ));
}

#[test]
fn rejects_cert_for_another_device() {
    let root = RootKey::from_seed(&seed(0x00));
    let (offer, secret) = LinkOffer::new(device(0x40), hubs()).unwrap();
    let (cert, list) = issue(&root, &device(0x60));
    let bundle = LinkBundle::new(&root, &cert, &list, None);
    let (sealed, _) = seal_link_bundle(&offer, &bundle).unwrap();
    assert!(matches!(
        open_link_bundle(&offer, &secret, &sealed),
        Err(LinkError::CertMismatch)
    ));
}

#[test]
fn rejects_mismatched_device_list() {
    let root = RootKey::from_seed(&seed(0x00));
    let new_device = device(0x40);
    let (offer, secret) = LinkOffer::new(new_device, hubs()).unwrap();
    let (cert, list) = issue(&root, &new_device);
    let open = |list: &SignedDeviceList| {
        let bundle = LinkBundle::new(&root, &cert, list, None);
        let (sealed, _) = seal_link_bundle(&offer, &bundle).unwrap();
        open_link_bundle(&offer, &secret, &sealed)
    };
    assert!(open(&list).is_ok());

    // Another user's list.
    let other_root = RootKey::from_seed(&seed(0x80));
    let (_, other_list) = issue(&other_root, &new_device);
    assert!(matches!(open(&other_list), Err(LinkError::ListMismatch)));

    // A list without the new device.
    let old = SignedDeviceCert::issue(&root, &device(0x20), CREATED_AT, 1);
    let without = DeviceList::new(root.public(), 1, vec![old], vec![]).unwrap();
    let signed_without = without.sign(&root).unwrap();
    assert!(matches!(
        open(&signed_without),
        Err(LinkError::ListMismatch)
    ));

    // A list that revokes the new device.
    let revoked = without
        .add_cert(cert.clone())
        .unwrap()
        .revoke(&new_device.device_id())
        .unwrap()
        .sign(&root)
        .unwrap();
    assert!(matches!(open(&revoked), Err(LinkError::Revoked(id)) if id == new_device.device_id()));
}

#[test]
fn sas_depends_on_sender_key() {
    let root = RootKey::from_seed(&seed(0x00));
    let new_device = device(0x40);
    let (offer, secret) = LinkOffer::from_parts([7; 16], &seed(0xa0), new_device, hubs());
    let (cert, list) = issue(&root, &new_device);
    let bundle = LinkBundle::new(&root, &cert, &list, None);

    let (sealed_a, sas_a) = seal_link_bundle_with(&offer, &bundle, &seed(0xc0), &[1; 12]).unwrap();
    let (sealed_b, sas_b) = seal_link_bundle_with(&offer, &bundle, &seed(0xe0), &[1; 12]).unwrap();
    assert_ne!(sas_a, sas_b);
    assert_eq!(
        open_link_bundle(&offer, &secret, &sealed_a).unwrap().1,
        sas_a
    );
    assert_eq!(
        open_link_bundle(&offer, &secret, &sealed_b).unwrap().1,
        sas_b
    );
}

#[test]
fn rejects_malformed_qr() {
    let (offer, _) = LinkOffer::new(device(0x40), hubs()).unwrap();
    let qr = offer.to_qr_string();
    for bad in [
        &qr["gimlink:".len()..],
        &qr.replacen("gimlink:", "GIMLINK:", 1),
        &format!("{qr}="),
        &qr[..qr.len() - 1],
    ] {
        assert!(LinkOffer::from_qr_string(bad).is_err(), "{bad}");
    }
}

fn compute() -> Value {
    let link_id: [u8; 16] = std::array::from_fn(|i| 0xf0u8.wrapping_add(i as u8));
    let offer_secret = seed(0xa0);
    let device_seed = seed(0x40);
    let new_device = DeviceSigningKey::from_seed(&device_seed).public();
    let (offer, secret) = LinkOffer::from_parts(link_id, &offer_secret, new_device, hubs());

    let root_seed = seed(0x00);
    let root = RootKey::from_seed(&root_seed);
    let (cert, list) = issue(&root, &new_device);
    let welcome = b"self-group welcome".to_vec();
    let bundle = LinkBundle::new(&root, &cert, &list, Some(welcome.clone()));

    let sender_secret = seed(0xc0);
    let nonce: [u8; 12] = std::array::from_fn(|i| i as u8);
    let (sealed, sas) = seal_link_bundle_with(&offer, &bundle, &sender_secret, &nonce).unwrap();
    let (_, opened_sas) = open_link_bundle(&offer, &secret, &sealed).unwrap();
    assert_eq!(sas, opened_sas);

    json!({
        "description": "gim device link test vectors, see docs/identity.md",
        "offer": {
            "link_id": HEXLOWER.encode(&link_id),
            "eph_secret": HEXLOWER.encode(&offer_secret),
            "eph_pub": HEXLOWER.encode(offer.eph_pub()),
            "device_seed": HEXLOWER.encode(&device_seed),
            "device_sig_pubkey": HEXLOWER.encode(new_device.as_bytes()),
            "hubs": hubs(),
            "bytes": HEXLOWER.encode(&offer.to_bytes()),
            "qr": offer.to_qr_string(),
        },
        "bundle": {
            "root_seed": HEXLOWER.encode(&root_seed),
            "cert": HEXLOWER.encode(&cert.to_bytes()),
            "device_list": HEXLOWER.encode(&list.to_bytes()),
            "self_group_welcome": HEXLOWER.encode(&welcome),
        },
        "seal": {
            "sender_eph_secret": HEXLOWER.encode(&sender_secret),
            "nonce": HEXLOWER.encode(&nonce),
            "sealed": HEXLOWER.encode(&sealed),
            "sas": sas.value(),
            "sas_display": sas.to_string(),
        },
    })
}

#[test]
fn vectors_match() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(file, compute());

    // The committed sealed bytes open on their own.
    let hex = |value: &Value| HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap();
    let offer = LinkOffer::from_bytes(&hex(&file["offer"]["bytes"])).unwrap();
    assert_eq!(
        LinkOffer::from_qr_string(file["offer"]["qr"].as_str().unwrap()).unwrap(),
        offer
    );
    let eph_secret: [u8; 32] = hex(&file["offer"]["eph_secret"]).try_into().unwrap();
    let (rebuilt, secret) = LinkOffer::from_parts(
        *offer.link_id(),
        &eph_secret,
        *offer.device_public_key(),
        offer.hubs().to_vec(),
    );
    assert_eq!(rebuilt, offer);
    let (opened, sas) = open_link_bundle(&offer, &secret, &hex(&file["seal"]["sealed"])).unwrap();
    assert_eq!(u64::from(sas.value()), file["seal"]["sas"]);
    assert_eq!(sas.to_string(), file["seal"]["sas_display"]);
    assert_eq!(
        opened.root.public(),
        RootKey::from_seed(&seed(0x00)).public()
    );
    assert_eq!(
        opened.self_group_welcome.unwrap(),
        hex(&file["bundle"]["self_group_welcome"])
    );
}

#[test]
#[ignore = "rewrites tests/vectors/link.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}
