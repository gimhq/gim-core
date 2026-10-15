use gim_identity::{
    DeviceList, DeviceSigningKey, IdentityError, RootKey, SignedDeviceCert, SignedDeviceList,
};

fn root() -> RootKey {
    RootKey::from_seed(&[1; 32])
}

fn device(n: u8) -> DeviceSigningKey {
    DeviceSigningKey::from_seed(&[n + 10; 32])
}

#[test]
fn cert_round_trip() {
    let root = root();
    let device = device(0).public();
    let signed = SignedDeviceCert::issue(&root, &device, 1_700_000_000_000, 3);
    let parsed = SignedDeviceCert::from_bytes(&signed.to_bytes()).unwrap();
    assert_eq!(parsed, signed);
    let cert = parsed.verify(&root.public()).unwrap();
    assert_eq!(cert.user_id, root.public().user_id());
    assert_eq!(cert.device_id, device.device_id());
    assert_eq!(cert.device_public_key, device);
    assert_eq!(cert.created_at, 1_700_000_000_000);
    assert_eq!(cert.seq, 3);
}

/// Byte offsets of tbs and sig inside `[bstr tbs, bstr(64) sig]`.
fn tbs_and_sig_offsets(bytes: &[u8]) -> (usize, usize) {
    // 0x82, then a bstr head of 2 bytes (tbs is 24..=255 bytes).
    assert_eq!(bytes[0], 0x82);
    assert_eq!(bytes[1], 0x58);
    let tbs_len = bytes[2] as usize;
    // sig head is 0x58 0x40.
    (3, 3 + tbs_len + 2)
}

#[test]
fn cert_tampering_rejected() {
    let root = root();
    let bytes = SignedDeviceCert::issue(&root, &device(0).public(), 5, 1).to_bytes();
    let (tbs_at, sig_at) = tbs_and_sig_offsets(&bytes);

    // Flip the last byte of tbs (the seq) and the first byte of the signature.
    for index in [sig_at - 3, sig_at] {
        let mut tampered = bytes.clone();
        tampered[index] ^= 1;
        let cert = SignedDeviceCert::from_bytes(&tampered).unwrap();
        assert!(matches!(
            cert.verify(&root.public()),
            Err(IdentityError::BadSignature)
        ));
    }
    // A user id character inside tbs.
    let mut tampered = bytes.clone();
    tampered[tbs_at + 4] ^= 1;
    assert!(matches!(
        SignedDeviceCert::from_bytes(&tampered)
            .unwrap()
            .verify(&root.public()),
        Err(IdentityError::BadSignature)
    ));

    let other_root = RootKey::from_seed(&[2; 32]);
    let cert = SignedDeviceCert::from_bytes(&bytes).unwrap();
    assert!(matches!(
        cert.verify(&other_root.public()),
        Err(IdentityError::BadSignature)
    ));

    assert!(SignedDeviceCert::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SignedDeviceCert::from_bytes(&trailing).is_err());
}

fn list_with_two(root: &RootKey) -> DeviceList {
    let certs = (0..2)
        .map(|n| SignedDeviceCert::issue(root, &device(n).public(), 0, 1))
        .collect();
    DeviceList::new(root.public(), 1, certs, vec![]).unwrap()
}

#[test]
fn list_round_trip_and_revoke() {
    let root = root();
    let list = list_with_two(&root);
    let id0 = device(0).public().device_id();
    let id1 = device(1).public().device_id();
    assert!(list.contains(&id0) && list.contains(&id1));

    let revoked = list.revoke(&id1).unwrap();
    assert_eq!(revoked.seq(), 2);
    assert!(revoked.is_revoked(&id1));
    assert!(!revoked.contains(&id1));
    assert!(revoked.contains(&id0));
    assert!(matches!(
        revoked.revoke(&id1),
        Err(IdentityError::Revoked(_))
    ));
    assert!(matches!(
        revoked.revoke(&device(5).public().device_id()),
        Err(IdentityError::UnknownDevice(_))
    ));
    assert!(matches!(
        revoked.add_cert(SignedDeviceCert::issue(&root, &device(1).public(), 0, 2)),
        Err(IdentityError::Revoked(_))
    ));

    let signed = revoked.sign(&root).unwrap();
    let parsed = SignedDeviceList::from_bytes(&signed.to_bytes()).unwrap();
    assert_eq!(parsed, signed);
    assert_eq!(parsed.verify(&root.public().user_id()).unwrap(), revoked);
}

#[test]
fn add_cert() {
    let root = root();
    let list = DeviceList::new(root.public(), 0, vec![], vec![]).unwrap();
    let cert = SignedDeviceCert::issue(&root, &device(0).public(), 0, 1);
    let list = list.add_cert(cert.clone()).unwrap();
    assert_eq!(list.seq(), 1);
    assert!(list.contains(&device(0).public().device_id()));
    assert!(matches!(
        list.add_cert(cert),
        Err(IdentityError::DuplicateDevice(_))
    ));
}

#[test]
fn list_rejects_foreign_cert() {
    let root = root();
    let other = RootKey::from_seed(&[2; 32]);
    let foreign = SignedDeviceCert::issue(&other, &device(0).public(), 0, 1);
    assert!(matches!(
        DeviceList::new(root.public(), 1, vec![foreign.clone()], vec![]),
        Err(IdentityError::BadSignature)
    ));
    let list = DeviceList::new(root.public(), 0, vec![], vec![]).unwrap();
    assert!(matches!(
        list.add_cert(foreign),
        Err(IdentityError::BadSignature)
    ));
}

#[test]
fn list_verify_rejects_wrong_user_root_or_signature() {
    let root = root();
    let other = RootKey::from_seed(&[2; 32]);
    let list = list_with_two(&root);
    assert!(matches!(
        list.sign(&other),
        Err(IdentityError::RootKeyMismatch)
    ));
    let signed = list.sign(&root).unwrap();
    assert!(matches!(
        signed.verify(&other.public().user_id()),
        Err(IdentityError::UserIdMismatch)
    ));

    let mut bytes = signed.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        SignedDeviceList::from_bytes(&bytes)
            .unwrap()
            .verify(&root.public().user_id()),
        Err(IdentityError::BadSignature)
    ));
}

#[test]
fn supersedes() {
    let root = root();
    let v1 = list_with_two(&root);
    let v2 = v1.revoke(&device(1).public().device_id()).unwrap();
    assert!(v2.supersedes(&v1).unwrap());
    assert!(!v1.supersedes(&v2).unwrap());
    assert!(!v2.supersedes(&v2.clone()).unwrap());

    // Same seq, different content.
    let fork = v1.revoke(&device(0).public().device_id()).unwrap();
    assert!(matches!(
        v2.supersedes(&fork),
        Err(IdentityError::SeqConflict(2))
    ));

    let other = RootKey::from_seed(&[2; 32]);
    let foreign = DeviceList::new(other.public(), 0, vec![], vec![]).unwrap();
    assert!(matches!(
        v2.supersedes(&foreign),
        Err(IdentityError::UserIdMismatch)
    ));
}
