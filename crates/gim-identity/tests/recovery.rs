//! Recovery code and backup tests; asserts `tests/vectors/recovery.json`.
//! After an intentional format change, regenerate it with
//! `cargo test -p gim-identity --test recovery -- --ignored regenerate`.

use data_encoding::HEXLOWER;
use gim_identity::recovery::{
    open_root_key_backup, seal_root_key_backup_with, KdfParams, RecoveryCode, RecoveryError,
    NONCE_LEN, RECOVERY_CODE_LEN, SALT_LEN,
};
use gim_identity::{IdentityError, RootKey};
use serde_json::{json, Value};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/recovery.json");
const LOW: KdfParams = KdfParams::new(64, 1, 1);

fn bytes<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn code() -> RecoveryCode {
    RecoveryCode::from_bytes(bytes(0xa0))
}

fn root() -> RootKey {
    RootKey::from_seed(&bytes(0x00))
}

fn seal(root: &RootKey, code: &RecoveryCode, params: KdfParams) -> Vec<u8> {
    seal_root_key_backup_with(root, code, params, &bytes(0x10), &bytes(0x30)).unwrap()
}

#[test]
fn display_parse_round_trip() {
    for _ in 0..32 {
        let code = RecoveryCode::generate().unwrap();
        let text = code.to_string();
        assert_eq!(text.len(), 39 + 9);
        assert!(text
            .split('-')
            .all(|group| group.len() == 4 || group.len() == 3));
        assert_eq!(text.parse::<RecoveryCode>().unwrap().to_string(), text);
    }
}

#[test]
fn parse_is_lenient_about_case_separators_and_lookalikes() {
    let code = RecoveryCode::from_bytes([0x08; RECOVERY_CODE_LEN]);
    let text = code.to_string();
    // 0x08 repeated contains both 0 and 1 symbols.
    assert!(text.contains('0') && text.contains('1'), "{text}");
    let canonical = code.to_string();
    for variant in [
        text.to_ascii_lowercase(),
        text.replace('-', ""),
        text.replace('-', " "),
        format!(" \t{}\n", text.replace('-', "\r\n")),
        text.replace('0', "O"),
        text.replace('0', "o"),
        text.replace('1', "I"),
        text.replace('1', "l"),
        text.replace('1', "L"),
        text.replace('1', "i"),
    ] {
        let parsed: RecoveryCode = variant.parse().unwrap();
        assert_eq!(parsed.to_string(), canonical, "{variant:?}");
    }
}

#[test]
fn parse_rejects_malformed_codes() {
    let text = code().to_string().replace('-', "");
    let last = text.chars().last().unwrap();
    // The last symbol carries 2 data bits; any of the low 3 bits set is
    // non-zero padding.
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let index = alphabet.find(last).unwrap();
    let bad_padding = alphabet.as_bytes()[index | 1] as char;
    for bad in [
        String::new(),
        text[..38].to_string(),
        format!("{text}0"),
        format!("{text}0000"),
        format!("{}U", &text[..38]),
        format!("{}*", &text[..38]),
        format!("{}é", &text[..37]),
        format!("{}{bad_padding}", &text[..38]),
        format!("{}_{}", &text[..20], &text[20..]),
    ] {
        assert!(
            matches!(
                bad.parse::<RecoveryCode>(),
                Err(RecoveryError::InvalidCode(_))
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn seal_open_round_trip() {
    let root = root();
    let user_id = root.public().user_id();
    let blob = seal(&root, &code(), LOW);
    let opened = open_root_key_backup(&blob, &code(), &user_id).unwrap();
    assert_eq!(opened.public(), root.public());
    // Parsing the displayed code opens it too.
    let parsed: RecoveryCode = code().to_string().to_ascii_lowercase().parse().unwrap();
    assert!(open_root_key_backup(&blob, &parsed, &user_id).is_ok());
}

#[test]
fn open_rejects_wrong_code_and_tampering() {
    let root = root();
    let user_id = root.public().user_id();
    let blob = seal(&root, &code(), LOW);

    let wrong = RecoveryCode::from_bytes(bytes(0xa1));
    assert!(matches!(
        open_root_key_backup(&blob, &wrong, &user_id),
        Err(RecoveryError::Decrypt)
    ));

    // Every ciphertext and tag byte (the plaintext `[1, seed]` is 36 bytes,
    // plus a 16-byte tag) and the salt and nonce are covered by the AEAD.
    for offset in 1..=(36 + 16) {
        let mut tampered = blob.clone();
        let at = tampered.len() - offset;
        tampered[at] ^= 0x01;
        assert!(
            matches!(
                open_root_key_backup(&tampered, &code(), &user_id),
                Err(RecoveryError::Decrypt)
            ),
            "offset {offset}"
        );
    }
    let salt_at = blob
        .windows(SALT_LEN)
        .position(|w| w == bytes::<SALT_LEN>(0x10))
        .unwrap();
    let nonce_at = blob
        .windows(NONCE_LEN)
        .position(|w| w == bytes::<NONCE_LEN>(0x30))
        .unwrap();
    for at in [salt_at, nonce_at] {
        let mut tampered = blob.clone();
        tampered[at] ^= 0x01;
        assert!(matches!(
            open_root_key_backup(&tampered, &code(), &user_id),
            Err(RecoveryError::Decrypt)
        ));
    }

    // Raising the cost changes the AAD and the key.
    let mut raised = blob.clone();
    let params_at = blob
        .windows(4)
        .position(|w| w == [0x83, 0x18, 0x40, 0x01])
        .unwrap();
    raised[params_at + 2] = 0x41;
    assert!(matches!(
        open_root_key_backup(&raised, &code(), &user_id),
        Err(RecoveryError::Decrypt)
    ));

    assert!(matches!(
        open_root_key_backup(&blob[..blob.len() - 1], &code(), &user_id),
        Err(RecoveryError::Identity(IdentityError::Decode(_)))
    ));
}

#[test]
fn open_rejects_other_user() {
    let blob = seal(&root(), &code(), LOW);
    let other = RootKey::from_seed(&bytes(0x01)).public().user_id();
    assert!(matches!(
        open_root_key_backup(&blob, &code(), &other),
        Err(RecoveryError::UserMismatch)
    ));
}

#[test]
fn open_rejects_weak_params() {
    let root = root();
    let user_id = root.public().user_id();
    for weak in [KdfParams::new(32, 1, 1), KdfParams::new(64, 0, 1)] {
        // Argon2 itself rejects t = 0, so build that blob from a valid one.
        let blob = if weak.t() == 0 {
            let mut blob = seal(&root, &code(), LOW);
            let at = blob
                .windows(4)
                .position(|w| w == [0x83, 0x18, 0x40, 0x01])
                .unwrap();
            blob[at + 3] = 0x00;
            blob
        } else {
            seal(&root, &code(), weak)
        };
        assert!(matches!(
            open_root_key_backup(&blob, &code(), &user_id),
            Err(RecoveryError::WeakParams)
        ));
    }
}

fn compute() -> Value {
    let code = code();
    let root = root();
    let salt: [u8; SALT_LEN] = bytes(0x10);
    let nonce: [u8; NONCE_LEN] = bytes(0x30);
    let blob = seal(&root, &code, LOW);
    json!({
        "description": "gim recovery backup test vectors, see docs/identity.md",
        "code_bytes": HEXLOWER.encode(&bytes::<RECOVERY_CODE_LEN>(0xa0)),
        "code_display": code.to_string(),
        "root_seed": HEXLOWER.encode(&bytes::<32>(0x00)),
        "user_id": root.public().user_id().as_str(),
        "kdf_params": { "m_kib": LOW.m_kib(), "t": LOW.t(), "p": LOW.p() },
        "salt": HEXLOWER.encode(&salt),
        "nonce": HEXLOWER.encode(&nonce),
        "blob": HEXLOWER.encode(&blob),
    })
}

#[test]
fn vectors_match() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(file, compute());

    // The committed blob opens on its own with the parsed display string.
    let blob = HEXLOWER
        .decode(file["blob"].as_str().unwrap().as_bytes())
        .unwrap();
    let code: RecoveryCode = file["code_display"].as_str().unwrap().parse().unwrap();
    let user_id = gim_identity::parse_user_id(file["user_id"].as_str().unwrap()).unwrap();
    let root = open_root_key_backup(&blob, &code, &user_id).unwrap();
    assert_eq!(root.public().user_id(), user_id);
}

#[test]
#[ignore = "rewrites tests/vectors/recovery.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&compute()).unwrap() + "\n";
    std::fs::write(PATH, text).unwrap();
}
