//! Hub URL normalization and the hub proof of possession. Asserts
//! `tests/vectors/public-url.json` and `tests/vectors/hub-proof.json`
//! (shared with gim-hub).

use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER};
use gim_identity::{normalize_hub_url, HubRootKey, IdentityError, HUB_PROOF_CONTEXT};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

#[test]
fn public_url_vectors() {
    let file = vectors("public-url.json");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 40);
    for case in cases {
        let input = case["input"].as_str().unwrap();
        let result = normalize_hub_url(input);
        match case["normalized"].as_str() {
            Some(normalized) => {
                assert_eq!(result.as_deref().ok(), Some(normalized), "{input:?}");
                // Normalization is idempotent.
                assert_eq!(normalize_hub_url(normalized).unwrap(), normalized);
            }
            None => assert!(
                matches!(result, Err(IdentityError::InvalidUrl(_))),
                "{input:?} ({}): {result:?}",
                case["error"]
            ),
        }
    }
}

#[test]
fn hub_proof_vectors() {
    let file = vectors("hub-proof.json");
    let cases = file["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let root = HubRootKey::from_seed(&hex(&case["root_seed"]).try_into().unwrap());
        let public = root.public();
        assert_eq!(public.as_bytes().to_vec(), hex(&case["hub_root_pubkey"]));
        assert_eq!(
            BASE64.encode(public.as_bytes()),
            case["hub_root_pubkey_base64"].as_str().unwrap()
        );
        let hub_id = case["hub_id"].as_str().unwrap();
        assert_eq!(public.hub_id(), hub_id);
        let url = case["public_url"].as_str().unwrap();
        let nonce: [u8; 32] = hex(&case["nonce"]).try_into().unwrap();
        assert_eq!(
            BASE64URL_NOPAD.encode(&nonce),
            case["nonce_base64url"].as_str().unwrap()
        );
        let message = hex(&case["message"]);
        assert!(message.starts_with(HUB_PROOF_CONTEXT));

        let proof = root.sign_hub_proof(&nonce, url).unwrap();
        assert_eq!(proof.to_vec(), hex(&case["proof"]));
        assert_eq!(
            BASE64URL_NOPAD.encode(&proof),
            case["proof_base64url"].as_str().unwrap()
        );
        // The proof is a plain Ed25519 signature over `message`.
        let key = ed25519_dalek::VerifyingKey::from_bytes(public.as_bytes()).unwrap();
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&proof))
            .unwrap();
        public
            .verify_hub_proof(&nonce, hub_id, url, &proof)
            .unwrap();
    }
}

#[test]
fn hub_proof_rejections() {
    let file = vectors("hub-proof.json");
    let case = &file["cases"][0];
    let other = &file["cases"][1];
    let root = HubRootKey::from_seed(&hex(&case["root_seed"]).try_into().unwrap());
    let public = root.public();
    let hub_id = case["hub_id"].as_str().unwrap();
    let url = case["public_url"].as_str().unwrap();
    let nonce: [u8; 32] = hex(&case["nonce"]).try_into().unwrap();
    let proof: [u8; 64] = hex(&case["proof"]).try_into().unwrap();
    let bad =
        |result: Result<(), IdentityError>| matches!(result, Err(IdentityError::BadSignature));

    // Another URL (a relay), another nonce (a replay) or a flipped bit.
    assert!(bad(public.verify_hub_proof(
        &nonce,
        hub_id,
        "https://relay.example.eu",
        &proof
    )));
    let mut replayed = nonce;
    replayed[0] ^= 1;
    assert!(bad(public.verify_hub_proof(&replayed, hub_id, url, &proof)));
    let mut tampered = proof;
    tampered[10] ^= 1;
    assert!(bad(public.verify_hub_proof(&nonce, hub_id, url, &tampered)));
    // Signed by another hub's root key for the same URL and nonce.
    let other_root = HubRootKey::from_seed(&hex(&other["root_seed"]).try_into().unwrap());
    let foreign = other_root.sign_hub_proof(&nonce, url).unwrap();
    assert!(bad(public.verify_hub_proof(&nonce, hub_id, url, &foreign)));
    // A hub_id that does not derive from the key.
    assert!(matches!(
        public.verify_hub_proof(&nonce, other["hub_id"].as_str().unwrap(), url, &proof),
        Err(IdentityError::HubKeyMismatch)
    ));
    // The hub only signs normalized URLs.
    assert!(matches!(
        root.sign_hub_proof(&nonce, "https://HUB-A.example.eu/"),
        Err(IdentityError::InvalidUrl(_))
    ));
}
