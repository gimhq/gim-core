//! Envelope encrypt/decrypt over a 2-member MLS group.

use gim_common::{DeviceRef, GroupId, MessageId};
use gim_crypto::{
    decrypt_to_envelope, encrypt_envelope, CryptoError, DecryptedMessage, MemoryCryptoStore,
    MlsEngine, ProcessedMessage,
};
use gim_proto::envelope::{Content, Envelope};

struct Device {
    me: DeviceRef,
    engine: MlsEngine,
    store: MemoryCryptoStore,
}

fn device(user: &str) -> Device {
    let me = DeviceRef::parse(user, "phone").unwrap();
    let engine = MlsEngine::new();
    let store = MemoryCryptoStore::new();
    engine.create_identity(&store, me.clone()).unwrap();
    Device { me, engine, store }
}

#[test]
fn envelope_round_trip_over_two_member_group() {
    let alice = device("alice");
    let bob = device("bob");
    let g = GroupId::new("g-piraeus").unwrap();

    alice.engine.create_group(&alice.store, &g).unwrap();
    let kp = bob
        .engine
        .generate_key_packages(&bob.store, 1)
        .unwrap()
        .remove(0);
    let out = alice.engine.add_members(&alice.store, &g, &[kp]).unwrap();
    let epoch = alice.engine.merge_pending_commit(&alice.store, &g).unwrap();
    bob.engine
        .join_from_welcome(&bob.store, &out.welcome.unwrap())
        .unwrap();

    let mut envelope = Envelope::new(
        MessageId::new("m-1").unwrap(),
        1_760_000_000_000,
        Content::Text {
            body: "Leaving Piraeus at 09:00".into(),
        },
    );
    envelope.reply_to = Some(MessageId::new("m-0").unwrap());
    let ct = encrypt_envelope(&alice.engine, &alice.store, &g, &envelope).unwrap();
    assert_eq!(
        decrypt_to_envelope(&bob.engine, &bob.store, &g, &ct).unwrap(),
        DecryptedMessage::Envelope {
            sender: alice.me.clone(),
            epoch,
            envelope,
        }
    );

    // Reply in the other direction.
    let reply = Envelope::new(
        MessageId::new("m-2").unwrap(),
        1_760_000_000_500,
        Content::Typing { active: true },
    );
    let ct = encrypt_envelope(&bob.engine, &bob.store, &g, &reply).unwrap();
    assert!(matches!(
        decrypt_to_envelope(&alice.engine, &alice.store, &g, &ct).unwrap(),
        DecryptedMessage::Envelope { sender, envelope, .. } if sender == bob.me && envelope == reply
    ));

    // Invalid envelopes are refused before encryption.
    let mut bad = reply.clone();
    bad.reply_to = Some(MessageId::new("m-1").unwrap());
    assert!(matches!(
        encrypt_envelope(&bob.engine, &bob.store, &g, &bad),
        Err(CryptoError::InvalidInput { .. })
    ));

    // Non-envelope application plaintext is reported as invalid.
    let ct = alice.engine.encrypt(&alice.store, &g, b"raw").unwrap();
    assert!(matches!(
        decrypt_to_envelope(&bob.engine, &bob.store, &g, &ct),
        Err(CryptoError::InvalidInput { .. })
    ));

    // Commits pass through as handshake messages.
    let carol = device("carol");
    let kp = carol
        .engine
        .generate_key_packages(&carol.store, 1)
        .unwrap()
        .remove(0);
    let out = alice.engine.add_members(&alice.store, &g, &[kp]).unwrap();
    alice.engine.merge_pending_commit(&alice.store, &g).unwrap();
    assert!(matches!(
        decrypt_to_envelope(&bob.engine, &bob.store, &g, &out.commit).unwrap(),
        DecryptedMessage::Handshake(ProcessedMessage::Commit { added, .. }) if added == [carol.me.clone()]
    ));
}
