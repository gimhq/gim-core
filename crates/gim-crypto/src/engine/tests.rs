use gim_test::TestIdentity;

use super::*;
use crate::MemoryCryptoStore;

struct Dev {
    engine: MlsEngine,
    store: MemoryCryptoStore,
}

fn dev(user: &str) -> Dev {
    let dev = Dev {
        engine: MlsEngine::new(),
        store: MemoryCryptoStore::new(),
    };
    create_identity(&dev, &TestIdentity::new(user)).unwrap();
    dev
}

fn create_identity(dev: &Dev, id: &TestIdentity) -> Result<()> {
    dev.engine
        .create_identity_v2(&dev.store, &id.device_key, id.root.public(), id.cert.clone())
}

fn gid(id: &str) -> GroupId {
    GroupId::new(id).unwrap()
}

impl Dev {
    fn me(&self) -> DeviceRef {
        self.engine.identity(&self.store).unwrap()
    }
    fn kps(&self, n: u32) -> Vec<Vec<u8>> {
        self.engine.generate_key_packages(&self.store, n).unwrap()
    }
    fn create(&self, g: &str) {
        self.engine.create_group(&self.store, &gid(g)).unwrap();
    }
    fn add(&self, g: &str, kps: &[Vec<u8>]) -> CommitOutput {
        self.engine.add_members(&self.store, &gid(g), kps).unwrap()
    }
    fn merge(&self, g: &str) -> u64 {
        self.engine
            .merge_pending_commit(&self.store, &gid(g))
            .unwrap()
    }
    fn join(&self, welcome: &[u8]) -> Result<GroupJoined> {
        self.engine.join_from_welcome(&self.store, welcome)
    }
    fn encrypt(&self, g: &str, pt: &[u8]) -> Vec<u8> {
        self.engine.encrypt(&self.store, &gid(g), pt).unwrap()
    }
    fn process(&self, g: &str, msg: &[u8]) -> Result<ProcessedMessage> {
        self.engine.process_message(&self.store, &gid(g), msg)
    }
    fn decrypt(&self, g: &str, msg: &[u8]) -> Vec<u8> {
        match self.process(g, msg).unwrap() {
            ProcessedMessage::Application { plaintext, .. } => plaintext,
            other => panic!("unexpected {other:?}"),
        }
    }
    fn epoch(&self, g: &str) -> u64 {
        self.engine.group_epoch(&self.store, &gid(g)).unwrap()
    }
}

/// Alice creates `g` and adds Bob.
fn pair() -> (Dev, Dev) {
    let (alice, bob) = (dev("alice"), dev("bob"));
    alice.create("g");
    let out = alice.add("g", &bob.kps(1));
    assert_eq!(out.epoch, 0);
    assert_eq!(alice.merge("g"), 1);
    let joined = bob.join(&out.welcome.unwrap()).unwrap();
    assert_eq!(joined.group_id, gid("g"));
    assert_eq!(joined.epoch, 1);
    assert_eq!(joined.members, vec![alice.me(), bob.me()]);
    (alice, bob)
}

#[test]
fn identity() {
    let alice = dev("alice");
    let id = TestIdentity::new("alice");
    assert_eq!(alice.me(), id.device);
    let pk = alice.engine.signature_public_key(&alice.store).unwrap();
    assert_eq!(pk, id.device_key.public().as_bytes().to_vec());
    assert!(matches!(
        create_identity(&alice, &TestIdentity::new("x")),
        Err(CryptoError::InvalidInput { .. })
    ));
    let empty = MemoryCryptoStore::new();
    assert!(matches!(
        alice.engine.identity(&empty),
        Err(CryptoError::Store { .. })
    ));
    assert!(alice.engine.generate_key_packages(&empty, 1).is_err());
}

#[test]
fn key_packages() {
    let alice = dev("alice");
    let kps = alice.kps(3);
    assert_eq!(kps.len(), 3);
    assert!(alice.kps(0).is_empty());
    assert!(alice
        .engine
        .generate_key_packages(&alice.store, MAX_KEY_PACKAGES_PER_CALL + 1)
        .is_err());
    for kp in &kps {
        assert!(!alice.engine.validate_key_package(kp).unwrap().last_resort());
    }
    let lr = alice
        .engine
        .generate_last_resort_key_package(&alice.store)
        .unwrap();
    assert!(alice
        .engine
        .validate_key_package(&lr)
        .unwrap()
        .last_resort());
}

#[test]
fn last_resort_key_package_is_reusable() {
    let (alice, bob) = (dev("alice"), dev("bob"));
    let lr = bob
        .engine
        .generate_last_resort_key_package(&bob.store)
        .unwrap();
    for g in ["g1", "g2"] {
        alice.create(g);
        let out = alice.add(g, std::slice::from_ref(&lr));
        alice.merge(g);
        assert_eq!(bob.join(&out.welcome.unwrap()).unwrap().group_id, gid(g));
    }
}

#[test]
fn one_time_key_package_is_consumed() {
    let (alice, bob) = (dev("alice"), dev("bob"));
    let kp = bob.kps(1);
    let welcomes: Vec<_> = ["g1", "g2"]
        .iter()
        .map(|g| {
            alice.create(g);
            let out = alice.add(g, &kp);
            alice.merge(g);
            out.welcome.unwrap()
        })
        .collect();
    bob.join(&welcomes[0]).unwrap();
    assert!(bob.join(&welcomes[1]).is_err());
}

#[test]
fn create_and_delete_group() {
    let alice = dev("alice");
    alice.create("g");
    let e = &alice.engine;
    assert!(e.has_group(&alice.store, &gid("g")).unwrap());
    assert_eq!(
        e.group_ids(&alice.store).unwrap(),
        BTreeSet::from([gid("g")])
    );
    assert_eq!(alice.epoch("g"), 0);
    assert_eq!(
        e.group_members(&alice.store, &gid("g")).unwrap(),
        vec![alice.me()]
    );
    assert!(matches!(
        e.create_group(&alice.store, &gid("g")),
        Err(CryptoError::InvalidInput { .. })
    ));
    e.delete_group(&alice.store, &gid("g")).unwrap();
    assert!(!e.has_group(&alice.store, &gid("g")).unwrap());
    assert!(e.group_ids(&alice.store).unwrap().is_empty());
}

#[test]
fn encrypt_decrypt() {
    let (alice, bob) = pair();
    let ct = alice.encrypt("g", b"hi bob");
    assert_eq!(
        bob.process("g", &ct).unwrap(),
        ProcessedMessage::Application {
            sender: alice.me(),
            plaintext: b"hi bob".to_vec(),
            epoch: 1
        }
    );
    assert_eq!(
        alice.decrypt("g", &bob.encrypt("g", b"hi alice")),
        b"hi alice"
    );
}

#[test]
fn own_message_is_rejected() {
    let (alice, _bob) = pair();
    let ct = alice.encrypt("g", b"echo");
    assert!(matches!(
        alice.process("g", &ct),
        Err(CryptoError::InvalidInput { .. })
    ));
}

#[test]
fn store_export_import_keeps_groups_usable() {
    let (alice, bob) = pair();
    assert_eq!(bob.decrypt("g", &alice.encrypt("g", b"before")), b"before");

    let bob = Dev {
        engine: MlsEngine::new(),
        store: MemoryCryptoStore::import(&bob.store.export().unwrap()).unwrap(),
    };
    assert_eq!(bob.me(), TestIdentity::new("bob").device);
    assert_eq!(bob.epoch("g"), 1);
    assert_eq!(bob.decrypt("g", &alice.encrypt("g", b"after")), b"after");
    assert_eq!(alice.decrypt("g", &bob.encrypt("g", b"reply")), b"reply");

    // The imported store can still commit.
    let carol = dev("carol");
    let out = bob.add("g", &carol.kps(1));
    bob.merge("g");
    alice.process("g", &out.commit).unwrap();
    carol.join(&out.welcome.unwrap()).unwrap();
    assert_eq!(alice.epoch("g"), 2);
}

#[test]
fn imported_store_keeps_key_packages() {
    let (alice, bob) = (dev("alice"), dev("bob"));
    let kp = bob.kps(1);
    let bob = Dev {
        engine: MlsEngine::new(),
        store: MemoryCryptoStore::import(&bob.store.export().unwrap()).unwrap(),
    };
    alice.create("g");
    let out = alice.add("g", &kp);
    alice.merge("g");
    bob.join(&out.welcome.unwrap()).unwrap();
}

#[test]
fn error_cases() {
    let (alice, bob) = pair();
    let (e, s) = (&alice.engine, &alice.store);
    let nope = gid("nope");
    assert!(matches!(
        e.encrypt(s, &nope, b"x"),
        Err(CryptoError::UnknownGroup { .. })
    ));
    assert!(matches!(
        e.group_epoch(s, &nope),
        Err(CryptoError::UnknownGroup { .. })
    ));
    assert!(matches!(
        e.delete_group(s, &nope),
        Err(CryptoError::UnknownGroup { .. })
    ));
    assert!(matches!(
        e.process_message(s, &nope, b"x"),
        Err(CryptoError::UnknownGroup { .. })
    ));
    assert!(matches!(
        e.merge_pending_commit(s, &gid("g")),
        Err(CryptoError::NoPendingCommit)
    ));
    assert!(matches!(
        e.clear_pending_commit(s, &gid("g")),
        Err(CryptoError::NoPendingCommit)
    ));
    assert!(matches!(
        e.add_members(s, &gid("g"), &[vec![1, 2, 3]]),
        Err(CryptoError::InvalidInput { .. })
    ));
    assert!(e.add_members(s, &gid("g"), &[]).is_err());
    assert!(matches!(
        e.remove_members(s, &gid("g"), &[DeviceRef::parse("x", "y").unwrap()]),
        Err(CryptoError::InvalidInput { .. })
    ));
    assert!(e.remove_members(s, &gid("g"), &[]).is_err());

    for bytes in [vec![], vec![0], vec![0xff; 64], b"not mls at all".to_vec()] {
        assert!(bob.process("g", &bytes).is_err());
        assert!(bob.join(&bytes).is_err());
    }
    // A KeyPackage is neither a Welcome nor a group message.
    let kp = dev("carol").kps(1).remove(0);
    assert!(bob.join(&kp).is_err());
    assert!(bob.process("g", &kp).is_err());
    assert!(matches!(
        e.add_members(s, &gid("g"), &[alice.encrypt("g", b"x")]),
        Err(CryptoError::InvalidInput { .. })
    ));
    // Garbage did not break the group.
    assert_eq!(
        bob.decrypt("g", &alice.encrypt("g", b"still ok")),
        b"still ok"
    );
}

#[test]
fn epoch_mismatch_is_wrong_epoch() {
    let (alice, bob) = pair();
    let out = alice.add("g", &dev("carol").kps(1));
    alice.merge("g");
    let ct = alice.encrypt("g", b"epoch 2");
    // Bob has not processed the commit yet.
    assert!(matches!(
        bob.process("g", &ct),
        Err(CryptoError::WrongEpoch { .. })
    ));
    bob.process("g", &out.commit).unwrap();
    assert_eq!(bob.decrypt("g", &ct), b"epoch 2");
    // Replaying the commit is from a past epoch.
    assert!(matches!(
        bob.process("g", &out.commit),
        Err(CryptoError::WrongEpoch { .. })
    ));
}

#[test]
fn late_message_from_past_epoch_decrypts() {
    let (alice, bob) = pair();
    let late = bob.encrypt("g", b"late");
    let out = alice.add("g", &dev("carol").kps(1));
    alice.merge("g");
    bob.process("g", &out.commit).unwrap();
    assert_eq!(alice.decrypt("g", &late), b"late");
}
