//! Multi-party MLS scenario over the in-memory fake delivery service.

use std::cell::Cell;

use gim_common::{ClientId, DeviceRef, GroupId};
use gim_crypto::{CommitOutput, CryptoError, MemoryCryptoStore, MlsEngine, ProcessedMessage};
use gim_test::{Delivered, DeliveryError, FakeDeliveryService, MessageKind, OutgoingMessage};

struct Device {
    me: DeviceRef,
    engine: MlsEngine,
    store: MemoryCryptoStore,
    posts: Cell<u32>,
}

impl Device {
    fn new(user: &str) -> Self {
        let me = DeviceRef::parse(user, "phone").unwrap();
        let engine = MlsEngine::new();
        let store = MemoryCryptoStore::new();
        engine.create_identity(&store, me.clone()).unwrap();
        Self {
            me,
            engine,
            store,
            posts: Cell::new(0),
        }
    }

    /// Simulates an app restart: the store is exported, dropped and imported.
    fn restart(self) -> Self {
        let bytes = self.store.export().unwrap();
        Self {
            me: self.me,
            engine: MlsEngine::new(),
            store: MemoryCryptoStore::import(&bytes).unwrap(),
            posts: self.posts,
        }
    }

    fn key_package(&self) -> Vec<u8> {
        self.engine
            .generate_key_packages(&self.store, 1)
            .unwrap()
            .remove(0)
    }

    fn post(
        &self,
        ds: &FakeDeliveryService,
        g: &GroupId,
        kind: MessageKind,
        epoch: u64,
        payload: Vec<u8>,
        recipients: Vec<DeviceRef>,
    ) -> Result<u64, DeliveryError> {
        self.posts.set(self.posts.get() + 1);
        let client_id = ClientId::new(format!("{}-{}", self.me.user_id, self.posts.get())).unwrap();
        ds.post(
            g,
            &self.me,
            OutgoingMessage {
                client_id,
                epoch,
                kind,
                payload,
                recipients,
            },
        )
    }

    /// Posts a commit; on acceptance merges it, registers the new members
    /// for fan-out and posts the Welcome to them.
    fn send_commit(
        &self,
        ds: &FakeDeliveryService,
        g: &GroupId,
        out: CommitOutput,
        new_members: &[&Device],
    ) -> Result<u64, DeliveryError> {
        self.post(ds, g, MessageKind::Commit, out.epoch, out.commit, vec![])?;
        let epoch = self.engine.merge_pending_commit(&self.store, g).unwrap();
        if let Some(welcome) = out.welcome {
            let recipients: Vec<_> = new_members.iter().map(|d| d.me.clone()).collect();
            for device in &recipients {
                ds.add_member(g, device).unwrap();
            }
            self.post(ds, g, MessageKind::Welcome, epoch, welcome, recipients)
                .unwrap();
        }
        Ok(epoch)
    }

    fn send_text(&self, ds: &FakeDeliveryService, g: &GroupId, text: &str) {
        let ct = self
            .engine
            .encrypt(&self.store, g, text.as_bytes())
            .unwrap();
        let epoch = self.engine.group_epoch(&self.store, g).unwrap();
        self.post(ds, g, MessageKind::Application, epoch, ct, vec![])
            .unwrap();
    }

    fn handle(&self, message: &Delivered) -> ProcessedMessage {
        match message.kind {
            MessageKind::Welcome => {
                let joined = self
                    .engine
                    .join_from_welcome(&self.store, &message.payload)
                    .unwrap();
                assert_eq!(joined.group_id, message.group_id);
                // Report joins as a commit adding this device, for uniform checks.
                ProcessedMessage::Commit {
                    sender: message.sender.clone(),
                    epoch: joined.epoch,
                    added: vec![self.me.clone()],
                    removed: vec![],
                    self_removed: false,
                }
            }
            MessageKind::Commit | MessageKind::Application => {
                let processed = self
                    .engine
                    .process_message(&self.store, &message.group_id, &message.payload)
                    .unwrap();
                match &processed {
                    ProcessedMessage::Application { sender, .. }
                    | ProcessedMessage::Commit { sender, .. }
                    | ProcessedMessage::Proposal { sender } => assert_eq!(sender, &message.sender),
                }
                processed
            }
        }
    }

    /// Pulls and processes the inbox in order.
    fn sync(&self, ds: &FakeDeliveryService) -> Vec<ProcessedMessage> {
        ds.pull(&self.me).iter().map(|m| self.handle(m)).collect()
    }

    /// Syncs and returns the decrypted texts.
    fn texts(&self, ds: &FakeDeliveryService) -> Vec<(String, String)> {
        self.sync(ds)
            .into_iter()
            .map(|p| match p {
                ProcessedMessage::Application {
                    sender, plaintext, ..
                } => (
                    sender.user_id.to_string(),
                    String::from_utf8(plaintext).unwrap(),
                ),
                other => panic!("expected application message, got {other:?}"),
            })
            .collect()
    }

    fn epoch(&self, g: &GroupId) -> u64 {
        self.engine.group_epoch(&self.store, g).unwrap()
    }

    fn members(&self, g: &GroupId) -> Vec<String> {
        self.engine
            .group_members(&self.store, g)
            .unwrap()
            .into_iter()
            .map(|d| d.user_id.to_string())
            .collect()
    }
}

fn pair(sender: &str, text: &str) -> (String, String) {
    (sender.to_string(), text.to_string())
}

#[test]
fn three_devices_full_lifecycle() {
    let ds = FakeDeliveryService::new();
    let g = GroupId::new("chat-1").unwrap();
    let mut a = Device::new("alice");
    let b = Device::new("bob");
    let c = Device::new("carol");

    // A creates the group and adds B.
    a.engine.create_group(&a.store, &g).unwrap();
    ds.create_group(&g, &a.me).unwrap();
    let out = a
        .engine
        .add_members(&a.store, &g, &[b.key_package()])
        .unwrap();
    assert_eq!(out.epoch, 0);
    assert_eq!(a.send_commit(&ds, &g, out, &[&b]), Ok(1));
    assert_eq!(b.sync(&ds).len(), 1);
    assert_eq!(b.epoch(&g), 1);

    // A adds C; B processes the commit, C joins from the Welcome.
    let out = a
        .engine
        .add_members(&a.store, &g, &[c.key_package()])
        .unwrap();
    assert_eq!(out.epoch, 1);
    a.send_commit(&ds, &g, out, &[&c]).unwrap();
    match &b.sync(&ds)[..] {
        [ProcessedMessage::Commit {
            epoch: 2,
            added,
            removed,
            self_removed: false,
            ..
        }] => {
            assert_eq!(added, &vec![c.me.clone()]);
            assert!(removed.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
    c.sync(&ds);
    for d in [&a, &b, &c] {
        assert_eq!(d.epoch(&g), 2);
        assert_eq!(d.members(&g), ["alice", "bob", "carol"]);
    }

    // Everyone talks; everyone else decrypts.
    a.send_text(&ds, &g, "hi from alice");
    b.send_text(&ds, &g, "hi from bob");
    c.send_text(&ds, &g, "hi from carol");
    assert_eq!(
        a.texts(&ds),
        [pair("bob", "hi from bob"), pair("carol", "hi from carol")]
    );
    assert_eq!(
        b.texts(&ds),
        [
            pair("alice", "hi from alice"),
            pair("carol", "hi from carol")
        ]
    );
    assert_eq!(
        c.texts(&ds),
        [pair("alice", "hi from alice"), pair("bob", "hi from bob")]
    );

    // Out-of-order delivery within one epoch: B sends 5, A receives shuffled.
    for i in 0..5 {
        b.send_text(&ds, &g, &format!("batch {i}"));
    }
    let inbox = ds.pull(&a.me);
    assert_eq!(inbox.len(), 5);
    for i in [3, 0, 4, 1, 2] {
        match a.handle(&inbox[i]) {
            ProcessedMessage::Application { plaintext, .. } => {
                assert_eq!(plaintext, format!("batch {i}").as_bytes());
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(c.texts(&ds).len(), 5);

    // Competing commits in epoch 2: B adds D, C adds E. B's lands first.
    let d = Device::new("dave");
    let e = Device::new("erin");
    let e_key_package = e.key_package();
    let b_out = b
        .engine
        .add_members(&b.store, &g, &[d.key_package()])
        .unwrap();
    let c_out = c
        .engine
        .add_members(&c.store, &g, std::slice::from_ref(&e_key_package))
        .unwrap();
    assert_eq!((b_out.epoch, c_out.epoch), (2, 2));
    assert_eq!(b.send_commit(&ds, &g, b_out, &[&d]), Ok(3));
    assert_eq!(
        c.send_commit(&ds, &g, c_out, &[&e]),
        Err(DeliveryError::Conflict409 {
            commit_epoch: 2,
            current_epoch: 3
        })
    );
    c.engine.clear_pending_commit(&c.store, &g).unwrap();
    assert!(matches!(
        c.engine.merge_pending_commit(&c.store, &g),
        Err(CryptoError::NoPendingCommit)
    ));
    // C processes the winning commit, then retries on top of it.
    c.sync(&ds);
    assert_eq!(c.epoch(&g), 3);
    let c_out = c
        .engine
        .add_members(&c.store, &g, &[e_key_package])
        .unwrap();
    assert_eq!(c_out.epoch, 3);
    assert_eq!(c.send_commit(&ds, &g, c_out, &[&e]), Ok(4));
    for dev in [&a, &b, &d, &e] {
        dev.sync(&ds);
    }
    for dev in [&a, &b, &c, &d, &e] {
        assert_eq!(dev.epoch(&g), 4);
        assert_eq!(dev.members(&g), ["alice", "bob", "carol", "dave", "erin"]);
    }

    // A restarts from its exported store and keeps working.
    a = a.restart();
    assert_eq!(a.epoch(&g), 4);
    a.send_text(&ds, &g, "alice is back");
    for dev in [&b, &c, &d, &e] {
        assert_eq!(dev.texts(&ds), [pair("alice", "alice is back")]);
    }

    // A removes C.
    let out = a
        .engine
        .remove_members(&a.store, &g, std::slice::from_ref(&c.me))
        .unwrap();
    assert!(out.welcome.is_none());
    assert_eq!(a.send_commit(&ds, &g, out, &[]), Ok(5));
    ds.remove_member(&g, &c.me).unwrap();
    match &c.sync(&ds)[..] {
        [ProcessedMessage::Commit {
            removed,
            self_removed: true,
            epoch: 5,
            ..
        }] => assert_eq!(removed, &vec![c.me.clone()]),
        other => panic!("unexpected {other:?}"),
    }
    assert!(!c.engine.has_group(&c.store, &g).unwrap());
    for dev in [&b, &d, &e] {
        match &dev.sync(&ds)[..] {
            [ProcessedMessage::Commit {
                removed,
                self_removed: false,
                ..
            }] => assert_eq!(removed, &vec![c.me.clone()]),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(dev.members(&g), ["alice", "bob", "dave", "erin"]);
    }

    // C no longer receives or decrypts new messages; A and B keep chatting.
    let secret = a.engine.encrypt(&a.store, &g, b"after carol left").unwrap();
    assert!(matches!(
        c.engine.process_message(&c.store, &g, &secret),
        Err(CryptoError::UnknownGroup { .. })
    ));
    a.send_text(&ds, &g, "carol is gone");
    b.send_text(&ds, &g, "indeed");
    assert!(ds.pull(&c.me).is_empty());
    assert_eq!(a.texts(&ds), [pair("bob", "indeed")]);
    assert_eq!(b.texts(&ds), [pair("alice", "carol is gone")]);
}
