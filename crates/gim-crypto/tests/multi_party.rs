//! Multi-party MLS scenario over the in-memory fake delivery service.

use std::cell::Cell;

use gim_common::{ClientId, DeviceRef, GroupId};
use gim_crypto::{
    inspect_handshake, CommitOutput, CryptoError, MemoryCryptoStore, MlsEngine, ProcessedMessage,
};
use gim_test::{Delivered, DeliveryError, Event, FakeDeliveryService, SubmitCommit};

struct Device {
    me: DeviceRef,
    engine: MlsEngine,
    store: MemoryCryptoStore,
    posts: Cell<u32>,
}

impl Device {
    fn new(user: &str) -> Self {
        let id = gim_test::TestIdentity::new(user);
        let me = id.device.clone();
        let engine =
            MlsEngine::with_device_list_lookup(std::sync::Arc::new(gim_test::test_device_list));
        let store = MemoryCryptoStore::new();
        engine
            .create_identity_v2(&store, &id.device_key, id.root.public(), id.cert.clone())
            .unwrap();
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
            engine: MlsEngine::with_device_list_lookup(std::sync::Arc::new(
                gim_test::test_device_list,
            )),
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

    fn client_id(&self) -> ClientId {
        self.posts.set(self.posts.get() + 1);
        ClientId::new(format!("{}-{}", self.me.user_id, self.posts.get())).unwrap()
    }

    /// Posts a commit with its Welcome; on acceptance merges it.
    fn send_commit(
        &self,
        ds: &FakeDeliveryService,
        g: &GroupId,
        out: CommitOutput,
        new_members: &[&Device],
    ) -> Result<u64, DeliveryError> {
        let info = inspect_handshake(&out.commit).unwrap();
        assert_eq!(info.added, out.added);
        ds.submit_commit(
            g,
            &self.me,
            SubmitCommit {
                client_id: self.client_id(),
                mls_message: out.commit,
                epoch: info.epoch,
                proposal: false,
                added: info.added,
                removed_leaves: info.removed_leaves,
                welcome: out.welcome,
                welcome_recipients: new_members.iter().map(|d| d.me.clone()).collect(),
            },
        )?;
        Ok(self.engine.merge_pending_commit(&self.store, g).unwrap())
    }

    fn send_text(&self, ds: &FakeDeliveryService, g: &GroupId, text: &str) {
        let ct = self
            .engine
            .encrypt(&self.store, g, text.as_bytes())
            .unwrap();
        let epoch = self.engine.group_epoch(&self.store, g).unwrap();
        ds.post_message(g, &self.me, self.client_id(), epoch, ct)
            .unwrap();
    }

    fn handle(&self, event: &Event) -> Option<ProcessedMessage> {
        match event {
            Event::Welcome(welcome) => {
                let joined = self
                    .engine
                    .join_from_welcome(&self.store, &welcome.welcome)
                    .unwrap();
                assert_eq!(joined.group_id, welcome.group_id);
                // Report joins as a commit adding this device, for uniform checks.
                Some(ProcessedMessage::Commit {
                    sender: welcome.sender.clone(),
                    epoch: joined.epoch,
                    added: vec![self.me.clone()],
                    removed: vec![],
                    self_removed: false,
                })
            }
            Event::Message(message) => Some(self.process(message)),
            _ => None,
        }
    }

    fn process(&self, message: &Delivered) -> ProcessedMessage {
        let processed = self
            .engine
            .process_message(&self.store, &message.group_id, &message.payload)
            .unwrap();
        match &processed {
            ProcessedMessage::Application { sender, .. }
            | ProcessedMessage::Commit { sender, .. }
            | ProcessedMessage::Proposal { sender, .. } => assert_eq!(sender, &message.sender),
        }
        processed
    }

    /// Pulls and processes the inbox in order; membership events are
    /// skipped.
    fn sync(&self, ds: &FakeDeliveryService) -> Vec<ProcessedMessage> {
        ds.pull(&self.me)
            .iter()
            .filter_map(|e| self.handle(e))
            .collect()
    }

    /// Syncs and returns the decrypted texts.
    fn texts(&self, ds: &FakeDeliveryService) -> Vec<(String, String)> {
        self.sync(ds)
            .into_iter()
            .map(|p| match p {
                ProcessedMessage::Application {
                    sender, plaintext, ..
                } => (name(&sender), String::from_utf8(plaintext).unwrap()),
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
            .iter()
            .map(name)
            .collect()
    }
}

/// The test name of a device's user.
fn name(device: &DeviceRef) -> String {
    ["alice", "bob", "carol", "dave", "erin"]
        .into_iter()
        .find(|n| gim_test::TestIdentity::new(n).device.user_id == device.user_id)
        .unwrap_or("?")
        .to_string()
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
    ds.put_device_list_of(&[&a, &b, &c]);
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
    let inbox: Vec<Delivered> = ds
        .pull(&a.me)
        .into_iter()
        .filter_map(|e| match e {
            Event::Message(m) => Some(m),
            _ => None,
        })
        .collect();
    assert_eq!(inbox.len(), 5);
    for i in [3, 0, 4, 1, 2] {
        match a.process(&inbox[i]) {
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
    ds.put_device_list_of(&[&d, &e]);
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
        Err(DeliveryError::StaleEpoch {
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

trait Directory {
    /// Uploads each device's DeviceList, so the hub knows them as active.
    fn put_device_list_of(&self, devices: &[&Device]);
}

impl Directory for FakeDeliveryService {
    fn put_device_list_of(&self, devices: &[&Device]) {
        for device in devices {
            self.put_device_list(
                &device.me.user_id,
                1,
                device.me.to_string().into_bytes(),
                [device.me.device_id.clone()].into(),
            )
            .unwrap();
        }
    }
}
