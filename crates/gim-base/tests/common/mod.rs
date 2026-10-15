//! Devices wired to the fake delivery service.

// Each test binary uses a different subset of the helpers.
#![allow(dead_code)]

use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, Message, MessageKind, StateChange};
use gim_base::{BaseClient, MemoryStore, StateReader, StateStore};
use gim_common::{ClientId, DeviceRef, GroupId, MessageId};
use gim_crypto::{CommitOutput, MlsEngine};
use gim_proto::envelope::Content;
use gim_test::{Delivered, FakeDeliveryService, OutgoingMessage};

pub const NOW: u64 = 1_790_000_000_000;

pub struct Device {
    pub me: DeviceRef,
    pub client: BaseClient,
    pub engine: MlsEngine,
    pub store: MemoryStore,
}

pub fn group(id: &str) -> GroupId {
    GroupId::new(id).unwrap()
}

pub fn to_event(delivered: Delivered) -> IncomingEvent {
    IncomingEvent::Message(GroupMessage {
        group_id: delivered.group_id,
        seq: delivered.seq,
        sender: delivered.sender,
        kind: match delivered.kind {
            gim_test::MessageKind::Commit => MessageKind::Commit,
            gim_test::MessageKind::Welcome => MessageKind::Welcome,
            gim_test::MessageKind::Application => MessageKind::Application,
        },
        payload: delivered.payload,
        client_id: None,
    })
}

impl Device {
    pub fn new(user: &str) -> Self {
        let id = gim_test::TestIdentity::new(user);
        let me = id.device.clone();
        let engine = MlsEngine::new();
        let store = MemoryStore::new();
        engine.create_identity_v2(&store, &id.device_key, id.root.public(), id.cert.clone()).unwrap();
        Self {
            client: BaseClient::new(me.clone()),
            me,
            engine,
            store,
        }
    }

    pub fn key_package(&self) -> Vec<u8> {
        self.store
            .transaction(|txn| Ok(self.engine.generate_key_packages(&*txn, 1)?))
            .unwrap()
            .remove(0)
    }

    pub fn epoch(&self, g: &GroupId) -> u64 {
        self.engine.group_epoch(&self.store, g).unwrap()
    }

    pub fn apply(&self, event: IncomingEvent) -> Vec<StateChange> {
        self.client.apply(&self.store, &self.engine, event).unwrap()
    }

    pub fn pull(&self, ds: &FakeDeliveryService) -> Vec<IncomingEvent> {
        ds.pull(&self.me).into_iter().map(to_event).collect()
    }

    /// Pulls and applies the whole inbox.
    pub fn sync(&self, ds: &FakeDeliveryService) -> Vec<StateChange> {
        self.pull(ds)
            .into_iter()
            .flat_map(|event| self.apply(event))
            .collect()
    }

    pub fn create_chat(&self, ds: &FakeDeliveryService, g: &GroupId) {
        ds.create_group(g, &self.me).unwrap();
        self.client
            .create_chat(&self.store, &self.engine, g, ChatKind::Group, None, NOW)
            .unwrap();
    }

    fn post_commit(&self, ds: &FakeDeliveryService, g: &GroupId, out: &CommitOutput) -> u64 {
        let seq = ds
            .post(
                g,
                &self.me,
                OutgoingMessage {
                    client_id: new_client_id(),
                    epoch: out.epoch,
                    kind: gim_test::MessageKind::Commit,
                    payload: out.commit.clone(),
                    recipients: vec![],
                },
            )
            .unwrap();
        self.client
            .merge_own_commit(&self.store, &self.engine, g, seq)
            .unwrap();
        seq
    }

    /// Adds the devices; returns the commit seq.
    pub fn add(&self, ds: &FakeDeliveryService, g: &GroupId, devices: &[&Device]) -> u64 {
        let key_packages: Vec<_> = devices.iter().map(|d| d.key_package()).collect();
        let out = self
            .store
            .transaction(|txn| Ok(self.engine.add_members(&*txn, g, &key_packages)?))
            .unwrap();
        let seq = self.post_commit(ds, g, &out);
        let recipients: Vec<_> = devices.iter().map(|d| d.me.clone()).collect();
        for device in &recipients {
            ds.add_member(g, device).unwrap();
        }
        ds.post(
            g,
            &self.me,
            OutgoingMessage {
                client_id: new_client_id(),
                epoch: out.epoch + 1,
                kind: gim_test::MessageKind::Welcome,
                payload: out.welcome.unwrap(),
                recipients,
            },
        )
        .unwrap();
        seq
    }

    pub fn remove(&self, ds: &FakeDeliveryService, g: &GroupId, devices: &[&Device]) -> u64 {
        let members: Vec<_> = devices.iter().map(|d| d.me.clone()).collect();
        let out = self
            .store
            .transaction(|txn| Ok(self.engine.remove_members(&*txn, g, &members)?))
            .unwrap();
        let seq = self.post_commit(ds, g, &out);
        for device in &members {
            ds.remove_member(g, device).unwrap();
        }
        seq
    }

    pub fn enqueue(&self, g: &GroupId, content: Content) -> MessageId {
        self.client
            .enqueue(&self.store, g, content, None, NOW)
            .unwrap()
            .0
    }

    /// Posts one outbox entry; returns its seq.
    pub fn post(&self, ds: &FakeDeliveryService, message_id: &MessageId) -> u64 {
        let entry = self.store.outbox_entry(message_id).unwrap().unwrap();
        let prepared = self
            .client
            .prepare(&self.store, &self.engine, message_id)
            .unwrap();
        ds.post(
            &entry.group_id,
            &self.me,
            OutgoingMessage {
                client_id: entry.client_id(),
                epoch: prepared.epoch,
                kind: gim_test::MessageKind::Application,
                payload: prepared.payload,
                recipients: vec![],
            },
        )
        .unwrap()
    }

    /// Sends every due outbox entry and marks it sent.
    pub fn flush(&self, ds: &FakeDeliveryService) {
        for entry in self.store.outbox_due(u64::MAX, usize::MAX).unwrap() {
            let seq = self.post(ds, &entry.message_id);
            self.client
                .mark_sent(&self.store, &entry.message_id, seq)
                .unwrap();
        }
    }

    pub fn send(&self, ds: &FakeDeliveryService, g: &GroupId, content: Content) -> MessageId {
        let id = self.enqueue(g, content);
        self.flush(ds);
        id
    }

    pub fn send_text(&self, ds: &FakeDeliveryService, g: &GroupId, body: &str) -> MessageId {
        self.send(ds, g, text(body))
    }

    pub fn message(&self, id: &MessageId) -> Message {
        self.store.message(id).unwrap().unwrap()
    }
}

pub fn text(body: &str) -> Content {
    Content::Text {
        body: body.to_string(),
    }
}

pub fn new_client_id() -> ClientId {
    ClientId::new(gim_base::new_message_id().unwrap().as_str()).unwrap()
}

/// alice creates `g` and adds the other devices one commit at a time; every
/// device is synced afterwards.
pub fn setup(ds: &FakeDeliveryService, g: &GroupId, devices: &[&Device]) {
    let (creator, others) = devices.split_first().unwrap();
    creator.create_chat(ds, g);
    for device in others {
        creator.add(ds, g, &[device]);
        for d in devices {
            d.sync(ds);
        }
    }
}
