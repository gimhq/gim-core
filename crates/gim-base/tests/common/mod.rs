//! Devices wired to the fake delivery service.

// Each test binary uses a different subset of the helpers.
#![allow(dead_code)]

use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, Message, MessageKind, StateChange};
use gim_base::{BaseClient, MemoryStore, StateReader, StateStore};
use gim_common::{ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_crypto::{inspect_handshake, CommitOutput, MlsEngine};
use gim_proto::envelope::Content;
use gim_test::{Event, FakeDeliveryService, SubmitCommit};

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

/// The gim-base events of a hub event, as gim-sdk maps them.
pub fn to_events(event: Event) -> Vec<IncomingEvent> {
    let devices = |change: gim_test::MembershipChange| {
        let user_id = change.user_id;
        let group_id = change.group_id;
        change
            .device_ids
            .into_iter()
            .map(move |id| (group_id.clone(), DeviceRef::new(user_id.clone(), id)))
    };
    match event {
        Event::Message(delivered) => vec![IncomingEvent::Message(GroupMessage {
            group_id: delivered.group_id,
            seq: delivered.seq,
            sender: delivered.sender,
            kind: match delivered.kind {
                gim_test::MessageKind::Commit => MessageKind::Commit,
                gim_test::MessageKind::Application => MessageKind::Application,
            },
            payload: delivered.payload,
            client_id: Some(delivered.client_id),
        })],
        Event::Welcome(welcome) => vec![IncomingEvent::Message(GroupMessage {
            group_id: welcome.group_id,
            seq: welcome.seq,
            sender: welcome.sender,
            kind: MessageKind::Welcome,
            payload: welcome.welcome,
            client_id: None,
        })],
        Event::MemberAdded(change) => devices(change)
            .map(|(group_id, device)| IncomingEvent::MemberAdded { group_id, device })
            .collect(),
        Event::MemberRemoved(change) => devices(change)
            .map(|(group_id, device)| IncomingEvent::MemberRemoved { group_id, device })
            .collect(),
        Event::KeyPackagesLow { .. } => vec![IncomingEvent::KeyPackagesLow],
        Event::DeviceListUpdated { .. } => vec![],
    }
}

impl Device {
    pub fn new(user: &str) -> Self {
        let id = gim_test::TestIdentity::new(user);
        let me = id.device.clone();
        let engine =
            MlsEngine::with_device_list_lookup(std::sync::Arc::new(gim_test::test_device_list));
        let store = MemoryStore::new();
        engine
            .create_identity_v2(&store, &id.device_key, id.root.public(), id.cert.clone())
            .unwrap();
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
        ds.pull(&self.me).into_iter().flat_map(to_events).collect()
    }

    /// Pulls and applies the whole inbox.
    pub fn sync(&self, ds: &FakeDeliveryService) -> Vec<StateChange> {
        self.pull(ds)
            .into_iter()
            .flat_map(|event| self.apply(event))
            .collect()
    }

    /// Uploads this device's DeviceList, so the hub knows it as active.
    pub fn register(&self, ds: &FakeDeliveryService) {
        ds.put_device_list(
            &self.me.user_id,
            1,
            self.me.to_string().into_bytes(),
            [self.me.device_id.clone()].into(),
        )
        .unwrap();
    }

    pub fn create_chat(&self, ds: &FakeDeliveryService, g: &GroupId) {
        self.register(ds);
        ds.create_group(g, &self.me).unwrap();
        self.client
            .create_chat(&self.store, &self.engine, g, ChatKind::Group, None, NOW)
            .unwrap();
    }

    /// Submits the commit with its Welcome and merges it.
    fn post_commit(&self, ds: &FakeDeliveryService, g: &GroupId, out: CommitOutput) -> u64 {
        let info = inspect_handshake(&out.commit).unwrap();
        let seq = ds
            .submit_commit(
                g,
                &self.me,
                SubmitCommit {
                    client_id: new_client_id(),
                    mls_message: out.commit,
                    epoch: info.epoch,
                    proposal: false,
                    welcome_recipients: if out.welcome.is_some() {
                        info.added.clone()
                    } else {
                        vec![]
                    },
                    added: info.added,
                    removed_leaves: info.removed_leaves,
                    welcome: out.welcome,
                },
            )
            .unwrap()
            .seq;
        self.client
            .merge_own_commit(&self.store, &self.engine, g, seq)
            .unwrap();
        seq
    }

    /// Proposes to remove this device (a self-remove proposal), which
    /// another member commits; returns the proposal seq.
    pub fn propose_leave(&self, ds: &FakeDeliveryService, g: &GroupId) -> u64 {
        let proposal = self
            .store
            .transaction(|txn| Ok(self.engine.leave_group(&*txn, g)?))
            .unwrap();
        let info = inspect_handshake(&proposal).unwrap();
        ds.submit_commit(
            g,
            &self.me,
            SubmitCommit {
                client_id: new_client_id(),
                mls_message: proposal,
                epoch: info.epoch,
                proposal: true,
                added: vec![],
                removed_leaves: vec![],
                welcome: None,
                welcome_recipients: vec![],
            },
        )
        .unwrap()
        .seq
    }

    /// Adds the devices; returns the commit seq.
    pub fn add(&self, ds: &FakeDeliveryService, g: &GroupId, devices: &[&Device]) -> u64 {
        for device in devices {
            device.register(ds);
        }
        let key_packages: Vec<_> = devices.iter().map(|d| d.key_package()).collect();
        let out = self
            .store
            .transaction(|txn| Ok(self.engine.add_members(&*txn, g, &key_packages)?))
            .unwrap();
        self.post_commit(ds, g, out)
    }

    pub fn remove(&self, ds: &FakeDeliveryService, g: &GroupId, devices: &[&Device]) -> u64 {
        let members: Vec<_> = devices.iter().map(|d| d.me.clone()).collect();
        let out = self
            .store
            .transaction(|txn| Ok(self.engine.remove_members(&*txn, g, &members)?))
            .unwrap();
        self.post_commit(ds, g, out)
    }

    /// Commits the pending proposals by reference; the fake hub does not
    /// resolve references, so the leaves they remove are passed along.
    /// Returns the commit seq.
    pub fn commit_proposals(
        &self,
        ds: &FakeDeliveryService,
        g: &GroupId,
        removed_leaves: Vec<u32>,
    ) -> u64 {
        let out = self
            .store
            .transaction(|txn| Ok(self.engine.commit_pending_proposals(&*txn, g)?))
            .unwrap()
            .expect("pending proposals");
        let epoch = inspect_handshake(&out.commit).unwrap().epoch;
        let seq = ds
            .submit_commit(
                g,
                &self.me,
                SubmitCommit {
                    client_id: new_client_id(),
                    mls_message: out.commit,
                    epoch,
                    proposal: false,
                    added: vec![],
                    removed_leaves,
                    welcome: None,
                    welcome_recipients: vec![],
                },
            )
            .unwrap()
            .seq;
        self.client
            .merge_own_commit(&self.store, &self.engine, g, seq)
            .unwrap();
        seq
    }

    /// Posts a proposal created by gim-base (e.g. a [`PendingLeave`]).
    ///
    /// [`PendingLeave`]: gim_base::model::PendingLeave
    pub fn post_proposal(&self, ds: &FakeDeliveryService, g: &GroupId, proposal: Vec<u8>) -> u64 {
        let info = inspect_handshake(&proposal).unwrap();
        ds.submit_commit(
            g,
            &self.me,
            SubmitCommit {
                client_id: new_client_id(),
                mls_message: proposal,
                epoch: info.epoch,
                proposal: true,
                added: vec![],
                removed_leaves: vec![],
                welcome: None,
                welcome_recipients: vec![],
            },
        )
        .unwrap()
        .seq
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
        ds.post_message(
            &entry.group_id,
            &self.me,
            entry.client_id(),
            prepared.epoch,
            prepared.payload,
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

/// User id of the test user `name`.
pub fn user(name: &str) -> UserId {
    gim_test::TestIdentity::new(name).device.user_id
}

/// Leaves removed by the proposal the hub sequenced at `seq`.
pub fn proposal_leaves(ds: &FakeDeliveryService, g: &GroupId, seq: u64) -> Vec<u32> {
    let proposal = ds.messages(g, seq - 1, 1).unwrap().remove(0);
    inspect_handshake(&proposal.payload).unwrap().removed_leaves
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
