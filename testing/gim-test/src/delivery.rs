//! Synchronous, in-memory model of gim-server message delivery
//! (`POST /v1/groups/{id}/messages` plus per-device event inboxes):
//!
//! - every accepted message gets the next per-group `seq` (1, 2, ...);
//! - posts are idempotent on `client_id` (a repeat returns the first `seq`);
//! - a commit is accepted only if its `epoch` equals the group's current
//!   epoch, otherwise it fails with [`DeliveryError::Conflict409`]; an
//!   accepted commit advances the epoch;
//! - commits and application messages fan out to every member device except
//!   the sender; Welcomes go only to the listed recipients;
//! - each device pulls its own inbox.
//!
//! Payloads are opaque bytes.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use gim_common::{ClientId, DeviceRef, GroupId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Commit,
    Welcome,
    Application,
}

/// Body of a post, mirroring the gim-server request.
#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    pub client_id: ClientId,
    pub epoch: u64,
    pub kind: MessageKind,
    pub payload: Vec<u8>,
    /// Welcome recipients; ignored for other kinds.
    pub recipients: Vec<DeviceRef>,
}

/// A message as it appears in a device inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub group_id: GroupId,
    pub seq: u64,
    pub sender: DeviceRef,
    pub kind: MessageKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    #[error("409 conflict: commit epoch {commit_epoch}, group epoch {current_epoch}")]
    Conflict409 {
        commit_epoch: u64,
        current_epoch: u64,
    },
    #[error("unknown group {0}")]
    UnknownGroup(GroupId),
    #[error("group {0} already exists")]
    GroupExists(GroupId),
    #[error("{0} is not a member")]
    NotAMember(DeviceRef),
}

#[derive(Debug, Default)]
struct Group {
    members: BTreeSet<DeviceRef>,
    epoch: u64,
    next_seq: u64,
    seq_by_client_id: HashMap<ClientId, u64>,
}

#[derive(Debug, Default)]
struct State {
    groups: HashMap<GroupId, Group>,
    inboxes: HashMap<DeviceRef, VecDeque<Delivered>>,
}

#[derive(Debug, Default)]
pub struct FakeDeliveryService {
    state: Mutex<State>,
}

impl FakeDeliveryService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a group (epoch 0) with its creator as the only member.
    pub fn create_group(
        &self,
        group_id: &GroupId,
        creator: &DeviceRef,
    ) -> Result<(), DeliveryError> {
        let mut state = self.lock();
        if state.groups.contains_key(group_id) {
            return Err(DeliveryError::GroupExists(group_id.clone()));
        }
        let mut group = Group {
            next_seq: 1,
            ..Group::default()
        };
        group.members.insert(creator.clone());
        state.groups.insert(group_id.clone(), group);
        Ok(())
    }

    /// Adds a device to the server-side fan-out list.
    pub fn add_member(&self, group_id: &GroupId, device: &DeviceRef) -> Result<(), DeliveryError> {
        self.lock()
            .group_mut(group_id)?
            .members
            .insert(device.clone());
        Ok(())
    }

    /// Removes a device from the server-side fan-out list.
    pub fn remove_member(
        &self,
        group_id: &GroupId,
        device: &DeviceRef,
    ) -> Result<(), DeliveryError> {
        self.lock().group_mut(group_id)?.members.remove(device);
        Ok(())
    }

    /// Current epoch as tracked by the server.
    pub fn epoch(&self, group_id: &GroupId) -> Result<u64, DeliveryError> {
        Ok(self.lock().group_mut(group_id)?.epoch)
    }

    /// Accepts a message and returns its `seq`.
    pub fn post(
        &self,
        group_id: &GroupId,
        sender: &DeviceRef,
        message: OutgoingMessage,
    ) -> Result<u64, DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        if !group.members.contains(sender) {
            return Err(DeliveryError::NotAMember(sender.clone()));
        }
        if let Some(&seq) = group.seq_by_client_id.get(&message.client_id) {
            return Ok(seq);
        }
        if message.kind == MessageKind::Commit {
            if message.epoch != group.epoch {
                return Err(DeliveryError::Conflict409 {
                    commit_epoch: message.epoch,
                    current_epoch: group.epoch,
                });
            }
            group.epoch += 1;
        }
        let seq = group.next_seq;
        group.next_seq += 1;
        group.seq_by_client_id.insert(message.client_id, seq);
        let recipients: Vec<DeviceRef> = match message.kind {
            MessageKind::Welcome => message.recipients,
            MessageKind::Commit | MessageKind::Application => group
                .members
                .iter()
                .filter(|d| *d != sender)
                .cloned()
                .collect(),
        };
        let delivered = Delivered {
            group_id: group_id.clone(),
            seq,
            sender: sender.clone(),
            kind: message.kind,
            payload: message.payload,
        };
        for device in recipients {
            state
                .inboxes
                .entry(device)
                .or_default()
                .push_back(delivered.clone());
        }
        Ok(seq)
    }

    /// Drains and returns the device's inbox in delivery order.
    pub fn pull(&self, device: &DeviceRef) -> Vec<Delivered> {
        self.lock()
            .inboxes
            .get_mut(device)
            .map(|inbox| inbox.drain(..).collect())
            .unwrap_or_default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl State {
    fn group_mut(&mut self, group_id: &GroupId) -> Result<&mut Group, DeliveryError> {
        self.groups
            .get_mut(group_id)
            .ok_or_else(|| DeliveryError::UnknownGroup(group_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(user: &str) -> DeviceRef {
        DeviceRef::parse(user, "d1").unwrap()
    }

    fn msg(client_id: &str, epoch: u64, kind: MessageKind) -> OutgoingMessage {
        OutgoingMessage {
            client_id: ClientId::new(client_id).unwrap(),
            epoch,
            kind,
            payload: client_id.as_bytes().to_vec(),
            recipients: vec![],
        }
    }

    #[test]
    fn delivery_semantics() {
        let ds = FakeDeliveryService::new();
        let g = GroupId::new("g").unwrap();
        let (a, b, c) = (device("a"), device("b"), device("c"));
        ds.create_group(&g, &a).unwrap();
        assert!(ds.create_group(&g, &a).is_err());
        ds.add_member(&g, &b).unwrap();

        assert_eq!(
            ds.post(&g, &a, msg("m1", 0, MessageKind::Application)),
            Ok(1)
        );
        // Idempotent on client_id: same seq, no second delivery.
        assert_eq!(
            ds.post(&g, &a, msg("m1", 0, MessageKind::Application)),
            Ok(1)
        );
        assert_eq!(ds.post(&g, &a, msg("c1", 0, MessageKind::Commit)), Ok(2));
        assert_eq!(ds.epoch(&g), Ok(1));
        assert_eq!(
            ds.post(&g, &b, msg("c2", 0, MessageKind::Commit)),
            Err(DeliveryError::Conflict409 {
                commit_epoch: 0,
                current_epoch: 1
            })
        );
        let mut welcome = msg("w1", 1, MessageKind::Welcome);
        welcome.recipients = vec![c.clone()];
        assert_eq!(ds.post(&g, &a, welcome), Ok(3));
        assert_eq!(
            ds.post(&g, &c, msg("x", 1, MessageKind::Application)),
            Err(DeliveryError::NotAMember(c.clone()))
        );

        let seqs = |d: &DeviceRef| ds.pull(d).iter().map(|m| m.seq).collect::<Vec<_>>();
        assert_eq!(seqs(&a), Vec::<u64>::new());
        assert_eq!(seqs(&b), vec![1, 2]);
        assert_eq!(seqs(&c), vec![3]);
        assert!(ds.pull(&b).is_empty());

        ds.remove_member(&g, &b).unwrap();
        ds.post(&g, &a, msg("m2", 1, MessageKind::Application))
            .unwrap();
        assert!(ds.pull(&b).is_empty());
        assert!(ds
            .post(
                &GroupId::new("nope").unwrap(),
                &a,
                msg("z", 0, MessageKind::Application)
            )
            .is_err());
    }
}
