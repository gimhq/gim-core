//! Synchronous, in-memory model of gim-server (§4.1 semantics):
//!
//! - devices register by handle (a user may own several devices) and get a
//!   bearer token; users are looked up by handle;
//! - KeyPackages are uploaded per device; claiming consumes a one-time
//!   package, falling back to the never-consumed last-resort package, and
//!   pushes `keypackages.low` to the device once fewer than
//!   [`KEY_PACKAGES_LOW_THRESHOLD`] one-time packages remain;
//! - every accepted message gets the next per-group `seq` (1, 2, ...);
//! - posts are idempotent on `client_id` (a repeat returns the first `seq`);
//! - a commit is accepted only if its `epoch` equals the group's current
//!   epoch, otherwise it fails with [`DeliveryError::Conflict409`]; an
//!   accepted commit advances the epoch;
//! - commits and application messages fan out to every member device except
//!   the sender; Welcomes go only to the listed recipients;
//! - membership changes push `group.member_added|removed` to the members
//!   (a removed device included);
//! - each device has an event log with a server-wide monotonic cursor
//!   ([`FakeDeliveryService::events`]), and every group keeps its message
//!   history by `seq` ([`FakeDeliveryService::messages`]);
//! - blobs are stored opaque and downloadable by byte range.
//!
//! Payloads are opaque bytes.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ops::Range;
use std::sync::{Mutex, MutexGuard};

use gim_common::{ClientId, DeviceId, DeviceRef, GroupId, UserId};

/// A device gets `keypackages.low` once fewer one-time KeyPackages remain.
pub const KEY_PACKAGES_LOW_THRESHOLD: usize = 10;

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
    pub client_id: ClientId,
    pub kind: MessageKind,
    pub epoch: u64,
    pub payload: Vec<u8>,
    /// Welcome recipients; empty for other kinds.
    pub recipients: Vec<DeviceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Direct,
    Group,
}

/// Delivery-service view of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_id: GroupId,
    pub kind: GroupKind,
    pub epoch: u64,
    pub members: Vec<DeviceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub user_id: UserId,
    pub handle: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub device: DeviceRef,
    pub token: String,
    /// Head cursor at registration; the device's events start after it.
    pub cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Message(Delivered),
    MemberAdded {
        group_id: GroupId,
        device: DeviceRef,
    },
    MemberRemoved {
        group_id: GroupId,
        device: DeviceRef,
    },
    KeyPackagesLow {
        available: usize,
    },
}

/// One entry of a device event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEvent {
    pub cursor: u64,
    pub event: Event,
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
    #[error("invalid or unknown token")]
    Unauthorized,
    #[error("unknown user {0}")]
    UnknownUser(UserId),
    #[error("no key package for {0}")]
    NoKeyPackage(DeviceRef),
    #[error("unknown blob {0}")]
    UnknownBlob(String),
    #[error("range {start}..{end} outside blob of {len} bytes")]
    InvalidRange { start: u64, end: u64, len: u64 },
}

#[derive(Debug)]
struct Group {
    kind: GroupKind,
    members: BTreeSet<DeviceRef>,
    epoch: u64,
    seq_by_client_id: HashMap<ClientId, u64>,
    history: Vec<Delivered>,
}

#[derive(Debug, Default)]
struct Inbox {
    events: Vec<StreamEvent>,
    /// Events already returned by [`FakeDeliveryService::pull`].
    pulled: usize,
}

#[derive(Debug, Default)]
struct KeyPackages {
    one_time: VecDeque<Vec<u8>>,
    last_resort: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct State {
    users: HashMap<UserId, User>,
    devices: BTreeSet<DeviceRef>,
    tokens: HashMap<String, DeviceRef>,
    key_packages: HashMap<DeviceRef, KeyPackages>,
    groups: HashMap<GroupId, Group>,
    inboxes: HashMap<DeviceRef, Inbox>,
    blobs: HashMap<String, Vec<u8>>,
    /// Last assigned event cursor.
    head: u64,
    /// Counter for server-assigned ids.
    next_id: u64,
}

#[derive(Debug, Default)]
pub struct FakeDeliveryService {
    state: Mutex<State>,
}

impl FakeDeliveryService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a device. A known handle gets a new device of the same
    /// user; the display name is kept from the first registration.
    pub fn register_device(&self, handle: &str, display_name: &str) -> Registration {
        let mut state = self.lock();
        let existing = state
            .users
            .values()
            .find(|u| u.handle == handle)
            .map(|u| u.user_id.clone());
        let user_id = match existing {
            Some(user_id) => user_id,
            None => {
                let user_id = UserId::new(format!("u{}", state.next_id())).expect("valid id");
                state.users.insert(
                    user_id.clone(),
                    User {
                        user_id: user_id.clone(),
                        handle: handle.to_string(),
                        display_name: display_name.to_string(),
                    },
                );
                user_id
            }
        };
        let id = state.next_id();
        let device = DeviceRef::new(user_id, DeviceId::new(format!("d{id}")).expect("valid id"));
        let token = format!("token-{id}");
        state.devices.insert(device.clone());
        state.tokens.insert(token.clone(), device.clone());
        Registration {
            device,
            token,
            cursor: state.head,
        }
    }

    /// The device a bearer token belongs to.
    pub fn authenticate(&self, token: &str) -> Result<DeviceRef, DeliveryError> {
        self.lock()
            .tokens
            .get(token)
            .cloned()
            .ok_or(DeliveryError::Unauthorized)
    }

    pub fn find_user(&self, handle: &str) -> Option<User> {
        self.lock()
            .users
            .values()
            .find(|u| u.handle == handle)
            .cloned()
    }

    /// Registered devices of a user.
    pub fn devices(&self, user_id: &UserId) -> Result<Vec<DeviceRef>, DeliveryError> {
        let state = self.lock();
        if !state.users.contains_key(user_id) {
            return Err(DeliveryError::UnknownUser(user_id.clone()));
        }
        Ok(state
            .devices
            .iter()
            .filter(|d| &d.user_id == user_id)
            .cloned()
            .collect())
    }

    /// Appends one-time KeyPackages; `last_resort` replaces the previous one.
    pub fn upload_key_packages(
        &self,
        device: &DeviceRef,
        key_packages: Vec<Vec<u8>>,
        last_resort: Option<Vec<u8>>,
    ) {
        let mut state = self.lock();
        let stored = state.key_packages.entry(device.clone()).or_default();
        stored.one_time.extend(key_packages);
        if last_resort.is_some() {
            stored.last_resort = last_resort;
        }
    }

    /// Claims a KeyPackage of `device`: a one-time one if left, else the
    /// last-resort one.
    pub fn claim_key_package(&self, device: &DeviceRef) -> Result<Vec<u8>, DeliveryError> {
        let mut state = self.lock();
        let no_key_package = || DeliveryError::NoKeyPackage(device.clone());
        let stored = state
            .key_packages
            .get_mut(device)
            .ok_or_else(no_key_package)?;
        if let Some(key_package) = stored.one_time.pop_front() {
            let available = stored.one_time.len();
            if available < KEY_PACKAGES_LOW_THRESHOLD {
                state.push_event(device, Event::KeyPackagesLow { available });
            }
            return Ok(key_package);
        }
        stored.last_resort.clone().ok_or_else(no_key_package)
    }

    /// Unclaimed one-time KeyPackages of `device`.
    pub fn key_package_count(&self, device: &DeviceRef) -> usize {
        self.lock()
            .key_packages
            .get(device)
            .map_or(0, |k| k.one_time.len())
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
        state.groups.insert(
            group_id.clone(),
            Group {
                kind: GroupKind::Group,
                members: BTreeSet::from([creator.clone()]),
                epoch: 0,
                seq_by_client_id: HashMap::new(),
                history: Vec::new(),
            },
        );
        Ok(())
    }

    /// Creates a group with a server-assigned id; the creator and `members`
    /// form the fan-out list.
    pub fn create_group_with(
        &self,
        kind: GroupKind,
        creator: &DeviceRef,
        members: &[DeviceRef],
    ) -> Result<GroupId, DeliveryError> {
        let group_id = GroupId::new(format!("g{}", self.lock().next_id())).expect("valid id");
        self.create_group(&group_id, creator)?;
        self.lock().group_mut(&group_id)?.kind = kind;
        for device in members {
            self.add_member(&group_id, device)?;
        }
        Ok(group_id)
    }

    pub fn group(&self, group_id: &GroupId) -> Result<GroupInfo, DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        Ok(GroupInfo {
            group_id: group_id.clone(),
            kind: group.kind,
            epoch: group.epoch,
            members: group.members.iter().cloned().collect(),
        })
    }

    /// Adds a device to the server-side fan-out list.
    pub fn add_member(&self, group_id: &GroupId, device: &DeviceRef) -> Result<(), DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        if !group.members.insert(device.clone()) {
            return Ok(());
        }
        let members: Vec<DeviceRef> = group.members.iter().cloned().collect();
        let event = Event::MemberAdded {
            group_id: group_id.clone(),
            device: device.clone(),
        };
        for member in &members {
            state.push_event(member, event.clone());
        }
        Ok(())
    }

    /// Removes a device from the server-side fan-out list.
    pub fn remove_member(
        &self,
        group_id: &GroupId,
        device: &DeviceRef,
    ) -> Result<(), DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        if !group.members.remove(device) {
            return Ok(());
        }
        let members: Vec<DeviceRef> = group.members.iter().cloned().collect();
        let event = Event::MemberRemoved {
            group_id: group_id.clone(),
            device: device.clone(),
        };
        for member in members.iter().chain([device]) {
            state.push_event(member, event.clone());
        }
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
        let seq = group.history.len() as u64 + 1;
        group
            .seq_by_client_id
            .insert(message.client_id.clone(), seq);
        let welcome = message.kind == MessageKind::Welcome;
        let fan_out: Vec<DeviceRef> = if welcome {
            message.recipients.clone()
        } else {
            group
                .members
                .iter()
                .filter(|d| *d != sender)
                .cloned()
                .collect()
        };
        let delivered = Delivered {
            group_id: group_id.clone(),
            seq,
            sender: sender.clone(),
            client_id: message.client_id,
            kind: message.kind,
            epoch: message.epoch,
            payload: message.payload,
            recipients: if welcome { message.recipients } else { vec![] },
        };
        group.history.push(delivered.clone());
        for device in &fan_out {
            state.push_event(device, Event::Message(delivered.clone()));
        }
        Ok(seq)
    }

    /// Returns the device's messages not returned by an earlier `pull`, in
    /// delivery order. Independent of [`FakeDeliveryService::events`].
    pub fn pull(&self, device: &DeviceRef) -> Vec<Delivered> {
        let mut state = self.lock();
        let Some(inbox) = state.inboxes.get_mut(device) else {
            return Vec::new();
        };
        let new = &inbox.events[inbox.pulled..];
        inbox.pulled = inbox.events.len();
        new.iter()
            .filter_map(|e| match &e.event {
                Event::Message(delivered) => Some(delivered.clone()),
                _ => None,
            })
            .collect()
    }

    /// Up to `limit` events of the device after `cursor`, and the cursor to
    /// pass next time.
    pub fn events(&self, device: &DeviceRef, cursor: u64, limit: usize) -> (Vec<StreamEvent>, u64) {
        let state = self.lock();
        let events: Vec<StreamEvent> = state
            .inboxes
            .get(device)
            .map(|inbox| {
                inbox
                    .events
                    .iter()
                    .filter(|e| e.cursor > cursor)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let next = events.last().map_or(cursor, |e| e.cursor);
        (events, next)
    }

    /// Up to `limit` messages of the group with `seq > after_seq`.
    pub fn messages(
        &self,
        group_id: &GroupId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Delivered>, DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        Ok(group
            .history
            .iter()
            .skip(usize::try_from(after_seq).unwrap_or(usize::MAX))
            .take(limit)
            .cloned()
            .collect())
    }

    pub fn upload_blob(&self, data: Vec<u8>) -> String {
        let mut state = self.lock();
        let blob_id = format!("blob{}", state.next_id());
        state.blobs.insert(blob_id.clone(), data);
        blob_id
    }

    /// The blob's bytes, or the given byte range of them.
    pub fn download_blob(
        &self,
        blob_id: &str,
        range: Option<Range<u64>>,
    ) -> Result<Vec<u8>, DeliveryError> {
        let state = self.lock();
        let data = state
            .blobs
            .get(blob_id)
            .ok_or_else(|| DeliveryError::UnknownBlob(blob_id.to_string()))?;
        let len = data.len() as u64;
        let Range { start, end } = range.unwrap_or(0..len);
        if start > end || end > len {
            return Err(DeliveryError::InvalidRange { start, end, len });
        }
        Ok(data[start as usize..end as usize].to_vec())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl State {
    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn push_event(&mut self, device: &DeviceRef, event: Event) {
        self.head += 1;
        let cursor = self.head;
        self.inboxes
            .entry(device.clone())
            .or_default()
            .events
            .push(StreamEvent { cursor, event });
    }

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

    #[test]
    fn directory_and_key_packages() {
        let ds = FakeDeliveryService::new();
        let a1 = ds.register_device("alice", "Alice");
        let a2 = ds.register_device("alice", "ignored");
        assert_eq!(a1.device.user_id, a2.device.user_id);
        assert_ne!(a1.device, a2.device);
        assert_eq!(ds.authenticate(&a2.token), Ok(a2.device.clone()));
        assert_eq!(ds.authenticate("nope"), Err(DeliveryError::Unauthorized));
        let user = ds.find_user("alice").unwrap();
        assert_eq!(user.display_name, "Alice");
        assert_eq!(
            ds.devices(&user.user_id).unwrap(),
            vec![a1.device.clone(), a2.device.clone()]
        );
        assert!(ds.find_user("bob").is_none());

        let a = &a1.device;
        assert_eq!(
            ds.claim_key_package(a),
            Err(DeliveryError::NoKeyPackage(a.clone()))
        );
        let packages = (0..=KEY_PACKAGES_LOW_THRESHOLD as u8)
            .map(|i| vec![i])
            .collect();
        ds.upload_key_packages(a, packages, Some(b"last".to_vec()));
        assert_eq!(ds.claim_key_package(a), Ok(vec![0]));
        assert_eq!(ds.events(a, a1.cursor, 10).0, vec![]);
        assert_eq!(ds.claim_key_package(a), Ok(vec![1]));
        let (events, next) = ds.events(a, a1.cursor, 10);
        assert_eq!(
            events.iter().map(|e| e.event.clone()).collect::<Vec<_>>(),
            vec![Event::KeyPackagesLow {
                available: KEY_PACKAGES_LOW_THRESHOLD - 1
            }]
        );
        assert_eq!(ds.events(a, next, 10).0, vec![]);
        for _ in 0..KEY_PACKAGES_LOW_THRESHOLD - 1 {
            ds.claim_key_package(a).unwrap();
        }
        assert_eq!(ds.key_package_count(a), 0);
        assert_eq!(ds.claim_key_package(a), Ok(b"last".to_vec()));
        assert_eq!(ds.claim_key_package(a), Ok(b"last".to_vec()));
    }

    #[test]
    fn events_history_and_blobs() {
        let ds = FakeDeliveryService::new();
        let a = ds.register_device("alice", "Alice").device;
        let b = ds.register_device("bob", "Bob");
        let g = ds
            .create_group_with(GroupKind::Direct, &a, std::slice::from_ref(&b.device))
            .unwrap();
        let info = ds.group(&g).unwrap();
        assert_eq!(info.kind, GroupKind::Direct);
        assert_eq!(info.members.len(), 2);
        ds.post(&g, &a, msg("m1", 0, MessageKind::Application))
            .unwrap();
        ds.post(&g, &a, msg("m2", 0, MessageKind::Application))
            .unwrap();
        ds.remove_member(&g, &b.device).unwrap();

        let (events, next) = ds.events(&b.device, b.cursor, 2);
        assert!(
            matches!(&events[0].event, Event::MemberAdded { device, .. } if *device == b.device)
        );
        assert!(matches!(&events[1].event, Event::Message(m) if m.seq == 1));
        let (events, next) = ds.events(&b.device, next, 10);
        assert!(matches!(&events[0].event, Event::Message(m) if m.seq == 2));
        assert!(
            matches!(&events[1].event, Event::MemberRemoved { device, .. } if *device == b.device)
        );
        assert_eq!(ds.events(&b.device, next, 10), (vec![], next));
        // `pull` is independent of the cursor API.
        assert_eq!(ds.pull(&b.device).len(), 2);

        let history = ds.messages(&g, 1, 10).unwrap();
        assert_eq!(history.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![2]);
        assert_eq!(history[0].client_id.as_str(), "m2");

        let blob = ds.upload_blob(b"hello".to_vec());
        assert_eq!(ds.download_blob(&blob, None), Ok(b"hello".to_vec()));
        assert_eq!(ds.download_blob(&blob, Some(1..3)), Ok(b"el".to_vec()));
        assert!(ds.download_blob(&blob, Some(3..9)).is_err());
        assert!(ds.download_blob("nope", None).is_err());
    }
}
