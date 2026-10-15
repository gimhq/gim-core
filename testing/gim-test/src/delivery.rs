//! Synchronous, in-memory model of gim-hub API v2 (semantics of
//! `crates/gim-proto/contract/hub-v2/api-v2.md`):
//!
//! - users exist once their DeviceList was uploaded; a list with a higher
//!   `seq` replaces it, the identical list is a no-op, anything else is
//!   [`DeliveryError::StaleDeviceList`]. Replacing a list pushes
//!   `device_list.updated` to the user's devices and to every device sharing
//!   a group with the user, drops the sessions and KeyPackages of devices no
//!   longer active, and removes nothing from groups (members commit that);
//! - devices sign in with a single-use challenge and get a bearer token
//!   while they are active in their user's list;
//! - handles are an optional directory (one handle per user);
//! - KeyPackages are uploaded per device; a claim for a user takes one per
//!   active device: a one-time package, else the never-consumed last-resort
//!   one, and pushes `keypackages.low` once fewer than
//!   [`KEY_PACKAGES_LOW_THRESHOLD`] one-time packages remain;
//! - groups get a hub-assigned `gid = <hub_id>/<n>`; the roster is a list of
//!   MLS leaves driven by the handshakes posted to
//!   [`FakeDeliveryService::submit_commit`]: removals blank their leaves,
//!   additions take the leftmost blank leaf or a new one (RFC 9420 order);
//! - a Commit is accepted only for the current epoch (else
//!   [`DeliveryError::StaleEpoch`]) and advances it; resending the same
//!   Commit (same bytes) returns its result with `duplicate`;
//! - every accepted message gets the next per-group `seq`; application
//!   messages are idempotent on the sender's `client_id`;
//! - handshakes and application messages fan out to every member device
//!   except the sender (devices removed by the Commit included); Welcomes
//!   go to their recipients as `welcome` events and stay pending until
//!   acknowledged; membership events carry the user and its devices;
//! - each device has an event log with a hub-wide monotonic cursor
//!   ([`FakeDeliveryService::events`]), and every group keeps its message
//!   history by `seq` ([`FakeDeliveryService::messages`]);
//! - blobs are stored opaque and downloadable by byte range.
//!
//! MLS messages and identity objects are opaque bytes: callers verify
//! DeviceLists and auth responses and parse the MLS framing (gim-crypto),
//! and pass the results in.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Range;
use std::sync::{Mutex, MutexGuard};

use gim_common::{ClientId, DeviceId, DeviceRef, GroupId, UserId};

/// A device gets `keypackages.low` once fewer one-time KeyPackages remain.
pub const KEY_PACKAGES_LOW_THRESHOLD: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A Commit or a standalone Proposal.
    Commit,
    Application,
}

/// A message as it appears in a device inbox and in the group history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub group_id: GroupId,
    pub seq: u64,
    pub sender: DeviceRef,
    pub client_id: ClientId,
    pub kind: MessageKind,
    pub epoch: u64,
    pub payload: Vec<u8>,
}

/// A handshake to post, with what the hub reads from its framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitCommit {
    pub client_id: ClientId,
    pub mls_message: Vec<u8>,
    /// Epoch from the framing.
    pub epoch: u64,
    /// A standalone Proposal rather than a Commit.
    pub proposal: bool,
    /// Devices of the inline Add proposals.
    pub added: Vec<DeviceRef>,
    /// Leaves of the inline Remove proposals.
    pub removed_leaves: Vec<u32>,
    pub welcome: Option<Vec<u8>>,
    pub welcome_recipients: Vec<DeviceRef>,
}

/// Result of an accepted [`SubmitCommit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitResult {
    pub seq: u64,
    /// Epoch after the Commit.
    pub epoch: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Direct,
    Group,
}

/// Hub view of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_id: GroupId,
    pub kind: GroupKind,
    pub epoch: u64,
    pub last_seq: u64,
    pub members: Vec<DeviceRef>,
}

/// A user as returned by the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub user_id: UserId,
    pub device_list: Vec<u8>,
    pub handle: Option<String>,
    /// Not part of hub API v2: a test-only profile name, see
    /// [`FakeDeliveryService::set_display_name`].
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipChange {
    pub group_id: GroupId,
    pub user_id: UserId,
    pub device_ids: Vec<DeviceId>,
    pub by: DeviceRef,
    /// Epoch after the Commit.
    pub epoch: u64,
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    pub group_id: GroupId,
    pub sender: DeviceRef,
    /// Epoch the Welcome joins.
    pub epoch: u64,
    /// Seq of the Commit that produced it.
    pub seq: u64,
    pub welcome: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Message(Delivered),
    MemberAdded(MembershipChange),
    MemberRemoved(MembershipChange),
    Welcome(Welcome),
    KeyPackagesLow {
        available: usize,
    },
    DeviceListUpdated {
        user_id: UserId,
        device_list: Vec<u8>,
    },
}

/// One entry of a device event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEvent {
    pub cursor: u64,
    pub event: Event,
}

/// A claimed KeyPackage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub device: DeviceRef,
    pub key_package: Vec<u8>,
    pub last_resort: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    #[error("409 stale_epoch: commit epoch {commit_epoch}, group epoch {current_epoch}")]
    StaleEpoch {
        commit_epoch: u64,
        current_epoch: u64,
    },
    #[error("409 stale_device_list")]
    StaleDeviceList,
    #[error("409 handle {0} is taken")]
    HandleTaken(String),
    #[error("400 validation_failed: {0}")]
    ValidationFailed(String),
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
    #[error("unknown blob {0}")]
    UnknownBlob(String),
    #[error("range {start}..{end} outside blob of {len} bytes")]
    InvalidRange { start: u64, end: u64, len: u64 },
}

#[derive(Debug)]
struct Group {
    kind: GroupKind,
    /// MLS leaves; `None` is a blank leaf.
    leaves: Vec<Option<DeviceRef>>,
    epoch: u64,
    seq_by_client_id: HashMap<(DeviceRef, ClientId), u64>,
    /// Accepted Commit bytes → (seq, epoch after).
    commits: HashMap<Vec<u8>, (u64, u64)>,
    history: Vec<Delivered>,
}

impl Group {
    fn members(&self) -> BTreeSet<DeviceRef> {
        self.leaves.iter().flatten().cloned().collect()
    }
}

#[derive(Debug)]
struct UserState {
    device_list: Vec<u8>,
    seq: u64,
    active: BTreeSet<DeviceId>,
    display_name: Option<String>,
    recovery_backup: Option<Vec<u8>>,
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
    users: HashMap<UserId, UserState>,
    handles: BTreeMap<String, UserId>,
    tokens: HashMap<String, DeviceRef>,
    challenges: HashSet<Vec<u8>>,
    key_packages: HashMap<DeviceRef, KeyPackages>,
    groups: HashMap<GroupId, Group>,
    inboxes: HashMap<DeviceRef, Inbox>,
    pending_welcomes: HashMap<DeviceRef, Vec<Welcome>>,
    blobs: HashMap<String, Vec<u8>>,
    /// Last assigned event cursor.
    head: u64,
    /// Counter for hub-assigned ids.
    next_id: u64,
}

#[derive(Debug)]
pub struct FakeDeliveryService {
    hub_id: String,
    state: Mutex<State>,
}

impl Default for FakeDeliveryService {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDeliveryService {
    pub fn new() -> Self {
        Self::with_hub_id(crate::fake_hub_id())
    }

    pub fn with_hub_id(hub_id: impl Into<String>) -> Self {
        Self {
            hub_id: hub_id.into(),
            state: Mutex::default(),
        }
    }

    /// This hub's `hub_id`: the audience of its challenges and the prefix
    /// of its group ids.
    pub fn hub_id(&self) -> &str {
        &self.hub_id
    }

    /// Stores a verified DeviceList of `user_id` with its `seq`, signed
    /// `bytes` and active devices. Returns whether it changed anything.
    pub fn put_device_list(
        &self,
        user_id: &UserId,
        seq: u64,
        bytes: Vec<u8>,
        active: BTreeSet<DeviceId>,
    ) -> Result<bool, DeliveryError> {
        let mut state = self.lock();
        if let Some(stored) = state.users.get(user_id) {
            if stored.seq == seq && stored.device_list == bytes {
                return Ok(false);
            }
            if stored.seq >= seq {
                return Err(DeliveryError::StaleDeviceList);
            }
        }
        let user = state
            .users
            .entry(user_id.clone())
            .or_insert_with(|| UserState {
                device_list: Vec::new(),
                seq,
                active: BTreeSet::new(),
                display_name: None,
                recovery_backup: None,
            });
        let gone: Vec<DeviceId> = user.active.difference(&active).cloned().collect();
        let first = user.device_list.is_empty();
        user.device_list = bytes.clone();
        user.seq = seq;
        user.active = active.clone();
        for device_id in gone {
            let device = DeviceRef::new(user_id.clone(), device_id);
            state.tokens.retain(|_, d| *d != device);
            state.key_packages.remove(&device);
        }
        if !first {
            let mut watchers: BTreeSet<DeviceRef> = active
                .iter()
                .map(|d| DeviceRef::new(user_id.clone(), d.clone()))
                .collect();
            for group in state.groups.values() {
                let members = group.members();
                if members.iter().any(|m| &m.user_id == user_id) {
                    watchers.extend(members);
                }
            }
            let event = Event::DeviceListUpdated {
                user_id: user_id.clone(),
                device_list: bytes,
            };
            for device in &watchers {
                state.push_event(device, event.clone());
            }
        }
        Ok(true)
    }

    /// The signed DeviceList of a user.
    pub fn device_list(&self, user_id: &UserId) -> Option<Vec<u8>> {
        self.lock()
            .users
            .get(user_id)
            .map(|u| u.device_list.clone())
    }

    /// Devices active in the user's DeviceList.
    pub fn devices(&self, user_id: &UserId) -> Result<Vec<DeviceRef>, DeliveryError> {
        let state = self.lock();
        let user = state
            .users
            .get(user_id)
            .ok_or_else(|| DeliveryError::UnknownUser(user_id.clone()))?;
        Ok(user
            .active
            .iter()
            .map(|d| DeviceRef::new(user_id.clone(), d.clone()))
            .collect())
    }

    pub fn user(&self, user_id: &UserId) -> Option<User> {
        let state = self.lock();
        let user = state.users.get(user_id)?;
        Some(User {
            user_id: user_id.clone(),
            device_list: user.device_list.clone(),
            handle: state.handle_of(user_id),
            display_name: user.display_name.clone(),
        })
    }

    /// Test-only profile: hub API v2 has no display names.
    pub fn set_display_name(&self, user_id: &UserId, name: &str) -> Result<(), DeliveryError> {
        self.lock()
            .users
            .get_mut(user_id)
            .ok_or_else(|| DeliveryError::UnknownUser(user_id.clone()))?
            .display_name = Some(name.to_string());
        Ok(())
    }

    /// Records an issued challenge; it can be redeemed once.
    pub fn issue_challenge(&self, challenge: Vec<u8>) {
        self.lock().challenges.insert(challenge);
    }

    /// Consumes an issued challenge; `false` if unknown or used.
    pub fn redeem_challenge(&self, challenge: &[u8]) -> bool {
        self.lock().challenges.remove(challenge)
    }

    /// A new bearer token for a device active in its user's list.
    pub fn create_session(&self, device: &DeviceRef) -> Result<String, DeliveryError> {
        let mut state = self.lock();
        if !state.is_active(device) {
            return Err(DeliveryError::Unauthorized);
        }
        let token = format!("token-{}", state.next_id());
        state.tokens.insert(token.clone(), device.clone());
        Ok(token)
    }

    /// The device a bearer token belongs to.
    pub fn authenticate(&self, token: &str) -> Result<DeviceRef, DeliveryError> {
        self.lock()
            .tokens
            .get(token)
            .cloned()
            .ok_or(DeliveryError::Unauthorized)
    }

    /// Drops every session of `device` (as after their expiry).
    pub fn expire_sessions(&self, device: &DeviceRef) {
        self.lock().tokens.retain(|_, d| d != device);
    }

    pub fn claim_handle(&self, user_id: &UserId, handle: &str) -> Result<(), DeliveryError> {
        let mut state = self.lock();
        match state.handles.get(handle) {
            Some(owner) if owner == user_id => return Ok(()),
            Some(_) => return Err(DeliveryError::HandleTaken(handle.to_string())),
            None => {}
        }
        state.handles.retain(|_, owner| owner != user_id);
        state.handles.insert(handle.to_string(), user_id.clone());
        Ok(())
    }

    pub fn release_handle(&self, user_id: &UserId, handle: &str) {
        let mut state = self.lock();
        if state.handles.get(handle) == Some(user_id) {
            state.handles.remove(handle);
        }
    }

    pub fn find_handle(&self, handle: &str) -> Option<UserId> {
        self.lock().handles.get(handle).cloned()
    }

    pub fn put_recovery_backup(
        &self,
        user_id: &UserId,
        backup: Vec<u8>,
    ) -> Result<(), DeliveryError> {
        self.lock()
            .users
            .get_mut(user_id)
            .ok_or_else(|| DeliveryError::UnknownUser(user_id.clone()))?
            .recovery_backup = Some(backup);
        Ok(())
    }

    pub fn recovery_backup(&self, user_id: &UserId) -> Option<Vec<u8>> {
        self.lock()
            .users
            .get(user_id)
            .and_then(|u| u.recovery_backup.clone())
    }

    /// Appends one-time KeyPackages, or replaces the last-resort one with
    /// the single package given.
    pub fn upload_key_packages(
        &self,
        device: &DeviceRef,
        mut key_packages: Vec<Vec<u8>>,
        last_resort: bool,
    ) {
        let mut state = self.lock();
        let stored = state.key_packages.entry(device.clone()).or_default();
        if last_resort {
            stored.last_resort = key_packages.pop();
        } else {
            stored.one_time.extend(key_packages);
        }
    }

    /// Claims one KeyPackage per active device of each user. Returns the
    /// claimed packages and the users without any.
    pub fn claim_key_packages(&self, users: &[UserId]) -> (Vec<Claimed>, Vec<UserId>) {
        let mut state = self.lock();
        let mut claimed = Vec::new();
        let mut missing = Vec::new();
        for user_id in users {
            let devices: Vec<DeviceRef> = state.users.get(user_id).map_or(vec![], |u| {
                u.active
                    .iter()
                    .map(|d| DeviceRef::new(user_id.clone(), d.clone()))
                    .collect()
            });
            let before = claimed.len();
            for device in devices {
                if let Some(c) = state.claim(&device) {
                    claimed.push(c);
                }
            }
            if claimed.len() == before {
                missing.push(user_id.clone());
            }
        }
        (claimed, missing)
    }

    /// Unclaimed one-time KeyPackages of `device`.
    pub fn key_package_count(&self, device: &DeviceRef) -> usize {
        self.lock()
            .key_packages
            .get(device)
            .map_or(0, |k| k.one_time.len())
    }

    /// Whether `device` has a last-resort KeyPackage.
    pub fn has_last_resort_key_package(&self, device: &DeviceRef) -> bool {
        self.lock()
            .key_packages
            .get(device)
            .is_some_and(|k| k.last_resort.is_some())
    }

    /// Registers a group with a caller-chosen id (epoch 0); the creator
    /// holds leaf 0.
    pub fn create_group(
        &self,
        group_id: &GroupId,
        creator: &DeviceRef,
    ) -> Result<(), DeliveryError> {
        self.create(group_id, GroupKind::Group, creator)
    }

    /// Creates a group with a hub-assigned `gid`.
    pub fn create_group_with(
        &self,
        kind: GroupKind,
        creator: &DeviceRef,
    ) -> Result<GroupId, DeliveryError> {
        let id = self.lock().next_id();
        let group_id = GroupId::new(format!("{}/g{id:024}", self.hub_id)).expect("valid group id");
        self.create(&group_id, kind, creator)?;
        Ok(group_id)
    }

    fn create(
        &self,
        group_id: &GroupId,
        kind: GroupKind,
        creator: &DeviceRef,
    ) -> Result<(), DeliveryError> {
        let mut state = self.lock();
        if state.groups.contains_key(group_id) {
            return Err(DeliveryError::GroupExists(group_id.clone()));
        }
        state.groups.insert(
            group_id.clone(),
            Group {
                kind,
                leaves: vec![Some(creator.clone())],
                epoch: 0,
                seq_by_client_id: HashMap::new(),
                commits: HashMap::new(),
                history: Vec::new(),
            },
        );
        Ok(())
    }

    pub fn group(&self, group_id: &GroupId) -> Result<GroupInfo, DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        Ok(info(group_id, group))
    }

    /// The groups whose roster has `device`.
    pub fn groups_of(&self, device: &DeviceRef) -> Vec<GroupInfo> {
        let state = self.lock();
        let mut groups: Vec<GroupInfo> = state
            .groups
            .iter()
            .filter(|(_, group)| group.members().contains(device))
            .map(|(group_id, group)| info(group_id, group))
            .collect();
        groups.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        groups
    }

    /// Hub-side removal of a device from the roster, without a Commit (as
    /// after a hub policy action).
    pub fn remove_member(
        &self,
        group_id: &GroupId,
        device: &DeviceRef,
    ) -> Result<(), DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        let Some(leaf) = group.leaves.iter_mut().find(|l| l.as_ref() == Some(device)) else {
            return Ok(());
        };
        *leaf = None;
        let change = MembershipChange {
            group_id: group_id.clone(),
            user_id: device.user_id.clone(),
            device_ids: vec![device.device_id.clone()],
            by: device.clone(),
            epoch: group.epoch,
            seq: group.history.len() as u64,
        };
        let members = group.members();
        for member in members.iter().chain([device]) {
            state.push_event(member, Event::MemberRemoved(change.clone()));
        }
        Ok(())
    }

    /// Current epoch as tracked by the hub.
    pub fn epoch(&self, group_id: &GroupId) -> Result<u64, DeliveryError> {
        Ok(self.lock().group_mut(group_id)?.epoch)
    }

    /// Accepts a Commit or Proposal of a member.
    pub fn submit_commit(
        &self,
        group_id: &GroupId,
        sender: &DeviceRef,
        commit: SubmitCommit,
    ) -> Result<CommitResult, DeliveryError> {
        let mut state = self.lock();
        let active: HashMap<UserId, BTreeSet<DeviceId>> = state
            .users
            .iter()
            .map(|(id, u)| (id.clone(), u.active.clone()))
            .collect();
        let group = state.group_mut(group_id)?;
        let before = group.members();
        if !before.contains(sender) {
            return Err(DeliveryError::NotAMember(sender.clone()));
        }
        if let Some(&(seq, epoch)) = group.commits.get(&commit.mls_message) {
            return Ok(CommitResult {
                seq,
                epoch,
                duplicate: true,
            });
        }
        if commit.epoch != group.epoch {
            return Err(DeliveryError::StaleEpoch {
                commit_epoch: commit.epoch,
                current_epoch: group.epoch,
            });
        }
        let invalid = |reason: String| Err(DeliveryError::ValidationFailed(reason));
        for device in &commit.added {
            if !active
                .get(&device.user_id)
                .is_some_and(|a| a.contains(&device.device_id))
            {
                return invalid(format!("{device} is not an active device"));
            }
        }
        let recipients: BTreeSet<&DeviceRef> = commit.welcome_recipients.iter().collect();
        if commit.welcome.is_some() != !commit.added.is_empty()
            || recipients != commit.added.iter().collect()
        {
            return invalid("Welcome does not match the added devices".into());
        }
        let mut removed = BTreeSet::new();
        if !commit.proposal {
            for &leaf in &commit.removed_leaves {
                let Some(device) = group.leaves.get_mut(leaf as usize).and_then(Option::take)
                else {
                    return invalid(format!("leaf {leaf} is not a member"));
                };
                removed.insert(device);
            }
            for device in &commit.added {
                match group.leaves.iter_mut().find(|l| l.is_none()) {
                    Some(blank) => *blank = Some(device.clone()),
                    None => group.leaves.push(Some(device.clone())),
                }
            }
            group.epoch += 1;
        }
        let seq = group.history.len() as u64 + 1;
        let delivered = Delivered {
            group_id: group_id.clone(),
            seq,
            sender: sender.clone(),
            client_id: commit.client_id.clone(),
            kind: MessageKind::Commit,
            epoch: commit.epoch,
            payload: commit.mls_message.clone(),
        };
        group.history.push(delivered.clone());
        group
            .seq_by_client_id
            .insert((sender.clone(), commit.client_id), seq);
        let epoch = group.epoch;
        if !commit.proposal {
            group.commits.insert(commit.mls_message, (seq, epoch));
        }
        let after = group.members();
        for device in before.iter().filter(|d| *d != sender) {
            state.push_event(device, Event::Message(delivered.clone()));
        }
        let change = |user_id: &UserId, devices: Vec<DeviceId>| MembershipChange {
            group_id: group_id.clone(),
            user_id: user_id.clone(),
            device_ids: devices,
            by: sender.clone(),
            epoch,
            seq,
        };
        for (user_id, devices) in by_user(commit.added.iter()) {
            let event = Event::MemberAdded(change(&user_id, devices));
            for device in &after {
                state.push_event(device, event.clone());
            }
        }
        for (user_id, devices) in by_user(removed.iter()) {
            let event = Event::MemberRemoved(change(&user_id, devices));
            for device in after.iter().chain(&removed) {
                state.push_event(device, event.clone());
            }
        }
        if let Some(welcome) = commit.welcome {
            let welcome = Welcome {
                group_id: group_id.clone(),
                sender: sender.clone(),
                epoch,
                seq,
                welcome,
            };
            for device in &commit.welcome_recipients {
                state.push_event(device, Event::Welcome(welcome.clone()));
                state
                    .pending_welcomes
                    .entry(device.clone())
                    .or_default()
                    .push(welcome.clone());
            }
        }
        Ok(CommitResult {
            seq,
            epoch,
            duplicate: false,
        })
    }

    /// Accepts an application message for the current epoch (or a resend
    /// of the same `client_id`); returns its `seq`.
    pub fn post_message(
        &self,
        group_id: &GroupId,
        sender: &DeviceRef,
        client_id: ClientId,
        epoch: u64,
        mls_message: Vec<u8>,
    ) -> Result<u64, DeliveryError> {
        let mut state = self.lock();
        let group = state.group_mut(group_id)?;
        let members = group.members();
        if !members.contains(sender) {
            return Err(DeliveryError::NotAMember(sender.clone()));
        }
        let key = (sender.clone(), client_id.clone());
        if let Some(&seq) = group.seq_by_client_id.get(&key) {
            return Ok(seq);
        }
        if epoch != group.epoch {
            return Err(DeliveryError::StaleEpoch {
                commit_epoch: epoch,
                current_epoch: group.epoch,
            });
        }
        let seq = group.history.len() as u64 + 1;
        group.seq_by_client_id.insert(key, seq);
        let delivered = Delivered {
            group_id: group_id.clone(),
            seq,
            sender: sender.clone(),
            client_id,
            kind: MessageKind::Application,
            epoch,
            payload: mls_message,
        };
        group.history.push(delivered.clone());
        for device in members.iter().filter(|d| *d != sender) {
            state.push_event(device, Event::Message(delivered.clone()));
        }
        Ok(seq)
    }

    /// Returns the device's events not returned by an earlier `pull`, in
    /// delivery order. Independent of [`FakeDeliveryService::events`].
    pub fn pull(&self, device: &DeviceRef) -> Vec<Event> {
        let mut state = self.lock();
        let Some(inbox) = state.inboxes.get_mut(device) else {
            return Vec::new();
        };
        let new = inbox.events[inbox.pulled..]
            .iter()
            .map(|e| e.event.clone())
            .collect();
        inbox.pulled = inbox.events.len();
        new
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

    /// Hub-wide head cursor.
    pub fn head(&self) -> u64 {
        self.lock().head
    }

    /// Up to `limit` unacknowledged Welcomes of the device, oldest first.
    pub fn pending_welcomes(&self, device: &DeviceRef, limit: usize) -> Vec<Welcome> {
        self.lock()
            .pending_welcomes
            .get(device)
            .map(|w| w.iter().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    /// Acknowledges the device's pending Welcomes of the group; idempotent.
    pub fn ack_welcome(&self, device: &DeviceRef, group_id: &GroupId) {
        if let Some(pending) = self.lock().pending_welcomes.get_mut(device) {
            pending.retain(|w| &w.group_id != group_id);
        }
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

fn info(group_id: &GroupId, group: &Group) -> GroupInfo {
    GroupInfo {
        group_id: group_id.clone(),
        kind: group.kind,
        epoch: group.epoch,
        last_seq: group.history.len() as u64,
        members: group.members().into_iter().collect(),
    }
}

fn by_user<'a>(devices: impl Iterator<Item = &'a DeviceRef>) -> BTreeMap<UserId, Vec<DeviceId>> {
    let mut users: BTreeMap<UserId, Vec<DeviceId>> = BTreeMap::new();
    for device in devices {
        users
            .entry(device.user_id.clone())
            .or_default()
            .push(device.device_id.clone());
    }
    users
}

impl State {
    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn is_active(&self, device: &DeviceRef) -> bool {
        self.users
            .get(&device.user_id)
            .is_some_and(|u| u.active.contains(&device.device_id))
    }

    fn handle_of(&self, user_id: &UserId) -> Option<String> {
        self.handles
            .iter()
            .find(|(_, owner)| *owner == user_id)
            .map(|(handle, _)| handle.clone())
    }

    fn claim(&mut self, device: &DeviceRef) -> Option<Claimed> {
        let stored = self.key_packages.get_mut(device)?;
        if let Some(key_package) = stored.one_time.pop_front() {
            let available = stored.one_time.len();
            if available < KEY_PACKAGES_LOW_THRESHOLD {
                self.push_event(device, Event::KeyPackagesLow { available });
            }
            return Some(Claimed {
                device: device.clone(),
                key_package,
                last_resort: false,
            });
        }
        stored.last_resort.clone().map(|key_package| Claimed {
            device: device.clone(),
            key_package,
            last_resort: true,
        })
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

    fn device(user: &str, device: &str) -> DeviceRef {
        DeviceRef::parse(user, device).unwrap()
    }

    fn client_id(id: &str) -> ClientId {
        ClientId::new(id).unwrap()
    }

    fn user(ds: &FakeDeliveryService, user: &str, devices: &[&str]) -> Vec<DeviceRef> {
        let user_id = UserId::new(user).unwrap();
        let active = devices.iter().map(|d| DeviceId::new(*d).unwrap()).collect();
        ds.put_device_list(&user_id, 1, user.as_bytes().to_vec(), active)
            .unwrap();
        devices.iter().map(|d| device(user, d)).collect()
    }

    fn commit(id: &str, epoch: u64) -> SubmitCommit {
        SubmitCommit {
            client_id: client_id(id),
            mls_message: id.as_bytes().to_vec(),
            epoch,
            proposal: false,
            added: vec![],
            removed_leaves: vec![],
            welcome: None,
            welcome_recipients: vec![],
        }
    }

    fn add(id: &str, epoch: u64, devices: &[DeviceRef]) -> SubmitCommit {
        SubmitCommit {
            added: devices.to_vec(),
            welcome: Some(b"welcome".to_vec()),
            welcome_recipients: devices.to_vec(),
            ..commit(id, epoch)
        }
    }

    #[test]
    fn commits_drive_roster_epoch_and_events() {
        let ds = FakeDeliveryService::new();
        let a = user(&ds, "a", &["d1"]).remove(0);
        let b = user(&ds, "b", &["d1", "d2"]);
        let g = ds.create_group_with(GroupKind::Group, &a).unwrap();
        assert!(g.as_str().starts_with(&format!("{}/", ds.hub_id())));

        let added = ds.submit_commit(&g, &a, add("c1", 0, &b)).unwrap();
        assert_eq!((added.seq, added.epoch, added.duplicate), (1, 1, false));
        // Same Commit again: success with `duplicate`.
        assert_eq!(
            ds.submit_commit(&g, &a, add("c1", 0, &b)).unwrap(),
            CommitResult {
                seq: 1,
                epoch: 1,
                duplicate: true
            }
        );
        assert_eq!(
            ds.submit_commit(&g, &b[0], commit("c2", 0)),
            Err(DeliveryError::StaleEpoch {
                commit_epoch: 0,
                current_epoch: 1
            })
        );
        let mut mismatched = add("c3", 1, &b[..1]);
        mismatched.welcome_recipients = b.clone();
        assert!(matches!(
            ds.submit_commit(&g, &a, mismatched),
            Err(DeliveryError::ValidationFailed(_))
        ));
        assert_eq!(ds.group(&g).unwrap().members.len(), 3);

        // b's devices got the member event and the Welcome, a only the
        // member event.
        for d in &b {
            let events = ds.pull(d);
            assert!(matches!(&events[0], Event::MemberAdded(c) if c.device_ids.len() == 2));
            assert!(matches!(&events[1], Event::Welcome(w) if w.seq == 1 && w.epoch == 1));
            assert_eq!(ds.pending_welcomes(d, 10).len(), 1);
        }
        ds.ack_welcome(&b[0], &g);
        ds.ack_welcome(&b[0], &g);
        assert!(ds.pending_welcomes(&b[0], 10).is_empty());
        assert!(matches!(&ds.pull(&a)[..], [Event::MemberAdded(_)]));

        // Remove b's leaves 1 and 2; the next add takes leaf 1.
        let mut remove = commit("c4", 1);
        remove.removed_leaves = vec![1, 2];
        assert_eq!(ds.submit_commit(&g, &a, remove).unwrap().epoch, 2);
        assert_eq!(ds.group(&g).unwrap().members, vec![a.clone()]);
        let removed = ds.pull(&b[1]);
        assert!(matches!(&removed[0], Event::Message(m) if m.seq == 2));
        assert!(matches!(&removed[1], Event::MemberRemoved(c) if c.device_ids.len() == 2));
        let c = user(&ds, "c", &["d1"]);
        ds.submit_commit(&g, &a, add("c5", 2, &c)).unwrap();
        let mut remove_c = commit("c6", 3);
        remove_c.removed_leaves = vec![1];
        ds.submit_commit(&g, &a, remove_c).unwrap();
        assert_eq!(ds.group(&g).unwrap().members, vec![a.clone()]);
    }

    #[test]
    fn messages_are_idempotent_per_sender() {
        let ds = FakeDeliveryService::new();
        let a = user(&ds, "a", &["d1"]).remove(0);
        let b = user(&ds, "b", &["d1"]);
        let g = ds.create_group_with(GroupKind::Direct, &a).unwrap();
        ds.submit_commit(&g, &a, add("c1", 0, &b)).unwrap();
        let post = |d: &DeviceRef, id: &str| ds.post_message(&g, d, client_id(id), 1, vec![1]);
        assert_eq!(post(&a, "m1"), Ok(2));
        assert_eq!(post(&a, "m1"), Ok(2));
        assert_eq!(post(&b[0], "m1"), Ok(3));
        let outsider = device("x", "d1");
        assert_eq!(
            post(&outsider, "m2"),
            Err(DeliveryError::NotAMember(outsider))
        );
        let history = ds.messages(&g, 1, 10).unwrap();
        assert_eq!(
            history.iter().map(|m| m.seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        let (events, next) = ds.events(&b[0], 0, 10);
        assert_eq!(events.len(), 3);
        assert_eq!(ds.events(&b[0], next, 10), (vec![], next));
    }

    #[test]
    fn device_lists_sessions_and_key_packages() {
        let ds = FakeDeliveryService::new();
        let a = user(&ds, "a", &["d1", "d2"]);
        let user_id = a[0].user_id.clone();
        let active = |ids: &[&str]| ids.iter().map(|d| DeviceId::new(*d).unwrap()).collect();
        // Identical list: no-op; stale or forked lists are rejected.
        assert_eq!(
            ds.put_device_list(&user_id, 1, b"a".to_vec(), active(&["d1", "d2"])),
            Ok(false)
        );
        assert_eq!(
            ds.put_device_list(&user_id, 1, b"x".to_vec(), active(&["d1"])),
            Err(DeliveryError::StaleDeviceList)
        );

        let token = ds.create_session(&a[1]).unwrap();
        assert_eq!(ds.authenticate(&token), Ok(a[1].clone()));
        let packages = (0..=KEY_PACKAGES_LOW_THRESHOLD as u8)
            .map(|i| vec![i])
            .collect();
        ds.upload_key_packages(&a[0], packages, false);
        ds.upload_key_packages(&a[0], vec![b"last".to_vec()], true);
        ds.upload_key_packages(&a[1], vec![b"two".to_vec()], false);
        let (claimed, missing) = ds.claim_key_packages(std::slice::from_ref(&user_id));
        assert!(missing.is_empty());
        assert_eq!(claimed.len(), 2);
        let (claimed, _) = ds.claim_key_packages(std::slice::from_ref(&user_id));
        assert_eq!(claimed.len(), 1);
        assert_eq!(ds.key_package_count(&a[0]), KEY_PACKAGES_LOW_THRESHOLD - 1);

        // Revoking d2 drops its session and KeyPackages and notifies d1.
        assert_eq!(
            ds.put_device_list(&user_id, 2, b"a2".to_vec(), active(&["d1"])),
            Ok(true)
        );
        assert_eq!(ds.authenticate(&token), Err(DeliveryError::Unauthorized));
        assert_eq!(ds.create_session(&a[1]), Err(DeliveryError::Unauthorized));
        assert!(ds.pull(&a[0]).iter().any(
            |e| matches!(e, Event::DeviceListUpdated { device_list, .. } if device_list == b"a2")
        ));
        assert_eq!(ds.devices(&user_id).unwrap(), vec![a[0].clone()]);

        ds.claim_handle(&user_id, "alice").unwrap();
        assert_eq!(ds.find_handle("alice"), Some(user_id.clone()));
        let other = user(&ds, "b", &["d1"])[0].user_id.clone();
        assert!(ds.claim_handle(&other, "alice").is_err());
        assert_eq!(ds.user(&user_id).unwrap().handle.as_deref(), Some("alice"));
        ds.release_handle(&user_id, "alice");
        assert_eq!(ds.find_handle("alice"), None);

        ds.issue_challenge(b"c".to_vec());
        assert!(ds.redeem_challenge(b"c"));
        assert!(!ds.redeem_challenge(b"c"));
    }

    #[test]
    fn blobs() {
        let ds = FakeDeliveryService::new();
        let blob = ds.upload_blob(b"hello".to_vec());
        assert_eq!(ds.download_blob(&blob, None), Ok(b"hello".to_vec()));
        assert_eq!(ds.download_blob(&blob, Some(1..3)), Ok(b"el".to_vec()));
        assert!(ds.download_blob(&blob, Some(3..9)).is_err());
        assert!(ds.download_blob("nope", None).is_err());
    }
}
