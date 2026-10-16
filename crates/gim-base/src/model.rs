//! Domain model persisted by a [`crate::StateStore`] and the event types
//! consumed and produced by [`crate::BaseClient`].

use std::collections::{BTreeMap, BTreeSet};

use gim_common::{ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_proto::envelope::{Envelope, MediaInfo, ReceiptKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChatKind {
    Direct,
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Membership {
    Joined,
    /// This device asked to leave (a [`PendingLeave`]) and stays an MLS
    /// member until another member commits its removal; nothing can be
    /// sent meanwhile.
    Leaving,
    /// This device was removed; history is kept.
    Left,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMember {
    pub device: DeviceRef,
    /// From the user directory cache when the member list was last updated.
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chat {
    pub group_id: GroupId,
    pub kind: ChatKind,
    pub name: Option<String>,
    pub avatar: Option<MediaInfo>,
    /// Current MLS group members, this device included.
    pub members: Vec<ChatMember>,
    pub unread_count: u32,
    pub last_message_id: Option<MessageId>,
    /// Seq of the latest sent or received message (0 if none).
    pub last_seq: u64,
    /// Highest seq covered by [`crate::BaseClient::mark_read`].
    pub last_read_seq: u64,
    pub updated_at_ms: u64,
    pub membership: Membership,
}

impl Chat {
    pub fn new(group_id: GroupId, kind: ChatKind, now_ms: u64) -> Self {
        Self {
            group_id,
            kind,
            name: None,
            avatar: None,
            members: Vec::new(),
            unread_count: 0,
            last_message_id: None,
            last_seq: 0,
            last_read_seq: 0,
            updated_at_ms: now_ms,
            membership: Membership::Joined,
        }
    }
}

/// Send state of a message sent by this user:
/// `Pending → Sent → Delivered → Read`, or `Pending → Failed`. `Delivered`
/// and `Read` need a receipt from every device of every other member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendState {
    Pending,
    Sent,
    Delivered,
    Read,
    Failed,
}

impl SendState {
    /// Progress rank; a state only ever moves to a higher rank, except for
    /// `Pending ⇄ Failed` (failure and manual retry).
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Pending | Self::Failed => 0,
            Self::Sent => 1,
            Self::Delivered => 2,
            Self::Read => 3,
        }
    }
}

/// An own media message whose blob has not been uploaded yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMedia {
    /// Plaintext file to encrypt and upload.
    pub local_path: String,
    pub mime: String,
    pub caption: Option<String>,
}

// Moved around by value and matched on; boxing would only complicate that.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageContent {
    Text {
        body: String,
    },
    Media {
        media: MediaInfo,
        caption: Option<String>,
    },
    PendingMedia(PendingMedia),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub message_id: MessageId,
    pub group_id: GroupId,
    /// Server seq; `None` until an own message was accepted.
    pub seq: Option<u64>,
    pub sender: DeviceRef,
    pub sent_at_ms: u64,
    /// Latest content: edits replace the text body or media caption; a
    /// delete clears it to an empty text.
    pub content: MessageContent,
    pub reply_to: Option<MessageId>,
    pub edited: bool,
    pub deleted: bool,
    /// Emojis per reacting user.
    pub reactions: BTreeMap<UserId, BTreeSet<String>>,
    /// `Some` for messages sent by this user (from any of its devices).
    pub send_state: Option<SendState>,
    /// Best receipt reported by each recipient device (own messages only).
    pub receipts: BTreeMap<DeviceRef, ReceiptKind>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxKind {
    /// Ready to encrypt and post.
    Envelope(Envelope),
    /// The media blob must be uploaded first; see
    /// [`crate::BaseClient::complete_media_upload`].
    MediaUpload(PendingMedia),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboxState {
    /// Waiting for (another) attempt at `next_attempt_at_ms`.
    Pending,
    /// Gave up; only a manual retry or cancel moves it on.
    Failed,
}

/// An encrypted MLS application message ready to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPayload {
    /// Epoch the payload was encrypted at (the hub reads it from the
    /// framing).
    pub epoch: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// Also the `client_id` posted to the hub.
    pub message_id: MessageId,
    pub group_id: GroupId,
    pub kind: OutboxKind,
    pub state: OutboxState,
    /// Failed attempts since creation or the last manual retry.
    pub attempts: u32,
    pub next_attempt_at_ms: u64,
    pub last_error: Option<String>,
    pub prepared: Option<PreparedPayload>,
    pub created_at_ms: u64,
}

impl OutboxEntry {
    pub fn client_id(&self) -> ClientId {
        to_client_id(&self.message_id)
    }
}

pub(crate) fn to_client_id(message_id: &MessageId) -> ClientId {
    ClientId::new(message_id.as_str()).expect("message ids are valid client ids")
}

pub(crate) fn to_message_id(client_id: &ClientId) -> MessageId {
    MessageId::new(client_id.as_str()).expect("client ids are valid message ids")
}

/// Seqs applied for one group: everything up to `contiguous_seq`, plus the
/// out-of-order seqs in `ahead`. A non-empty `ahead` means there is a hole
/// `(contiguous_seq, first ahead)`, which gim-sdk confirms against the hub
/// history before backfilling it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupCursor {
    pub contiguous_seq: u64,
    pub ahead: BTreeSet<u64>,
}

impl GroupCursor {
    pub fn contains(&self, seq: u64) -> bool {
        seq <= self.contiguous_seq || self.ahead.contains(&seq)
    }

    pub fn insert(&mut self, seq: u64) {
        if !self.contains(seq) {
            self.ahead.insert(seq);
            self.compact();
        }
    }

    /// Marks every seq up to `seq` as applied (e.g. on joining at `seq`).
    pub fn advance_to(&mut self, seq: u64) {
        if seq > self.contiguous_seq {
            self.contiguous_seq = seq;
            self.ahead.retain(|&s| s > seq);
            self.compact();
        }
    }

    /// First missing seq range `(from, to)`, both inclusive.
    pub fn first_gap(&self) -> Option<(u64, u64)> {
        self.ahead
            .first()
            .map(|&next| (self.contiguous_seq + 1, next - 1))
    }

    fn compact(&mut self) {
        while self.ahead.remove(&(self.contiguous_seq + 1)) {
            self.contiguous_seq += 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaCacheEntry {
    pub blob_id: String,
    pub local_path: String,
    pub size: u64,
    pub last_access_ms: u64,
}

/// An own commit whose acceptance is not confirmed yet. One per group;
/// written in the transaction that creates the MLS pending commit, so a
/// restarted client re-posts the same commit (same bytes and `client_id`,
/// with its Welcome) before any other work in the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCommit {
    pub group_id: GroupId,
    pub client_id: ClientId,
    pub epoch: u64,
    pub payload: Vec<u8>,
    /// Welcome of the devices the commit adds.
    pub welcome: Option<PendingWelcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWelcome {
    pub payload: Vec<u8>,
    pub recipients: Vec<DeviceRef>,
}

/// This device's Remove proposal for its own leaf, kept while the chat is
/// [`Membership::Leaving`]: re-posted (same bytes and `client_id`) while
/// its outcome is unknown, and replaced by a fresh one when the epoch
/// advances without removing this device. One per group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLeave {
    pub group_id: GroupId,
    pub client_id: ClientId,
    /// Epoch the proposal was created in.
    pub epoch: u64,
    pub payload: Vec<u8>,
    /// Proposals created since leaving started (or the client started).
    pub attempts: u32,
    /// The hub accepted this proposal.
    pub accepted: bool,
}

/// A user added to a chat whose hub was unreachable when their KeyPackages
/// were claimed; the sync loop claims them again until the invite expires.
/// One per (group, user).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvite {
    pub group_id: GroupId,
    pub user_id: UserId,
    /// Unix milliseconds of the first claim; the invite expires a TTL later.
    pub created_at_ms: u64,
    /// Unix milliseconds of the next claim.
    pub next_retry_at_ms: u64,
    /// Claims after the first one.
    pub attempts: u32,
}

/// Where a hub of the own user's hosting record stands for this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HubState {
    /// Listed, but no URL is known yet or `GET /v2/hub` at the URL did not
    /// prove the hub's identity: never used, no credentials sent there.
    Unverified,
    /// Listed, and the URL proved the hub's identity.
    Verified,
    /// No longer listed by the current hosting record.
    Removed,
}

/// A hub of the own user's hosting record, as this device knows it. One
/// per `hub_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubRecord {
    pub hub_id: String,
    /// Client API base URL, once known.
    pub url: Option<String>,
    /// Priority in the hosting record; lower is preferred.
    pub priority: u8,
    /// The 32-byte root public key `GET /v2/hub` at `url` returned, once
    /// verified against `hub_id`.
    pub verified_root_pubkey: Option<Vec<u8>>,
    /// Unix milliseconds of the last successful contact.
    pub last_seen_ms: Option<u64>,
    pub state: HubState,
}

/// A device that left a group (a self-remove proposal, or a hub-side
/// `member_removed` without a commit) or was revoked in its user's
/// DeviceList, and may still be in the MLS tree: a member has to remove it
/// by a commit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DepartedMember {
    pub group_id: GroupId,
    pub device: DeviceRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MembershipChangeKind {
    Added,
    /// Removed by another member.
    Removed,
    /// Removed after leaving by themselves.
    Left,
}

/// A user joining or leaving a chat, recorded when the MLS commit or
/// Welcome that did it is applied. One per (group, seq, user).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEvent {
    pub group_id: GroupId,
    /// Seq of the commit or Welcome.
    pub seq: u64,
    /// The user who joined or left.
    pub user_id: UserId,
    /// The user whose commit (or Welcome) did it.
    pub actor: UserId,
    pub kind: MembershipChangeKind,
    pub at_ms: u64,
}

/// User directory cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub user_id: UserId,
    pub handle: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// A Commit or Proposal (PublicMessage).
    Commit,
    /// A Welcome addressed to this device (a `welcome` event); its `seq` is
    /// the seq of the Commit that produced it.
    Welcome,
    Application,
}

/// A group message of the device stream or the group history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessage {
    pub group_id: GroupId,
    pub seq: u64,
    pub sender: DeviceRef,
    pub kind: MessageKind,
    pub payload: Vec<u8>,
    /// Present on the echo of a message this device posted.
    pub client_id: Option<ClientId>,
}

/// An event of the device stream, independent of the hub DTOs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingEvent {
    Message(GroupMessage),
    MemberAdded {
        group_id: GroupId,
        device: DeviceRef,
    },
    MemberRemoved {
        group_id: GroupId,
        device: DeviceRef,
    },
    KeyPackagesLow,
}

/// A change produced by [`crate::BaseClient`], for gim-ui to turn into diffs.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateChange {
    ChatUpserted(Chat),
    ChatRemoved(GroupId),
    MessageUpserted(Message),
    MessageRemoved {
        group_id: GroupId,
        message_id: MessageId,
    },
    MembershipChanged(MembershipEvent),
    /// Transient; never persisted.
    Typing {
        group_id: GroupId,
        user_id: UserId,
        active: bool,
    },
    /// The hub asks for more KeyPackages.
    KeyPackagesLow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_cursor_tracks_holes() {
        let mut cursor = GroupCursor::default();
        cursor.insert(1);
        cursor.insert(3);
        cursor.insert(5);
        assert_eq!(cursor.contiguous_seq, 1);
        assert!(cursor.contains(3) && !cursor.contains(2) && !cursor.contains(4));
        assert_eq!(cursor.first_gap(), Some((2, 2)));
        cursor.insert(2);
        assert_eq!(cursor.contiguous_seq, 3);
        assert_eq!(cursor.first_gap(), Some((4, 4)));
        cursor.advance_to(4);
        assert_eq!(cursor.contiguous_seq, 5);
        assert!(cursor.ahead.is_empty());
        assert_eq!(cursor.first_gap(), None);
        cursor.advance_to(2);
        assert_eq!(cursor.contiguous_seq, 5);
    }

    #[test]
    fn send_state_rank_orders_progress() {
        assert!(SendState::Read.rank() > SendState::Delivered.rank());
        assert!(SendState::Delivered.rank() > SendState::Sent.rank());
        assert!(SendState::Sent.rank() > SendState::Pending.rank());
        assert_eq!(SendState::Failed.rank(), SendState::Pending.rank());
    }
}
