//! Records and enums shared by the client, chat list and timeline APIs.
//! All ids are strings; all timestamps are Unix epoch milliseconds.

/// The signed-in account on this device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Session {
    pub user_id: String,
    pub device_id: String,
    /// Empty until `claim_handle`.
    pub handle: String,
    pub display_name: String,
}

/// A device of a user, from the user's signed DeviceList.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceInfo {
    pub device_id: String,
    /// When the device was certified; 0 for revoked devices.
    pub created_at_ms: u64,
    /// This client's device.
    pub is_current: bool,
    pub revoked: bool,
}

/// Public profile of a user.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UserProfile {
    pub user_id: String,
    pub handle: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatKind {
    Direct,
    Group,
}

/// One row of the chat list.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatSummary {
    pub chat_id: String,
    pub kind: ChatKind,
    /// Group name, or the other user's display name for a direct chat.
    pub name: String,
    pub avatar: Option<MediaRef>,
    pub last_message: Option<MessagePreview>,
    pub unread_count: u32,
    pub updated_at_ms: u64,
    pub member_count: u32,
    /// Where this device stands in the chat; read from local state, so it is
    /// right from the first callback after a restart.
    pub state: ChatState,
}

/// Where this device stands in a chat. Changes reach the chat list as a
/// `Set` diff of the row: `Active -> Leaving` when `leave_chat` starts,
/// `Leaving -> Left` once another member commits the removal, and
/// `Leaving -> Active` if the hub refuses the leave for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatState {
    /// A member; messages can be sent.
    Active,
    /// Leaving was asked for: still a member until another member commits
    /// the removal, but nothing can be sent (`GimError::ChatNotActive`).
    /// gim-core keeps and re-sends the leave across restarts.
    Leaving,
    /// Removed (after leaving, by another member or by the hub); history is
    /// kept, nothing can be sent.
    Left,
}

/// Last message shown in a chat list row.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessagePreview {
    pub sender_name: String,
    /// Plain-text rendering ("Photo", "File: report.pdf" for media).
    pub text: String,
    pub sent_at_ms: u64,
    pub is_own: bool,
}

/// One row of a chat timeline.
// Passed by value over FFI; boxing would not shrink anything there.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TimelineItem {
    Message {
        item: MessageItem,
    },
    /// Inserted before the first item of each local calendar day.
    DateSeparator {
        day_start_ms: u64,
    },
    MembershipChange {
        user_name: String,
        change: MembershipChangeKind,
        at_ms: u64,
        /// The user who joined or left; the signed-in user's own `Left` has
        /// their user id here.
        user_id: String,
        /// The user who caused the change: the adder or remover, the user
        /// themselves for `Left`. `None` if unknown.
        actor_user_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MembershipChangeKind {
    Added,
    Removed,
    Left,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessageItem {
    /// Client id of the message; stable from local echo to delivery.
    pub message_id: String,
    pub chat_id: String,
    pub sender: UserProfile,
    pub is_own: bool,
    pub sent_at_ms: u64,
    pub content: MessageContent,
    pub reply_to: Option<ReplyPreview>,
    pub reactions: Vec<ReactionGroup>,
    pub edited: bool,
    /// Delivery state of own messages; `None` for messages from others.
    pub send_state: Option<SendState>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MessageContent {
    Text {
        body: String,
    },
    Image {
        media: MediaRef,
        width: Option<u32>,
        height: Option<u32>,
        caption: Option<String>,
    },
    File {
        media: MediaRef,
        file_name: Option<String>,
        caption: Option<String>,
    },
    /// The sender deleted the message.
    Deleted,
    /// Content this client version cannot render.
    Unsupported,
}

/// Handle to an encrypted attachment. Pass it back to `fetch_media` /
/// `fetch_thumbnail`; keys and blob ids never leave Rust.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MediaRef {
    pub chat_id: String,
    pub message_id: String,
    pub mime: String,
    pub size: u64,
    pub has_thumbnail: bool,
}

/// Quoted message shown above a reply.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReplyPreview {
    pub message_id: String,
    pub sender_name: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReactionGroup {
    pub emoji: String,
    pub count: u32,
    /// Whether the signed-in user is among the reactors.
    pub own: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SendState {
    /// Queued in the outbox or being uploaded.
    Pending,
    /// Accepted by the server.
    Sent,
    /// Delivered to every device of every other member.
    Delivered,
    /// Read on every device of every other member.
    Read,
    /// Gave up; `retry_send` or `cancel_send`.
    Failed { reason: String },
}

/// Where a hub of the user's hosting record stands on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HubState {
    /// Listed, but this device has no URL for it that proved the hub's
    /// identity (none known yet, or only one shared by another own device):
    /// never contacted.
    Unverified,
    /// Listed, and its URL proved the hub's identity.
    Verified,
    /// No longer listed by the hosting record.
    Removed,
}

/// A hub of the user's hosting record, for the hub settings screen.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HubInfo {
    pub hub_id: String,
    /// Client API base URL, once known.
    pub url: Option<String>,
    pub state: HubState,
    /// Priority in the hosting record; lower is preferred.
    pub priority: u8,
    /// The first listed hub: submissions go there first.
    pub is_primary: bool,
    /// The hub this client was created for (`ClientConfig.server_url`);
    /// it cannot be removed.
    pub is_home: bool,
    /// This device holds a session on the hub.
    pub signed_in: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    Offline,
    Connecting,
    Connected,
    /// Connected and catching up on missed events.
    Syncing,
}

/// The device's push registration on its hubs (contract `push.md` §1).
/// Every field is opaque to the hub and passed to the push server.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushRegistration {
    /// Push platform for the push server (`apns`, `fcm`, `unifiedpush`,
    /// ...): 1-64 characters of `a-z 0-9 . _ -`.
    pub provider: String,
    /// Platform token: 1-4096 bytes without control characters.
    pub token: String,
    /// App identifier (e.g. the bundle ID): 1-255 characters of
    /// `A-Z a-z 0-9 . - _ :`.
    pub app_id: Option<String>,
    /// Platform sandbox flag (e.g. the APNs development environment).
    pub sandbox: Option<bool>,
    /// Web Push `p256dh` key: 1-256 characters of base64url.
    pub p256dh: Option<String>,
    /// Web Push `auth` secret: 1-256 characters of base64url.
    pub auth: Option<String>,
}

impl std::fmt::Debug for PushRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRegistration")
            .field("provider", &self.provider)
            .field("app_id", &self.app_id)
            .field("sandbox", &self.sandbox)
            .finish_non_exhaustive()
    }
}

/// What a notification is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NotificationKind {
    /// A text or media message (also the silent edit or delete of one).
    Message,
    /// A reaction to a message.
    Reaction,
    /// The user was added to a chat.
    Invite,
    /// A member was added to or removed from a chat.
    Membership,
    /// Content unknown: show `body` ("New message").
    Generic,
}

/// What to show for a push, from `GimClient::process_push`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NotificationContent {
    pub chat_id: Option<String>,
    /// Group name, or the other user's name for a direct chat.
    pub chat_title: Option<String>,
    pub sender_user_id: Option<String>,
    pub sender_display_name: Option<String>,
    /// Text preview: the text, the media caption, "Photo" or
    /// "File: <name>"; "reacted <emoji>" for a reaction; "New message" for
    /// generic content.
    pub body: String,
    pub message_id: Option<String>,
    /// The push's `collapse_id`: use it as the notification identifier, so
    /// the same message pushed by several hubs shows once.
    pub collapse_id: Option<String>,
    pub kind: NotificationKind,
    /// `false`: show nothing (own messages, edits, deletes, receipts,
    /// membership changes, already read).
    pub should_display: bool,
    /// Unix milliseconds: when the message was sent, or now.
    pub timestamp: u64,
}
