//! Records and enums shared by the client, chat list and timeline APIs.
//! All ids are strings; all timestamps are Unix epoch milliseconds.

/// The signed-in account on this device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Session {
    pub user_id: String,
    pub device_id: String,
    pub handle: String,
    pub display_name: String,
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
    /// Delivered to at least one recipient device.
    Delivered,
    /// Read by at least one recipient.
    Read,
    /// Gave up; `retry_send` or `cancel_send`.
    Failed { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    Offline,
    Connecting,
    Connected,
    /// Connected and catching up on missed events.
    Syncing,
}
