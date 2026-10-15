//! Plain domain types of the chat list and timeline. Field for field what
//! gim-ffi exposes (`bindings/gim-ffi/src/types.rs`), with typed ids, so
//! the gim-ffi mapping is 1:1.

use std::collections::BTreeMap;

use gim_base::model::{self, Chat, Message};
use gim_base::{StateReader, StoreError};
use gim_common::{GroupId, MessageId, UserId};
use gim_proto::envelope::MediaInfo;

pub use gim_base::model::ChatKind;

/// Public profile of a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    pub user_id: UserId,
    pub handle: String,
    pub display_name: String,
}

/// One row of the chat list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatListItem {
    pub chat_id: GroupId,
    pub kind: ChatKind,
    /// Group name, or the other user's display name for a direct chat.
    pub name: String,
    pub avatar: Option<MediaRef>,
    pub last_message: Option<MessagePreview>,
    pub unread_count: u32,
    pub updated_at_ms: u64,
    /// Distinct users in the chat, this user included.
    pub member_count: u32,
}

/// Last message shown in a chat list row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePreview {
    pub sender_name: String,
    /// Plain-text rendering ("Photo", "File: report.pdf" for media).
    pub text: String,
    pub sent_at_ms: u64,
    pub is_own: bool,
}

/// One row of a chat timeline.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineItem {
    Message(MessageItem),
    /// Inserted before the first item of each local calendar day.
    DateSeparator { day_start_ms: u64 },
    MembershipChange {
        user_name: String,
        change: MembershipChangeKind,
        at_ms: u64,
    },
}

impl TimelineItem {
    pub fn as_message(&self) -> Option<&MessageItem> {
        match self {
            Self::Message(item) => Some(item),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipChangeKind {
    Added,
    Removed,
    Left,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageItem {
    /// Client id of the message; stable from local echo to delivery.
    pub message_id: MessageId,
    pub chat_id: GroupId,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Handle to an encrypted attachment; keys and blob ids stay in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRef {
    pub chat_id: GroupId,
    /// The message carrying the attachment; `None` for a chat avatar.
    pub message_id: Option<MessageId>,
    pub mime: String,
    pub size: u64,
    pub has_thumbnail: bool,
}

/// Quoted message shown above a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyPreview {
    pub message_id: MessageId,
    pub sender_name: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionGroup {
    pub emoji: String,
    pub count: u32,
    /// Whether the signed-in user is among the reactors.
    pub own: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendState {
    /// Queued in the outbox or being uploaded.
    Pending,
    /// Accepted by the server.
    Sent,
    /// Delivered to every recipient device.
    Delivered,
    /// Read by every recipient.
    Read,
    /// Gave up; retry or cancel.
    Failed { reason: String },
}

type StoreResult<T> = Result<T, StoreError>;

/// Profile from the user directory, else the chat member list, else the
/// bare user id.
pub(crate) fn profile<R: StateReader + ?Sized>(
    store: &R,
    chat: Option<&Chat>,
    user_id: &UserId,
) -> StoreResult<UserProfile> {
    if let Some(user) = store.user(user_id)? {
        return Ok(UserProfile {
            user_id: user.user_id,
            handle: user.handle,
            display_name: user.display_name,
        });
    }
    let member_name = chat.and_then(|chat| {
        chat.members
            .iter()
            .filter(|m| &m.device.user_id == user_id)
            .find_map(|m| m.display_name.clone())
    });
    Ok(UserProfile {
        user_id: user_id.clone(),
        handle: user_id.to_string(),
        display_name: member_name.unwrap_or_else(|| user_id.to_string()),
    })
}

pub(crate) fn chat_list_item<R: StateReader + ?Sized>(
    store: &R,
    own: &UserId,
    chat: &Chat,
) -> StoreResult<ChatListItem> {
    let mut users: Vec<&UserId> = chat.members.iter().map(|m| &m.device.user_id).collect();
    users.sort();
    users.dedup();
    let mut others = Vec::new();
    for user_id in users.iter().filter(|u| **u != own) {
        others.push(profile(store, Some(chat), user_id)?.display_name);
    }
    let name = match (chat.kind, &chat.name) {
        (ChatKind::Group, Some(name)) => name.clone(),
        (ChatKind::Direct, _) if !others.is_empty() => others[0].clone(),
        (_, Some(name)) => name.clone(),
        (_, None) => others.join(", "),
    };
    let last_message = match &chat.last_message_id {
        Some(id) => match store.message(id)? {
            Some(message) => Some(MessagePreview {
                sender_name: profile(store, Some(chat), &message.sender.user_id)?.display_name,
                text: preview_text(&message),
                sent_at_ms: message.sent_at_ms,
                is_own: &message.sender.user_id == own,
            }),
            None => None,
        },
        None => None,
    };
    Ok(ChatListItem {
        chat_id: chat.group_id.clone(),
        kind: chat.kind,
        name,
        avatar: chat
            .avatar
            .as_ref()
            .map(|media| media_ref(&chat.group_id, None, media)),
        last_message,
        unread_count: chat.unread_count,
        updated_at_ms: chat.updated_at_ms,
        member_count: users.len() as u32,
    })
}

/// Plain-text rendering of a message for previews.
pub(crate) fn preview_text(message: &Message) -> String {
    if message.deleted {
        return "Message deleted".to_string();
    }
    let media_text = |mime: &str, file_name: Option<&str>, caption: Option<&str>| {
        if let Some(caption) = caption.filter(|c| !c.is_empty()) {
            caption.to_string()
        } else if mime.starts_with("image/") {
            "Photo".to_string()
        } else {
            match file_name {
                Some(name) => format!("File: {name}"),
                None => "File".to_string(),
            }
        }
    };
    match &message.content {
        model::MessageContent::Text { body } => body.clone(),
        model::MessageContent::Media { media, caption } => media_text(
            &media.mime,
            media.file_name.as_deref(),
            caption.as_deref(),
        ),
        model::MessageContent::PendingMedia(pending) => {
            let file_name = std::path::Path::new(&pending.local_path)
                .file_name()
                .and_then(|n| n.to_str());
            media_text(&pending.mime, file_name, pending.caption.as_deref())
        }
    }
}

pub(crate) fn message_content(message: &Message) -> MessageContent {
    if message.deleted {
        return MessageContent::Deleted;
    }
    let reference = |mime: &str, size: u64, has_thumbnail: bool| MediaRef {
        chat_id: message.group_id.clone(),
        message_id: Some(message.message_id.clone()),
        mime: mime.to_string(),
        size,
        has_thumbnail,
    };
    match &message.content {
        model::MessageContent::Text { body } => MessageContent::Text { body: body.clone() },
        model::MessageContent::Media { media, caption } => {
            let media_ref = media_ref(&message.group_id, Some(&message.message_id), media);
            if media.mime.starts_with("image/") {
                MessageContent::Image {
                    media: media_ref,
                    width: media.width,
                    height: media.height,
                    caption: caption.clone(),
                }
            } else {
                MessageContent::File {
                    media: media_ref,
                    file_name: media.file_name.clone(),
                    caption: caption.clone(),
                }
            }
        }
        // Not uploaded yet: size and thumbnail are unknown.
        model::MessageContent::PendingMedia(pending) => {
            let media = reference(&pending.mime, 0, false);
            if pending.mime.starts_with("image/") {
                MessageContent::Image {
                    media,
                    width: None,
                    height: None,
                    caption: pending.caption.clone(),
                }
            } else {
                MessageContent::File {
                    media,
                    file_name: std::path::Path::new(&pending.local_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(str::to_string),
                    caption: pending.caption.clone(),
                }
            }
        }
    }
}

fn media_ref(chat_id: &GroupId, message_id: Option<&MessageId>, media: &MediaInfo) -> MediaRef {
    MediaRef {
        chat_id: chat_id.clone(),
        message_id: message_id.cloned(),
        mime: media.mime.clone(),
        size: media.size,
        has_thumbnail: media.thumbnail.is_some(),
    }
}

/// Reactions grouped by emoji, in emoji order.
pub(crate) fn reaction_groups(message: &Message, own: &UserId) -> Vec<ReactionGroup> {
    let mut groups: BTreeMap<&str, ReactionGroup> = BTreeMap::new();
    for (user_id, emojis) in &message.reactions {
        for emoji in emojis {
            let group = groups.entry(emoji).or_insert_with(|| ReactionGroup {
                emoji: emoji.clone(),
                count: 0,
                own: false,
            });
            group.count += 1;
            group.own |= user_id == own;
        }
    }
    groups.into_values().collect()
}

/// The UI send state; a failure carries the outbox error.
pub(crate) fn send_state<R: StateReader + ?Sized>(
    store: &R,
    message: &Message,
) -> StoreResult<Option<SendState>> {
    Ok(match message.send_state {
        None => None,
        Some(model::SendState::Pending) => Some(SendState::Pending),
        Some(model::SendState::Sent) => Some(SendState::Sent),
        Some(model::SendState::Delivered) => Some(SendState::Delivered),
        Some(model::SendState::Read) => Some(SendState::Read),
        Some(model::SendState::Failed) => Some(SendState::Failed {
            reason: store
                .outbox_entry(&message.message_id)?
                .and_then(|entry| entry.last_error)
                .unwrap_or_default(),
        }),
    })
}
