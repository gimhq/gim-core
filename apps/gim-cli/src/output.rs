//! Human and `--json` output.
//!
//! With `--json` every command prints exactly one JSON object on stdout.
//! Ids are strings, timestamps are integer milliseconds since the Unix
//! epoch, and absent values are `null`. Shapes (stable):
//!
//! - error: `{"error": {"code": "other"|"usage"|"timeout"|"not_found"|"server",
//!   "message": str}}`
//! - `register`: `{"user_id", "device_id", "handle", "server"}`
//! - `whoami`: `{"user_id", "device_id", "handle", "display_name", "server"}`
//!   (`handle` / `display_name` may be `null`)
//! - `users search`: `{"users": [User]}`, User = `{"user_id", "handle",
//!   "display_name"}`
//! - `chats list`: `{"chats": [ChatSummary]}`, ChatSummary =
//!   `{"id", "kind": "direct"|"group", "name": str|null, "peer_handle": str|null,
//!   "members": int (distinct users), "unread_count": int,
//!   "last_message": LastMessage|null, "membership": "joined"|"left"}`,
//!   LastMessage = `{"id", "sender_user_id", "sent_at_ms", "summary": str}`.
//!   `name` of a direct chat is the peer's display name (else handle, else
//!   user id); `peer_handle` is set for direct chats only.
//! - `dm`, `group create|add|remove|rename|leave`: `{"chat_id"}`
//! - `members`: `{"members": [Member]}`, Member = `{"user_id",
//!   "handle": str|null, "display_name": str|null, "devices": [str]}`
//! - `send`, `send-image`, `send-file`, `react`, `edit`, `delete`:
//!   `{"message_id", "chat_id", "send_state": SendState|null}` (the id of
//!   the new message: the reaction, edit or delete event for those
//!   commands; `send_state` is that of the sent message itself and `null`
//!   for events)
//! - `read`, `typing`: `{"chat_id"}`
//! - `history`: `{"messages": [Message]}`, oldest first, Message =
//!   `{"id", "chat_id", "seq": int|null, "sender": {"user_id", "device_id",
//!   "handle": str|null}, "sent_at_ms", "kind": "text"|"media",
//!   "text": str|null (body or caption), "media": {"mime", "size": int|null,
//!   "name": str|null}|null, "reply_to": str|null, "edited": bool,
//!   "deleted": bool, "reactions": {handle-or-user-id: [emoji]},
//!   "send_state": SendState|null, "receipts": {handle-or-user-id:
//!   "delivered"|"read"}}`. SendState = `"pending"|"sent"|"delivered"|
//!   "read"|"failed"` (own messages only).
//! - `download`: `{"path", "size"}`

use std::collections::BTreeMap;
use std::path::Path;

use gim_base::model::{Chat, ChatKind, Membership, Message, MessageContent, SendState, UserInfo};
use gim_common::UserId;
use serde::Serialize;

use crate::error::CliError;
use crate::resolve::{peer_of, users_of, Directory};

/// What a command prints.
#[derive(Debug)]
pub struct Output {
    pub json: serde_json::Value,
    pub human: String,
}

impl Output {
    pub fn new(value: &impl Serialize, human: impl Into<String>) -> Self {
        Self {
            json: serde_json::to_value(value).expect("output serializes"),
            human: human.into(),
        }
    }

    pub fn print(&self, json: bool) {
        if json {
            println!("{}", self.json);
        } else if !self.human.is_empty() {
            println!("{}", self.human);
        }
    }
}

pub fn print_error(err: &CliError, json: bool) {
    if json {
        let value = serde_json::json!({
            "error": {"code": err.kind.name(), "message": err.message},
        });
        println!("{value}");
    } else {
        eprintln!("gim: {}", err.message);
    }
}

#[derive(Debug, Serialize)]
pub struct RegisterOut {
    pub user_id: String,
    pub device_id: String,
    pub handle: String,
    pub server: String,
}

#[derive(Debug, Serialize)]
pub struct WhoamiOut {
    pub user_id: String,
    pub device_id: String,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub server: String,
}

#[derive(Debug, Serialize)]
pub struct UserOut {
    pub user_id: String,
    pub handle: String,
    pub display_name: String,
}

impl From<&UserInfo> for UserOut {
    fn from(user: &UserInfo) -> Self {
        Self {
            user_id: user.user_id.to_string(),
            handle: user.handle.clone(),
            display_name: user.display_name.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UsersOut {
    pub users: Vec<UserOut>,
}

#[derive(Debug, Serialize)]
pub struct ChatSummaryOut {
    pub id: String,
    pub kind: &'static str,
    pub name: Option<String>,
    pub peer_handle: Option<String>,
    pub members: usize,
    pub unread_count: u32,
    pub last_message: Option<LastMessageOut>,
    pub membership: &'static str,
}

#[derive(Debug, Serialize)]
pub struct LastMessageOut {
    pub id: String,
    pub sender_user_id: String,
    pub sent_at_ms: u64,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct ChatsOut {
    pub chats: Vec<ChatSummaryOut>,
}

#[derive(Debug, Serialize)]
pub struct ChatIdOut {
    pub chat_id: String,
}

#[derive(Debug, Serialize)]
pub struct MemberOut {
    pub user_id: String,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub devices: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MembersOut {
    pub members: Vec<MemberOut>,
}

#[derive(Debug, Serialize)]
pub struct SentOut {
    pub message_id: String,
    pub chat_id: String,
    pub send_state: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SenderOut {
    pub user_id: String,
    pub device_id: String,
    pub handle: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MediaOut {
    pub mime: String,
    pub size: Option<u64>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MessageOut {
    pub id: String,
    pub chat_id: String,
    pub seq: Option<u64>,
    pub sender: SenderOut,
    pub sent_at_ms: u64,
    pub kind: &'static str,
    pub text: Option<String>,
    pub media: Option<MediaOut>,
    pub reply_to: Option<String>,
    pub edited: bool,
    pub deleted: bool,
    pub reactions: BTreeMap<String, Vec<String>>,
    pub send_state: Option<&'static str>,
    pub receipts: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct MessagesOut {
    pub messages: Vec<MessageOut>,
}

#[derive(Debug, Serialize)]
pub struct DownloadOut {
    pub path: String,
    pub size: u64,
}

pub fn kind_name(kind: ChatKind) -> &'static str {
    match kind {
        ChatKind::Direct => "direct",
        ChatKind::Group => "group",
    }
}

pub fn membership_name(membership: Membership) -> &'static str {
    match membership {
        Membership::Joined => "joined",
        Membership::Left => "left",
    }
}

pub fn send_state_name(state: SendState) -> &'static str {
    match state {
        SendState::Pending => "pending",
        SendState::Sent => "sent",
        SendState::Delivered => "delivered",
        SendState::Read => "read",
        SendState::Failed => "failed",
    }
}

/// Snake-case serde name of a unit enum (e.g. a receipt kind).
fn serde_name(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        other => format!("{other:?}"),
    }
}

/// Text body or caption of a message.
pub fn text_of(message: &Message) -> Option<&str> {
    match &message.content {
        MessageContent::Text { body } => Some(body),
        MessageContent::Media { caption, .. } => caption.as_deref(),
        MessageContent::PendingMedia(media) => media.caption.as_deref(),
    }
}

/// One-line summary of a message's content.
pub fn summary_of(message: &Message) -> String {
    if message.deleted {
        return "(deleted)".into();
    }
    let media = match &message.content {
        MessageContent::Text { body } => return body.clone(),
        MessageContent::Media { media, .. } => media.mime.as_str(),
        MessageContent::PendingMedia(media) => media.mime.as_str(),
    };
    match text_of(message) {
        Some(caption) => format!("[{media}] {caption}"),
        None => format!("[{media}]"),
    }
}

pub fn chat_summary(
    chat: &Chat,
    me: &UserId,
    directory: &Directory,
    last: Option<&Message>,
) -> ChatSummaryOut {
    let peer = (chat.kind == ChatKind::Direct)
        .then(|| peer_of(chat, me))
        .flatten();
    let name = match peer {
        Some(peer) => Some(
            directory
                .get(peer)
                .map(|u| u.display_name.clone())
                .filter(|n| !n.is_empty())
                .or_else(|| {
                    chat.members
                        .iter()
                        .find(|m| &m.device.user_id == peer)
                        .and_then(|m| m.display_name.clone())
                })
                .unwrap_or_else(|| directory.label(peer)),
        ),
        None => chat.name.clone(),
    };
    ChatSummaryOut {
        id: chat.group_id.to_string(),
        kind: kind_name(chat.kind),
        name,
        peer_handle: peer.and_then(|p| directory.handle(p)).map(str::to_string),
        members: users_of(chat).len(),
        unread_count: chat.unread_count,
        last_message: last.map(|m| LastMessageOut {
            id: m.message_id.to_string(),
            sender_user_id: m.sender.user_id.to_string(),
            sent_at_ms: m.sent_at_ms,
            summary: summary_of(m),
        }),
        membership: membership_name(chat.membership),
    }
}

pub fn message_out(message: &Message, directory: &Directory) -> MessageOut {
    let media = match &message.content {
        MessageContent::Text { .. } => None,
        MessageContent::Media { media, .. } => Some(MediaOut {
            mime: media.mime.clone(),
            size: Some(media.size),
            name: media.file_name.clone(),
        }),
        MessageContent::PendingMedia(media) => Some(MediaOut {
            mime: media.mime.clone(),
            size: None,
            name: Path::new(&media.local_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned()),
        }),
    };
    let reactions = message
        .reactions
        .iter()
        .map(|(user, emojis)| (directory.label(user), emojis.iter().cloned().collect()))
        .collect();
    // Best receipt per user over their devices: read beats delivered.
    let mut receipts: BTreeMap<String, String> = BTreeMap::new();
    for (device, kind) in &message.receipts {
        let kind = serde_name(kind);
        let entry = receipts
            .entry(directory.label(&device.user_id))
            .or_default();
        if entry.as_str() != "read" {
            *entry = kind;
        }
    }
    MessageOut {
        id: message.message_id.to_string(),
        chat_id: message.group_id.to_string(),
        seq: message.seq,
        sender: SenderOut {
            user_id: message.sender.user_id.to_string(),
            device_id: message.sender.device_id.to_string(),
            handle: directory
                .handle(&message.sender.user_id)
                .map(str::to_string),
        },
        sent_at_ms: message.sent_at_ms,
        kind: if media.is_some() { "media" } else { "text" },
        text: text_of(message).map(str::to_string),
        media,
        reply_to: message.reply_to.as_ref().map(ToString::to_string),
        edited: message.edited,
        deleted: message.deleted,
        reactions,
        send_state: message.send_state.map(send_state_name),
        receipts,
    }
}

/// One history line: `[seq] id handle: text (flags)`.
pub fn message_line(m: &MessageOut) -> String {
    let seq = m.seq.map_or_else(|| "-".to_string(), |s| s.to_string());
    let who = m.sender.handle.as_deref().unwrap_or(&m.sender.user_id);
    let mut line = format!("[{seq}] {} {who}:", m.id);
    if let Some(media) = &m.media {
        line.push_str(&format!(" [{}", media.mime));
        if let Some(name) = &media.name {
            line.push_str(&format!(" {name}"));
        }
        line.push(']');
    }
    if let Some(text) = &m.text {
        line.push_str(&format!(" {text}"));
    }
    if let Some(reply) = &m.reply_to {
        line.push_str(&format!(" (reply to {reply})"));
    }
    if m.edited {
        line.push_str(" (edited)");
    }
    if m.deleted {
        line.push_str(" (deleted)");
    }
    for (user, emojis) in &m.reactions {
        line.push_str(&format!(" {user}:{}", emojis.join("")));
    }
    if let Some(state) = m.send_state {
        line.push_str(&format!(" <{state}>"));
    }
    line
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use gim_common::{DeviceRef, GroupId, MessageId};

    use super::*;

    fn message() -> Message {
        let bob = UserId::new("u-bob").unwrap();
        let carol = UserId::new("u-carol").unwrap();
        Message {
            message_id: MessageId::new("m-2").unwrap(),
            group_id: GroupId::new("g-1").unwrap(),
            seq: Some(7),
            sender: DeviceRef::parse("u-alice", "d-a1").unwrap(),
            sent_at_ms: 1_760_000_000_123,
            content: MessageContent::Text {
                body: "Anchored in Hvar".into(),
            },
            reply_to: Some(MessageId::new("m-1").unwrap()),
            edited: true,
            deleted: false,
            reactions: BTreeMap::from([
                (bob, BTreeSet::from(["⛵".to_string(), "👍".to_string()])),
                (carol, BTreeSet::from(["👍".to_string()])),
            ]),
            send_state: Some(SendState::Sent),
            receipts: BTreeMap::new(),
        }
    }

    #[test]
    fn message_json_shape_is_stable() {
        let directory = Directory::from_users([
            UserInfo {
                user_id: UserId::new("u-alice").unwrap(),
                handle: "alice".into(),
                display_name: "Alice".into(),
            },
            UserInfo {
                user_id: UserId::new("u-bob").unwrap(),
                handle: "bob".into(),
                display_name: "Bob".into(),
            },
        ]);
        let out = message_out(&message(), &directory);
        // Field order is the struct's.
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            concat!(
                r#"{"id":"m-2","chat_id":"g-1","seq":7,"#,
                r#""sender":{"user_id":"u-alice","device_id":"d-a1","handle":"alice"},"#,
                r#""sent_at_ms":1760000000123,"kind":"text","text":"Anchored in Hvar","#,
                r#""media":null,"reply_to":"m-1","edited":true,"deleted":false,"#,
                r#""reactions":{"bob":["⛵","👍"],"u-carol":["👍"]},"#,
                r#""send_state":"sent","receipts":{}}"#
            )
        );
        assert_eq!(
            message_line(&out),
            "[7] m-2 alice: Anchored in Hvar (reply to m-1) (edited) bob:⛵👍 u-carol:👍 <sent>"
        );
    }

    #[test]
    fn deleted_message_summary() {
        let mut m = message();
        assert_eq!(summary_of(&m), "Anchored in Hvar");
        m.deleted = true;
        assert_eq!(summary_of(&m), "(deleted)");
    }
}
