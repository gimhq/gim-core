//! gim-ui domain types to FFI records: typed ids become strings, indices
//! `u32`.

use gim_ui::VectorDiff;

use crate::{
    ChatKind, ChatListDiff, ChatState, ChatSummary, DeviceInfo, HubInfo, HubState, MediaRef,
    MembershipChangeKind, MessageContent, MessageItem, MessagePreview, NotificationContent,
    NotificationKind, PushRegistration, ReactionGroup, ReplyPreview, SendState, TimelineDiff,
    TimelineItem, UserProfile,
};

/// Maps a gim-ui diff onto an FFI diff enum with the same variants.
macro_rules! map_diff {
    ($diff:expr, $ty:ident) => {
        match $diff {
            VectorDiff::Append { values } => $ty::Append {
                values: values.into_iter().map(Into::into).collect(),
            },
            VectorDiff::Clear => $ty::Clear,
            VectorDiff::PushFront { value } => $ty::PushFront {
                value: value.into(),
            },
            VectorDiff::PushBack { value } => $ty::PushBack {
                value: value.into(),
            },
            VectorDiff::PopFront => $ty::PopFront,
            VectorDiff::PopBack => $ty::PopBack,
            VectorDiff::Insert { index, value } => $ty::Insert {
                index: index as u32,
                value: value.into(),
            },
            VectorDiff::Set { index, value } => $ty::Set {
                index: index as u32,
                value: value.into(),
            },
            VectorDiff::Remove { index } => $ty::Remove {
                index: index as u32,
            },
            VectorDiff::Truncate { length } => $ty::Truncate {
                length: length as u32,
            },
            VectorDiff::Reset { values } => $ty::Reset {
                values: values.into_iter().map(Into::into).collect(),
            },
        }
    };
}

impl From<VectorDiff<gim_ui::ChatListItem>> for ChatListDiff {
    fn from(diff: VectorDiff<gim_ui::ChatListItem>) -> Self {
        map_diff!(diff, ChatListDiff)
    }
}

impl From<VectorDiff<gim_ui::TimelineItem>> for TimelineDiff {
    fn from(diff: VectorDiff<gim_ui::TimelineItem>) -> Self {
        map_diff!(diff, TimelineDiff)
    }
}

impl From<gim_ui::UserProfile> for UserProfile {
    fn from(p: gim_ui::UserProfile) -> Self {
        Self {
            user_id: p.user_id.into(),
            handle: p.handle,
            display_name: p.display_name,
        }
    }
}

impl From<gim_base::model::UserInfo> for UserProfile {
    fn from(u: gim_base::model::UserInfo) -> Self {
        Self {
            user_id: u.user_id.into(),
            handle: u.handle,
            display_name: u.display_name,
        }
    }
}

impl From<gim_sdk::DeviceInfo> for DeviceInfo {
    fn from(d: gim_sdk::DeviceInfo) -> Self {
        Self {
            device_id: d.device_id.into(),
            created_at_ms: d.created_at,
            is_current: d.is_current,
            revoked: d.revoked,
        }
    }
}

impl From<gim_ui::ChatKind> for ChatKind {
    fn from(kind: gim_ui::ChatKind) -> Self {
        match kind {
            gim_ui::ChatKind::Direct => Self::Direct,
            gim_ui::ChatKind::Group => Self::Group,
        }
    }
}

impl From<gim_ui::ChatListItem> for ChatSummary {
    fn from(c: gim_ui::ChatListItem) -> Self {
        Self {
            chat_id: c.chat_id.into(),
            kind: c.kind.into(),
            name: c.name,
            avatar: c.avatar.map(Into::into),
            last_message: c.last_message.map(Into::into),
            unread_count: c.unread_count,
            updated_at_ms: c.updated_at_ms,
            member_count: c.member_count,
            state: c.state.into(),
        }
    }
}

impl From<gim_ui::ChatState> for ChatState {
    fn from(state: gim_ui::ChatState) -> Self {
        match state {
            gim_ui::ChatState::Active => Self::Active,
            gim_ui::ChatState::Leaving => Self::Leaving,
            gim_ui::ChatState::Left => Self::Left,
        }
    }
}

impl From<gim_ui::MessagePreview> for MessagePreview {
    fn from(p: gim_ui::MessagePreview) -> Self {
        Self {
            sender_name: p.sender_name,
            text: p.text,
            sent_at_ms: p.sent_at_ms,
            is_own: p.is_own,
        }
    }
}

impl From<gim_ui::TimelineItem> for TimelineItem {
    fn from(item: gim_ui::TimelineItem) -> Self {
        match item {
            gim_ui::TimelineItem::Message(item) => Self::Message { item: item.into() },
            gim_ui::TimelineItem::DateSeparator { day_start_ms } => {
                Self::DateSeparator { day_start_ms }
            }
            gim_ui::TimelineItem::MembershipChange {
                user_name,
                change,
                at_ms,
                user_id,
                actor_user_id,
            } => Self::MembershipChange {
                user_name,
                change: change.into(),
                at_ms,
                user_id: user_id.into(),
                actor_user_id: actor_user_id.map(Into::into),
            },
        }
    }
}

impl From<gim_ui::MembershipChangeKind> for MembershipChangeKind {
    fn from(kind: gim_ui::MembershipChangeKind) -> Self {
        match kind {
            gim_ui::MembershipChangeKind::Added => Self::Added,
            gim_ui::MembershipChangeKind::Removed => Self::Removed,
            gim_ui::MembershipChangeKind::Left => Self::Left,
        }
    }
}

impl From<gim_ui::MessageItem> for MessageItem {
    fn from(m: gim_ui::MessageItem) -> Self {
        Self {
            message_id: m.message_id.into(),
            chat_id: m.chat_id.into(),
            sender: m.sender.into(),
            is_own: m.is_own,
            sent_at_ms: m.sent_at_ms,
            content: m.content.into(),
            reply_to: m.reply_to.map(Into::into),
            reactions: m.reactions.into_iter().map(Into::into).collect(),
            edited: m.edited,
            send_state: m.send_state.map(Into::into),
        }
    }
}

impl From<gim_ui::MessageContent> for MessageContent {
    fn from(content: gim_ui::MessageContent) -> Self {
        match content {
            gim_ui::MessageContent::Text { body } => Self::Text { body },
            gim_ui::MessageContent::Image {
                media,
                width,
                height,
                caption,
            } => Self::Image {
                media: media.into(),
                width,
                height,
                caption,
            },
            gim_ui::MessageContent::File {
                media,
                file_name,
                caption,
            } => Self::File {
                media: media.into(),
                file_name,
                caption,
            },
            gim_ui::MessageContent::Deleted => Self::Deleted,
            gim_ui::MessageContent::Unsupported => Self::Unsupported,
        }
    }
}

impl From<gim_ui::MediaRef> for MediaRef {
    fn from(m: gim_ui::MediaRef) -> Self {
        Self {
            chat_id: m.chat_id.into(),
            // A chat avatar has no message.
            message_id: m.message_id.map(String::from).unwrap_or_default(),
            mime: m.mime,
            size: m.size,
            has_thumbnail: m.has_thumbnail,
        }
    }
}

impl From<gim_ui::ReplyPreview> for ReplyPreview {
    fn from(r: gim_ui::ReplyPreview) -> Self {
        Self {
            message_id: r.message_id.into(),
            sender_name: r.sender_name,
            text: r.text,
        }
    }
}

impl From<gim_ui::ReactionGroup> for ReactionGroup {
    fn from(r: gim_ui::ReactionGroup) -> Self {
        Self {
            emoji: r.emoji,
            count: r.count,
            own: r.own,
        }
    }
}

impl From<gim_ui::SendState> for SendState {
    fn from(state: gim_ui::SendState) -> Self {
        match state {
            gim_ui::SendState::Pending => Self::Pending,
            gim_ui::SendState::Sent => Self::Sent,
            gim_ui::SendState::Delivered => Self::Delivered,
            gim_ui::SendState::Read => Self::Read,
            gim_ui::SendState::Failed { reason } => Self::Failed { reason },
        }
    }
}

impl From<gim_base::model::HubState> for HubState {
    fn from(state: gim_base::model::HubState) -> Self {
        match state {
            gim_base::model::HubState::Unverified => Self::Unverified,
            gim_base::model::HubState::Verified => Self::Verified,
            gim_base::model::HubState::Removed => Self::Removed,
        }
    }
}

/// The hubs in registry order; the first one not removed is the primary.
pub(crate) fn hub_infos(hubs: Vec<gim_sdk::HubStatus>) -> Vec<HubInfo> {
    let primary = hubs
        .iter()
        .find(|h| h.hub.state != gim_base::model::HubState::Removed)
        .map(|h| h.hub.hub_id.clone());
    hubs.into_iter()
        .map(|h| HubInfo {
            is_primary: primary.as_ref() == Some(&h.hub.hub_id),
            hub_id: h.hub.hub_id,
            url: h.hub.url,
            state: h.hub.state.into(),
            priority: h.hub.priority,
            is_home: h.home,
            signed_in: h.signed_in,
        })
        .collect()
}

impl From<PushRegistration> for gim_sdk::PushRegistration {
    fn from(registration: PushRegistration) -> Self {
        Self {
            provider: registration.provider,
            token: registration.token,
            app_id: registration.app_id,
            sandbox: registration.sandbox,
            p256dh: registration.p256dh,
            auth: registration.auth,
        }
    }
}

impl From<gim_sdk::NotificationKind> for NotificationKind {
    fn from(kind: gim_sdk::NotificationKind) -> Self {
        match kind {
            gim_sdk::NotificationKind::Message => Self::Message,
            gim_sdk::NotificationKind::Reaction => Self::Reaction,
            gim_sdk::NotificationKind::Invite => Self::Invite,
            gim_sdk::NotificationKind::Membership => Self::Membership,
            gim_sdk::NotificationKind::Generic => Self::Generic,
        }
    }
}

impl From<gim_sdk::NotificationContent> for NotificationContent {
    fn from(content: gim_sdk::NotificationContent) -> Self {
        Self {
            chat_id: content.chat_id.map(Into::into),
            chat_title: content.chat_title,
            sender_user_id: content.sender_user_id.map(Into::into),
            sender_display_name: content.sender_display_name,
            body: content.body,
            message_id: content.message_id.map(Into::into),
            collapse_id: content.collapse_id,
            kind: content.kind.into(),
            should_display: content.should_display,
            timestamp: content.timestamp_ms,
        }
    }
}
