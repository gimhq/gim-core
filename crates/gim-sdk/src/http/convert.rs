//! gim-proto DTO ↔ domain type conversions.

use gim_base::model::{ChatKind, GroupMessage, MessageKind};
use gim_common::DeviceRef;
use gim_proto::dto;

use crate::transport::GroupInfo;

pub(super) fn group_kind(kind: ChatKind) -> dto::GroupKind {
    match kind {
        ChatKind::Direct => dto::GroupKind::Direct,
        ChatKind::Group => dto::GroupKind::Group,
    }
}

pub(super) fn message_kind(kind: MessageKind) -> dto::MessageKind {
    match kind {
        MessageKind::Commit => dto::MessageKind::Commit,
        MessageKind::Welcome => dto::MessageKind::Welcome,
        MessageKind::Application => dto::MessageKind::Application,
    }
}

pub(super) fn message(message: dto::Message) -> GroupMessage {
    GroupMessage {
        group_id: message.group_id,
        seq: message.seq,
        sender: DeviceRef::new(message.sender_user_id, message.sender_device_id),
        kind: match message.kind {
            dto::MessageKind::Commit => MessageKind::Commit,
            dto::MessageKind::Welcome => MessageKind::Welcome,
            dto::MessageKind::Application => MessageKind::Application,
        },
        payload: message.payload,
        client_id: Some(message.client_id),
    }
}

pub(super) fn group(group: dto::Group) -> GroupInfo {
    GroupInfo {
        group_id: group.group_id,
        kind: match group.kind {
            dto::GroupKind::Direct => ChatKind::Direct,
            dto::GroupKind::Group => ChatKind::Group,
        },
        epoch: group.epoch,
        members: group
            .members
            .into_iter()
            .map(|m| DeviceRef::new(m.user_id, m.device_id))
            .collect(),
    }
}
