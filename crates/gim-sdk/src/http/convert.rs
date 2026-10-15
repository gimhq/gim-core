//! gim-proto v2 DTO ↔ domain type conversions. Ids from the hub are parsed
//! at this boundary (gim-identity formats for users and devices); events
//! that do not parse are skipped.

use gim_base::model::{ChatKind, GroupMessage, IncomingEvent, MessageKind};
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use gim_identity::{parse_device_id, parse_user_id};
use gim_proto::v2;

use crate::transport::{GroupInfo, HubEvent, TransportError};

fn invalid(what: &str, err: impl std::fmt::Display) -> TransportError {
    TransportError::Server(format!("invalid {what} from the hub: {err}"))
}

pub(super) fn user_id(text: &str) -> Result<UserId, TransportError> {
    parse_user_id(text).map_err(|e| invalid("user id", e))
}

pub(super) fn device(user_id: &str, device_id: &str) -> Result<DeviceRef, TransportError> {
    Ok(DeviceRef::new(
        self::user_id(user_id)?,
        parse_device_id(device_id).map_err(|e| invalid("device id", e))?,
    ))
}

pub(super) fn group_id(gid: &str) -> Result<GroupId, TransportError> {
    GroupId::new(gid).map_err(|e| invalid("group id", e))
}

pub(super) fn group_kind(kind: ChatKind) -> v2::GroupKind {
    match kind {
        ChatKind::Direct => v2::GroupKind::Direct,
        ChatKind::Group => v2::GroupKind::Group,
    }
}

pub(super) fn member(device: &DeviceRef) -> v2::GroupMember {
    v2::GroupMember {
        user_id: device.user_id.to_string(),
        device_id: device.device_id.to_string(),
    }
}

/// `None` for unknown kinds: they are skipped, and their seq is then
/// confirmed as a hole by the gap backfill. Proposals are handshakes like
/// Commits (gim-crypto tells them apart from the MLS framing). The hub's
/// `message_id` is not used yet (cross-hub dedup).
pub(super) fn message(message: v2::Message) -> Result<Option<GroupMessage>, TransportError> {
    let kind = match message.kind {
        v2::MessageKind::Commit | v2::MessageKind::Proposal => MessageKind::Commit,
        v2::MessageKind::Application => MessageKind::Application,
        v2::MessageKind::Unknown => {
            tracing::debug!(gid = %message.gid, seq = message.seq, "skipping a message of an unknown kind");
            return Ok(None);
        }
    };
    Ok(Some(GroupMessage {
        group_id: group_id(&message.gid)?,
        seq: message.seq,
        sender: device(&message.sender_user_id, &message.sender_device_id)?,
        kind,
        payload: message.mls_message,
        client_id: Some(ClientId::new(message.client_id).map_err(|e| invalid("client id", e))?),
    }))
}

/// A Welcome as gim-base takes it: a message at the seq of its Commit.
pub(super) fn welcome(welcome: v2::Welcome) -> Result<GroupMessage, TransportError> {
    Ok(GroupMessage {
        group_id: group_id(&welcome.gid)?,
        seq: welcome.seq,
        sender: device(&welcome.sender_user_id, &welcome.sender_device_id)?,
        kind: MessageKind::Welcome,
        payload: welcome.welcome,
        client_id: None,
    })
}

pub(super) fn group(group: v2::Group) -> Result<GroupInfo, TransportError> {
    Ok(GroupInfo {
        group_id: group_id(&group.gid)?,
        kind: match group.kind {
            v2::GroupKind::Direct => ChatKind::Direct,
            v2::GroupKind::Group => ChatKind::Group,
        },
        epoch: group.epoch,
        last_seq: group.last_seq,
        members: group
            .members
            .iter()
            .map(|m| device(&m.user_id, &m.device_id))
            .collect::<Result<_, _>>()?,
    })
}

fn membership(
    change: v2::MembershipChange,
    event: impl Fn(GroupId, DeviceRef) -> IncomingEvent,
) -> Result<Vec<HubEvent>, TransportError> {
    let group_id = group_id(&change.gid)?;
    change
        .device_ids
        .iter()
        .map(|device_id| {
            let device = device(&change.user_id, device_id)?;
            Ok(HubEvent::Group(event(group_id.clone(), device)))
        })
        .collect()
}

/// Maps a stream event; unknown types and events that do not parse are
/// skipped.
pub(super) fn event(event: v2::Event) -> Vec<HubEvent> {
    let cursor = event.cursor;
    let converted = match event.data {
        v2::EventData::Message(m) => message(m).map(|m| {
            m.map(|m| HubEvent::Group(IncomingEvent::Message(m)))
                .into_iter()
                .collect()
        }),
        v2::EventData::MemberAdded(change) => membership(change, |group_id, device| {
            IncomingEvent::MemberAdded { group_id, device }
        }),
        v2::EventData::MemberRemoved(change) => membership(change, |group_id, device| {
            IncomingEvent::MemberRemoved { group_id, device }
        }),
        v2::EventData::Welcome(w) => {
            welcome(w).map(|m| vec![HubEvent::Group(IncomingEvent::Message(m))])
        }
        v2::EventData::KeyPackagesLow(_) => {
            Ok(vec![HubEvent::Group(IncomingEvent::KeyPackagesLow)])
        }
        v2::EventData::DeviceListUpdated(list) => user_id(&list.user_id).map(|user_id| {
            vec![HubEvent::DeviceListUpdated {
                user_id,
                device_list: list.device_list,
            }]
        }),
        v2::EventData::Unknown { event_type, .. } => {
            tracing::debug!(%event_type, cursor, "skipping unknown event");
            Ok(vec![])
        }
    };
    converted.unwrap_or_else(|err| {
        tracing::warn!(cursor, error = %err, "skipping an invalid event");
        vec![]
    })
}
