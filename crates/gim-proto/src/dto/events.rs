use gim_common::{DeviceId, GroupId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ErrorBody, Message};

/// WebSocket close code after a `cursor_expired` error frame.
pub const STREAM_CLOSE_CURSOR_EXPIRED: u16 = 4410;
/// WebSocket close code for an invalid or missing token.
pub const STREAM_CLOSE_UNAUTHORIZED: u16 = 4401;

/// `Event`: one entry of the calling device's event stream.
///
/// The `type` discriminator selects [`EventData`]; a type this build does not
/// know becomes [`EventData::Unknown`] instead of failing, so newer servers
/// never break the stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawEvent", into = "RawEvent")]
pub struct Event {
    /// Global event cursor (event id).
    pub cursor: u64,
    /// Unix milliseconds.
    pub created_at: i64,
    pub data: EventData,
}

/// Typed `data` of an [`Event`], keyed by its `type`.
#[derive(Debug, Clone, PartialEq)]
pub enum EventData {
    /// `message` (`MessageEvent`).
    Message(Message),
    /// `group.member_added` (`MemberAddedEvent`).
    MemberAdded(MembershipChange),
    /// `group.member_removed` (`MemberRemovedEvent`).
    MemberRemoved(MembershipChange),
    /// `keypackages.low` (`KeyPackagesLowEvent`).
    KeyPackagesLow(KeyPackagesLow),
    /// Any other `type`, kept verbatim.
    Unknown { event_type: String, data: Value },
}

impl EventData {
    const MESSAGE: &'static str = "message";
    const MEMBER_ADDED: &'static str = "group.member_added";
    const MEMBER_REMOVED: &'static str = "group.member_removed";
    const KEY_PACKAGES_LOW: &'static str = "keypackages.low";

    /// The wire `type` of this event.
    pub fn event_type(&self) -> &str {
        match self {
            Self::Message(_) => Self::MESSAGE,
            Self::MemberAdded(_) => Self::MEMBER_ADDED,
            Self::MemberRemoved(_) => Self::MEMBER_REMOVED,
            Self::KeyPackagesLow(_) => Self::KEY_PACKAGES_LOW,
            Self::Unknown { event_type, .. } => event_type,
        }
    }
}

/// `MembershipChange`: data of the `group.member_*` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipChange {
    pub group_id: GroupId,
    pub device_ids: Vec<DeviceId>,
    pub by_device_id: DeviceId,
}

/// Data of `keypackages.low`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackagesLow {
    /// Remaining one-time key packages of the receiving device.
    pub available: u64,
}

#[derive(Serialize, Deserialize)]
struct RawEvent {
    cursor: u64,
    created_at: i64,
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    data: Value,
}

impl TryFrom<RawEvent> for Event {
    type Error = serde_json::Error;

    fn try_from(raw: RawEvent) -> Result<Self, Self::Error> {
        let data = match raw.event_type.as_str() {
            EventData::MESSAGE => EventData::Message(serde_json::from_value(raw.data)?),
            EventData::MEMBER_ADDED => EventData::MemberAdded(serde_json::from_value(raw.data)?),
            EventData::MEMBER_REMOVED => {
                EventData::MemberRemoved(serde_json::from_value(raw.data)?)
            }
            EventData::KEY_PACKAGES_LOW => {
                EventData::KeyPackagesLow(serde_json::from_value(raw.data)?)
            }
            _ => EventData::Unknown {
                event_type: raw.event_type,
                data: raw.data,
            },
        };
        Ok(Self {
            cursor: raw.cursor,
            created_at: raw.created_at,
            data,
        })
    }
}

impl From<Event> for RawEvent {
    fn from(event: Event) -> Self {
        let event_type = event.data.event_type().to_owned();
        // Serializing these plain structs into a `Value` cannot fail.
        let data = match event.data {
            EventData::Message(data) => serde_json::to_value(data),
            EventData::MemberAdded(data) | EventData::MemberRemoved(data) => {
                serde_json::to_value(data)
            }
            EventData::KeyPackagesLow(data) => serde_json::to_value(data),
            EventData::Unknown { data, .. } => Ok(data),
        }
        .expect("event data serializes to JSON");
        Self {
            cursor: event.cursor,
            created_at: event.created_at,
            event_type,
            data,
        }
    }
}

/// `EventList`: `GET /v1/events`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventList {
    pub events: Vec<Event>,
    /// Pass as `cursor` in the next request.
    pub next_cursor: u64,
}

/// Query of `GET /v1/events`; absent fields use the server defaults
/// (`cursor=0`, `wait=0`, `limit=100`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsQuery {
    /// Last cursor the client has processed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    /// Long-poll timeout in seconds (0-30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<u32>,
    /// 1-500.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Query of the `/v1/stream` WebSocket upgrade.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamQuery {
    /// Last cursor the client has processed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    /// Bearer token, where the `Authorization` header cannot be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// A server-to-client JSON text frame of `/v1/stream`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamFrame {
    /// One event, in ascending `cursor` order.
    Event { event: Event },
    /// `cursor_expired`, followed by close code
    /// [`STREAM_CLOSE_CURSOR_EXPIRED`]; resync, then reconnect from `cursor`.
    Error {
        error: ErrorBody,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<u64>,
    },
    /// A frame type this build does not know; ignore it.
    #[serde(other)]
    Unknown,
}
