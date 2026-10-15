//! Test fixtures and helpers, including [`FakeDeliveryService`]: an
//! in-memory stand-in for gim-server.

#![forbid(unsafe_code)]

mod delivery;

pub use delivery::{
    Delivered, DeliveryError, Event, FakeDeliveryService, GroupInfo, GroupKind, MessageKind,
    OutgoingMessage, Registration, StreamEvent, User, KEY_PACKAGES_LOW_THRESHOLD,
};
