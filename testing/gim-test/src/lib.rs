//! Test fixtures and helpers, including [`FakeDeliveryService`]: an
//! in-memory stand-in for gim-server message delivery.

#![forbid(unsafe_code)]

mod delivery;

pub use delivery::{Delivered, DeliveryError, FakeDeliveryService, MessageKind, OutgoingMessage};
