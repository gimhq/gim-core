//! gim-server REST and stream DTOs.
//!
//! Source contract: `crates/gim-proto/openapi.json`, a verbatim copy of
//! `openapi.json` at gim-server commit `8333ca2`. Field names match the spec
//! exactly; binary values travel as standard base64 and are decoded into
//! `Vec<u8>`. Timestamps are Unix milliseconds.
//!
//! Every schema in `components.schemas` has a type here:
//!
//! | Schema | Type |
//! |---|---|
//! | `Health` | [`Health`] |
//! | `RegisterDeviceRequest` / `RegisterDeviceResponse` | [`RegisterDeviceRequest`] / [`RegisterDeviceResponse`] |
//! | `Me`, `User`, `UserDevices`, `Device` | [`Me`], [`User`], [`UserDevices`], [`Device`] |
//! | `UploadKeyPackagesRequest`, `KeyPackageCount` | [`UploadKeyPackagesRequest`], [`KeyPackageCount`] |
//! | `ClaimKeyPackagesRequest` / `ClaimKeyPackagesResponse`, `ClaimedKeyPackage` | [`ClaimKeyPackagesRequest`] / [`ClaimKeyPackagesResponse`], [`ClaimedKeyPackage`] |
//! | `Group`, `GroupKind`, `GroupMember`, `GroupList` | [`Group`], [`GroupKind`], [`GroupMember`], [`GroupList`] |
//! | `CreateGroupRequest`, `AddMembersRequest` | [`CreateGroupRequest`], [`AddMembersRequest`] |
//! | `Message`, `MessageKind`, `MessageList`, `SendMessageRequest` | [`Message`], [`MessageKind`], [`MessageList`], [`SendMessageRequest`] |
//! | `Event`, `EventList` | [`Event`], [`EventList`] |
//! | `MessageEvent`, `MemberAddedEvent`, `MemberRemovedEvent`, `KeyPackagesLowEvent` | [`EventData`] variants |
//! | `MembershipChange` | [`MembershipChange`] |
//! | `Error`, `StaleEpochError`, `CursorExpiredError` | [`ErrorResponse`], [`StaleEpochError`], [`CursorExpiredError`] |
//! | `BlobCreated` | [`BlobCreated`] |
//!
//! The `/v1/stream` WebSocket frames (described in prose, not as a schema)
//! are [`StreamFrame`]. Blob bodies are raw `application/octet-stream`
//! bytes and have no DTO.

pub mod base64;
mod blobs;
mod devices;
mod error;
mod events;
mod groups;
mod keypackages;
mod messages;
pub mod paths;

pub use blobs::BlobCreated;
pub use devices::{
    Device, Health, HealthStatus, Me, RegisterDeviceRequest, RegisterDeviceResponse, User,
    UserDevices, UsersQuery,
};
pub use error::{
    CursorExpiredError, ErrorBody, ErrorResponse, StaleEpochError, CURSOR_EXPIRED, STALE_EPOCH,
};
pub use events::{
    Event, EventData, EventList, EventsQuery, KeyPackagesLow, MembershipChange, StreamFrame,
    StreamQuery, STREAM_CLOSE_CURSOR_EXPIRED, STREAM_CLOSE_UNAUTHORIZED,
};
pub use groups::{AddMembersRequest, CreateGroupRequest, Group, GroupKind, GroupList, GroupMember};
pub use keypackages::{
    ClaimKeyPackagesRequest, ClaimKeyPackagesResponse, ClaimedKeyPackage, KeyPackageCount,
    UploadKeyPackagesRequest,
};
pub use messages::{Message, MessageKind, MessageList, MessagesQuery, SendMessageRequest};
