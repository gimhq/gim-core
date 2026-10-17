//! gim-hub API v2 REST and stream DTOs.
//!
//! Source contract: `crates/gim-proto/contract/hub-v2/openapi.json`, a
//! verbatim copy from gim-hub (see `contract/hub-v2/SOURCE`). Field names
//! match the spec exactly; binary values travel as standard base64 and are
//! decoded into `Vec<u8>`; identity objects (DeviceList, AuthChallenge,
//! AuthResponse, recovery backup, link bundle) are opaque gim-identity CBOR.
//! IDs are opaque strings whose formats are owned by gim-identity. Timestamps
//! are Unix milliseconds.
//!
//! The sign-in shapes follow the hub contract update relayed after the
//! vendored commit (`AuthChallenge.hub_id`, `CreateSessionRequest.response`);
//! `tests/dto_v2.rs` tolerates the older vendored shape until it is
//! re-vendored.
//!
//! | Schema | Type |
//! |---|---|
//! | `Health`, `HealthStatus`, `HubInfo` | [`Health`], [`HealthStatus`], [`HubInfo`] |
//! | `AuthChallengeRequest`, `AuthChallenge`, `CreateSessionRequest`, `Session` | [`AuthChallengeRequest`], [`AuthChallenge`], [`CreateSessionRequest`], [`Session`] |
//! | `Me`, `User`, `DeviceList`, `PutDeviceListRequest`, `Handle` | [`Me`], [`User`], [`DeviceList`], [`PutDeviceListRequest`], [`Handle`] |
//! | `PutRecoveryBackupRequest`, `RecoveryBackup` | [`PutRecoveryBackupRequest`], [`RecoveryBackup`] |
//! | `CreateLinkBundleRequest`, `LinkBundleCreated`, `LinkBundle` | [`CreateLinkBundleRequest`], [`LinkBundleCreated`], [`LinkBundle`] |
//! | `CreateHostingEntryRequest`, `HostingEntry`, `PutHostingRecordRequest`, `HostingRecord`, `HostingRecordHub` | [`CreateHostingEntryRequest`], [`HostingEntry`], [`PutHostingRecordRequest`], [`HostingRecord`], [`HostingRecordHub`] |
//! | `UploadKeyPackagesRequest`, `KeyPackageCount` | [`UploadKeyPackagesRequest`], [`KeyPackageCount`] |
//! | `ClaimKeyPackagesRequest`, `ClaimTarget`, `ClaimKeyPackagesResponse`, `ClaimedKeyPackage` | [`ClaimKeyPackagesRequest`], [`ClaimTarget`], [`ClaimKeyPackagesResponse`], [`ClaimedKeyPackage`] |
//! | `Group`, `GroupKind`, `GroupMember`, `GroupList`, `CreateGroupRequest` | [`Group`], [`GroupKind`], [`GroupMember`], [`GroupList`], [`CreateGroupRequest`] |
//! | `SubmitCommitRequest`, `CommitResult` | [`SubmitCommitRequest`], [`CommitResult`] |
//! | `Message`, `MessageKind`, `MessageList`, `SendMessageRequest` | [`Message`], [`MessageKind`], [`MessageList`], [`SendMessageRequest`] |
//! | `Event`, `EventList` | [`Event`], [`EventList`] |
//! | `MessageEvent`, `MemberAddedEvent`, `MemberRemovedEvent`, `WelcomeEvent`, `KeyPackagesLowEvent`, `DeviceListUpdatedEvent`, `HostingRecordExpiringEvent`, `HostingRecordUpdatedEvent` | [`EventData`] variants |
//! | `MembershipChange`, `Welcome`, `KeyPackagesLow`, `HostingRecordExpiring`, `HostingRecordUpdated` | [`MembershipChange`], [`Welcome`], [`KeyPackagesLow`], [`HostingRecordExpiring`], [`HostingRecordUpdated`] |
//! | `PendingWelcome`, `PendingWelcomeList` | [`PendingWelcome`], [`PendingWelcomeList`] |
//! | `PushRegistration` | [`PushRegistration`] |
//! | `BlobCreated` | [`BlobCreated`] |
//! | `Error`, `ErrorBody`, `StaleEpochError`, `CursorExpiredError` | [`ErrorResponse`], [`ErrorBody`], [`StaleEpochError`], [`CursorExpiredError`] |
//!
//! Error codes the SDK branches on are constants ([`STALE_EPOCH`],
//! [`CURSOR_EXPIRED`], [`HOSTING_RECORD_REQUIRED`], ...).
//!
//! Query strings are [`HubQuery`], [`EventsQuery`], [`StreamQuery`],
//! [`MessagesQuery`], [`PendingWelcomesQuery`] and [`LinkBundleQuery`]. The `/v2/stream`
//! WebSocket frames (described in prose, not as a schema) are
//! [`StreamFrame`]. Blob bodies are raw `application/octet-stream` bytes and
//! have no DTO.

use crate::base64;

mod auth;
mod events;
mod groups;
mod hosting;
mod keypackages;
pub mod paths;
mod service;
mod users;

pub use auth::{AuthChallenge, AuthChallengeRequest, CreateSessionRequest, Session};
pub use events::{
    Event, EventData, EventList, EventsQuery, KeyPackagesLow, MembershipChange, PendingWelcome,
    PendingWelcomeList, PendingWelcomesQuery, StreamFrame, StreamQuery, Welcome,
    STREAM_CLOSE_CURSOR_EXPIRED, STREAM_CLOSE_UNAUTHORIZED,
};
pub use groups::{
    CommitResult, CreateGroupRequest, Group, GroupKind, GroupList, GroupMember, Message,
    MessageKind, MessageList, MessagesQuery, SendMessageRequest, SubmitCommitRequest,
};
pub use hosting::{
    CreateHostingEntryRequest, HostingEntry, HostingRecord, HostingRecordExpiring,
    HostingRecordHub, HostingRecordUpdated, PutHostingRecordRequest,
};
pub use keypackages::{
    ClaimKeyPackagesRequest, ClaimKeyPackagesResponse, ClaimTarget, ClaimedKeyPackage,
    KeyPackageCount, UploadKeyPackagesRequest,
};
pub use service::{
    BlobCreated, CursorExpiredError, ErrorBody, ErrorResponse, Health, HealthStatus, HubInfo,
    HubQuery, PushRegistration, StaleEpochError, CURSOR_EXPIRED, DUPLICATE_KEY_PACKAGE,
    HOSTING_RECORD_REQUIRED, INVALID_HOSTING_RECORD, KP_NOT_CLAIMED, PEER_REFUSED,
    PEER_UNAVAILABLE, STALE_EPOCH, STALE_HOSTING_RECORD, USER_SUSPENDED,
};
pub use users::{
    CreateLinkBundleRequest, DeviceList, Handle, LinkBundle, LinkBundleCreated, LinkBundleQuery,
    Me, PutDeviceListRequest, PutRecoveryBackupRequest, RecoveryBackup, User,
};
