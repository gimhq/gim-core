//! Route paths, relative to the server base URL. Ids are validated by
//! `gim_common` to contain no `/`, so they are inserted as-is.

use gim_common::{DeviceId, GroupId, UserId};

/// `GET` → [`Health`](super::Health).
pub const HEALTHZ: &str = "/healthz";
/// `POST` [`RegisterDeviceRequest`](super::RegisterDeviceRequest) →
/// 201 [`RegisterDeviceResponse`](super::RegisterDeviceResponse).
pub const DEVICES: &str = "/v1/devices";
/// `GET` → [`Me`](super::Me).
pub const ME: &str = "/v1/me";
/// `GET ?`[`UsersQuery`](super::UsersQuery) → [`User`](super::User).
pub const USERS: &str = "/v1/users";
/// `POST` [`UploadKeyPackagesRequest`](super::UploadKeyPackagesRequest) →
/// [`KeyPackageCount`](super::KeyPackageCount).
pub const KEY_PACKAGES: &str = "/v1/keypackages";
/// `GET` → [`KeyPackageCount`](super::KeyPackageCount).
pub const KEY_PACKAGES_COUNT: &str = "/v1/keypackages/count";
/// `POST` [`ClaimKeyPackagesRequest`](super::ClaimKeyPackagesRequest) →
/// [`ClaimKeyPackagesResponse`](super::ClaimKeyPackagesResponse).
pub const KEY_PACKAGES_CLAIM: &str = "/v1/keypackages/claim";
/// `GET` → [`GroupList`](super::GroupList); `POST`
/// [`CreateGroupRequest`](super::CreateGroupRequest) → 201 [`Group`](super::Group).
pub const GROUPS: &str = "/v1/groups";
/// `GET ?`[`EventsQuery`](super::EventsQuery) → [`EventList`](super::EventList),
/// 410 [`CursorExpiredError`](super::CursorExpiredError).
pub const EVENTS: &str = "/v1/events";
/// WebSocket `?`[`StreamQuery`](super::StreamQuery) delivering
/// [`StreamFrame`](super::StreamFrame)s.
pub const STREAM: &str = "/v1/stream";
/// `POST` raw encrypted bytes → 201 [`BlobCreated`](super::BlobCreated).
pub const BLOBS: &str = "/v1/blobs";

/// `GET` → [`User`](super::User).
pub fn user(user_id: &UserId) -> String {
    format!("{USERS}/{user_id}")
}

/// `GET` → [`UserDevices`](super::UserDevices).
pub fn user_devices(user_id: &UserId) -> String {
    format!("{USERS}/{user_id}/devices")
}

/// `GET` → [`Group`](super::Group).
pub fn group(group_id: &GroupId) -> String {
    format!("{GROUPS}/{group_id}")
}

/// `POST` [`AddMembersRequest`](super::AddMembersRequest) → [`Group`](super::Group).
pub fn group_members(group_id: &GroupId) -> String {
    format!("{GROUPS}/{group_id}/members")
}

/// `DELETE` → [`Group`](super::Group).
pub fn group_member(group_id: &GroupId, device_id: &DeviceId) -> String {
    format!("{GROUPS}/{group_id}/members/{device_id}")
}

/// `GET ?`[`MessagesQuery`](super::MessagesQuery) →
/// [`MessageList`](super::MessageList); `POST`
/// [`SendMessageRequest`](super::SendMessageRequest) → 201 (200 on an idempotent
/// resend) [`Message`](super::Message), 409 [`StaleEpochError`](super::StaleEpochError).
pub fn group_messages(group_id: &GroupId) -> String {
    format!("{GROUPS}/{group_id}/messages")
}

/// `GET` (optional `Range` header) → raw encrypted bytes (200/206).
pub fn blob(blob_id: &str) -> String {
    format!("{BLOBS}/{blob_id}")
}
