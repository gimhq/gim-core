//! Route paths, relative to the hub base URL. Path parameters are
//! percent-encoded as one segment: every byte outside the RFC 3986
//! unreserved set is escaped, so a `gid`'s `/` becomes `%2F`.

use std::fmt::Write;

/// `GET` → [`Health`](super::Health).
pub const HEALTHZ: &str = "/healthz";
/// `POST` [`AuthChallengeRequest`](super::AuthChallengeRequest) →
/// [`AuthChallenge`](super::AuthChallenge).
pub const AUTH_CHALLENGE: &str = "/v2/auth/challenge";
/// `POST` [`CreateSessionRequest`](super::CreateSessionRequest) →
/// [`Session`](super::Session).
pub const AUTH_SESSION: &str = "/v2/auth/session";
/// `GET` → [`Me`](super::Me).
pub const ME: &str = "/v2/me";
/// `POST` [`UploadKeyPackagesRequest`](super::UploadKeyPackagesRequest) →
/// [`KeyPackageCount`](super::KeyPackageCount).
pub const KEY_PACKAGES: &str = "/v2/keypackages";
/// `POST` [`ClaimKeyPackagesRequest`](super::ClaimKeyPackagesRequest) →
/// [`ClaimKeyPackagesResponse`](super::ClaimKeyPackagesResponse).
pub const KEY_PACKAGES_CLAIM: &str = "/v2/keypackages/claim";
/// `GET` → [`KeyPackageCount`](super::KeyPackageCount).
pub const KEY_PACKAGES_COUNT: &str = "/v2/keypackages/count";
/// `POST` [`CreateLinkBundleRequest`](super::CreateLinkBundleRequest) →
/// 201 [`LinkBundleCreated`](super::LinkBundleCreated).
pub const LINK_BUNDLES: &str = "/v2/link-bundles";
/// `GET` → [`GroupList`](super::GroupList); `POST`
/// [`CreateGroupRequest`](super::CreateGroupRequest) → 201 [`Group`](super::Group).
pub const GROUPS: &str = "/v2/groups";
/// `GET ?`[`EventsQuery`](super::EventsQuery) → [`EventList`](super::EventList),
/// 410 [`CursorExpiredError`](super::CursorExpiredError).
pub const EVENTS: &str = "/v2/events";
/// WebSocket `?`[`StreamQuery`](super::StreamQuery) delivering
/// [`StreamFrame`](super::StreamFrame)s.
pub const STREAM: &str = "/v2/stream";
/// `GET ?`[`PendingWelcomesQuery`](super::PendingWelcomesQuery) →
/// [`PendingWelcomeList`](super::PendingWelcomeList).
pub const WELCOMES_PENDING: &str = "/v2/welcomes/pending";
/// `PUT` [`PushRegistration`](super::PushRegistration) → 204; `DELETE` → 204.
pub const PUSH_REGISTRATION: &str = "/v2/push/registration";
/// `POST` raw encrypted bytes → 201 [`BlobCreated`](super::BlobCreated).
pub const BLOBS: &str = "/v2/blobs";

/// Percent-encodes `value` as a single path segment.
fn segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `GET` → [`User`](super::User).
pub fn user(user_id: &str) -> String {
    format!("/v2/users/{}", segment(user_id))
}

/// `GET` → [`DeviceList`](super::DeviceList); `PUT`
/// [`PutDeviceListRequest`](super::PutDeviceListRequest) → 200/201
/// [`DeviceList`](super::DeviceList).
pub fn user_device_list(user_id: &str) -> String {
    format!("/v2/users/{}/device-list", segment(user_id))
}

/// `GET` (no token) → [`RecoveryBackup`](super::RecoveryBackup); `PUT`
/// [`PutRecoveryBackupRequest`](super::PutRecoveryBackupRequest) →
/// [`RecoveryBackup`](super::RecoveryBackup).
pub fn user_recovery_backup(user_id: &str) -> String {
    format!("/v2/users/{}/recovery-backup", segment(user_id))
}

/// `GET`/`PUT` (no body) → [`Handle`](super::Handle); `DELETE` → 204.
pub fn handle(handle: &str) -> String {
    format!("/v2/handles/{}", segment(handle))
}

/// `GET ?`[`LinkBundleQuery`](super::LinkBundleQuery) (no token) →
/// [`LinkBundle`](super::LinkBundle).
pub fn link_bundle(link_id: &str) -> String {
    format!("{LINK_BUNDLES}/{}", segment(link_id))
}

/// `GET` → [`Group`](super::Group).
pub fn group(gid: &str) -> String {
    format!("{GROUPS}/{}", segment(gid))
}

/// `POST` [`SubmitCommitRequest`](super::SubmitCommitRequest) → 201 (200 on a
/// duplicate) [`CommitResult`](super::CommitResult), 409
/// [`StaleEpochError`](super::StaleEpochError).
pub fn group_commits(gid: &str) -> String {
    format!("{GROUPS}/{}/commits", segment(gid))
}

/// `GET ?`[`MessagesQuery`](super::MessagesQuery) →
/// [`MessageList`](super::MessageList); `POST`
/// [`SendMessageRequest`](super::SendMessageRequest) → 201 (200 on an
/// idempotent resend) [`Message`](super::Message), 409
/// [`StaleEpochError`](super::StaleEpochError).
pub fn group_messages(gid: &str) -> String {
    format!("{GROUPS}/{}/messages", segment(gid))
}

/// `POST` (no body) → 204.
pub fn welcome_ack(gid: &str) -> String {
    format!("/v2/welcomes/{}/ack", segment(gid))
}

/// `GET` (optional `Range` header) → raw encrypted bytes (200/206).
pub fn blob(blob_id: &str) -> String {
    format!("{BLOBS}/{}", segment(blob_id))
}
