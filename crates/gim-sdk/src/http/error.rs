//! HTTP status and reqwest error mapping onto [`TransportError`].

use std::error::Error as _;
use std::time::Duration;

use gim_proto::v2::{self, CursorExpiredError, ErrorResponse};
use reqwest::StatusCode;

use crate::transport::TransportError;

/// `code: message` of an error body, or the status.
fn message(status: StatusCode, body: &[u8]) -> String {
    serde_json::from_slice::<ErrorResponse>(body)
        .map(|e| format!("{}: {}", e.error.code, e.error.message))
        .unwrap_or_else(|_| status.to_string())
}

/// Maps a throttled response whose retries are used up.
pub(super) fn retry_later(
    status: StatusCode,
    retry_after: Duration,
    body: &[u8],
) -> TransportError {
    TransportError::RetryLater {
        status: status.as_u16(),
        retry_after_secs: retry_after.as_secs(),
        reason: message(status, body),
    }
}

/// Maps a non-2xx response; `retry_after` is its `Retry-After` in seconds.
pub(super) fn from_status(
    status: StatusCode,
    retry_after: Option<u64>,
    body: &[u8],
) -> TransportError {
    let error = serde_json::from_slice::<ErrorResponse>(body).ok();
    let code = error
        .as_ref()
        .map(|e| e.error.code.clone())
        .unwrap_or_default();
    let message = message(status, body);
    match status {
        StatusCode::UNAUTHORIZED => TransportError::Unauthorized,
        StatusCode::NOT_FOUND => TransportError::NotFound(message),
        StatusCode::CONFLICT => TransportError::Conflict(message),
        StatusCode::PAYLOAD_TOO_LARGE => TransportError::TooLarge(message),
        StatusCode::FORBIDDEN if code == v2::HOSTING_RECORD_REQUIRED => {
            TransportError::HostingRecordRequired(message)
        }
        StatusCode::BAD_GATEWAY if code == v2::PEER_REFUSED => TransportError::PeerRefused(message),
        StatusCode::SERVICE_UNAVAILABLE if code == v2::PEER_UNAVAILABLE => {
            TransportError::PeerUnavailable {
                retry_after_secs: retry_after,
                reason: message,
            }
        }
        StatusCode::GONE => match serde_json::from_slice::<CursorExpiredError>(body) {
            Ok(expired) => TransportError::Gone {
                cursor: expired.cursor,
            },
            Err(_) => TransportError::Server(format!("410 without a head cursor: {message}")),
        },
        _ if status.is_server_error() => TransportError::Server(message),
        // Throttled or timed out: the request may still be applied.
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => {
            TransportError::Server(format!("{status}: {message}"))
        }
        _ if status.is_client_error() => TransportError::Rejected {
            status: status.as_u16(),
            code,
            message: error.map_or_else(|| status.to_string(), |e| e.error.message),
        },
        _ => TransportError::Server(format!("{status}: {message}")),
    }
}

/// Maps the error of a sign-in request (`POST /v2/auth/challenge`,
/// `POST /v2/auth/session`): 403 `user_suspended` becomes
/// [`TransportError::UserSuspended`], 403 `user_not_admitted`
/// [`TransportError::UserNotAdmitted`]. Only these endpoints (and the
/// DeviceList upload for `user_not_admitted`) return those codes; elsewhere
/// they stay a generic [`TransportError::Rejected`].
pub(super) fn sign_in(err: TransportError) -> TransportError {
    match err {
        TransportError::Rejected {
            status: 403, code, ..
        } if code == v2::USER_SUSPENDED => TransportError::UserSuspended {
            hub_id: String::new(),
        },
        err => device_list(err),
    }
}

/// Maps the error of `PUT /v2/users/{user_id}/device-list`: 403
/// `user_not_admitted` (a registration the hub's user policy refuses)
/// becomes [`TransportError::UserNotAdmitted`].
pub(super) fn device_list(err: TransportError) -> TransportError {
    match err {
        TransportError::Rejected {
            status: 403, code, ..
        } if code == v2::USER_NOT_ADMITTED => TransportError::UserNotAdmitted {
            hub_id: String::new(),
        },
        err => err,
    }
}

/// Maps the error of `POST /v2/groups/{gid}/commits` and `/messages`: 403
/// `not_admitted_by_peer` becomes [`TransportError::NotAdmittedByPeer`]
/// for `group_id`, owned by the hub its id starts with.
pub(super) fn group_post(err: TransportError, group_id: &str) -> TransportError {
    match err {
        TransportError::Rejected {
            status: 403, code, ..
        } if code == v2::NOT_ADMITTED_BY_PEER => TransportError::NotAdmittedByPeer {
            hub_id: group_id
                .split_once('/')
                .map(|(hub, _)| hub)
                .unwrap_or_default()
                .to_string(),
            group_id: group_id.to_string(),
        },
        err => err,
    }
}

/// Maps a failed send or body read. Undecodable bodies are the server's
/// fault; everything else (connect, TLS, timeout, reset) is a retryable
/// [`TransportError::Network`]. The URL in the message loses its query.
pub(super) fn from_reqwest(mut err: reqwest::Error) -> TransportError {
    if let Some(url) = err.url_mut() {
        url.set_query(None);
    }
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    if err.is_decode() {
        TransportError::Server(message)
    } else {
        TransportError::Network(message)
    }
}
