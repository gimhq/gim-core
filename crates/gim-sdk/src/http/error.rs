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

/// Maps a non-2xx response.
pub(super) fn from_status(status: StatusCode, body: &[u8]) -> TransportError {
    let message = message(status, body);
    match status {
        StatusCode::UNAUTHORIZED => TransportError::Unauthorized,
        StatusCode::NOT_FOUND => TransportError::NotFound(message),
        StatusCode::CONFLICT => TransportError::Conflict(message),
        StatusCode::PAYLOAD_TOO_LARGE => TransportError::TooLarge(message),
        StatusCode::FORBIDDEN
            if serde_json::from_slice::<ErrorResponse>(body)
                .is_ok_and(|e| e.error.code == v2::HOSTING_RECORD_REQUIRED) =>
        {
            TransportError::HostingRecordRequired(message)
        }
        StatusCode::GONE => match serde_json::from_slice::<CursorExpiredError>(body) {
            Ok(expired) => TransportError::Gone {
                cursor: expired.cursor,
            },
            Err(_) => TransportError::Server(format!("410 without a head cursor: {message}")),
        },
        _ if status.is_server_error() => TransportError::Server(message),
        _ => TransportError::Server(format!("{status}: {message}")),
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
