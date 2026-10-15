//! HTTP status and reqwest error mapping onto [`TransportError`].

use std::error::Error as _;

use gim_proto::v2::{CursorExpiredError, ErrorResponse};
use reqwest::StatusCode;

use crate::transport::TransportError;

/// Maps a non-2xx response.
pub(super) fn from_status(status: StatusCode, body: &[u8]) -> TransportError {
    let message = serde_json::from_slice::<ErrorResponse>(body)
        .map(|e| format!("{}: {}", e.error.code, e.error.message))
        .unwrap_or_else(|_| status.to_string());
    match status {
        StatusCode::UNAUTHORIZED => TransportError::Unauthorized,
        StatusCode::NOT_FOUND => TransportError::NotFound(message),
        StatusCode::CONFLICT => TransportError::Conflict(message),
        StatusCode::PAYLOAD_TOO_LARGE => TransportError::TooLarge(message),
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
/// [`TransportError::Network`].
pub(super) fn from_reqwest(err: reqwest::Error) -> TransportError {
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
