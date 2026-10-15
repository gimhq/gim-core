//! Errors of the CLI and their stable exit codes.

use std::fmt;

use gim_base::{BaseError, StoreError};
use gim_sdk::{ClientError, TransportError};

pub const EXIT_OK: u8 = 0;
pub const EXIT_OTHER: u8 = 1;
/// Also what clap uses for usage errors.
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_TIMEOUT: u8 = 3;
pub const EXIT_NOT_FOUND: u8 = 4;
pub const EXIT_SERVER: u8 = 5;

/// The exit-code table of `gim --help`.
pub fn exit_codes_help() -> String {
    format!(
        "Exit codes:\n  \
         {EXIT_OK}  ok\n  \
         {EXIT_OTHER}  other error\n  \
         {EXIT_USAGE}  usage error or invalid input\n  \
         {EXIT_TIMEOUT}  timeout\n  \
         {EXIT_NOT_FOUND}  not found (profile not registered, unknown user, chat or message)\n  \
         {EXIT_SERVER}  server, network or transport error"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Other,
    Usage,
    Timeout,
    NotFound,
    Server,
}

impl ErrorKind {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Other => EXIT_OTHER,
            Self::Usage => EXIT_USAGE,
            Self::Timeout => EXIT_TIMEOUT,
            Self::NotFound => EXIT_NOT_FOUND,
            Self::Server => EXIT_SERVER,
        }
    }

    /// `error.code` of the JSON output.
    pub fn name(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::Usage => "usage",
            Self::Timeout => "timeout",
            Self::NotFound => "not_found",
            Self::Server => "server",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CliError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, message)
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Other, message)
    }

    pub fn not_registered() -> Self {
        Self::not_found("profile not registered")
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub type Result<T, E = CliError> = std::result::Result<T, E>;

/// Error kind of an SDK error.
pub fn classify(err: &ClientError) -> ErrorKind {
    match err {
        ClientError::NotLoggedIn | ClientError::NotRegistered => ErrorKind::NotFound,
        ClientError::AlreadyLoggedIn | ClientError::InvalidInput(_) => ErrorKind::Usage,
        ClientError::Transport(TransportError::NotFound(_)) => ErrorKind::NotFound,
        ClientError::Transport(_) | ClientError::CommitConflict(_) => ErrorKind::Server,
        ClientError::Base(BaseError::NotFound(_)) => ErrorKind::NotFound,
        _ => ErrorKind::Other,
    }
}

impl From<ClientError> for CliError {
    fn from(err: ClientError) -> Self {
        Self::new(classify(&err), err.to_string())
    }
}

impl From<StoreError> for CliError {
    fn from(err: StoreError) -> Self {
        Self::other(err.to_string())
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        Self::other(format!("io error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_errors_map_to_stable_exit_codes() {
        let code = |err: ClientError| CliError::from(err).kind.exit_code();
        assert_eq!(code(ClientError::InvalidInput("x".into())), 2);
        assert_eq!(code(ClientError::AlreadyLoggedIn), 2);
        assert_eq!(code(ClientError::NotLoggedIn), 4);
        assert_eq!(code(ClientError::NotRegistered), 4);
        assert_eq!(code(BaseError::NotFound("chat".into()).into()), 4);
        assert_eq!(code(TransportError::NotFound("user".into()).into()), 4);
        assert_eq!(code(TransportError::Network("down".into()).into()), 5);
        assert_eq!(code(TransportError::Server("500".into()).into()), 5);
        assert_eq!(code(TransportError::Unauthorized.into()), 5);
        assert_eq!(code(ClientError::CommitConflict(3)), 5);
        assert_eq!(code(ClientError::Task("panic".into())), 1);
        assert_eq!(code(std::io::Error::other("disk").into()), 1);
    }

    #[test]
    fn kinds_have_distinct_codes_and_names() {
        let kinds = [
            ErrorKind::Other,
            ErrorKind::Usage,
            ErrorKind::Timeout,
            ErrorKind::NotFound,
            ErrorKind::Server,
        ];
        let codes: Vec<u8> = kinds.iter().map(|k| k.exit_code()).collect();
        assert_eq!(codes, [1, 2, 3, 4, 5]);
        assert_eq!(ErrorKind::NotFound.name(), "not_found");
        assert_eq!(CliError::not_registered().kind.exit_code(), EXIT_NOT_FOUND);
        assert!(exit_codes_help().contains("4  not found"));
    }
}
