use crate::ChatState;

/// Error returned by every fallible gim-core call.
///
/// Kotlin: `GimException.<Variant>`; Swift: `GimError.<Variant>`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum GimError {
    /// The server could not be reached or the connection broke.
    #[error("network error: {reason}")]
    Network { reason: String },
    /// The call needs a session: create an identity, restore one from its
    /// recovery code or link this device first. Also returned after
    /// `sign_out` and once the hub reports this device as revoked.
    #[error("not registered")]
    NotRegistered,
    /// An argument was rejected before anything was sent.
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    /// The chat, message, user or media does not exist locally or on the server.
    #[error("not found: {reason}")]
    NotFound { reason: String },
    /// MLS or media encryption/decryption failed.
    #[error("crypto error: {reason}")]
    Crypto { reason: String },
    /// The local database or file system failed.
    #[error("storage error: {reason}")]
    Storage { reason: String },
    /// The hub answered with a non-success HTTP status.
    #[error("server error {status}: {reason}")]
    Server { status: u16, reason: String },
    /// The hub is throttling the call (HTTP 429 `rate_limited`) or a remote
    /// hub is unavailable (HTTP 503 `peer_unavailable`), and gim-core's
    /// bounded retries are used up; try again after `retry_after_secs`.
    #[error("retry after {retry_after_secs} s ({status}): {reason}")]
    RetryLater {
        status: u16,
        retry_after_secs: u64,
        reason: String,
    },
    /// The operation was cancelled (sign-out, `stop_sync`, `cancel_send`).
    #[error("cancelled")]
    Cancelled,
    /// The call is part of the API contract but not implemented yet.
    #[error("not implemented")]
    NotImplemented,
    /// A bug or an unexpected failure inside gim-core or a platform callback.
    #[error("internal error: {reason}")]
    Internal { reason: String },
    /// The call sends to (or changes) a chat this device is leaving or has
    /// left. `state` is `Leaving` or `Left`; see `ChatState`.
    #[error("chat {chat_id} is not active: {state:?}")]
    ChatNotActive { chat_id: String, state: ChatState },
    /// The server at the configured URL did not prove that it is the
    /// expected hub at that URL (a wrong URL, or a relay in between); the
    /// device did not sign in there. Check the hub URL.
    #[error("hub not verified: {reason}")]
    HubNotVerified { reason: String },
    /// `remove_hub` without `confirm_owned_groups`: the hub owns
    /// `group_count` chats of this user. They are not moved; after the
    /// removal they stay reachable through the other members' hubs. Ask
    /// the user, then call `remove_hub` again with `confirm_owned_groups`.
    #[error("hub {hub_id} owns {group_count} chats")]
    HubOwnsGroups { hub_id: String, group_count: u32 },
    /// The hub is the only listed hub and cannot be removed.
    #[error("hub {hub_id} is the only hub")]
    LastHub { hub_id: String },
    /// The hub is the one this client was created for (`HubInfo.is_home`)
    /// and cannot be removed.
    #[error("hub {hub_id} is the home hub")]
    HomeHub { hub_id: String },
    /// Messages or membership changes sent through the hub are not settled
    /// yet, so it cannot be removed now; try again later.
    #[error("hub {hub_id} is not drained: {reason}")]
    HubNotDrained { hub_id: String, reason: String },
    /// An admin of the hub `hub_id` suspended this user: the hub refuses
    /// to sign this device in. The session is kept. Show "account
    /// suspended" and do not retry: gim-core does not sign in there again
    /// for 10 minutes and keeps using the user's other hubs meanwhile.
    /// `hub_id` is empty if the home hub has no hub identity.
    #[error("user suspended on hub {hub_id}")]
    UserSuspended { hub_id: String },
    /// The user policy of the hub `hub_id` does not admit this user: the
    /// hub refused the registration (onboarding, `add_hub`: nothing was
    /// kept) or a sign-in. Handled like `UserSuspended`. Show "this hub
    /// does not admit you" and do not retry. `hub_id` is empty if unknown.
    #[error("user not admitted on hub {hub_id}")]
    UserNotAdmitted { hub_id: String },
    /// The hub `hub_id` owning the chat `chat_id` does not admit this user:
    /// the message or member change was refused there and is not retried.
    /// Other chats are not affected. Do not offer a retry.
    #[error("hub {hub_id} owning chat {chat_id} does not admit this user")]
    NotAdmittedByPeer { hub_id: String, chat_id: String },
    /// `create_direct_chat` / `create_group_chat` / `add_members`: no user
    /// could be added, and the hubs of `user_ids` do not admit this user.
    /// Show "this user does not accept contacts from you".
    #[error("users {user_ids:?} do not accept contacts from this user")]
    ContactNotAdmitted { user_ids: Vec<String> },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for GimError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Internal { reason: e.reason }
    }
}

impl From<gim_sdk::ClientError> for GimError {
    fn from(err: gim_sdk::ClientError) -> Self {
        use gim_sdk::ClientError as E;
        match err {
            E::NotLoggedIn | E::NotRegistered | E::DeviceNotActive(_) => Self::NotRegistered,
            E::AlreadyLoggedIn | E::InvalidInput(_) => Self::InvalidInput {
                reason: err.to_string(),
            },
            E::CommitConflict(_) => Self::Server {
                status: 409,
                reason: err.to_string(),
            },
            E::Transport(err) => err.into(),
            E::Base(err) => err.into(),
            E::Media(_) | E::Identity(_) => Self::Crypto {
                reason: err.to_string(),
            },
            E::InvalidSession(_)
            | E::SecretStorage(_)
            | E::Io(_)
            | E::StoreBusy(_)
            | E::StoreWiped => Self::Storage {
                reason: err.to_string(),
            },
            E::Task(_) => Self::Internal {
                reason: err.to_string(),
            },
            E::HubOwnsGroups {
                hub_id,
                group_count,
            } => Self::HubOwnsGroups {
                hub_id,
                group_count,
            },
            E::LastHub(hub_id) => Self::LastHub { hub_id },
            E::HomeHub(hub_id) => Self::HomeHub { hub_id },
            E::HubNotDrained { hub_id, reason } => Self::HubNotDrained { hub_id, reason },
            E::UserSuspended { hub_id } => Self::UserSuspended { hub_id },
            E::UserNotAdmitted { hub_id } => Self::UserNotAdmitted { hub_id },
            E::NotAdmittedByPeer { hub_id, group_id } => Self::NotAdmittedByPeer {
                hub_id,
                chat_id: group_id,
            },
            E::ContactNotAdmitted { user_ids } => Self::ContactNotAdmitted {
                user_ids: user_ids.into_iter().map(Into::into).collect(),
            },
        }
    }
}

impl From<gim_sdk::TransportError> for GimError {
    fn from(err: gim_sdk::TransportError) -> Self {
        use gim_sdk::TransportError as E;
        let reason = err.to_string();
        match err {
            E::Network(_) => Self::Network { reason },
            E::NotFound(_) => Self::NotFound { reason },
            E::Unauthorized => Self::Server {
                status: 401,
                reason,
            },
            E::Conflict(_) => Self::Server {
                status: 409,
                reason,
            },
            E::Gone { .. } => Self::Server {
                status: 410,
                reason,
            },
            E::Server(_) => Self::Server {
                status: 500,
                reason,
            },
            E::Rejected {
                status: 400 | 422, ..
            } => Self::InvalidInput { reason },
            E::Rejected { status, .. } => Self::Server { status, reason },
            E::TooLarge(_) => Self::InvalidInput { reason },
            E::DeviceNotActive(_) => Self::NotRegistered,
            E::UserSuspended { hub_id } => Self::UserSuspended { hub_id },
            E::UserNotAdmitted { hub_id } => Self::UserNotAdmitted { hub_id },
            E::NotAdmittedByPeer { hub_id, group_id } => Self::NotAdmittedByPeer {
                hub_id,
                chat_id: group_id,
            },
            E::HubNotVerified(_) => Self::HubNotVerified { reason },
            E::HostingRecordRequired(_) => Self::Server {
                status: 403,
                reason,
            },
            E::RetryLater {
                status,
                retry_after_secs,
                reason,
            } => Self::RetryLater {
                status,
                retry_after_secs,
                reason,
            },
            E::PeerUnavailable {
                retry_after_secs: Some(retry_after_secs),
                ..
            } => Self::RetryLater {
                status: 503,
                retry_after_secs,
                reason,
            },
            E::PeerUnavailable {
                retry_after_secs: None,
                ..
            } => Self::Server {
                status: 503,
                reason,
            },
            E::PeerRefused(_) => Self::Server {
                status: 502,
                reason,
            },
        }
    }
}

impl From<gim_base::BaseError> for GimError {
    fn from(err: gim_base::BaseError) -> Self {
        use gim_base::BaseError as E;
        let reason = err.to_string();
        match err {
            E::Store(_) => Self::Storage { reason },
            E::Crypto(_) => Self::Crypto { reason },
            E::NotFound(_) => Self::NotFound { reason },
            E::InvalidState(_) => Self::InvalidInput { reason },
            E::Proto(_) | E::Random(_) => Self::Internal { reason },
        }
    }
}

impl From<gim_base::StoreError> for GimError {
    fn from(err: gim_base::StoreError) -> Self {
        Self::Storage {
            reason: err.to_string(),
        }
    }
}

impl From<gim_ui::UiError> for GimError {
    fn from(err: gim_ui::UiError) -> Self {
        match err {
            gim_ui::UiError::Client(err) => err.into(),
            gim_ui::UiError::Base(err) => err.into(),
            gim_ui::UiError::Task(_) => Self::Internal {
                reason: err.to_string(),
            },
        }
    }
}

impl From<std::io::Error> for GimError {
    fn from(err: std::io::Error) -> Self {
        Self::Storage {
            reason: err.to_string(),
        }
    }
}

impl From<tokio::task::JoinError> for GimError {
    fn from(err: tokio::task::JoinError) -> Self {
        Self::Internal {
            reason: err.to_string(),
        }
    }
}

/// Parses an id argument; a malformed id is `InvalidInput`.
pub(crate) fn parse_id<T: TryFrom<String, Error = gim_common::GimCommonError>>(
    what: &str,
    value: String,
) -> Result<T, GimError> {
    T::try_from(value).map_err(|e| GimError::InvalidInput {
        reason: format!("{what}: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::GimError;
    use gim_sdk::{ClientError, TransportError};

    #[test]
    fn unknown_users_and_unavailable_peers() {
        let unknown = ClientError::Base(gim_base::BaseError::NotFound("users".into()));
        assert!(matches!(GimError::from(unknown), GimError::NotFound { .. }));
        let missing = ClientError::Transport(TransportError::NotFound("blob".into()));
        assert!(matches!(GimError::from(missing), GimError::NotFound { .. }));
        let peer = TransportError::PeerUnavailable {
            retry_after_secs: Some(7),
            reason: "peer_unavailable".into(),
        };
        assert!(matches!(
            GimError::from(ClientError::Transport(peer)),
            GimError::RetryLater {
                status: 503,
                retry_after_secs: 7,
                ..
            }
        ));
        let blob = TransportError::RetryLater {
            status: 503,
            retry_after_secs: 7,
            reason: "peer_unavailable".into(),
        };
        assert!(matches!(
            GimError::from(ClientError::Transport(blob)),
            GimError::RetryLater { status: 503, .. }
        ));
        let refused = TransportError::PeerRefused("peer_refused".into());
        assert!(matches!(
            GimError::from(ClientError::Transport(refused)),
            GimError::Server { status: 502, .. }
        ));
    }

    #[test]
    fn hub_management_errors() {
        let owns = ClientError::HubOwnsGroups {
            hub_id: "hb".into(),
            group_count: 2,
        };
        assert_eq!(
            GimError::from(owns),
            GimError::HubOwnsGroups {
                hub_id: "hb".into(),
                group_count: 2
            }
        );
        assert_eq!(
            GimError::from(ClientError::LastHub("hb".into())),
            GimError::LastHub {
                hub_id: "hb".into()
            }
        );
        assert_eq!(
            GimError::from(ClientError::HomeHub("ha".into())),
            GimError::HomeHub {
                hub_id: "ha".into()
            }
        );
        let drained = ClientError::HubNotDrained {
            hub_id: "hb".into(),
            reason: "1 message".into(),
        };
        assert!(matches!(
            GimError::from(drained),
            GimError::HubNotDrained { .. }
        ));
    }

    #[test]
    fn rejections() {
        let rejected = |status: u16| {
            GimError::from(ClientError::Transport(TransportError::Rejected {
                status,
                code: "validation_failed".into(),
                message: "bad".into(),
            }))
        };
        assert!(matches!(rejected(400), GimError::InvalidInput { .. }));
        assert!(matches!(rejected(422), GimError::InvalidInput { .. }));
        assert!(matches!(
            rejected(403),
            GimError::Server { status: 403, .. }
        ));
        let relay = TransportError::HubNotVerified("relay".into());
        assert!(matches!(
            GimError::from(ClientError::Transport(relay)),
            GimError::HubNotVerified { .. }
        ));
    }

    #[test]
    fn suspended_users() {
        let suspended = GimError::UserSuspended {
            hub_id: "hb".into(),
        };
        let from_client = ClientError::UserSuspended {
            hub_id: "hb".into(),
        };
        assert_eq!(GimError::from(from_client), suspended);
        let from_transport = TransportError::UserSuspended {
            hub_id: "hb".into(),
        };
        assert_eq!(
            GimError::from(ClientError::Transport(from_transport.clone())),
            suspended
        );
        assert_eq!(GimError::from(from_transport), suspended);
        // Another 403 stays a server error.
        let forbidden = TransportError::Rejected {
            status: 403,
            code: "user_suspended".into(),
            message: "user is suspended".into(),
        };
        assert!(matches!(
            GimError::from(ClientError::Transport(forbidden)),
            GimError::Server { status: 403, .. }
        ));
    }

    #[test]
    fn user_policy_refusals() {
        let not_admitted = GimError::UserNotAdmitted {
            hub_id: "hb".into(),
        };
        let from_transport = TransportError::UserNotAdmitted {
            hub_id: "hb".into(),
        };
        assert_eq!(
            GimError::from(ClientError::from(from_transport.clone())),
            not_admitted
        );
        assert_eq!(GimError::from(from_transport), not_admitted);
        let by_peer = TransportError::NotAdmittedByPeer {
            hub_id: "hb".into(),
            group_id: "hb/g1".into(),
        };
        let expected = GimError::NotAdmittedByPeer {
            hub_id: "hb".into(),
            chat_id: "hb/g1".into(),
        };
        assert_eq!(GimError::from(ClientError::from(by_peer.clone())), expected);
        assert_eq!(GimError::from(by_peer), expected);
        let user = gim_common::UserId::new("u_contact").unwrap();
        assert_eq!(
            GimError::from(ClientError::ContactNotAdmitted {
                user_ids: vec![user.clone()]
            }),
            GimError::ContactNotAdmitted {
                user_ids: vec![user.to_string()]
            }
        );
    }
}
