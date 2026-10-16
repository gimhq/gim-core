//! The only UniFFI crate: `GimClient`, listener traits and platform-hook
//! callbacks, as a thin mapping over gim-ui / gim-sdk. Built as
//! `libgim_core.{so,a,dylib}`. The contract is documented in `docs/API.md`.

mod chat_list;
mod client;
mod convert;
mod error;
mod hooks;
mod link;
mod task_handle;
mod timeline;
mod types;

pub use chat_list::{ChatListDiff, ChatListListener};
#[cfg(feature = "testing")]
pub use client::create_client_with_fake_transport;
pub use client::{create_client, ClientConfig, ConnectionStateListener, GimClient, TypingListener};
pub use error::GimError;
pub use hooks::PlatformHooks;
pub use link::{LinkSession, PendingApproval};
pub use task_handle::TaskHandle;
pub use timeline::{LocalTimeZone, Timeline, TimelineDiff, TimelineListener};
pub use types::{
    ChatKind, ChatState, ChatSummary, ConnectionState, DeviceInfo, MediaRef, MembershipChangeKind,
    MessageContent, MessageItem, MessagePreview, ReactionGroup, ReplyPreview, SendState, Session,
    TimelineItem, UserProfile,
};

uniffi::setup_scaffolding!();

/// Version of the gim core library.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Name of the MLS ciphersuite every gim group uses.
#[uniffi::export]
pub fn ciphersuite_name() -> String {
    format!("{:?}", gim_crypto::CIPHERSUITE)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    struct Hooks(tempfile::TempDir);

    impl PlatformHooks for Hooks {
        fn secure_store_get(&self, _key: String) -> Result<Option<Vec<u8>>, GimError> {
            Ok(None)
        }
        fn secure_store_set(&self, _key: String, _value: Vec<u8>) -> Result<(), GimError> {
            Ok(())
        }
        fn secure_store_delete(&self, _key: String) {}
        fn data_dir(&self) -> String {
            self.0.path().to_str().unwrap().to_string()
        }
        fn is_network_reachable(&self) -> bool {
            true
        }
    }

    fn hooks() -> Arc<Hooks> {
        Arc::new(Hooks(tempfile::tempdir().unwrap()))
    }

    fn config(url: &str) -> ClientConfig {
        ClientConfig {
            server_url: url.to_string(),
        }
    }

    #[test]
    fn metadata() {
        assert_eq!(super::core_version(), "0.1.0");
        assert_eq!(
            super::ciphersuite_name(),
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        );
    }

    #[tokio::test]
    async fn rejects_bad_url() {
        for url in ["", "not a url", "ftp://gim.example.org", "file:///tmp/x"] {
            let result = create_client(config(url), hooks()).await;
            assert!(
                matches!(result, Err(GimError::InvalidInput { .. })),
                "{url:?} accepted"
            );
        }
    }

    #[tokio::test]
    async fn opens_local_state_without_network() {
        let hooks = hooks();
        // Nothing listens on the discard port.
        let client = create_client(config("http://127.0.0.1:9"), hooks.clone())
            .await
            .unwrap();
        assert!(hooks.0.path().join("gim.sqlite3").is_file());
        assert_eq!(client.session().await, Ok(None));
        client.set_network_reachable(false);

        assert!(matches!(
            client.create_identity("Alice".to_string()).await,
            Err(GimError::Network { .. })
        ));
        // Everything else needs a session.
        let id = || "x".to_string();
        assert_eq!(client.start_sync().await, Err(GimError::NotRegistered));
        assert_eq!(client.find_user(id()).await, Err(GimError::NotRegistered));
        assert_eq!(
            client.send_text(id(), id(), None).await,
            Err(GimError::NotRegistered)
        );
        assert!(matches!(
            client.timeline(id()).await,
            Err(GimError::NotRegistered)
        ));
        assert_eq!(
            client.chat_members(id()).await,
            Err(GimError::NotFound {
                reason: "chat x".to_string()
            })
        );
        assert!(matches!(
            client.send_text(String::new(), id(), None).await,
            Err(GimError::InvalidInput { .. })
        ));
    }
}
