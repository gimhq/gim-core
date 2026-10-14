//! The only UniFFI crate: `GimClient`, listener traits and platform-hook
//! callbacks, as a thin mapping over gim-ui / gim-sdk. Built as
//! `libgim_core.{so,a,dylib}`. The contract is documented in `docs/API.md`.

mod chat_list;
mod client;
mod error;
mod hooks;
mod task_handle;
mod timeline;
mod types;

pub use chat_list::{ChatListDiff, ChatListListener};
pub use client::{create_client, ClientConfig, ConnectionStateListener, GimClient, TypingListener};
pub use error::GimError;
pub use hooks::PlatformHooks;
pub use task_handle::TaskHandle;
pub use timeline::{Timeline, TimelineDiff, TimelineListener};
pub use types::{
    ChatKind, ChatSummary, ConnectionState, MediaRef, MembershipChangeKind, MessageContent,
    MessageItem, MessagePreview, ReactionGroup, ReplyPreview, SendState, Session, TimelineItem,
    UserProfile,
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
    use std::time::Duration;

    use super::*;

    struct Hooks;

    impl PlatformHooks for Hooks {
        fn secure_store_get(&self, _key: String) -> Option<Vec<u8>> {
            None
        }
        fn secure_store_set(&self, _key: String, _value: Vec<u8>) -> Result<(), GimError> {
            Ok(())
        }
        fn secure_store_delete(&self, _key: String) {}
        fn data_dir(&self) -> String {
            "/tmp".to_string()
        }
        fn is_network_reachable(&self) -> bool {
            true
        }
    }

    struct Listener;

    impl ChatListListener for Listener {
        fn on_update(&self, _diffs: Vec<ChatListDiff>) {
            panic!("stub listener must never fire");
        }
    }

    impl TimelineListener for Listener {
        fn on_update(&self, _diffs: Vec<TimelineDiff>) {
            panic!("stub listener must never fire");
        }
    }

    async fn client() -> Arc<GimClient> {
        let config = ClientConfig {
            server_url: "https://gim.example.org".to_string(),
        };
        create_client(config, Arc::new(Hooks)).await.unwrap()
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
    async fn stub_constructs() {
        let client = client().await;
        client.set_network_reachable(false);
        let timeline = client.timeline("g1".to_string()).await.unwrap();
        assert_eq!(timeline.chat_id(), "g1");
    }

    #[tokio::test]
    async fn rejects_bad_url() {
        for url in ["", "not a url", "ftp://gim.example.org", "file:///tmp/x"] {
            let config = ClientConfig {
                server_url: url.to_string(),
            };
            let result = create_client(config, Arc::new(Hooks)).await;
            assert!(
                matches!(result, Err(GimError::InvalidInput { .. })),
                "{url:?} accepted"
            );
        }
    }

    #[tokio::test]
    async fn methods_return_not_implemented() {
        let client = client().await;
        let id = || "x".to_string();
        assert_eq!(client.session().await, Err(GimError::NotImplemented));
        assert_eq!(
            client.register(id(), id()).await,
            Err(GimError::NotImplemented)
        );
        assert_eq!(client.start_sync().await, Err(GimError::NotImplemented));
        assert_eq!(
            client.send_text(id(), id(), None).await,
            Err(GimError::NotImplemented)
        );
        assert_eq!(
            client.fetch_media(id(), id(), id()).await,
            Err(GimError::NotImplemented)
        );
        assert_eq!(
            client.chat_members(id()).await,
            Err(GimError::NotImplemented)
        );
        let timeline = client.timeline(id()).await.unwrap();
        assert_eq!(
            timeline.paginate_backwards(20).await,
            Err(GimError::NotImplemented)
        );
    }

    #[tokio::test]
    async fn task_handle_cancel() {
        let client = client().await;
        let handle = client.chat_list(Arc::new(Listener)).await.unwrap();
        let timeline_handle = client
            .timeline("g1".to_string())
            .await
            .unwrap()
            .add_listener(Arc::new(Listener))
            .await;
        tokio::task::yield_now().await;
        assert!(!handle.is_finished());

        handle.cancel();
        handle.cancel();
        timeline_handle.cancel();
        for _ in 0..100 {
            if handle.is_finished() && timeline_handle.is_finished() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("cancelled task did not finish");
    }
}
