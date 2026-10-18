//! The hub user policy (allow/deny list, hub H12) against a real gim-hub:
//! a user the hub stops admitting loses the session and cannot sign in
//! again, and a listed user cannot register there.

use std::time::{SystemTime, UNIX_EPOCH};

use gim_common::now_ms;
use gim_core::{GimError, SendFailure, SendState};
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert};
use gim_integration_testing::policy::{hub_container, DenyList};
use gim_integration_testing::{eventually, message, server_url, TestUser};
use gim_sdk::transport::{Transport, TransportError};
use gim_sdk::HttpTransport;

/// A seed unique to this run.
fn seed(n: u8) -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut seed = [n; 32];
    seed[..16].copy_from_slice(&nanos.to_le_bytes());
    seed[16..20].copy_from_slice(&std::process::id().to_le_bytes());
    seed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn deny_list_refuses_sign_in_and_registration() {
    let test = "deny_list_refuses_sign_in_and_registration";
    let (Some(url), Some(container)) = (server_url(test), hub_container(test)) else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    let chat = bob
        .client
        .create_direct_chat(alice.user_id.clone())
        .await
        .unwrap();
    let hub_id = alice.client.hubs().await.unwrap()[0].hub_id.clone();
    // A user that does not exist on the hub yet: its keys are made here.
    let root = RootKey::from_seed(&seed(1));
    let newcomer = root.public().user_id();
    let device = DeviceSigningKey::from_seed(&seed(2)).public();
    let cert = SignedDeviceCert::issue(&root, &device, now_ms(), 1);
    let list = DeviceList::new(root.public(), 1, vec![cert], vec![])
        .and_then(|list| list.sign(&root))
        .unwrap();

    let policy = DenyList::new(&container, &[&alice.user_id, newcomer.as_str()]);
    policy.applied().await;

    // Alice's session was deleted: the next call signs in once and gets
    // `UserNotAdmitted`.
    let found = alice.client.find_user(bob.handle.clone()).await;
    assert!(
        matches!(&found, Err(GimError::UserNotAdmitted { hub_id: h }) if *h == hub_id),
        "{found:?}"
    );
    // A send fails with that cause (no Retry in the app).
    let id = alice
        .client
        .send_text(chat.clone(), "anyone?".into(), None)
        .await
        .unwrap();
    let (timeline, _handle) = alice.timeline(&chat).await;
    timeline
        .wait("the send failed as not admitted", |items| {
            message(items, &id).is_some_and(|m| {
                matches!(
                    m.send_state,
                    Some(SendState::Failed {
                        cause: SendFailure::UserNotAdmitted,
                        ..
                    })
                )
            })
        })
        .await;
    // Bob is admitted and unaffected.
    let found = bob.client.find_user(alice.handle.clone()).await;
    assert!(found.is_ok(), "{found:?}");

    // The listed newcomer cannot register; nothing is stored.
    let http = HttpTransport::new(url.parse().unwrap()).unwrap();
    let registered = http.put_device_list(&newcomer, list.to_bytes()).await;
    assert!(
        matches!(registered, Err(TransportError::UserNotAdmitted { .. })),
        "{registered:?}"
    );
    assert_eq!(http.device_list(None, &newcomer).await.unwrap(), None);

    // Open again: the newcomer registers.
    drop(policy);
    eventually("the newcomer registers once the hub is open", || {
        let (http, bytes) = (&http, list.to_bytes());
        let newcomer = &newcomer;
        async move { http.put_device_list(newcomer, bytes).await.ok() }
    })
    .await;
}
