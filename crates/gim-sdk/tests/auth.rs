//! Sign-in retries and fail-closed DeviceList fetching against a hub that
//! misbehaves on purpose.

mod common;

use common::{Device, FlakyTransport};
use gim_base::model::Membership;
use gim_base::StateReader;
use gim_sdk::transport::{SessionError, TransportError};
use gim_sdk::ClientError;

#[tokio::test]
async fn invalid_challenge_is_retried_once() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let before = alice.client.session().unwrap();

    // One stale challenge: a fresh one signs in.
    transport.inner.service().expire_sessions(&before.device);
    transport
        .faults
        .sessions
        .lock()
        .unwrap()
        .push_back(SessionError::InvalidChallenge);
    alice.sync().await;
    let after = alice.client.session().unwrap();
    assert_ne!(after.token, before.token);

    // A fresh challenge rejected too is an error, not a sign-out.
    transport.inner.service().expire_sessions(&after.device);
    transport.faults.sessions.lock().unwrap().extend([
        SessionError::InvalidChallenge,
        SessionError::InvalidChallenge,
    ]);
    let result = alice.client.sync_once().await;
    assert!(
        matches!(
            result,
            Err(ClientError::Transport(TransportError::Server(_)))
        ),
        "{result:?}"
    );
    assert!(alice.client.session().is_some());
    alice.sync().await;
}

#[tokio::test]
async fn rejected_signature_signs_out() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    transport.inner.service().expire_sessions(&alice.device());
    transport
        .faults
        .sessions
        .lock()
        .unwrap()
        .push_back(SessionError::Rejected("invalid_signature".into()));
    let result = alice.client.sync_once().await;
    assert!(
        matches!(result, Err(ClientError::DeviceNotActive(_))),
        "{result:?}"
    );
    assert!(alice.client.session().is_none());
}

/// Alice invites bob while the hub answers bob's first `hidden` fetches of
/// her DeviceList with "unknown".
async fn invite_with_hidden_list(
    hidden: usize,
) -> (FlakyTransport, Device, Device, gim_common::GroupId) {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    transport
        .faults
        .hidden_lists
        .lock()
        .unwrap()
        .insert(alice.user_id(), hidden);
    transport.faults.list_requests.lock().unwrap().clear();
    bob.sync().await;
    (transport, alice, bob, g)
}

#[tokio::test]
async fn unknown_device_list_is_fetched_and_retried_once() {
    let (transport, alice, bob, g) = invite_with_hidden_list(1).await;
    let fetches = |transport: &FlakyTransport| {
        transport
            .faults
            .list_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|u| **u == alice.user_id())
            .count()
    };
    // The pre-fetch got nothing; the Welcome fails with
    // `device_list_unknown`, the retry fetches the list and joins.
    assert_eq!(fetches(&transport), 2);
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.membership, Membership::Joined);
}

#[tokio::test]
async fn second_unknown_device_list_rejects_the_welcome() {
    let (transport, _alice, bob, g) = invite_with_hidden_list(2).await;
    assert!(bob
        .store
        .chat(&g)
        .unwrap()
        .is_none_or(|chat| chat.membership != Membership::Joined));

    // The rejected Welcome does not block later syncs.
    assert_eq!(transport.faults.list_requests.lock().unwrap().len(), 2);
    bob.sync().await;
}
