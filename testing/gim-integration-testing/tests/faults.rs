//! gim-sdk clients against a real gim-hub, with lost replies and an expired
//! cursor injected at the transport boundary (see `gim_integration_testing::sdk`).

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use gim_common::DeviceRef;
use gim_integration_testing::sdk::SdkDevice;
use gim_integration_testing::server_url;

fn devices(of: &[&SdkDevice]) -> BTreeSet<DeviceRef> {
    of.iter()
        .map(|d| d.client.session().unwrap().device)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn duplicate_commit_and_message_retry() {
    let Some(url) = server_url("duplicate_commit_and_message_retry") else {
        return;
    };
    let alice = SdkDevice::create(&url, "Alice").await;
    let bob = SdkDevice::create(&url, "Bob").await;
    let carol = SdkDevice::create(&url, "Carol").await;
    let g = alice
        .client
        .create_group_chat(Some("Crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    let epoch = alice.hub_group(&g).await.epoch;

    // The hub accepts the Add but its reply is lost: the client re-posts
    // the same Commit and the hub answers with the original result.
    alice
        .hub
        .faults
        .lose_commit_reply
        .store(true, Ordering::SeqCst);
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    let results = alice.hub.faults.commit_results.lock().unwrap().clone();
    let [.., first, retry] = results.as_slice() else {
        panic!("expected a re-post: {results:?}");
    };
    assert!(!first.duplicate);
    assert!(retry.duplicate, "{results:?}");
    assert_eq!((retry.seq, retry.epoch), (first.seq, first.epoch));
    let group = alice.hub_group(&g).await;
    assert_eq!(group.epoch, epoch + 1, "the Commit was applied once");
    assert_eq!(
        group.members.into_iter().collect::<BTreeSet<_>>(),
        devices(&[&alice, &bob, &carol])
    );

    // Same for an application message: re-posted with its client_id and
    // stored once.
    alice
        .hub
        .faults
        .lose_message_reply
        .store(true, Ordering::SeqCst);
    alice.client.send_text(&g, "hi carol", None).await.unwrap();
    let seqs = alice.hub.faults.message_seqs.lock().unwrap().clone();
    let [.., first, retry] = seqs.as_slice() else {
        panic!("expected a re-post: {seqs:?}");
    };
    assert_eq!(first, retry, "the hub returned the stored message");
    bob.sync().await;
    carol.sync().await;
    assert_eq!(bob.texts(&g), ["hi carol"]);
    assert_eq!(carol.texts(&g), ["hi carol"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn stale_epoch_race_between_two_devices() {
    let Some(url) = server_url("stale_epoch_race_between_two_devices") else {
        return;
    };
    let alice = SdkDevice::create(&url, "Alice").await;
    let bob = SdkDevice::create(&url, "Bob").await;
    let carol = SdkDevice::create(&url, "Carol").await;
    let dave = SdkDevice::create(&url, "Dave").await;
    let g = alice
        .client
        .create_group_chat(Some("Race".into()), &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    let epoch = alice.hub_group(&g).await.epoch;

    // Both devices commit from the same epoch; Bob has not seen Alice's
    // Commit, so the hub answers 409 stale_epoch and Bob's client catches
    // up and commits again on top.
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    bob.client.add_members(&g, &[dave.user_id()]).await.unwrap();
    let group = alice.hub_group(&g).await;
    assert_eq!(group.epoch, epoch + 2);
    assert_eq!(
        group.members.into_iter().collect::<BTreeSet<_>>(),
        devices(&[&alice, &bob, &carol, &dave])
    );

    // Everybody ends in the same epoch and reads everybody, also for
    // messages posted at the same time.
    let concurrent = tokio::join!(
        alice.client.send_text(&g, "from alice", None),
        bob.client.send_text(&g, "from bob", None),
    );
    concurrent.0.unwrap();
    concurrent.1.unwrap();
    for device in [&alice, &bob, &carol, &dave] {
        device.sync().await;
    }
    let expected = BTreeSet::from(["from alice".to_string(), "from bob".to_string()]);
    for (name, device) in [
        ("alice", &alice),
        ("bob", &bob),
        ("carol", &carol),
        ("dave", &dave),
    ] {
        let texts: BTreeSet<String> = device.texts(&g).into_iter().collect();
        assert_eq!(texts, expected, "{name}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn expired_cursor_recovers_through_pending_welcomes() {
    let Some(url) = server_url("expired_cursor_recovers_through_pending_welcomes") else {
        return;
    };
    let alice = SdkDevice::create(&url, "Alice").await;
    let bob = SdkDevice::create(&url, "Bob").await;
    let dm = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    alice.client.send_text(&dm, "before", None).await.unwrap();
    bob.sync().await;
    assert_eq!(bob.texts(&dm), ["before"]);

    // While Bob is away, Alice writes in the chat he is in and adds him to
    // a new group; then his cursor expires (410 at the hub's head cursor).
    alice
        .client
        .send_text(&dm, "while away", None)
        .await
        .unwrap();
    let group = alice
        .client
        .create_group_chat(Some("Crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    alice
        .client
        .send_text(&group, "in the group", None)
        .await
        .unwrap();
    bob.hub.faults.expire_cursor.store(true, Ordering::SeqCst);

    // Bob joins the group from the pending Welcomes and backfills both
    // chats by seq from the hub.
    bob.sync().await;
    assert!(!bob.hub.faults.expire_cursor.load(Ordering::SeqCst));
    assert_eq!(bob.texts(&dm), ["before", "while away"]);
    assert_eq!(bob.texts(&group), ["in the group"]);

    // And continues from the head cursor.
    alice.client.send_text(&group, "after", None).await.unwrap();
    bob.sync().await;
    assert_eq!(bob.texts(&group), ["in the group", "after"]);
    bob.client.send_text(&group, "back", None).await.unwrap();
    alice.sync().await;
    assert_eq!(alice.texts(&group), ["in the group", "after", "back"]);
}
