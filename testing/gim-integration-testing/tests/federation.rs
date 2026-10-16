//! Real gim-core clients on different hubs of a closed federation (see
//! `gim_integration_testing::federation`): users on hub a and hub b talk to
//! each other; hub x is on nobody's allowlist. Run with
//! `GIM_FEDERATION=1 scripts/integration-test.sh`, one test at a time (the
//! outage test stops hub b).

use std::collections::BTreeSet;
use std::fs;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gim_base::model::Membership;
use gim_base::StateReader;
use gim_common::{ClientId, DeviceRef, GroupId, UserId};
use gim_core::{GimError, MediaRef, MessageContent, TimelineItem};
use gim_integration_testing::federation::{Federation, Hub, FED_TIMEOUT};
use gim_integration_testing::sdk::{FaultyHub, SdkDevice};
use gim_integration_testing::{
    eventually, eventually_within, member_ids, message, text, Mirror, TestUser,
};
use gim_sdk::transport::{PostError, Transport, TransportError};

/// A valid 2x2 RGB PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a,
    0x73, 0x00, 0x00, 0x00, 0x11, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0x00, 0x04,
    0x50, 0xe2, 0xff, 0xff, 0xff, 0x00, 0x23, 0xec, 0x05, 0xfb, 0xd5, 0xaa, 0x1e, 0x66, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

fn devices(of: &[&SdkDevice]) -> BTreeSet<DeviceRef> {
    of.iter()
        .map(|d| d.client.session().unwrap().device)
        .collect()
}

/// Whether `group_id` is owned (sequenced) by `hub`.
fn owned_by(group_id: &str, hub: &Hub) -> bool {
    group_id.split_once('/').map(|(owner, _)| owner) == Some(hub.hub_id.as_str())
}

/// Syncs `device` until `check` holds; tolerates sync errors (a peer hub
/// may be coming back).
async fn sync_until(what: &str, device: &SdkDevice, check: impl Fn(&SdkDevice) -> bool) {
    eventually_within(what, FED_TIMEOUT, || async {
        let _ = device.client.sync_once().await;
        check(device).then_some(())
    })
    .await
}

fn joined(device: &SdkDevice, group_id: &GroupId) -> bool {
    device
        .store
        .chat(group_id)
        .unwrap()
        .is_some_and(|c| c.membership == Membership::Joined)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub federation: GIM_FEDERATION=1 scripts/integration-test.sh"]
async fn hosting_records_resolve_across_hubs() {
    let Some(fed) = Federation::from_env("hosting_records_resolve_across_hubs") else {
        return;
    };
    let alice = SdkDevice::create(&fed.a.url, "Alice").await;
    let bob = SdkDevice::create(&fed.b.url, "Bob").await;

    for (name, user, own, peer) in [
        ("alice", alice.user_id(), &fed.a, &fed.b),
        ("bob", bob.user_id(), &fed.b, &fed.a),
    ] {
        let published = FaultyHub::new(&own.url)
            .hosting_record(&user)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{name}'s record is not on the own hub"));
        assert!(published.hosted, "{name}: the own hub hosts the user");
        let peer_hub = FaultyHub::new(&peer.url);
        let resolved = eventually_within(
            &format!("{name}'s record on the peer hub"),
            FED_TIMEOUT,
            || async { peer_hub.hosting_record(&user).await.ok().flatten() },
        )
        .await;
        assert!(
            !resolved.hosted,
            "{name}: the peer hub does not host the user"
        );
        assert_eq!(resolved.seq, published.seq, "{name}");
        assert_eq!(resolved.record, published.record, "{name}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub federation: GIM_FEDERATION=1 scripts/integration-test.sh"]
async fn cross_hub_direct_chat() {
    let Some(fed) = Federation::from_env("cross_hub_direct_chat") else {
        return;
    };
    let alice = TestUser::register(&fed.a.url, "alice", "Alice").await;
    let bob = TestUser::register(&fed.b.url, "bob", "Bob").await;

    let chat = alice
        .client
        .create_direct_chat(bob.user_id.clone())
        .await
        .unwrap();
    assert!(owned_by(&chat, &fed.a), "{chat}");
    let (alice_timeline, _alice_handle) = alice.timeline(&chat).await;
    let (bob_chats, _bob_chats_handle) = bob.chat_list().await;

    // a -> b.
    let hello = alice
        .client
        .send_text(chat.clone(), "Leaving Split at 06:00".to_string(), None)
        .await
        .unwrap();
    bob_chats
        .wait("chat at bob", |c| c.iter().any(|c| c.chat_id == chat))
        .await;
    let (bob_timeline, _bob_handle) = bob.timeline(&chat).await;
    let items = bob_timeline
        .wait("hello at bob", |items| message(items, &hello).is_some())
        .await;
    let received = message(&items, &hello).unwrap();
    assert_eq!(text(&received), Some("Leaving Split at 06:00"));
    assert_eq!(received.sender.user_id, alice.user_id);

    // b -> a.
    let reply = bob
        .client
        .send_text(chat.clone(), "See you in Hvar".to_string(), None)
        .await
        .unwrap();
    let items = alice_timeline
        .wait("reply at alice", |items| message(items, &reply).is_some())
        .await;
    let received = message(&items, &reply).unwrap();
    assert_eq!(text(&received), Some("See you in Hvar"));
    assert_eq!(received.sender.user_id, bob.user_id);

    // An image each way: the message arrives with its media reference.
    for (from, to_timeline, caption) in [
        (&alice, &bob_timeline, "Stiniva bay"),
        (&bob, &alice_timeline, "Hvar harbour"),
    ] {
        let (id, media) = send_image(from, &chat, to_timeline, caption).await;
        assert_eq!(media.mime, "image/png");
        assert_eq!(media.size, PNG.len() as u64);
        assert_eq!(media.message_id, id);
    }
}

/// Sends [`PNG`] from `from` and waits for it in `to_timeline`; its id and
/// media reference there.
async fn send_image(
    from: &TestUser,
    chat: &str,
    to_timeline: &Mirror<TimelineItem>,
    caption: &str,
) -> (String, MediaRef) {
    let source = from.hooks.path(&format!("{caption}.png"));
    fs::write(&source, PNG).unwrap();
    let id = from
        .client
        .send_media(
            chat.to_string(),
            source.to_str().unwrap().to_string(),
            "image/png".to_string(),
            Some(caption.to_string()),
            None,
        )
        .await
        .unwrap();
    let items = to_timeline
        .wait(&format!("{caption} at the receiver"), |items| {
            message(items, &id).is_some()
        })
        .await;
    let MessageContent::Image {
        media, caption: c, ..
    } = message(&items, &id).unwrap().content
    else {
        panic!("not an image");
    };
    assert_eq!(c.as_deref(), Some(caption));
    (id, media)
}

/// The receiver of an image sent from another hub downloads it: the
/// receiver's hub fetches the blob from its origin hub (hub-v2
/// federation.md §5.6, gim-hub H5 at 18afc7bdde8cd643e4f4e21a35758fdb3a0bc155).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub federation: GIM_FEDERATION=1 scripts/integration-test.sh"]
async fn cross_hub_image_fetch() {
    let Some(fed) = Federation::from_env("cross_hub_image_fetch") else {
        return;
    };
    let alice = TestUser::register(&fed.a.url, "alice", "Alice").await;
    let bob = TestUser::register(&fed.b.url, "bob", "Bob").await;
    let chat = alice
        .client
        .create_direct_chat(bob.user_id.clone())
        .await
        .unwrap();
    let (bob_timeline, _handle) = bob.timeline(&chat).await;
    let (_, media) = send_image(&alice, &chat, &bob_timeline, "Stiniva bay").await;
    let dest = bob.hooks.path("downloaded.png");
    let path = bob
        .client
        .fetch_media(
            media.chat_id,
            media.message_id,
            dest.to_str().unwrap().to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("fetching an image uploaded to hub a from hub b: {e:?}"));
    assert_eq!(fs::read(path).unwrap(), PNG);
}

/// A group owned by hub a with members on a and b: create, add (from both
/// hubs), messages both ways, leave by Proposal from b, remove.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub federation: GIM_FEDERATION=1 scripts/integration-test.sh"]
async fn cross_hub_group() {
    let Some(fed) = Federation::from_env("cross_hub_group") else {
        return;
    };
    let alice = TestUser::register(&fed.a.url, "alice", "Alice").await;
    let carol = TestUser::register(&fed.a.url, "carol", "Carol").await;
    let bob = TestUser::register(&fed.b.url, "bob", "Bob").await;
    let dave = TestUser::register(&fed.b.url, "dave", "Dave").await;
    let ids = |users: &[&TestUser]| -> BTreeSet<String> {
        users.iter().map(|u| u.user_id.clone()).collect()
    };

    let chat = alice
        .client
        .create_group_chat("Crew Adriatic".to_string(), vec![bob.user_id.clone()])
        .await
        .unwrap();
    assert!(owned_by(&chat, &fed.a), "{chat}");
    let (alice_timeline, _alice_handle) = alice.timeline(&chat).await;
    let (bob_timeline, _bob_handle) = bob.timeline(&chat).await;
    let first = alice
        .client
        .send_text(chat.clone(), "Welcome aboard".to_string(), None)
        .await
        .unwrap();
    bob_timeline
        .wait("first at bob", |items| message(items, &first).is_some())
        .await;
    let back = bob
        .client
        .send_text(chat.clone(), "Thanks, skipper".to_string(), None)
        .await
        .unwrap();
    alice_timeline
        .wait("bob's answer at alice", |items| {
            message(items, &back).is_some()
        })
        .await;

    // Bob adds Dave from hub b (a Commit forwarded to the owner), Alice
    // adds Carol on hub a.
    bob.client
        .add_members(chat.clone(), vec![dave.user_id.clone()])
        .await
        .unwrap();
    eventually("dave added at alice", || async {
        (member_ids(&alice.client, &chat).await == ids(&[&alice, &bob, &dave])).then_some(())
    })
    .await;
    alice
        .client
        .add_members(chat.clone(), vec![carol.user_id.clone()])
        .await
        .unwrap();
    let all = ids(&[&alice, &bob, &carol, &dave]);
    assert_eq!(member_ids(&alice.client, &chat).await, all);

    let (carol_timeline, _carol_handle) = carol.timeline(&chat).await;
    let (dave_timeline, _dave_handle) = dave.timeline(&chat).await;
    let from_a = alice
        .client
        .send_text(chat.clone(), "Course 140, wind NW 4".to_string(), None)
        .await
        .unwrap();
    let from_b = dave
        .client
        .send_text(chat.clone(), "Dave on watch".to_string(), None)
        .await
        .unwrap();
    for (name, timeline) in [
        ("alice", &alice_timeline),
        ("bob", &bob_timeline),
        ("carol", &carol_timeline),
        ("dave", &dave_timeline),
    ] {
        timeline
            .wait(&format!("both messages at {name}"), |items| {
                message(items, &from_a).is_some() && message(items, &from_b).is_some()
            })
            .await;
    }

    // Dave leaves: his Proposal goes through hub b to the owner and a
    // member commits it.
    dave.client.leave_chat(chat.clone()).await.unwrap();
    let without_dave = ids(&[&alice, &bob, &carol]);
    for (name, user) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        eventually_within(&format!("dave removed at {name}"), FED_TIMEOUT, || async {
            (member_ids(&user.client, &chat).await == without_dave).then_some(())
        })
        .await;
    }
    assert!(matches!(
        dave.client
            .send_text(chat.clone(), "still here?".to_string(), None)
            .await,
        Err(GimError::InvalidInput { .. })
    ));

    // Alice removes Bob: later messages reach Carol, not Bob or Dave.
    alice
        .client
        .remove_member(chat.clone(), bob.user_id.clone())
        .await
        .unwrap();
    assert_eq!(
        member_ids(&alice.client, &chat).await,
        ids(&[&alice, &carol])
    );
    let secret = alice
        .client
        .send_text(chat.clone(), "Secret course to Vis".to_string(), None)
        .await
        .unwrap();
    carol_timeline
        .wait("secret at carol", |items| message(items, &secret).is_some())
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (name, timeline) in [("bob", &bob_timeline), ("dave", &dave_timeline)] {
        assert!(
            message(&timeline.get(), &secret).is_none(),
            "{name} read a message sent after leaving the group"
        );
    }
}

/// Members on hub a and hub b commit at the same epoch: one Commit wins,
/// the other gets 409 `stale_epoch`, catches up and commits again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub federation: GIM_FEDERATION=1 scripts/integration-test.sh"]
async fn concurrent_commits_across_hubs() {
    let Some(fed) = Federation::from_env("concurrent_commits_across_hubs") else {
        return;
    };
    let alice = SdkDevice::create(&fed.a.url, "Alice").await;
    let carol = SdkDevice::create(&fed.a.url, "Carol").await;
    let bob = SdkDevice::create(&fed.b.url, "Bob").await;
    let dave = SdkDevice::create(&fed.b.url, "Dave").await;
    let g = alice
        .client
        .create_group_chat(Some("Race".into()), &[bob.user_id()])
        .await
        .unwrap();
    assert!(owned_by(g.as_str(), &fed.a), "{g}");
    sync_until("bob joined", &bob, |d| joined(d, &g)).await;
    let epoch = alice.hub_group(&g).await.epoch;

    let (carol_id, dave_id) = (carol.user_id(), dave.user_id());
    let (by_alice, by_bob) = tokio::join!(
        alice
            .client
            .add_members(&g, std::slice::from_ref(&carol_id)),
        bob.client.add_members(&g, std::slice::from_ref(&dave_id)),
    );
    by_alice.unwrap();
    by_bob.unwrap();
    let stale = alice.hub.faults.stale_commits.load(Ordering::SeqCst)
        + bob.hub.faults.stale_commits.load(Ordering::SeqCst);
    assert!(stale >= 1, "one of the Commits lost the epoch");
    let group = alice.hub_group(&g).await;
    assert_eq!(group.epoch, epoch + 2);
    assert_eq!(
        group.members.into_iter().collect::<BTreeSet<_>>(),
        devices(&[&alice, &bob, &carol, &dave])
    );

    // Everybody reaches the same epoch and reads both hubs' messages.
    let (from_alice, from_bob) = tokio::join!(
        alice.client.send_text(&g, "from alice", None),
        bob.client.send_text(&g, "from bob", None),
    );
    from_alice.unwrap();
    from_bob.unwrap();
    let expected = BTreeSet::from(["from alice".to_string(), "from bob".to_string()]);
    for (name, device) in [
        ("alice", &alice),
        ("bob", &bob),
        ("carol", &carol),
        ("dave", &dave),
    ] {
        sync_until(&format!("both messages at {name}"), device, |d| {
            d.texts(&g).into_iter().collect::<BTreeSet<_>>() == expected
        })
        .await;
        assert_eq!(device.texts(&g).len(), 2, "{name}: no duplicates");
    }
}

/// Hub b is down: a message from hub a to a b-owned group and an invite of
/// a b user are retried (503 / `unavailable`) and go through once b is
/// back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub federation: GIM_FEDERATION=1 scripts/integration-test.sh"]
async fn peer_outage_and_recovery() {
    let Some(fed) = Federation::from_env("peer_outage_and_recovery") else {
        return;
    };
    let alice = SdkDevice::create(&fed.a.url, "Alice").await;
    let bob = SdkDevice::create(&fed.b.url, "Bob").await;
    let dave = SdkDevice::create(&fed.b.url, "Dave").await;
    let owned_by_b = bob
        .client
        .create_group_chat(Some("Owned by b".into()), &[alice.user_id()])
        .await
        .unwrap();
    assert!(owned_by(owned_by_b.as_str(), &fed.b), "{owned_by_b}");
    sync_until("alice joined", &alice, |d| joined(d, &owned_by_b)).await;
    // Hub a knows Dave's hosting record before b goes down.
    let dave_id = dave.user_id();
    let a_hub = FaultyHub::new(&fed.a.url);
    eventually_within("dave's record on hub a", FED_TIMEOUT, || async {
        a_hub.hosting_record(&dave_id).await.ok().flatten()
    })
    .await;

    fed.b.stop();
    // Hub b runs again for the other tests whatever happens.
    let _restart = Restart(&fed.b);
    let sender = alice.client.start_outbox_sender();
    alice
        .client
        .send_text(&owned_by_b, "while b is down", None)
        .await
        .unwrap();
    eventually_within("the post failed at the owner", FED_TIMEOUT, || async {
        let failures = alice.hub.faults.peer_failures.lock().unwrap().clone();
        failures
            .iter()
            .any(|e| matches!(e, TransportError::PeerUnavailable { .. }))
            .then_some(())
    })
    .await;

    let owned_by_a = alice
        .client
        .create_group_chat(Some("Owned by a".into()), std::slice::from_ref(&dave_id))
        .await
        .unwrap();
    assert!(alice
        .hub
        .faults
        .unavailable_claims
        .lock()
        .unwrap()
        .contains(&dave_id));
    assert_eq!(
        alice.client.pending_invites(&owned_by_a),
        std::slice::from_ref(&dave_id)
    );

    fed.b.start().await;
    sync_until("the message at bob", &bob, |d| {
        d.texts(&owned_by_b) == ["while b is down"]
    })
    .await;
    drop(sender);
    eventually_within("dave invited", FED_TIMEOUT, || async {
        let _ = alice.client.retry_pending_invites().await;
        alice
            .client
            .pending_invites(&owned_by_a)
            .is_empty()
            .then_some(())
    })
    .await;
    sync_until("dave joined", &dave, |d| joined(d, &owned_by_a)).await;
    alice
        .client
        .send_text(&owned_by_a, "welcome dave", None)
        .await
        .unwrap();
    sync_until("the message at dave", &dave, |d| {
        d.texts(&owned_by_a) == ["welcome dave"]
    })
    .await;
}

/// Starts the hub when dropped, e.g. by a failing assertion.
struct Restart<'a>(&'a Hub);

impl Drop for Restart<'_> {
    fn drop(&mut self) {
        self.0.start_container();
    }
}

/// `message` (an MLSMessage of a PrivateMessage) with its plaintext
/// `group_id` replaced by `group_id` (RFC 9420 §6.3.2: version, wire format,
/// then the group id as a variable-length vector, §2.1.2).
fn readdress(message: &[u8], group_id: &GroupId) -> Vec<u8> {
    let (header, rest) = message.split_at(4);
    assert_eq!(header[2..], [0, 2], "not a PrivateMessage");
    let (len, prefix) = match rest[0] >> 6 {
        0 => (usize::from(rest[0] & 0x3f), 1),
        1 => (
            usize::from(u16::from_be_bytes([rest[0] & 0x3f, rest[1]])),
            2,
        ),
        _ => panic!("group id too long"),
    };
    let id = group_id.as_str().as_bytes();
    let mut out = header.to_vec();
    match u16::try_from(id.len()).unwrap() {
        n @ 0..=0x3f => out.push(n as u8),
        n @ 0x40..=0x3fff => out.extend_from_slice(&(n | 0x4000).to_be_bytes()),
        _ => panic!("group id too long"),
    }
    out.extend_from_slice(id);
    out.extend_from_slice(&rest[prefix + len..]);
    out
}

/// Hub x is on nobody's allowlist: hub a refuses its `Hello`, so nothing
/// of x's users reaches a, and a's users cannot reach them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub federation: GIM_FEDERATION=1 scripts/integration-test.sh"]
async fn non_allowlisted_hub_refused() {
    let Some(fed) = Federation::from_env("non_allowlisted_hub_refused") else {
        return;
    };
    let alice = SdkDevice::create(&fed.a.url, "Alice").await;
    let bob = SdkDevice::create(&fed.b.url, "Bob").await;
    let eve = SdkDevice::create(&fed.x.url, "Eve").await;
    let g = alice
        .client
        .create_group_chat(Some("Closed".into()), &[bob.user_id()])
        .await
        .unwrap();
    let eve_token = eve.client.session().unwrap().token;
    let alice_token = alice.client.session().unwrap().token;

    // Hub a refused hub x's Hello (x dials a, the only hub on its
    // allowlist).
    let refused = fed.a.logs().lines().any(|line| {
        line.contains("Hello refused")
            && line.contains(&fed.x.hub_id)
            && line.contains("hub not allowlisted")
    });
    assert!(refused, "hub a did not log the refusal of hub x");

    // Eve cannot resolve Alice or claim her KeyPackages through hub x.
    let alice_id = alice.user_id();
    let x_hub = FaultyHub::new(&fed.x.url);
    assert!(
        !matches!(x_hub.hosting_record(&alice_id).await, Ok(Some(_))),
        "hub x resolved alice's hosting record"
    );
    let claim = eve
        .hub
        .claim_key_packages_federated(&eve_token, std::slice::from_ref(&alice_id))
        .await
        .unwrap();
    eprintln!("eve's claim of alice: {claim:?}");
    assert!(claim.key_packages.is_empty(), "{claim:?}");
    // A direct chat with her adds nobody.
    let dm = eve.client.create_direct_chat(&alice_id).await;
    eprintln!("eve's direct chat with alice: {dm:?}");
    if let Ok(dm) = &dm {
        let members = eve.hub_group(dm).await.members;
        assert_eq!(
            members.into_iter().collect::<BTreeSet<_>>(),
            devices(&[&eve])
        );
    }

    // Eve posts to the group owned by hub a through hub x (an MLS message
    // of her own chat on x, readdressed to that group): rejected, and
    // nothing reaches hub a.
    let mallory = SdkDevice::create(&fed.x.url, "Mallory").await;
    let own = eve
        .client
        .create_direct_chat(&mallory.user_id())
        .await
        .unwrap();
    eve.client.send_text(&own, "hi", None).await.unwrap();
    let mls_message = eve.hub.faults.last_message.lock().unwrap().clone().unwrap();
    let mls_message = readdress(&mls_message, &g);
    let last_seq = alice.hub_group(&g).await.last_seq;
    let err = eve
        .hub
        .post_message(&eve_token, &g, ClientId::new("eve-1").unwrap(), mls_message)
        .await
        .unwrap_err();
    eprintln!("eve's post to a group owned by hub a: {err:?}");
    assert!(
        matches!(
            err,
            PostError::Transport(TransportError::PeerRefused(_) | TransportError::NotFound(_))
        ),
        "{err:?}"
    );
    assert_eq!(alice.hub_group(&g).await.last_seq, last_seq);
    alice.sync().await;
    assert!(alice.texts(&g).is_empty());

    // Alice cannot resolve Eve or claim her KeyPackages.
    let eve_id: UserId = eve.user_id();
    let claim = alice
        .hub
        .claim_key_packages_federated(&alice_token, std::slice::from_ref(&eve_id))
        .await
        .unwrap();
    eprintln!("alice's claim of eve: {claim:?}");
    assert!(claim.key_packages.is_empty(), "{claim:?}");
    assert!(
        !matches!(
            FaultyHub::new(&fed.a.url).hosting_record(&eve_id).await,
            Ok(Some(_))
        ),
        "hub a resolved eve's hosting record"
    );
}
