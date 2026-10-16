//! Multi-homing (M2c) against three real hubs of a closed federation (see
//! `gim_integration_testing::federation`, `GIM_FED_HUBS=3`): a user listed
//! on two hubs adds and removes hubs, keeps messaging while one of them is
//! stopped, receives every message once and never gets a KeyPackage claimed
//! twice. Run with `GIM_MULTIHOMING=1 scripts/integration-test.sh`, one test
//! at a time (some tests stop hub a).
//!
//! M2c acceptance ("a user on two hubs keeps messaging when one hub is
//! stopped; no duplicate messages; no KeyPackage claimed twice"):
//! [`failover_keeps_messaging_while_the_primary_hub_is_stopped`],
//! [`added_hub_is_listed_learned_by_a_linked_device_and_delivers_once`] and
//! [`key_packages_are_disjoint_per_hub_and_never_claimed_twice`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use std::time::Duration;

use gim_base::model::{HubState, Membership};
use gim_base::StateReader;
use gim_common::{now_ms, GroupId, UserId};
use gim_crypto::MlsEngine;
use gim_identity::SignedHostingRecord;
use gim_integration_testing::eventually_within;
use gim_integration_testing::federation::{Federation, Hub, FED_TIMEOUT};
use gim_integration_testing::sdk::{FaultyHub, SdkDevice};
use gim_proto::envelope::{Content, HubLocation};
use gim_sdk::transport::Transport;
use gim_sdk::{ClientError, HubStatus};

/// The federation with hub c, or `None` when the test should be skipped.
fn three_hubs(test: &str) -> Option<(Federation, Hub)> {
    let fed = Federation::from_env(test)?;
    let c = fed.c.clone().expect("GIM_FED_HUBS=3: hub c");
    Some((fed, c))
}

/// Whether `group_id` is owned (sequenced) by `hub`.
fn owned_by(group_id: &GroupId, hub: &Hub) -> bool {
    group_id.as_str().split_once('/').map(|(owner, _)| owner) == Some(hub.hub_id.as_str())
}

/// Syncs `device` until `check` holds; tolerates sync errors (a hub may be
/// stopped or coming back). On timeout, panics with the device's view of
/// its hubs.
async fn sync_until(what: &str, device: &SdkDevice, check: impl Fn(&SdkDevice) -> bool) {
    let deadline = tokio::time::Instant::now() + FED_TIMEOUT;
    loop {
        let synced = device.client.sync_once().await.map(drop);
        if check(device) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for {what}; last sync: {synced:?}\n{}",
                dump(device).await
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The device's hubs, cursors, chats and the group messages each hub
/// delivered, for timeout messages.
async fn dump(device: &SdkDevice) -> String {
    let mut out = format!("hubs: {:?}\n", device.client.hubs().await);
    out += &format!("home cursor: {:?}\n", device.store.global_cursor().unwrap());
    for hub in device.client.hubs().await.unwrap_or_default() {
        out += &format!(
            "cursor on {}: {:?}\n",
            hub.hub.hub_id,
            device.store.hub_cursor(&hub.hub.hub_id).unwrap()
        );
    }
    for chat in device.store.chats().unwrap() {
        out += &format!(
            "chat {} {:?}: seqs {:?}\n",
            chat.group_id,
            chat.membership,
            stored_seqs(device, &chat.group_id)
        );
    }
    let mut hubs = vec![device.hub.clone()];
    hubs.extend(device.hubs.lock().unwrap().values().cloned());
    for hub in hubs {
        out += &format!(
            "{:?} delivered {:?}\n",
            hub.base_url(),
            hub.faults.delivered.lock().unwrap()
        );
    }
    out
}

fn joined(device: &SdkDevice, group_id: &GroupId) -> bool {
    device
        .store
        .chat(group_id)
        .unwrap()
        .is_some_and(|c| c.membership == Membership::Joined)
}

fn has_texts(device: &SdkDevice, group_id: &GroupId, texts: &[&str]) -> bool {
    let have = device.texts(group_id);
    texts.iter().all(|t| have.iter().any(|h| h == t))
}

/// The seqs of `group_id`'s messages stored on `device`.
fn stored_seqs(device: &SdkDevice, group_id: &GroupId) -> BTreeSet<u64> {
    device
        .messages(group_id)
        .into_iter()
        .filter_map(|m| m.seq)
        .collect()
}

/// Whether the hub at `url` delivered every stored message of `group_id`
/// that another device sent to `device` (in its events; a hub does not
/// echo a device's own messages).
fn delivered_all(device: &SdkDevice, url: &str, group_id: &GroupId) -> bool {
    let delivered: BTreeSet<u64> = device
        .hub(url)
        .faults
        .delivered
        .lock()
        .unwrap()
        .iter()
        .filter(|(g, _)| g == group_id)
        .map(|(_, seq)| *seq)
        .collect();
    let own = device.client.session().unwrap().device;
    let stored: BTreeSet<u64> = device
        .messages(group_id)
        .into_iter()
        .filter(|m| m.sender != own)
        .filter_map(|m| m.seq)
        .collect();
    !stored.is_empty() && stored.is_subset(&delivered)
}

/// Every text appears once.
fn assert_no_duplicates(name: &str, texts: &[String]) {
    let unique: BTreeSet<&String> = texts.iter().collect();
    assert_eq!(unique.len(), texts.len(), "{name}: duplicates in {texts:?}");
}

async fn hub_status(device: &SdkDevice, hub_id: &str) -> Option<HubStatus> {
    device
        .client
        .hubs()
        .await
        .unwrap()
        .into_iter()
        .find(|h| h.hub.hub_id == hub_id)
}

/// Syncs `device` until it is signed in on the verified hub `hub`.
async fn sync_until_signed_in(what: &str, device: &SdkDevice, hub: &Hub) {
    eventually_within(what, FED_TIMEOUT, || async {
        let _ = device.client.sync_once().await;
        hub_status(device, &hub.hub_id)
            .await
            .filter(|h| h.hub.state == HubState::Verified && h.signed_in)
            .map(drop)
    })
    .await
}

/// `(hosted, [(hub_id, priority)])` of `user`'s hosting record as `hub`
/// serves it; `None` if it has none.
async fn record_on(hub: &Hub, user: &UserId) -> Option<(bool, Vec<(String, u8)>)> {
    let stored = FaultyHub::new(&hub.url).hosting_record(user).await.ok()??;
    let record = SignedHostingRecord::from_bytes(&stored.record)
        .and_then(|r| r.verify(now_ms()))
        .unwrap();
    assert_eq!(record.user_id(), user);
    let hubs = record
        .hubs()
        .iter()
        .map(|e| (e.hub_id(), e.priority()))
        .collect();
    Some((stored.hosted, hubs))
}

/// Alice, created on `home` and with `other` added (priority 1).
async fn homed_on_two(home: &Hub, other: &Hub) -> SdkDevice {
    let alice = SdkDevice::create(&home.url, "Alice").await;
    let added = alice.client.add_hub(&other.url).await.unwrap();
    assert_eq!(added.hub.hub_id, other.hub_id);
    assert_eq!(added.hub.state, HubState::Verified);
    assert_eq!(added.hub.priority, 1);
    assert!(added.signed_in && !added.home, "{added:?}");
    alice
}

/// Starts the hub when dropped, e.g. by a failing assertion.
struct Restart<'a>(&'a Hub);

impl Drop for Restart<'_> {
    fn drop(&mut self) {
        self.0.start_container();
    }
}

/// Add hub: alice (on a) adds b. Both hubs store a record listing a and b
/// and c resolves it; a device linked afterwards learns b's URL through
/// the self group, verifies it with the hub proof and signs in there.
/// A message from bob on c reaches both of alice's devices through both
/// hubs and is stored once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs 3 federated hubs: GIM_MULTIHOMING=1 scripts/integration-test.sh"]
async fn added_hub_is_listed_learned_by_a_linked_device_and_delivers_once() {
    let Some((fed, c)) =
        three_hubs("added_hub_is_listed_learned_by_a_linked_device_and_delivers_once")
    else {
        return;
    };
    let alice = homed_on_two(&fed.a, &fed.b).await;
    let alice_id = alice.user_id();
    let listed = vec![(fed.a.hub_id.clone(), 0), (fed.b.hub_id.clone(), 1)];
    for hub in [&fed.a, &fed.b] {
        let record = record_on(hub, &alice_id).await;
        assert_eq!(record, Some((true, listed.clone())), "on {}", hub.hub_id);
    }
    eventually_within("c resolves alice's record", FED_TIMEOUT, || async {
        (record_on(&c, &alice_id).await == Some((false, listed.clone()))).then_some(())
    })
    .await;

    let phone = alice.link(&fed.a.url).await;
    sync_until_signed_in("the phone signed in on b", &phone, &fed.b).await;
    let on_b = hub_status(&phone, &fed.b.hub_id).await.unwrap();
    assert!(on_b.hub.url_shared, "the phone got b's URL from alice");
    assert_eq!(on_b.hub.url.as_deref(), Some(fed.b.url.as_str()));
    assert!(phone.hub(&fed.b.url).faults.sign_ins.load(Ordering::SeqCst) > 0);

    let bob = SdkDevice::create(&c.url, "Bob").await;
    let g = bob.client.create_direct_chat(&alice_id).await.unwrap();
    assert!(owned_by(&g, &c), "{g}");
    bob.client
        .send_text(&g, "Anchored in Vis", None)
        .await
        .unwrap();
    for (name, device) in [("alice", &alice), ("phone", &phone)] {
        sync_until(&format!("the message via a and b at {name}"), device, |d| {
            has_texts(d, &g, &["Anchored in Vis"])
                && delivered_all(d, &fed.a.url, &g)
                && delivered_all(d, &fed.b.url, &g)
        })
        .await;
        assert_eq!(device.texts(&g), ["Anchored in Vis"], "{name}");
    }
}

/// Failover: hub a, alice's primary (and home) hub, is stopped. Alice's
/// messages go through b, messages from bob (c) and carol (b) reach her
/// devices through b. After a is back, a delivers the backlog: every
/// device holds every message once, in the same order, and the cursors on
/// both hubs moved on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs 3 federated hubs: GIM_MULTIHOMING=1 scripts/integration-test.sh"]
async fn failover_keeps_messaging_while_the_primary_hub_is_stopped() {
    let Some((fed, c)) = three_hubs("failover_keeps_messaging_while_the_primary_hub_is_stopped")
    else {
        return;
    };
    let alice = homed_on_two(&fed.a, &fed.b).await;
    let phone = alice.link(&fed.a.url).await;
    sync_until_signed_in("the phone signed in on b", &phone, &fed.b).await;
    let bob = SdkDevice::create(&c.url, "Bob").await;
    let carol = SdkDevice::create(&fed.b.url, "Carol").await;
    let g = bob
        .client
        .create_group_chat(
            Some("Crew Ionian".into()),
            &[alice.user_id(), carol.user_id()],
        )
        .await
        .unwrap();
    assert!(owned_by(&g, &c), "{g}");
    for (name, device) in [("alice", &alice), ("phone", &phone), ("carol", &carol)] {
        sync_until(&format!("{name} joined"), device, |d| joined(d, &g)).await;
    }
    bob.client
        .send_text(&g, "Leaving Corfu", None)
        .await
        .unwrap();
    for (name, device) in [("alice", &alice), ("phone", &phone)] {
        sync_until(&format!("the first message at {name}"), device, |d| {
            has_texts(d, &g, &["Leaving Corfu"]) && delivered_all(d, &fed.a.url, &g)
        })
        .await;
    }
    let cursor_a = alice.store.global_cursor().unwrap().unwrap();
    let cursor_b = alice.store.hub_cursor(&fed.b.hub_id).unwrap().unwrap();

    fed.a.stop();
    // Hub a runs again for the other tests whatever happens.
    let restart = Restart(&fed.a);
    let on_b = alice.hub(&fed.b.url);
    let id = alice
        .client
        .send_text(&g, "Alice via b", None)
        .await
        .unwrap();
    let posted = on_b.faults.message_posts.lock().unwrap().clone();
    assert!(
        posted
            .iter()
            .any(|(client_id, _)| client_id.as_str() == id.as_str()),
        "alice's message was not submitted to b: {posted:?}"
    );
    bob.client
        .send_text(&g, "Bob while a is down", None)
        .await
        .unwrap();
    carol
        .client
        .send_text(&g, "Carol while a is down", None)
        .await
        .unwrap();
    let all = [
        "Leaving Corfu",
        "Alice via b",
        "Bob while a is down",
        "Carol while a is down",
    ];
    for (name, device) in [
        ("alice", &alice),
        ("phone", &phone),
        ("bob", &bob),
        ("carol", &carol),
    ] {
        sync_until(
            &format!("every message at {name} while a is down"),
            device,
            |d| has_texts(d, &g, &all),
        )
        .await;
    }

    fed.a.start().await;
    drop(restart);
    let order = bob.texts(&g);
    assert_eq!(order.len(), all.len(), "{order:?}");
    for (name, device) in [("alice", &alice), ("phone", &phone)] {
        sync_until(&format!("a's backlog at {name}"), device, |d| {
            delivered_all(d, &fed.a.url, &g) && delivered_all(d, &fed.b.url, &g)
        })
        .await;
        let texts = device.texts(&g);
        assert_no_duplicates(name, &texts);
        assert_eq!(texts, order, "{name}: the timeline order");
    }
    assert_eq!(carol.texts(&g), order, "carol: the timeline order");
    assert!(alice.store.global_cursor().unwrap().unwrap() > cursor_a);
    assert!(alice.store.hub_cursor(&fed.b.hub_id).unwrap().unwrap() > cursor_b);
}

/// The ledger entries of `devices`: `kp_ref` -> (hub id, last resort).
fn ledger(devices: &[&SdkDevice]) -> BTreeMap<Vec<u8>, (String, bool)> {
    let mut ledger = BTreeMap::new();
    for device in devices {
        for record in device.store.key_package_records().unwrap() {
            let previous = ledger.insert(
                record.kp_ref.clone(),
                (record.hub_id.clone(), record.last_resort),
            );
            assert!(previous.is_none(), "a kp_ref is in two ledgers");
        }
    }
    ledger
}

/// The `kp_ref`s of `user`'s KeyPackages the hub of `claimer` handed out,
/// from claim number `from` on.
fn claimed_refs(claimer: &SdkDevice, user: &UserId, from: usize) -> Vec<Vec<u8>> {
    let engine = MlsEngine::new();
    claimer.hub.faults.claimed.lock().unwrap()[from..]
        .iter()
        .filter(|k| &k.device.user_id == user)
        .map(|k| engine.key_package_ref(&k.key_package).unwrap())
        .collect()
}

/// KeyPackages: alice's two devices each hold their own KeyPackages and
/// last-resort KeyPackage on a and on b. Users on a, b and c add alice
/// (claims served by a, b and by a through c), then with a stopped (by b,
/// also through c). Every claimed one-time KeyPackage is distinct and came
/// from the hub that served the claim; once b's one-time KeyPackages are
/// used up, b hands out its last-resort ones, which still let alice join,
/// and alice tops b up with fresh ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs 3 federated hubs: GIM_MULTIHOMING=1 scripts/integration-test.sh"]
async fn key_packages_are_disjoint_per_hub_and_never_claimed_twice() {
    let Some((fed, c)) = three_hubs("key_packages_are_disjoint_per_hub_and_never_claimed_twice")
    else {
        return;
    };
    let alice = homed_on_two(&fed.a, &fed.b).await;
    let phone = alice.link(&fed.a.url).await;
    sync_until_signed_in("the phone signed in on b", &phone, &fed.b).await;
    let alice_id = alice.user_id();
    // Each device holds one last-resort KeyPackage per hub.
    let phone_device = phone.client.session().unwrap().device;
    sync_until("the phone's KeyPackages on b", &phone, |d| {
        ledger(&[d])
            .values()
            .any(|(hub_id, last_resort)| *hub_id == fed.b.hub_id && *last_resort)
    })
    .await;
    for (name, device) in [("alice", &alice), ("phone", &phone)] {
        let mut last_resort: Vec<String> = ledger(&[device])
            .into_values()
            .filter(|(_, last_resort)| *last_resort)
            .map(|(hub_id, _)| hub_id)
            .collect();
        last_resort.sort();
        let mut expected = vec![fed.a.hub_id.clone(), fed.b.hub_id.clone()];
        expected.sort();
        assert_eq!(last_resort, expected, "{name}: one last resort per hub");
    }

    let dave = SdkDevice::create(&fed.a.url, "Dave").await;
    let carol = SdkDevice::create(&fed.b.url, "Carol").await;
    let bob = SdkDevice::create(&c.url, "Bob").await;
    let erin = SdkDevice::create(&c.url, "Erin").await;
    let mut groups = Vec::new();
    // (claimer, the hub whose KeyPackages it must get)
    let mut served = Vec::new();
    for (claimer, hub) in [(&dave, &fed.a), (&carol, &fed.b), (&bob, &fed.a)] {
        let from = claimer.hub.faults.claimed.lock().unwrap().len();
        let g = claimer
            .client
            .create_group_chat(Some("Regatta".into()), std::slice::from_ref(&alice_id))
            .await
            .unwrap();
        groups.push(g);
        served.push((claimed_refs(claimer, &alice_id, from), hub.hub_id.clone()));
    }

    // A group owned by a cannot be joined while a is down (its creator's
    // DeviceList is on a only): alice's devices join these first.
    for (name, device) in [("alice", &alice), ("phone", &phone)] {
        sync_until(&format!("{name} joined the first groups"), device, |d| {
            groups.iter().all(|g| joined(d, g))
        })
        .await;
    }

    fed.a.stop();
    let restart = Restart(&fed.a);
    for claimer in [&carol, &erin] {
        let from = claimer.hub.faults.claimed.lock().unwrap().len();
        let g = claimer
            .client
            .create_group_chat(
                Some("While a is down".into()),
                std::slice::from_ref(&alice_id),
            )
            .await
            .unwrap();
        groups.push(g);
        served.push((claimed_refs(claimer, &alice_id, from), fed.b.hub_id.clone()));
    }
    for (name, device) in [("alice", &alice), ("phone", &phone)] {
        sync_until(&format!("{name} joined every group"), device, |d| {
            groups.iter().all(|g| joined(d, g))
        })
        .await;
    }

    let known = ledger(&[&alice, &phone]);
    let mut one_time = BTreeSet::new();
    for (i, (refs, hub_id)) in served.iter().enumerate() {
        assert_eq!(refs.len(), 2, "claim {i}: one KeyPackage per device");
        for kp_ref in refs {
            let (from_hub, last_resort) = known.get(kp_ref).expect("a KeyPackage alice made");
            assert_eq!(from_hub, hub_id, "claim {i}: served from the routed hub");
            assert!(!last_resort, "claim {i}: one-time KeyPackages are left");
            assert!(one_time.insert(kp_ref.clone()), "claim {i}: claimed twice");
        }
    }

    // Use up b's one-time KeyPackages of the phone: b then hands out the
    // phone's last-resort KeyPackage, again and again.
    let token = carol.client.session().unwrap().token;
    let engine = MlsEngine::new();
    let mut last_resort_claims = 0;
    for _ in 0..(2 * gim_sdk::KEY_PACKAGE_BATCH + 10) {
        let claim = carol
            .hub
            .claim_key_packages_federated(&token, std::slice::from_ref(&alice_id))
            .await
            .unwrap();
        let phone_kp = claim
            .key_packages
            .iter()
            .find(|k| k.device == phone_device)
            .expect("a KeyPackage of the phone");
        let kp_ref = engine.key_package_ref(&phone_kp.key_package).unwrap();
        let (hub_id, last_resort) = known.get(&kp_ref).expect("a KeyPackage of the phone");
        assert_eq!(*hub_id, fed.b.hub_id);
        if *last_resort {
            last_resort_claims += 1;
            if last_resort_claims == 2 {
                break;
            }
        } else {
            assert!(
                one_time.insert(kp_ref),
                "a one-time KeyPackage claimed twice"
            );
        }
    }
    assert_eq!(last_resort_claims, 2, "b handed out the last resort twice");
    let uploaded = ledger(&[&phone]).len();
    // The last resort still lets the phone join.
    let g = carol
        .client
        .create_group_chat(Some("Last resort".into()), std::slice::from_ref(&alice_id))
        .await
        .unwrap();
    sync_until("the phone joined with its last resort", &phone, |d| {
        joined(d, &g)
    })
    .await;
    // `keypackages.low` on b: the phone tops b up with fresh ones (no
    // later than the sync that joins the group above).
    sync_until("the phone topped b up", &phone, |d| {
        ledger(&[d]).len() > uploaded
    })
    .await;
    let fresh = ledger(&[&phone]);
    let claim = carol
        .hub
        .claim_key_packages_federated(&token, std::slice::from_ref(&alice_id))
        .await
        .unwrap();
    let phone_kp = claim
        .key_packages
        .iter()
        .find(|k| k.device == phone_device)
        .unwrap();
    let kp_ref = engine.key_package_ref(&phone_kp.key_package).unwrap();
    assert_eq!(fresh.get(&kp_ref), Some(&(fed.b.hub_id.clone(), false)));
    assert!(
        one_time.insert(kp_ref),
        "a one-time KeyPackage claimed twice"
    );

    fed.a.start().await;
    drop(restart);
}

/// `set_primary_hub(b)`: the record lists b first on both hubs, and the
/// next message and Commit go to b instead of a.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs 3 federated hubs: GIM_MULTIHOMING=1 scripts/integration-test.sh"]
async fn new_primary_hub_gets_the_next_submissions() {
    let Some((fed, c)) = three_hubs("new_primary_hub_gets_the_next_submissions") else {
        return;
    };
    let alice = homed_on_two(&fed.a, &fed.b).await;
    let alice_id = alice.user_id();
    let bob = SdkDevice::create(&c.url, "Bob").await;
    let erin = SdkDevice::create(&c.url, "Erin").await;
    let g = bob
        .client
        .create_group_chat(Some("Passage".into()), std::slice::from_ref(&alice_id))
        .await
        .unwrap();
    sync_until("alice joined", &alice, |d| joined(d, &g)).await;
    let (on_a, on_b) = (alice.hub(&fed.a.url), alice.hub(&fed.b.url));
    let posts = |hub: &FaultyHub| hub.faults.message_posts.lock().unwrap().clone();
    let commits = |hub: &FaultyHub| hub.faults.commit_results.lock().unwrap().len();

    let (before_a, before_b) = (posts(&on_a).len(), posts(&on_b).len());
    let first = alice.client.send_text(&g, "Via a", None).await.unwrap();
    assert_eq!(posts(&on_a).len(), before_a + 1);
    assert_eq!(posts(&on_a).last().unwrap().0.as_str(), first.as_str());
    assert_eq!(posts(&on_b).len(), before_b);

    alice.client.set_primary_hub(&fed.b.hub_id).await.unwrap();
    let listed = vec![(fed.b.hub_id.clone(), 0), (fed.a.hub_id.clone(), 1)];
    for hub in [&fed.a, &fed.b] {
        let record = record_on(hub, &alice_id).await;
        assert_eq!(record, Some((true, listed.clone())), "on {}", hub.hub_id);
    }
    let order: Vec<(String, u8)> = alice
        .client
        .hubs()
        .await
        .unwrap()
        .into_iter()
        .map(|h| (h.hub.hub_id, h.hub.priority))
        .collect();
    assert_eq!(order, listed);

    let (before_a, before_b) = (posts(&on_a).len(), posts(&on_b).len());
    let second = alice.client.send_text(&g, "Via b", None).await.unwrap();
    assert_eq!(posts(&on_a).len(), before_a);
    assert_eq!(posts(&on_b).len(), before_b + 1);
    assert_eq!(posts(&on_b).last().unwrap().0.as_str(), second.as_str());
    let (commits_a, commits_b) = (commits(&on_a), commits(&on_b));
    alice
        .client
        .add_members(&g, &[erin.user_id()])
        .await
        .unwrap();
    assert_eq!(commits(&on_a), commits_a);
    assert_eq!(commits(&on_b), commits_b + 1);

    sync_until("both messages at bob", &bob, |d| {
        d.texts(&g) == ["Via a", "Via b"]
    })
    .await;
    sync_until("erin joined", &erin, |d| joined(d, &g)).await;
}

/// `remove_hub(a)` for alice (home b): a owns a group alice is in, so the
/// call needs a confirmation; the home hub is never removed. After the
/// removal a no longer hosts alice, and she keeps messaging in a's group
/// through b (b forwards to the owner a).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs 3 federated hubs: GIM_MULTIHOMING=1 scripts/integration-test.sh"]
async fn removing_a_hub_that_owns_a_group_needs_a_confirmation() {
    let Some((fed, _c)) = three_hubs("removing_a_hub_that_owns_a_group_needs_a_confirmation")
    else {
        return;
    };
    let alice = homed_on_two(&fed.b, &fed.a).await;
    let alice_id = alice.user_id();
    let dave = SdkDevice::create(&fed.a.url, "Dave").await;
    let g = dave
        .client
        .create_group_chat(Some("Owned by a".into()), std::slice::from_ref(&alice_id))
        .await
        .unwrap();
    assert!(owned_by(&g, &fed.a), "{g}");
    sync_until("alice joined", &alice, |d| joined(d, &g)).await;

    let warned = alice.client.remove_hub(&fed.a.hub_id, false).await;
    assert!(
        matches!(
            &warned,
            Err(ClientError::HubOwnsGroups { hub_id, group_count: 1 }) if *hub_id == fed.a.hub_id
        ),
        "{warned:?}"
    );
    let home = alice.client.remove_hub(&fed.b.hub_id, true).await;
    assert!(
        matches!(&home, Err(ClientError::HomeHub(hub_id)) if *hub_id == fed.b.hub_id),
        "{home:?}"
    );
    let listed = vec![(fed.b.hub_id.clone(), 0), (fed.a.hub_id.clone(), 1)];
    assert_eq!(record_on(&fed.b, &alice_id).await, Some((true, listed)));

    alice.client.remove_hub(&fed.a.hub_id, true).await.unwrap();
    let removed = hub_status(&alice, &fed.a.hub_id).await.unwrap();
    assert_eq!(removed.hub.state, HubState::Removed);
    let only_b = vec![(fed.b.hub_id.clone(), 0)];
    assert_eq!(
        record_on(&fed.b, &alice_id).await,
        Some((true, only_b.clone()))
    );
    assert_eq!(record_on(&fed.a, &alice_id).await, Some((false, only_b)));

    let (on_a, on_b) = (alice.hub(&fed.a.url), alice.hub(&fed.b.url));
    let posts_a = on_a.faults.message_posts.lock().unwrap().len();
    alice
        .client
        .send_text(&g, "Still aboard via b", None)
        .await
        .unwrap();
    assert_eq!(on_a.faults.message_posts.lock().unwrap().len(), posts_a);
    assert!(!on_b.faults.message_posts.lock().unwrap().is_empty());
    sync_until("alice's message at dave", &dave, |d| {
        has_texts(d, &g, &["Still aboard via b"])
    })
    .await;
    dave.client
        .send_text(&g, "Welcome back", None)
        .await
        .unwrap();
    sync_until("dave's answer at alice", &alice, |d| {
        has_texts(d, &g, &["Welcome back"])
    })
    .await;
    assert_no_duplicates("alice", &alice.texts(&g));
}

/// The only listed hub is never removed: another device of alice (home a,
/// restored from the recovery code) removes b, alice's home hub, so a is
/// the only hub left for the device on b.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs 3 federated hubs: GIM_MULTIHOMING=1 scripts/integration-test.sh"]
async fn the_last_listed_hub_is_never_removed() {
    let Some((fed, _c)) = three_hubs("the_last_listed_hub_is_never_removed") else {
        return;
    };
    let alice = homed_on_two(&fed.b, &fed.a).await;
    let alice_id = alice.user_id();
    let restored = SdkDevice::open(&fed.a.url);
    restored
        .client
        .restore_from_recovery(&alice_id, alice.recovery_code.as_ref().unwrap(), false)
        .await
        .unwrap();
    restored.client.refresh_hubs().await.unwrap();
    restored
        .client
        .remove_hub(&fed.b.hub_id, true)
        .await
        .unwrap();
    // Removing a hub does not renumber the others.
    let only_a = vec![(fed.a.hub_id.clone(), 1)];
    assert_eq!(record_on(&fed.a, &alice_id).await, Some((true, only_a)));

    eventually_within(
        "alice's device on b sees b removed",
        FED_TIMEOUT,
        || async {
            let _ = alice.client.refresh_hubs().await;
            hub_status(&alice, &fed.b.hub_id)
                .await
                .filter(|h| h.hub.state == HubState::Removed)
                .map(drop)
        },
    )
    .await;
    let last = alice.client.remove_hub(&fed.a.hub_id, true).await;
    assert!(
        matches!(&last, Err(ClientError::LastHub(hub_id)) if *hub_id == fed.a.hub_id),
        "{last:?}"
    );
}

/// A hub URL shared through the self group that does not prove the listed
/// hub (c's URL under b's hub id) leaves b unverified on the receiving
/// device: only the hub proof is asked there, never a sign-in. The right
/// URL, shared when alice adds b, verifies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs 3 federated hubs: GIM_MULTIHOMING=1 scripts/integration-test.sh"]
async fn a_shared_url_of_another_hub_stays_unverified() {
    let Some((fed, c)) = three_hubs("a_shared_url_of_another_hub_stays_unverified") else {
        return;
    };
    let alice = SdkDevice::create(&fed.a.url, "Alice").await;
    let phone = alice.link(&fed.a.url).await;
    let self_group = alice
        .store
        .self_groups()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    sync_until("the phone joined the self group", &phone, |d| {
        d.store.self_groups().unwrap().contains(&self_group)
    })
    .await;
    alice
        .client
        .send(
            &self_group,
            Content::SelfHubs {
                hubs: vec![HubLocation {
                    hub_id: fed.b.hub_id.clone(),
                    url: c.url.clone(),
                    priority: 1,
                }],
            },
        )
        .await
        .unwrap();
    eventually_within("the phone checked c's URL for b", FED_TIMEOUT, || async {
        let _ = phone.client.sync_once().await;
        let asked = phone.hubs.lock().unwrap().contains_key(&c.url);
        let b = hub_status(&phone, &fed.b.hub_id).await;
        (asked && b.is_some_and(|b| b.hub.url.as_deref() == Some(c.url.as_str()))).then_some(())
    })
    .await;
    for _ in 0..3 {
        let _ = phone.client.sync_once().await;
    }
    let b = hub_status(&phone, &fed.b.hub_id).await.unwrap();
    assert_eq!(b.hub.state, HubState::Unverified, "{b:?}");
    assert!(!b.signed_in, "{b:?}");
    let relay = phone.hub(&c.url);
    assert_eq!(relay.faults.sign_ins.load(Ordering::SeqCst), 0);
    assert!(relay.faults.delivered.lock().unwrap().is_empty());

    alice.client.add_hub(&fed.b.url).await.unwrap();
    sync_until_signed_in("the phone verified b's URL", &phone, &fed.b).await;
    assert_eq!(relay.faults.sign_ins.load(Ordering::SeqCst), 0);
}
