//! Push end to end on one real hub (plan §4 P: "hub -> push -> device
//! processes it"). Devices register with the hub's test provider `log`; the
//! test reads the pushed payloads from the hub's push log and feeds each to
//! `process_push` of an extension-mode client on the app's data directory
//! while the app's client exists but does not sync, as an iOS Notification
//! Service Extension would. The app's sync afterwards applies nothing
//! twice.
//!
//! The hub keeps one pending push per device (`push.md` §4), so a push may
//! replace an earlier one, e.g. the Welcome's by the inviter's display name
//! announcement right after it. The tests therefore process every push the
//! device got and check what is displayed.
//!
//! `membership_push_is_silent` needs a hub started with
//! `GIM_HUB_PUSH_MEMBER_EVENTS=true` (and the same variable in the test's
//! environment); `minimal_push_wakes_and_shows_the_newest_message` needs a
//! second hub with `GIM_HUB_PUSH_MINIMAL=true` at `GIM_HUB_MINIMAL_URL`.
//! `scripts/integration-test.sh` provides both.

use std::time::Duration;

use gim_core::{ChatKind, NotificationKind};
use gim_integration_testing::push::{
    assert_message_payload, displayed, log_registration, new_pushes, process_all, push_log,
};
use gim_integration_testing::{member_ids, messages, server_url, text, TestUser};
use serde_json::Value;

/// How long a push may take to show in the hub's push log: the dispatcher
/// tails the events every 500 ms.
const PUSH_WAIT: Duration = Duration::from_secs(20);

/// Registers `user` for push with the log provider.
async fn register_log_push(user: &TestUser) {
    user.client.register_push(log_registration()).await.unwrap();
}

/// Waits until `user`'s chat list has `chat`, then a moment for the
/// receipts and announcements that follow a join.
async fn wait_joined(user: &TestUser, chat: &str) {
    let (chats, _handle) = user.chat_list().await;
    chats
        .wait("the chat joined", |c| c.iter().any(|c| c.chat_id == chat))
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
}

/// A direct chat bob created with alice, joined on alice's side.
async fn direct_chat(alice: &TestUser, bob: &TestUser) -> String {
    bob.client.find_user(alice.handle.clone()).await.unwrap();
    let chat = bob
        .client
        .create_direct_chat(alice.user_id.clone())
        .await
        .unwrap();
    wait_joined(alice, &chat).await;
    chat
}

/// The text bodies in `user`'s timeline of `chat` once it holds `last`.
async fn texts_once_synced(user: &TestUser, chat: &str, last: &str) -> Vec<String> {
    let (timeline, _handle) = user.timeline(chat).await;
    let items = timeline
        .wait(&format!("{last:?} in the timeline"), |items| {
            messages(items).iter().any(|m| text(m) == Some(last))
        })
        .await;
    messages(&items)
        .iter()
        .filter_map(|m| text(m).map(str::to_string))
        .collect()
}

fn for_chat(chat: &str) -> impl Fn(&[Value]) -> bool + '_ {
    move |pushed| pushed.iter().any(|p| p["gid"] == chat)
}

/// A text from bob is pushed to alice; the extension shows it with bob's
/// name, and the app's stream does not apply it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn pushed_message_is_shown_by_the_extension_and_applied_once() {
    let Some(url) = server_url("pushed_message_is_shown_by_the_extension_and_applied_once") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    register_log_push(&alice).await;
    let chat = direct_chat(&alice, &bob).await;

    alice.client.stop_sync().await.unwrap();
    let before = push_log(&url, &alice.device_id).len();
    bob.client
        .send_text(chat.clone(), "Anchored off Hvar".into(), None)
        .await
        .unwrap();
    let pushed = new_pushes(&url, &alice.device_id, before, PUSH_WAIT, for_chat(&chat)).await;
    let payload = pushed.last().unwrap();
    assert_message_payload(payload, &chat);

    let shown = process_all(&url, &alice.hooks, &pushed).await;
    let shown = displayed(&shown);
    assert_eq!(shown.len(), 1, "{shown:?}");
    let shown = shown[0];
    assert_eq!(shown.kind, NotificationKind::Message, "{shown:?}");
    assert_eq!(shown.body, "Anchored off Hvar");
    assert_eq!(shown.chat_id.as_deref(), Some(chat.as_str()));
    assert_eq!(shown.chat_title.as_deref(), Some("Bob"));
    assert_eq!(shown.sender_user_id.as_deref(), Some(bob.user_id.as_str()));
    assert_eq!(shown.sender_display_name.as_deref(), Some("Bob"));
    assert_eq!(
        shown.collapse_id.as_deref(),
        payload["collapse_id"].as_str()
    );

    // The same push again (a duplicate delivery) describes the stored
    // message.
    let again = process_all(&url, &alice.hooks, &pushed[pushed.len() - 1..]).await;
    assert_eq!(again[0].kind, NotificationKind::Message, "{again:?}");
    assert_eq!(again[0].body, "Anchored off Hvar");
    assert_eq!(again[0].message_id, shown.message_id);

    // The app's stream delivers the pushed message again and a later one.
    alice.client.start_sync().await.unwrap();
    bob.client
        .send_text(chat.clone(), "Fenders out".into(), None)
        .await
        .unwrap();
    let texts = texts_once_synced(&alice, &chat, "Fenders out").await;
    assert_eq!(texts, ["Anchored off Hvar", "Fenders out"]);
}

/// Bob adds alice to a group: the Welcome is pushed (or a push replacing
/// it), the extension joins the group and shows the invite once, and the
/// app lists the group once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn pushed_invite_joins_the_group_once() {
    let Some(url) = server_url("pushed_invite_joins_the_group_once") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    register_log_push(&alice).await;
    alice.client.stop_sync().await.unwrap();

    let before = push_log(&url, &alice.device_id).len();
    let group = bob
        .client
        .create_group_chat("Crew Kornati".into(), vec![alice.user_id.clone()])
        .await
        .unwrap();
    let pushed = new_pushes(&url, &alice.device_id, before, PUSH_WAIT, for_chat(&group)).await;
    for payload in &pushed {
        assert_eq!(payload["collapse_id"], payload["message_id"], "{payload}");
    }

    let shown = process_all(&url, &alice.hooks, &pushed).await;
    let shown = displayed(&shown);
    assert_eq!(shown.len(), 1, "{shown:?}");
    let shown = shown[0];
    assert_eq!(shown.kind, NotificationKind::Invite, "{shown:?}");
    assert_eq!(shown.chat_id.as_deref(), Some(group.as_str()));
    assert!(shown.chat_title.is_some(), "{shown:?}");
    assert_eq!(shown.sender_user_id.as_deref(), Some(bob.user_id.as_str()));

    alice.client.start_sync().await.unwrap();
    bob.client
        .send_text(group.clone(), "Welcome aboard".into(), None)
        .await
        .unwrap();
    let texts = texts_once_synced(&alice, &group, "Welcome aboard").await;
    assert_eq!(texts, ["Welcome aboard"]);
    let (chats, _handle) = alice.chat_list().await;
    let chats = chats
        .wait("the group named in alice's list", |c| {
            c.iter()
                .any(|c| c.chat_id == group && c.name == "Crew Kornati")
        })
        .await;
    let listed: Vec<_> = chats.iter().filter(|c| c.chat_id == group).collect();
    assert_eq!(listed.len(), 1, "{chats:?}");
    assert_eq!(listed[0].kind, ChatKind::Group);
}

/// With `GIM_HUB_PUSH_MEMBER_EVENTS=true`, a member removed from alice's
/// group is pushed; the extension catches the group up and shows nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn membership_push_is_silent() {
    let Some(url) = server_url("membership_push_is_silent") else {
        return;
    };
    if std::env::var("GIM_HUB_PUSH_MEMBER_EVENTS").as_deref() != Ok("true") {
        eprintln!("skipping membership_push_is_silent: GIM_HUB_PUSH_MEMBER_EVENTS is not true");
        return;
    }
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    let carol = TestUser::register(&url, "carol", "Carol").await;
    register_log_push(&alice).await;
    let group = bob
        .client
        .create_group_chat(
            "Crew Lastovo".into(),
            vec![alice.user_id.clone(), carol.user_id.clone()],
        )
        .await
        .unwrap();
    wait_joined(&alice, &group).await;
    wait_joined(&carol, &group).await;

    alice.client.stop_sync().await.unwrap();
    carol.client.stop_sync().await.unwrap();
    let before = push_log(&url, &alice.device_id).len();
    bob.client
        .remove_member(group.clone(), carol.user_id.clone())
        .await
        .unwrap();
    let pushed = new_pushes(&url, &alice.device_id, before, PUSH_WAIT, |pushed| {
        pushed
            .iter()
            .any(|p| p["type"] == "group.member_removed" && p["gid"] == group.as_str())
    })
    .await;
    let removal = pushed
        .iter()
        .position(|p| p["type"] == "group.member_removed")
        .unwrap();
    assert!(pushed[removal].get("mls_message").is_none(), "{pushed:?}");

    let shown = process_all(&url, &alice.hooks, &pushed).await;
    assert!(displayed(&shown).is_empty(), "{shown:?}");
    assert_eq!(
        shown[removal].kind,
        NotificationKind::Membership,
        "{shown:?}"
    );
    assert_eq!(shown[removal].chat_id.as_deref(), Some(group.as_str()));

    alice.client.start_sync().await.unwrap();
    bob.client
        .send_text(group.clone(), "Carol went ashore".into(), None)
        .await
        .unwrap();
    let texts = texts_once_synced(&alice, &group, "Carol went ashore").await;
    assert_eq!(texts, ["Carol went ashore"]);
    let remaining = [&alice, &bob].iter().map(|u| u.user_id.clone()).collect();
    assert_eq!(member_ids(&alice.client, &group).await, remaining);
}

/// With `GIM_HUB_PUSH_MINIMAL=true` the payload only wakes the device: the
/// extension reads the pending events and shows the newest message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn minimal_push_wakes_and_shows_the_newest_message() {
    let url = match std::env::var("GIM_HUB_MINIMAL_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!(
                "skipping minimal_push_wakes_and_shows_the_newest_message: GIM_HUB_MINIMAL_URL is not set"
            );
            return;
        }
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    register_log_push(&alice).await;
    let chat = direct_chat(&alice, &bob).await;

    alice.client.stop_sync().await.unwrap();
    let before = push_log(&url, &alice.device_id).len();
    bob.client
        .send_text(chat.clone(), "Mooring at Komiža".into(), None)
        .await
        .unwrap();
    let pushed = new_pushes(&url, &alice.device_id, before, PUSH_WAIT, |p| !p.is_empty()).await;
    for payload in &pushed {
        assert_eq!(payload["v"], 1, "{payload}");
        assert_eq!(payload["type"], "wake", "{payload}");
        for field in ["gid", "seq", "message_id", "mls_message"] {
            assert!(payload.get(field).is_none(), "{field} in {payload}");
        }
        assert!(payload["collapse_id"].is_string(), "{payload}");
    }

    let shown = process_all(&url, &alice.hooks, &pushed).await;
    let shown = displayed(&shown);
    assert_eq!(shown.len(), 1, "{shown:?}");
    let shown = shown[0];
    assert_eq!(shown.kind, NotificationKind::Message, "{shown:?}");
    assert_eq!(shown.body, "Mooring at Komiža");
    assert_eq!(shown.chat_id.as_deref(), Some(chat.as_str()));
    assert_eq!(shown.sender_display_name.as_deref(), Some("Bob"));

    alice.client.start_sync().await.unwrap();
    bob.client
        .send_text(chat.clone(), "Lines ashore".into(), None)
        .await
        .unwrap();
    let texts = texts_once_synced(&alice, &chat, "Lines ashore").await;
    assert_eq!(texts, ["Mooring at Komiža", "Lines ashore"]);
}

/// Sends a text from bob and waits until carol (always registered) got a
/// push for it, then a moment more: by then the hub decided about every
/// device. Returns how many pushes alice's device got meanwhile.
async fn alice_pushes_for_a_text(
    url: &str,
    alice: &TestUser,
    bob: &TestUser,
    carol: &TestUser,
    group: &str,
    body: &str,
) -> usize {
    let (alice_before, carol_before) = (
        push_log(url, &alice.device_id).len(),
        push_log(url, &carol.device_id).len(),
    );
    bob.client
        .send_text(group.to_string(), body.into(), None)
        .await
        .unwrap();
    new_pushes(
        url,
        &carol.device_id,
        carol_before,
        PUSH_WAIT,
        for_chat(group),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    push_log(url, &alice.device_id).len() - alice_before
}

/// Registration lifecycle: unregistered, alice's device gets no pushes;
/// registered, it does; unregistered again, none; registered again, it
/// does; signed out, none. Carol, registered throughout, shows that every
/// text was pushed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn registration_lifecycle_controls_pushes() {
    let Some(url) = server_url("registration_lifecycle_controls_pushes") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    let carol = TestUser::register(&url, "carol", "Carol").await;
    register_log_push(&carol).await;
    let group = bob
        .client
        .create_group_chat(
            "Crew Mljet".into(),
            vec![alice.user_id.clone(), carol.user_id.clone()],
        )
        .await
        .unwrap();
    wait_joined(&alice, &group).await;
    wait_joined(&carol, &group).await;
    let pushes =
        |body: &'static str| alice_pushes_for_a_text(&url, &alice, &bob, &carol, &group, body);

    assert_eq!(pushes("zero").await, 0, "not registered yet");
    register_log_push(&alice).await;
    assert!(pushes("one").await > 0, "registered");
    alice.client.unregister_push().await.unwrap();
    assert_eq!(pushes("two").await, 0, "unregistered");
    register_log_push(&alice).await;
    assert!(pushes("three").await > 0, "registered again");
    alice.client.sign_out().await.unwrap();
    assert_eq!(pushes("four").await, 0, "signed out");
}

/// With priority-aware coalescing (hub H8) a text and the read receipt
/// right after it reach alice as one alert push carrying the receipt's
/// payload: the extension catches the chat up and shows the text.
/// `scripts/integration-test.sh` runs ignored tests too, so this one also
/// needs `GIM_HUB_PRIORITY_COALESCING=1` until the pinned hub has H8.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs hub H8 priority-aware coalescing"]
async fn coalesced_receipt_push_shows_the_text_before_it() {
    let Some(url) = server_url("coalesced_receipt_push_shows_the_text_before_it") else {
        return;
    };
    if std::env::var("GIM_HUB_PRIORITY_COALESCING").as_deref() != Ok("1") {
        eprintln!(
            "skipping coalesced_receipt_push_shows_the_text_before_it: GIM_HUB_PRIORITY_COALESCING is not 1"
        );
        return;
    }
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    register_log_push(&alice).await;
    let chat = direct_chat(&alice, &bob).await;
    let (bob_timeline, _handle) = bob.timeline(&chat).await;
    let ahoy = alice
        .client
        .send_text(chat.clone(), "Ahoy".into(), None)
        .await
        .unwrap();
    bob_timeline
        .wait("ahoy at bob", |items| {
            messages(items).iter().any(|m| m.message_id == ahoy)
        })
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    alice.client.stop_sync().await.unwrap();
    let before = push_log(&url, &alice.device_id).len();
    let text = bob
        .client
        .send_text(chat.clone(), "Anchored off Hvar".into(), None)
        .await
        .unwrap();
    bob.client.mark_read(chat.clone(), text).await.unwrap();
    let pushed = new_pushes(&url, &alice.device_id, before, PUSH_WAIT, for_chat(&chat)).await;
    assert_eq!(pushed.len(), 1, "one coalesced push: {pushed:?}");

    let shown = process_all(&url, &alice.hooks, &pushed).await;
    assert_eq!(shown[0].kind, NotificationKind::Message, "{shown:?}");
    assert!(shown[0].should_display, "{shown:?}");
    assert_eq!(shown[0].body, "Anchored off Hvar");
    assert_eq!(shown[0].sender_display_name.as_deref(), Some("Bob"));

    alice.client.start_sync().await.unwrap();
    let texts = texts_once_synced(&alice, &chat, "Anchored off Hvar").await;
    assert_eq!(texts, ["Ahoy", "Anchored off Hvar"]);
}
