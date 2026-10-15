//! gim-ffi `GimClient`s in this process against a real gim-hub.

use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;

use gim_core::{ChatKind, ConnectionState, GimError, MessageContent, ReactionGroup, SendState};
use gim_integration_testing::{
    eventually, member_ids, message, messages, open, server_url, text, timeline, MemoryHooks,
    Recorder, TestUser,
};

/// A valid 2x2 RGB PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a,
    0x73, 0x00, 0x00, 0x00, 0x11, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0x00, 0x04,
    0x50, 0xe2, 0xff, 0xff, 0xff, 0x00, 0x23, 0xec, 0x05, 0xfb, 0xd5, 0xaa, 0x1e, 0x66, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn identity_and_sign_in() {
    let Some(url) = server_url("identity_and_sign_in") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    assert!(!alice.recovery_code.is_empty());
    let session = alice.client.session().await.unwrap().unwrap();
    assert_eq!(session.handle, alice.handle);
    assert_eq!(session.display_name, "Alice");
    let devices = alice.client.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert!(devices[0].is_current && !devices[0].revoked);
    assert_eq!(devices[0].device_id, alice.device_id);

    // The handle is taken.
    let bob = TestUser::register(&url, "bob", "Bob").await;
    assert!(matches!(
        bob.client.claim_handle(alice.handle.clone()).await,
        Err(GimError::Server { status: 409, .. })
    ));

    // A restarted client signs in again with its device key and syncs.
    let connection = Recorder::new();
    alice.client.stop_sync().await.unwrap();
    let TestUser { client, hooks, .. } = alice;
    drop(client);
    let client = open(&url, &hooks).await;
    assert_eq!(client.session().await.unwrap(), Some(session.clone()));
    client.start_sync().await.unwrap();
    let _connection_handle = client.connection_state(connection.clone()).await.unwrap();
    connection
        .wait("alice connected", |s| *s == ConnectionState::Connected)
        .await;
    let found = client
        .find_user(bob.handle.clone())
        .await
        .unwrap()
        .expect("bob is in the directory");
    assert_eq!(found.user_id, bob.user_id);
    let devices = bob
        .client
        .user_devices(session.user_id.clone())
        .await
        .unwrap();
    assert_eq!(
        devices
            .iter()
            .map(|d| d.device_id.as_str())
            .collect::<Vec<_>>(),
        [session.device_id.as_str()]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn direct_chat_lifecycle() {
    let Some(url) = server_url("direct_chat_lifecycle") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;

    let found = alice
        .client
        .find_user(bob.handle.clone())
        .await
        .unwrap()
        .expect("bob is in the directory");
    assert_eq!(found.user_id, bob.user_id);
    assert_eq!(found.display_name, "Bob");
    assert_eq!(
        alice
            .client
            .find_user(format!("{}_none", bob.handle))
            .await
            .unwrap(),
        None
    );
    // Fills Bob's directory cache so the chat is named after Alice.
    bob.client.find_user(alice.handle.clone()).await.unwrap();

    let chat = alice
        .client
        .create_direct_chat(bob.user_id.clone())
        .await
        .unwrap();
    assert_eq!(
        alice
            .client
            .create_direct_chat(bob.user_id.clone())
            .await
            .unwrap(),
        chat,
        "the existing direct chat is reused"
    );

    let (alice_timeline, _alice_timeline_handle) = alice.timeline(&chat).await;
    let (bob_chats, _bob_chats_handle) = bob.chat_list().await;
    let bob_connection = Recorder::new();
    let _bob_connection_handle = bob
        .client
        .connection_state(bob_connection.clone())
        .await
        .unwrap();
    bob_connection
        .wait("bob connected", |s| *s == ConnectionState::Connected)
        .await;

    // Alice -> Bob.
    let hello = alice
        .client
        .send_text(chat.clone(), "hello bob".to_string(), None)
        .await
        .unwrap();
    let items = alice_timeline
        .wait("local echo", |items| message(items, &hello).is_some())
        .await;
    assert!(message(&items, &hello).unwrap().is_own);

    let chats = bob_chats
        .wait("chat at bob", |c| {
            c.iter().any(|c| {
                c.chat_id == chat
                    && c.last_message
                        .as_ref()
                        .is_some_and(|m| m.text == "hello bob")
            })
        })
        .await;
    let summary = chats.iter().find(|c| c.chat_id == chat).unwrap();
    assert_eq!(summary.kind, ChatKind::Direct);
    assert_eq!(summary.name, "Alice");
    assert_eq!(summary.member_count, 2);
    assert_eq!(summary.unread_count, 1);

    let (bob_timeline, bob_timeline_handle) = bob.timeline(&chat).await;
    let items = bob_timeline
        .wait("hello at bob", |items| message(items, &hello).is_some())
        .await;
    let received = message(&items, &hello).unwrap();
    assert_eq!(text(&received), Some("hello bob"));
    assert_eq!(received.sender.user_id, alice.user_id);
    assert!(!received.is_own);
    assert_eq!(received.send_state, None);

    // Receipts: delivered, then read.
    alice_timeline
        .wait("delivered", |items| {
            message(items, &hello).is_some_and(|m| {
                matches!(m.send_state, Some(SendState::Delivered | SendState::Read))
            })
        })
        .await;
    bob.client
        .mark_read(chat.clone(), hello.clone())
        .await
        .unwrap();
    bob_chats
        .wait("unread cleared", |c| {
            c.iter().any(|c| c.chat_id == chat && c.unread_count == 0)
        })
        .await;
    alice_timeline
        .wait("read", |items| {
            message(items, &hello).is_some_and(|m| m.send_state == Some(SendState::Read))
        })
        .await;

    // Typing.
    let typing = Recorder::new();
    let _typing_handle = bob
        .client
        .typing(chat.clone(), typing.clone())
        .await
        .unwrap();
    typing.wait("nobody typing", |users| users.is_empty()).await;
    alice.client.set_typing(chat.clone(), true).await.unwrap();
    typing
        .wait("alice typing", |users| {
            users == std::slice::from_ref(&alice.user_id)
        })
        .await;
    alice.client.set_typing(chat.clone(), false).await.unwrap();
    typing
        .wait("alice stopped typing", |users| users.is_empty())
        .await;

    // Bob -> Alice, as a reply.
    let reply = bob
        .client
        .send_text(chat.clone(), "hi alice".to_string(), Some(hello.clone()))
        .await
        .unwrap();
    let items = alice_timeline
        .wait("reply at alice", |items| message(items, &reply).is_some())
        .await;
    let received = message(&items, &reply).unwrap();
    assert_eq!(text(&received), Some("hi alice"));
    assert!(!received.is_own);
    let quoted = received.reply_to.expect("reply preview");
    assert_eq!(quoted.message_id, hello);
    assert_eq!(quoted.text, "hello bob");

    // Edit.
    alice
        .client
        .edit_message(chat.clone(), hello.clone(), "hello bob!".to_string())
        .await
        .unwrap();
    bob_timeline
        .wait("edit at bob", |items| {
            message(items, &hello).is_some_and(|m| m.edited && text(&m) == Some("hello bob!"))
        })
        .await;

    // Reaction.
    bob.client
        .react(chat.clone(), hello.clone(), "👍".to_string())
        .await
        .unwrap();
    let thumbs = |own| {
        vec![ReactionGroup {
            emoji: "👍".to_string(),
            count: 1,
            own,
        }]
    };
    alice_timeline
        .wait("reaction at alice", |items| {
            message(items, &hello).is_some_and(|m| m.reactions == thumbs(false))
        })
        .await;
    bob_timeline
        .wait("own reaction at bob", |items| {
            message(items, &hello).is_some_and(|m| m.reactions == thumbs(true))
        })
        .await;

    // Delete.
    let doomed = alice
        .client
        .send_text(chat.clone(), "oops".to_string(), None)
        .await
        .unwrap();
    bob_timeline
        .wait("oops at bob", |items| message(items, &doomed).is_some())
        .await;
    alice
        .client
        .delete_message(chat.clone(), doomed.clone())
        .await
        .unwrap();
    bob_timeline
        .wait("delete at bob", |items| {
            message(items, &doomed).is_some_and(|m| m.content == MessageContent::Deleted)
        })
        .await;

    // Stream drop: Bob disconnects, Alice keeps sending, Bob reconnects and
    // resumes from his cursor without losing or duplicating anything.
    bob.client.stop_sync().await.unwrap();
    bob_connection
        .wait("bob offline", |s| *s == ConnectionState::Offline)
        .await;
    let mut missed = Vec::new();
    for body in ["while away 1", "while away 2"] {
        missed.push(
            alice
                .client
                .send_text(chat.clone(), body.to_string(), None)
                .await
                .unwrap(),
        );
    }
    for id in &missed {
        alice_timeline
            .wait("sent while bob away", |items| {
                message(items, id).is_some_and(|m| m.send_state != Some(SendState::Pending))
            })
            .await;
    }
    bob.client.start_sync().await.unwrap();
    bob_connection
        .wait("bob reconnected", |s| *s == ConnectionState::Connected)
        .await;
    let items = bob_timeline
        .wait("missed messages at bob", |items| {
            missed.iter().all(|id| message(items, id).is_some())
        })
        .await;
    let ids: Vec<String> = messages(&items).into_iter().map(|m| m.message_id).collect();
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "duplicates after reconnect: {ids:?}"
    );

    // Bob restarts from the same data directory; history persists.
    let session = bob.client.session().await.unwrap().unwrap();
    let expected: Vec<(String, MessageContent)> = messages(&items)
        .into_iter()
        .map(|m| (m.message_id, m.content))
        .collect();
    bob.client.stop_sync().await.unwrap();
    drop((bob_timeline_handle, bob_timeline));
    drop((_bob_chats_handle, bob_chats));
    drop((_typing_handle, typing));
    drop(_bob_connection_handle);
    let TestUser {
        client: bob_client,
        hooks: bob_hooks,
        ..
    } = bob;
    drop(bob_client);

    let bob_client = open(&url, &bob_hooks).await;
    assert_eq!(bob_client.session().await.unwrap(), Some(session));
    let (history, _history_handle) = timeline(&bob_client, &chat).await;
    let items = history
        .wait("history after restart", |items| {
            messages(items).len() >= expected.len()
        })
        .await;
    let restored: Vec<(String, MessageContent)> = messages(&items)
        .into_iter()
        .map(|m| (m.message_id, m.content))
        .collect();
    assert_eq!(restored, expected);
    let restored_hello = message(&items, &hello).unwrap();
    assert!(restored_hello.edited);
    assert_eq!(restored_hello.reactions, thumbs(true));

    // The restarted client keeps syncing.
    bob_client.start_sync().await.unwrap();
    let after = alice
        .client
        .send_text(chat.clone(), "welcome back".to_string(), None)
        .await
        .unwrap();
    history
        .wait("message after restart", |items| {
            message(items, &after).is_some()
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn media_send_and_fetch() {
    let Some(url) = server_url("media_send_and_fetch") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    let chat = alice
        .client
        .create_direct_chat(bob.user_id.clone())
        .await
        .unwrap();
    let (bob_timeline, _handle) = bob.timeline(&chat).await;

    let source = alice.hooks.path("chart.bin");
    let data: Vec<u8> = (0..256 * 1024u32).map(|i| (i * 7 % 251) as u8).collect();
    fs::write(&source, &data).unwrap();
    let id = alice
        .client
        .send_media(
            chat.clone(),
            source.to_str().unwrap().to_string(),
            "application/octet-stream".to_string(),
            Some("route chart".to_string()),
            None,
        )
        .await
        .unwrap();

    let items = bob_timeline
        .wait("media at bob", |items| message(items, &id).is_some())
        .await;
    let MessageContent::File {
        media,
        file_name,
        caption,
    } = message(&items, &id).unwrap().content
    else {
        panic!("not a file");
    };
    assert_eq!(file_name.as_deref(), Some("chart.bin"));
    assert_eq!(caption.as_deref(), Some("route chart"));
    assert_eq!(media.size, data.len() as u64);

    let dest = bob.hooks.path("downloaded.bin");
    let path = bob
        .client
        .fetch_media(
            media.chat_id,
            media.message_id,
            dest.to_str().unwrap().to_string(),
        )
        .await
        .unwrap();
    assert_eq!(fs::read(path).unwrap(), data);

    // An image: an encrypted blob plus its MIME type.
    let source = alice.hooks.path("bay.png");
    fs::write(&source, PNG).unwrap();
    let id = alice
        .client
        .send_media(
            chat.clone(),
            source.to_str().unwrap().to_string(),
            "image/png".to_string(),
            Some("Stiniva bay".to_string()),
            None,
        )
        .await
        .unwrap();
    let items = bob_timeline
        .wait("image at bob", |items| message(items, &id).is_some())
        .await;
    let MessageContent::Image { media, caption, .. } = message(&items, &id).unwrap().content else {
        panic!("not an image");
    };
    assert_eq!(caption.as_deref(), Some("Stiniva bay"));
    assert_eq!(media.mime, "image/png");
    assert_eq!(media.size, PNG.len() as u64);
    let dest = bob.hooks.path("bay.png");
    let path = bob
        .client
        .fetch_media(
            media.chat_id,
            media.message_id,
            dest.to_str().unwrap().to_string(),
        )
        .await
        .unwrap();
    assert_eq!(fs::read(path).unwrap(), PNG);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn group_add_remove_leave() {
    let Some(url) = server_url("group_add_remove_leave") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    let carol = TestUser::register(&url, "carol", "Carol").await;

    let chat = alice
        .client
        .create_group_chat("Crew".to_string(), vec![bob.user_id.clone()])
        .await
        .unwrap();
    let (bob_timeline, _bob_handle) = bob.timeline(&chat).await;
    let first = alice
        .client
        .send_text(chat.clone(), "before carol".to_string(), None)
        .await
        .unwrap();
    bob_timeline
        .wait("first at bob", |items| message(items, &first).is_some())
        .await;

    // Add Carol: she joins and reads what is sent from then on.
    alice
        .client
        .add_members(chat.clone(), vec![carol.user_id.clone()])
        .await
        .unwrap();
    let (carol_chats, _carol_chats_handle) = carol.chat_list().await;
    carol_chats
        .wait("group at carol", |c| {
            c.iter()
                .any(|c| c.chat_id == chat && c.kind == ChatKind::Group)
        })
        .await;
    let (carol_timeline, _carol_handle) = carol.timeline(&chat).await;
    let welcome = alice
        .client
        .send_text(chat.clone(), "hi carol".to_string(), None)
        .await
        .unwrap();
    let items = carol_timeline
        .wait("hi carol at carol", |items| {
            message(items, &welcome).is_some()
        })
        .await;
    assert_eq!(text(&message(&items, &welcome).unwrap()), Some("hi carol"));
    let ids = |members: Vec<gim_core::UserProfile>| -> BTreeSet<String> {
        members.into_iter().map(|p| p.user_id).collect()
    };
    let all: BTreeSet<String> = [&alice, &bob, &carol]
        .iter()
        .map(|u| u.user_id.clone())
        .collect();
    assert_eq!(
        ids(alice.client.chat_members(chat.clone()).await.unwrap()),
        all
    );

    // Remove Carol: later messages reach Bob but not her.
    alice
        .client
        .remove_member(chat.clone(), carol.user_id.clone())
        .await
        .unwrap();
    let remaining: BTreeSet<String> = [&alice, &bob].iter().map(|u| u.user_id.clone()).collect();
    assert_eq!(
        ids(alice.client.chat_members(chat.clone()).await.unwrap()),
        remaining
    );
    let secret = alice
        .client
        .send_text(chat.clone(), "after carol".to_string(), None)
        .await
        .unwrap();
    bob_timeline
        .wait("after carol at bob", |items| {
            message(items, &secret).is_some()
        })
        .await;
    // Give Carol's sync loop time to see anything it could.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let items = carol_timeline.get();
    assert!(message(&items, &welcome).is_some());
    assert!(
        message(&items, &secret).is_none(),
        "removed member read a later message"
    );
    assert!(messages(&items)
        .iter()
        .all(|m| text(m) != Some("after carol")));

    // Bob leaves: Alice commits his removal and stops sending to him.
    bob.client.leave_chat(chat.clone()).await.unwrap();
    let only_alice = BTreeSet::from([alice.user_id.clone()]);
    eventually("bob removed at alice", || async {
        (member_ids(&alice.client, &chat).await == only_alice).then_some(())
    })
    .await;
    let alone = alice
        .client
        .send_text(chat.clone(), "after bob".to_string(), None)
        .await
        .unwrap();
    let (alice_timeline, _alice_handle) = alice.timeline(&chat).await;
    alice_timeline
        .wait("after bob sent", |items| {
            message(items, &alone).is_some_and(|m| m.send_state != Some(SendState::Pending))
        })
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        message(&bob_timeline.get(), &alone).is_none(),
        "a member who left read a later message"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn link_device_then_revoke() {
    let Some(url) = server_url("link_device_then_revoke") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;
    let chat = alice
        .client
        .create_direct_chat(bob.user_id.clone())
        .await
        .unwrap();
    let (bob_timeline, _bob_handle) = bob.timeline(&chat).await;
    let before = alice
        .client
        .send_text(chat.clone(), "before the tablet".to_string(), None)
        .await
        .unwrap();
    bob_timeline
        .wait("before at bob", |items| message(items, &before).is_some())
        .await;

    // Link a tablet: same SAS on both devices, then both accept.
    let (tablet, sas) = alice.link_device(&url).await;
    assert_eq!(sas.len(), 7, "SAS format is \"123 456\": {sas}");
    assert_ne!(tablet.device_id, alice.device_id);
    let devices = alice.client.devices().await.unwrap();
    let ids: BTreeSet<&str> = devices.iter().map(|d| d.device_id.as_str()).collect();
    assert_eq!(
        ids,
        BTreeSet::from([alice.device_id.as_str(), tablet.device_id.as_str()])
    );
    eventually("tablet in bob's view of alice", || async {
        let devices = bob
            .client
            .user_devices(alice.user_id.clone())
            .await
            .unwrap();
        devices
            .iter()
            .any(|d| d.device_id == tablet.device_id && !d.revoked)
            .then_some(())
    })
    .await;

    // The tablet joined the existing chat: it reads Bob's next message and
    // its own messages reach Bob as Alice's.
    let (tablet_chats, _tablet_chats_handle) = tablet.chat_list().await;
    tablet_chats
        .wait("chat at tablet", |c| c.iter().any(|c| c.chat_id == chat))
        .await;
    let (tablet_timeline, _tablet_handle) = tablet.timeline(&chat).await;
    let hello = bob
        .client
        .send_text(chat.clone(), "hello tablet".to_string(), None)
        .await
        .unwrap();
    let items = tablet_timeline
        .wait("hello at tablet", |items| message(items, &hello).is_some())
        .await;
    assert_eq!(
        text(&message(&items, &hello).unwrap()),
        Some("hello tablet")
    );
    let (alice_timeline, _alice_handle) = alice.timeline(&chat).await;
    alice_timeline
        .wait("hello at phone", |items| message(items, &hello).is_some())
        .await;
    let from_tablet = tablet
        .client
        .send_text(chat.clone(), "sent from the tablet".to_string(), None)
        .await
        .unwrap();
    let items = bob_timeline
        .wait("tablet message at bob", |items| {
            message(items, &from_tablet).is_some()
        })
        .await;
    assert_eq!(
        message(&items, &from_tablet).unwrap().sender.user_id,
        alice.user_id
    );
    alice_timeline
        .wait("tablet message at phone", |items| {
            message(items, &from_tablet).is_some_and(|m| m.is_own)
        })
        .await;

    // Revoke the tablet from the phone: the hub rejects its credential.
    alice
        .client
        .revoke_device(tablet.device_id.clone())
        .await
        .unwrap();
    let devices = alice.client.devices().await.unwrap();
    assert!(devices
        .iter()
        .any(|d| d.device_id == tablet.device_id && d.revoked));
    eventually("tablet rejected", || async {
        match tablet.client.find_user(bob.handle.clone()).await {
            Err(GimError::NotRegistered) => Some(()),
            _ => None,
        }
    })
    .await;
    eventually("tablet revoked in bob's view of alice", || async {
        let devices = bob
            .client
            .user_devices(alice.user_id.clone())
            .await
            .unwrap();
        devices
            .iter()
            .all(|d| d.device_id != tablet.device_id || d.revoked)
            .then_some(())
    })
    .await;

    // The chat goes on without it.
    let after = bob
        .client
        .send_text(chat.clone(), "after the revoke".to_string(), None)
        .await
        .unwrap();
    alice_timeline
        .wait("after at phone", |items| message(items, &after).is_some())
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        message(&tablet_timeline.get(), &after).is_none(),
        "a revoked device read a later message"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a gim-hub: scripts/integration-test.sh"]
async fn restore_from_recovery_code() {
    let Some(url) = server_url("restore_from_recovery_code") else {
        return;
    };
    let alice = TestUser::register(&url, "alice", "Alice").await;
    let bob = TestUser::register(&url, "bob", "Bob").await;

    // Alice lost her phone; a fresh install restores her from the code.
    let hooks = MemoryHooks::new();
    let restored = open(&url, &hooks).await;
    restored
        .restore_from_recovery(alice.user_id.clone(), alice.recovery_code.clone(), true)
        .await
        .unwrap();
    let session = restored.session().await.unwrap().unwrap();
    assert_eq!(session.user_id, alice.user_id);
    assert_ne!(session.device_id, alice.device_id);
    restored.start_sync().await.unwrap();

    // The lost device's credential is rejected.
    eventually("old device rejected", || async {
        match alice.client.find_user(bob.handle.clone()).await {
            Err(GimError::NotRegistered) => Some(()),
            _ => None,
        }
    })
    .await;
    eventually("restored device in bob's view of alice", || async {
        let devices = bob
            .client
            .user_devices(alice.user_id.clone())
            .await
            .unwrap();
        let active: Vec<&str> = devices
            .iter()
            .filter(|d| !d.revoked)
            .map(|d| d.device_id.as_str())
            .collect();
        (active == [session.device_id.as_str()]).then_some(())
    })
    .await;

    // Bob reaches the restored device in a new chat, and back.
    let chat = bob
        .client
        .create_group_chat("Regatta".to_string(), vec![alice.user_id.clone()])
        .await
        .unwrap();
    let (timeline_restored, _handle) = timeline(&restored, &chat).await;
    let hello = bob
        .client
        .send_text(chat.clone(), "welcome back".to_string(), None)
        .await
        .unwrap();
    let items = timeline_restored
        .wait("hello at restored", |items| {
            message(items, &hello).is_some()
        })
        .await;
    assert_eq!(
        text(&message(&items, &hello).unwrap()),
        Some("welcome back")
    );
    let reply = restored
        .send_text(chat.clone(), "thanks".to_string(), None)
        .await
        .unwrap();
    let (bob_timeline, _bob_handle) = bob.timeline(&chat).await;
    bob_timeline
        .wait("reply at bob", |items| message(items, &reply).is_some())
        .await;
}
