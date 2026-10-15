//! gim-ffi `GimClient`s in this process against a real gim-server.

use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;

use gim_core::{ChatKind, ConnectionState, MessageContent, ReactionGroup, SendState};
use gim_integration_testing::{
    message, messages, open, server_url, text, timeline, Recorder, TestUser,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "gim-server v1 removed; replaced by gim-hub tests (C2-T6)"]
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
#[ignore = "gim-server v1 removed; replaced by gim-hub tests (C2-T6)"]
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "gim-server v1 removed; replaced by gim-hub tests (C2-T6)"]
async fn group_add_then_remove_member() {
    let Some(url) = server_url("group_add_then_remove_member") else {
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
}
