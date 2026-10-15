//! Outbox sender, receipts, typing and idempotent commits against the fake
//! server, with injected network faults.

mod common;

use std::time::Duration;

use gim_base::model::{MessageContent, MessageKind, SendState, StateChange};
use gim_base::{StateReader, MAX_SEND_ATTEMPTS};
use gim_sdk::{ClientError, COMMIT_POST_ATTEMPTS};

use common::{server_messages, Device, FlakyTransport};

fn body(device: &Device, id: &gim_common::MessageId) -> String {
    match device.message(id).content {
        MessageContent::Text { body } => body,
        other => panic!("not a text: {other:?}"),
    }
}

#[tokio::test]
async fn send_state_goes_pending_sent_delivered_read() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let mut changes = alice.client.subscribe_changes();

    let hello = alice.client.send_text(&g, "hello", None).await.unwrap();
    let states: Vec<SendState> = std::iter::from_fn(|| changes.try_recv().ok())
        .filter_map(|c| match c {
            StateChange::MessageUpserted(m) if m.message_id == hello => m.send_state,
            _ => None,
        })
        .collect();
    assert_eq!(states, vec![SendState::Pending, SendState::Sent]);

    // Bob's sync queues a delivered receipt; his outbox sends it.
    bob.sync().await;
    bob.client.flush_outbox().await.unwrap();
    alice.sync().await;
    assert_eq!(alice.message(&hello).send_state, Some(SendState::Delivered));

    bob.client.mark_read(&g).await.unwrap();
    assert_eq!(bob.store.chat(&g).unwrap().unwrap().unread_count, 0);
    alice.sync().await;
    assert_eq!(alice.message(&hello).send_state, Some(SendState::Read));

    // Replies keep their target.
    let reply = bob
        .client
        .send_text(&g, "hi", Some(hello.clone()))
        .await
        .unwrap();
    alice.sync().await;
    assert_eq!(alice.message(&reply).reply_to, Some(hello));
}

#[tokio::test]
async fn edit_delete_and_reactions_reach_the_other_client() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let first = alice.client.send_text(&g, "frist", None).await.unwrap();
    let second = alice.client.send_text(&g, "bye", None).await.unwrap();
    alice.client.edit(&g, &first, "first").await.unwrap();
    bob.sync().await;
    bob.client.react(&g, &first, "👍").await.unwrap();
    bob.client.react(&g, &second, "👋").await.unwrap();
    bob.client.unreact(&g, &second, "👋").await.unwrap();
    alice.client.delete(&g, &second).await.unwrap();
    alice.sync().await;
    bob.sync().await;

    for device in [&alice, &bob] {
        let first = device.message(&first);
        assert!(first.edited);
        assert_eq!(body(device, &first.message_id), "first");
        assert_eq!(
            first.reactions[&bob.user_id()].iter().collect::<Vec<_>>(),
            vec!["👍"]
        );
        let second = device.message(&second);
        assert!(second.deleted);
        assert!(second.reactions.is_empty());
    }
}

#[tokio::test]
async fn retry_after_lost_reply_keeps_one_server_message() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();

    // The server stores the message but the reply never arrives, twice.
    transport
        .faults
        .fail_posts(MessageKind::Application, true, 2);
    let id = alice.client.send_text(&g, "once", None).await.unwrap();
    assert_eq!(alice.message(&id).send_state, Some(SendState::Pending));
    let entry = alice.store.outbox_entry(&id).unwrap().unwrap();
    assert_eq!(entry.attempts, 1);
    // Backing off: a normal pass does not post it again.
    let due = alice.client.flush_outbox().await.unwrap().unwrap();
    assert_eq!(due, entry.next_attempt_at_ms);
    assert_eq!(transport.faults.posts.lock().unwrap().len(), 1);

    for _ in 0..2 {
        alice.client.network_reachable();
        alice.client.flush_outbox().await.unwrap();
    }
    assert_eq!(alice.message(&id).send_state, Some(SendState::Sent));
    assert!(alice.store.outbox_entry(&id).unwrap().is_none());
    let posted = server_messages(&transport, &g, &alice.device());
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].client_id.as_str(), id.as_str());
    assert_eq!(alice.message(&id).seq, Some(posted[0].seq));

    bob.sync().await;
    let texts: Vec<String> = bob
        .messages(&g)
        .iter()
        .map(|m| body(&bob, &m.message_id))
        .collect();
    assert_eq!(texts, vec!["once"]);
}

#[tokio::test]
async fn failed_entry_blocks_nothing_and_can_be_retried_or_cancelled() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();

    transport
        .faults
        .fail_posts(MessageKind::Application, false, MAX_SEND_ATTEMPTS as usize);
    let first = alice.client.send_text(&g, "first", None).await.unwrap();
    // Strict per-chat order: the second waits behind the first.
    let second = alice.client.send_text(&g, "second", None).await.unwrap();
    assert_eq!(alice.message(&second).send_state, Some(SendState::Pending));
    assert_eq!(
        alice.store.outbox_entry(&second).unwrap().unwrap().attempts,
        0
    );
    for _ in 1..MAX_SEND_ATTEMPTS {
        assert!(server_messages(&transport, &g, &alice.device()).is_empty());
        alice.client.network_reachable();
        alice.client.flush_outbox().await.unwrap();
    }
    assert_eq!(alice.message(&first).send_state, Some(SendState::Failed));
    // A failed entry no longer holds the chat back.
    alice.client.flush_outbox().await.unwrap();
    assert_eq!(alice.message(&second).send_state, Some(SendState::Sent));

    alice.client.retry_send(&first).await.unwrap();
    assert_eq!(alice.message(&first).send_state, Some(SendState::Sent));

    transport
        .faults
        .fail_posts(MessageKind::Application, false, 1);
    let third = alice.client.send_text(&g, "third", None).await.unwrap();
    alice.client.cancel_send(&third).await.unwrap();
    assert!(alice.store.message(&third).unwrap().is_none());
    assert!(alice.store.outbox_entries().unwrap().is_empty());
    alice.client.network_reachable();
    alice.client.flush_outbox().await.unwrap();

    bob.sync().await;
    let texts: Vec<String> = bob
        .messages(&g)
        .iter()
        .map(|m| body(&bob, &m.message_id))
        .collect();
    assert_eq!(texts, vec!["second", "first"]);
}

#[tokio::test]
async fn epoch_change_between_enqueue_and_send_reencrypts() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;

    transport
        .faults
        .fail_posts(MessageKind::Application, false, 1);
    let id = alice.client.send_text(&g, "for carol", None).await.unwrap();
    let prepared = alice.store.outbox_entry(&id).unwrap().unwrap().prepared;
    assert_eq!(prepared.unwrap().epoch, 1);

    bob.client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    alice.sync().await;
    alice.client.network_reachable();
    alice.client.flush_outbox().await.unwrap();
    assert_eq!(alice.message(&id).send_state, Some(SendState::Sent));
    let posted = server_messages(&transport, &g, &alice.device());
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].epoch, 2);

    // Carol joined at epoch 2 and can only read it because it was
    // re-encrypted.
    carol.sync().await;
    let texts: Vec<String> = carol
        .messages(&g)
        .iter()
        .map(|m| body(&carol, &m.message_id))
        .collect();
    assert_eq!(texts, vec!["for carol"]);
}

#[tokio::test]
async fn commit_with_lost_reply_is_reposted_with_the_same_client_id() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    let service = transport.inner.service();
    assert_eq!(service.epoch(&g), Ok(1));

    transport.faults.fail_posts(MessageKind::Commit, true, 1);
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    assert_eq!(service.epoch(&g), Ok(2));

    alice.client.send_text(&g, "hi carol", None).await.unwrap();
    carol.sync().await;
    assert_eq!(carol.messages(&g).len(), 1);
}

#[tokio::test]
async fn commit_of_unknown_outcome_stays_pending_until_the_next_sync() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    let service = transport.inner.service();

    // Accepted by the server, but alice never learns it.
    transport
        .faults
        .fail_posts(MessageKind::Commit, true, COMMIT_POST_ATTEMPTS as usize);
    let added = alice.client.add_members(&g, &[carol.user_id()]).await;
    assert!(matches!(
        added,
        Err(ClientError::Transport(gim_sdk::TransportError::Network(_)))
    ));
    assert_eq!(service.epoch(&g), Ok(2));
    // Kept on the fan-out list: the commit may have been accepted.
    assert!(service.group(&g).unwrap().members.contains(&carol.device()));

    // The next sync re-posts it (same client_id), merges it and sends the
    // Welcome.
    alice.sync().await;
    assert_eq!(service.epoch(&g), Ok(2));
    assert_eq!(alice.store.chat(&g).unwrap().unwrap().members.len(), 3);
    alice.client.send_text(&g, "hi carol", None).await.unwrap();
    bob.sync().await;
    carol.sync().await;
    assert_eq!(carol.messages(&g).len(), 1);
    assert_eq!(bob.messages(&g).len(), 1);
}

#[tokio::test]
async fn self_departed_member_is_removed_by_the_lowest_leaf() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id(), carol.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    carol.sync().await;
    let service = transport.inner.service();
    assert_eq!(service.epoch(&g), Ok(1));

    carol.client.leave(&g).await.unwrap();
    // Bob is not the lowest remaining leaf: he does nothing.
    bob.sync().await;
    assert_eq!(service.epoch(&g), Ok(1));
    // Alice (leaf 0) commits the removal.
    alice.sync().await;
    assert_eq!(service.epoch(&g), Ok(2));
    bob.sync().await;
    for device in [&alice, &bob] {
        let members = device.store.chat(&g).unwrap().unwrap().members;
        assert_eq!(members.len(), 2);
        assert!(members.iter().all(|m| m.device != carol.device()));
    }
    // Nothing more to do.
    alice.sync().await;
    assert_eq!(service.epoch(&g), Ok(2));
}

#[tokio::test]
async fn typing_is_sent_directly_and_rate_limited() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();

    for _ in 0..3 {
        alice.client.set_typing(&g, true).await.unwrap();
    }
    assert_eq!(server_messages(&transport, &g, &alice.device()).len(), 1);
    assert!(alice.store.outbox_entries().unwrap().is_empty());
    let changes = bob.sync().await;
    let typing = StateChange::Typing {
        group_id: g.clone(),
        user_id: alice.user_id(),
        active: true,
    };
    assert!(changes.contains(&typing));

    alice.client.set_typing(&g, false).await.unwrap();
    alice.client.set_typing(&g, false).await.unwrap();
    assert_eq!(server_messages(&transport, &g, &alice.device()).len(), 2);
    let changes = bob.sync().await;
    assert!(changes.contains(&StateChange::Typing {
        group_id: g.clone(),
        user_id: alice.user_id(),
        active: false,
    }));
    // Typing creates no timeline rows.
    assert!(bob.messages(&g).is_empty());
}

#[tokio::test]
async fn background_sender_flushes_queued_receipts() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let id = alice.client.send_text(&g, "ping", None).await.unwrap();

    let _sender = bob.client.start_outbox_sender();
    bob.sync().await;
    for _ in 0..100 {
        alice.sync().await;
        if alice.message(&id).send_state == Some(SendState::Delivered) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("delivered receipt not sent");
}
