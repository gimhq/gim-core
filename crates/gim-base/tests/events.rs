//! Event processing: Welcome, commit and application messages.

mod common;

use common::{group, setup, text, Device, NOW};
use gim_base::model::{GroupMessage, IncomingEvent, Membership, MessageContent, StateChange};
use gim_base::{StateReader, StateStore, WriteTarget};
use gim_proto::envelope::Content;
use gim_test::FakeDeliveryService;

#[test]
fn welcome_commit_and_application_end_to_end() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    alice.create_chat(&ds, &g);
    assert_eq!(alice.store.chat(&g).unwrap().unwrap().members.len(), 1);

    alice.add(&ds, &g, &[&bob]);
    let changes = bob.sync(&ds);
    let Some(StateChange::ChatUpserted(chat)) = changes.first() else {
        panic!("expected a chat, got {changes:?}");
    };
    assert_eq!(chat.members.len(), 2);
    assert_eq!(chat.membership, Membership::Joined);
    assert_eq!(alice.store.chat(&g).unwrap().unwrap().members.len(), 2);

    let hi = alice.send_text(&ds, &g, "hi");
    let changes = bob.sync(&ds);
    assert!(changes
        .iter()
        .any(|c| matches!(c, StateChange::MessageUpserted(m) if m.message_id == hi)));
    let received = bob.message(&hi);
    assert_eq!(received.sender, alice.me);
    assert_eq!(received.content, MessageContent::Text { body: "hi".into() });
    assert_eq!(received.send_state, None);
    let bob_chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(bob_chat.unread_count, 1);
    assert_eq!(bob_chat.last_message_id.as_ref(), Some(&hi));

    alice.add(&ds, &g, &[&carol]);
    let changes = bob.sync(&ds);
    assert!(matches!(
        &changes[..],
        [StateChange::ChatUpserted(c), StateChange::MembershipChanged(e)]
            if c.members.len() == 3 && e.user_id == carol.me.user_id
    ));
    carol.sync(&ds);
    assert_eq!(carol.store.chat(&g).unwrap().unwrap().members.len(), 3);
    assert_eq!(carol.store.messages(&g, None, 10).unwrap(), vec![]);

    let hey = carol.send_text(&ds, &g, "hey");
    alice.sync(&ds);
    bob.sync(&ds);
    for device in [&alice, &bob] {
        assert_eq!(device.message(&hey).sender, carol.me);
        assert_eq!(device.epoch(&g), alice.epoch(&g));
    }
    assert_eq!(carol.epoch(&g), alice.epoch(&g));
    let timeline: Vec<_> = bob
        .store
        .messages(&g, None, 10)
        .unwrap()
        .into_iter()
        .map(|m| m.message_id)
        .collect();
    assert_eq!(timeline, vec![hi, hey]);
}

#[test]
fn reapplying_events_is_idempotent() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    alice.create_chat(&ds, &g);
    alice.add(&ds, &g, &[&bob]);
    let welcome = bob.pull(&ds).into_iter().find(is_message).unwrap();
    assert!(!bob.apply(welcome.clone()).is_empty());
    assert!(bob.apply(welcome).is_empty());

    alice.send_text(&ds, &g, "one");
    alice.send_text(&ds, &g, "two");
    let events: Vec<_> = bob.pull(&ds).into_iter().filter(is_message).collect();
    for event in &events {
        assert!(!bob.apply(event.clone()).is_empty());
    }
    for event in &events {
        assert!(bob.apply(event.clone()).is_empty());
    }
    assert_eq!(bob.store.messages(&g, None, 10).unwrap().len(), 2);
    assert_eq!(bob.store.chat(&g).unwrap().unwrap().unread_count, 2);
    let cursor = bob.store.group_cursor(&g).unwrap();
    assert_eq!(cursor.first_gap(), None);
    assert_eq!(cursor.contiguous_seq, 3);
}

fn is_message(event: &IncomingEvent) -> bool {
    matches!(event, IncomingEvent::Message(_))
}

#[test]
fn failed_write_rolls_back_mls_state() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob]);

    // A commit whose chat update fails leaves the epoch where it was.
    let commit_seq = alice.add(&ds, &g, &[&carol]);
    let commit = bob.pull(&ds).remove(0);
    let epoch = bob.epoch(&g);
    bob.store.fail_writes(Some(WriteTarget::Chat));
    assert!(bob
        .client
        .apply(&bob.store, &bob.engine, commit.clone())
        .is_err());
    assert_eq!(bob.epoch(&g), epoch);
    assert!(!bob.store.group_cursor(&g).unwrap().contains(commit_seq));
    bob.store.fail_writes(None);
    assert!(!bob.apply(commit).is_empty());
    assert_eq!(bob.epoch(&g), epoch + 1);
    carol.sync(&ds);

    // An application message whose row insert fails leaves the ratchet
    // unconsumed, so it still decrypts afterwards.
    let id = alice.send_text(&ds, &g, "fair winds");
    let message = bob.pull(&ds).remove(0);
    bob.store.fail_writes(Some(WriteTarget::Message));
    assert!(bob
        .client
        .apply(&bob.store, &bob.engine, message.clone())
        .is_err());
    assert!(bob.store.message(&id).unwrap().is_none());
    assert!(bob.store.outbox_entries().unwrap().is_empty());
    bob.store.fail_writes(None);
    bob.apply(message);
    assert_eq!(
        bob.message(&id).content,
        MessageContent::Text {
            body: "fair winds".into()
        }
    );
}

#[test]
fn own_echo_marks_sent_without_decrypting() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    setup(&ds, &g, &[&alice, &bob]);

    let id = alice.enqueue(&g, text("echo"));
    let seq = alice.post(&ds, &id);
    let payload = alice
        .store
        .outbox_entry(&id)
        .unwrap()
        .unwrap()
        .prepared
        .unwrap()
        .payload;
    let echo = IncomingEvent::Message(GroupMessage {
        group_id: g.clone(),
        seq,
        sender: alice.me.clone(),
        kind: gim_base::model::MessageKind::Application,
        payload,
        client_id: Some(alice.store.outbox_entry(&id).unwrap().unwrap().client_id()),
    });
    let changes = alice.apply(echo);
    assert!(changes.iter().any(|c| matches!(
        c,
        StateChange::MessageUpserted(m) if m.message_id == id && m.seq == Some(seq)
    )));
    let message = alice.message(&id);
    assert_eq!(message.send_state, Some(gim_base::model::SendState::Sent));
    assert!(alice.store.outbox_entry(&id).unwrap().is_none());
    assert_eq!(alice.store.messages(&g, None, 10).unwrap().len(), 1);
    // The HTTP response arriving afterwards changes nothing.
    assert!(alice
        .client
        .mark_sent(&alice.store, &id, seq)
        .unwrap()
        .is_empty());

    // Echo of an own commit: nothing to decrypt, the seq is recorded.
    let commit_echo = IncomingEvent::Message(GroupMessage {
        group_id: g.clone(),
        seq: seq + 1,
        sender: alice.me.clone(),
        kind: gim_base::model::MessageKind::Commit,
        payload: vec![1, 2, 3],
        client_id: None,
    });
    assert!(alice.apply(commit_echo).is_empty());
    assert!(alice.store.group_cursor(&g).unwrap().contains(seq + 1));
}

#[test]
fn future_epoch_message_waits_for_its_commit() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob]);

    alice.add(&ds, &g, &[&carol]);
    let id = alice.send_text(&ds, &g, "after the commit");
    let mut events: Vec<_> = bob.pull(&ds).into_iter().filter(is_message).collect();
    assert_eq!(events.len(), 2);
    let message = events.pop().unwrap();
    let commit = events.pop().unwrap();

    assert!(bob.apply(message.clone()).is_empty());
    assert_eq!(bob.store.parked_messages(&g).unwrap().len(), 1);
    let changes = bob.apply(commit);
    assert!(changes
        .iter()
        .any(|c| matches!(c, StateChange::MessageUpserted(m) if m.message_id == id)));
    assert!(bob.store.parked_messages(&g).unwrap().is_empty());
    assert!(bob.apply(message).is_empty());
    assert_eq!(bob.store.group_cursor(&g).unwrap().first_gap(), None);
}

#[test]
fn typing_is_transient_and_group_info_renames() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    setup(&ds, &g, &[&alice, &bob]);

    alice.send(&ds, &g, Content::Typing { active: true });
    alice.send(
        &ds,
        &g,
        Content::GroupInfo {
            name: Some("Aegean crew".into()),
            avatar: None,
        },
    );
    assert_eq!(
        alice.store.chat(&g).unwrap().unwrap().name.as_deref(),
        Some("Aegean crew")
    );
    let changes = bob.sync(&ds);
    assert_eq!(
        changes[0],
        StateChange::Typing {
            group_id: g.clone(),
            user_id: alice.me.user_id.clone(),
            active: true,
        }
    );
    assert!(
        matches!(&changes[1], StateChange::ChatUpserted(c) if c.name.as_deref() == Some("Aegean crew"))
    );
    assert!(bob.store.messages(&g, None, 10).unwrap().is_empty());
    assert_eq!(bob.store.chat(&g).unwrap().unwrap().unread_count, 0);
}

#[test]
fn removed_member_leaves_the_chat() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob, &carol]);

    alice.remove(&ds, &g, &[&bob]);
    assert_eq!(alice.store.chat(&g).unwrap().unwrap().members.len(), 2);
    bob.sync(&ds);
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.membership, Membership::Left);
    assert!(!bob.engine.has_group(&bob.store, &g).unwrap());
    assert!(bob
        .client
        .enqueue(&bob.store, &g, text("x"), None, NOW)
        .is_err());
    carol.sync(&ds);
    assert_eq!(carol.store.chat(&g).unwrap().unwrap().members.len(), 2);

    let changes = alice
        .client
        .forget_chat(&alice.store, &alice.engine, &g)
        .unwrap();
    assert_eq!(changes, vec![StateChange::ChatRemoved(g.clone())]);
    assert!(alice.store.chat(&g).unwrap().is_none());
    assert!(alice
        .store
        .transaction(|txn| Ok(alice.engine.group_ids(&*txn)?))
        .unwrap()
        .is_empty());
}

#[test]
fn key_packages_low_is_forwarded() {
    let alice = Device::new("alice");
    assert_eq!(
        alice.apply(IncomingEvent::KeyPackagesLow),
        vec![StateChange::KeyPackagesLow]
    );
}
