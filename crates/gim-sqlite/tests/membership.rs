//! Membership events recorded from commits and Welcomes, and messages
//! applied from the hub history, on the SQLite store.

mod common;

use common::{group, Device, NOW};
use gim_base::model::{
    GroupMessage, IncomingEvent, Membership, MembershipChangeKind as Kind, MessageContent,
    MessageKind, StateChange,
};
use gim_base::{StateReader, StateStore};
use gim_common::GroupId;
use gim_proto::envelope::Content;
use gim_test::{Event, FakeDeliveryService};

fn events(device: &Device, g: &GroupId) -> Vec<(u64, String, String, Kind)> {
    device
        .store
        .membership_events(g)
        .unwrap()
        .into_iter()
        .map(|e| (e.seq, e.user_id.to_string(), e.actor.to_string(), e.kind))
        .collect()
}

fn event(seq: u64, user: &str, actor: &str, kind: Kind) -> (u64, String, String, Kind) {
    (seq, user_id(user), user_id(actor), kind)
}

fn user_id(name: &str) -> String {
    common::user(name).to_string()
}

#[test]
fn commits_and_welcomes_record_membership_changes() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol, dave) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
        Device::new("dave"),
    );
    alice.create_chat(&ds, &g);
    let add_bob = alice.add(&ds, &g, &[&bob]);
    bob.sync(&ds);
    let add_carol = alice.add(&ds, &g, &[&carol, &dave]);
    bob.sync(&ds);
    carol.sync(&ds);
    dave.sync(&ds);

    let remove_bob = alice.remove(&ds, &g, &[&bob]);
    let changes = carol.sync(&ds);
    assert!(changes.iter().any(|c| matches!(
        c,
        StateChange::MembershipChanged(e) if e.seq == remove_bob && e.kind == Kind::Removed
    )));
    bob.sync(&ds);
    dave.sync(&ds);

    // Dave proposes to leave; alice's commit of his proposal removes him
    // from the tree, which records that he left.
    let proposal = dave.propose_leave(&ds, &g);
    alice.sync(&ds);
    carol.sync(&ds);
    let remove_dave = alice.commit_proposals(&ds, &g, common::proposal_leaves(&ds, &g, proposal));
    carol.sync(&ds);

    let added_bob = event(add_bob, "bob", "alice", Kind::Added);
    // Ordered by seq, then user id.
    let mut added = [
        event(add_carol, "carol", "alice", Kind::Added),
        event(add_carol, "dave", "alice", Kind::Added),
    ];
    added.sort_by(|a, b| a.1.cmp(&b.1));
    let [added_carol, added_dave] = added;
    let removed_bob = event(remove_bob, "bob", "alice", Kind::Removed);
    let left_dave = event(remove_dave, "dave", "alice", Kind::Left);
    assert_eq!(
        events(&alice, &g),
        [
            added_bob.clone(),
            added_carol.clone(),
            added_dave.clone(),
            removed_bob.clone(),
            left_dave.clone()
        ]
    );
    // Joiners record their own Welcome (at the commit seq), not what came
    // before it.
    let welcome_bob = event(add_bob, "bob", "alice", Kind::Added);
    assert_eq!(
        events(&bob, &g),
        [
            welcome_bob,
            added_carol.clone(),
            added_dave,
            removed_bob.clone()
        ]
    );
    let welcome_carol = event(add_carol, "carol", "alice", Kind::Added);
    assert_eq!(events(&carol, &g), [welcome_carol, removed_bob, left_dave]);
}

#[test]
fn history_messages_are_inserted_once_without_unread() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    alice.create_chat(&ds, &g);
    alice.add(&ds, &g, &[&bob]);
    bob.sync(&ds);
    let old = alice.send_text(&ds, &g, "old news");
    alice.send(
        &ds,
        &g,
        Content::GroupInfo {
            name: Some("stale".into()),
            avatar: None,
        },
    );
    alice.send(&ds, &g, Content::Typing { active: true });
    let edited = alice.send_text(&ds, &g, "typo");
    alice.send(
        &ds,
        &g,
        Content::Edit {
            target: edited.clone(),
            new_body: "fixed".into(),
        },
    );
    let history: Vec<GroupMessage> = ds
        .messages(&g, 0, 100)
        .unwrap()
        .into_iter()
        .flat_map(|d| common::to_events(Event::Message(d)))
        .map(|e| match e {
            IncomingEvent::Message(m) => m,
            _ => unreachable!(),
        })
        .collect();
    assert!(history.iter().any(|m| m.kind == MessageKind::Commit));

    let apply = |messages: Vec<GroupMessage>| {
        bob.client
            .apply_history(&bob.store, &bob.engine, messages)
            .unwrap()
    };
    let changes = apply(history.clone());
    assert!(!changes
        .iter()
        .any(|c| matches!(c, StateChange::Typing { .. })));
    let bodies: Vec<_> = bob
        .store
        .messages(&g, None, 10)
        .unwrap()
        .into_iter()
        .map(|m| m.content)
        .collect();
    assert_eq!(
        bodies,
        [
            MessageContent::Text {
                body: "old news".into()
            },
            MessageContent::Text {
                body: "fixed".into()
            },
        ]
    );
    assert!(bob.message(&edited).edited);
    assert!(bob.message(&old).seq.is_some());
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.unread_count, 0);
    assert_eq!(chat.name, None);
    assert!(bob.store.outbox_entries().unwrap().is_empty());

    // Everything was applied (or cannot be decrypted again).
    assert!(apply(history).is_empty());
    assert_eq!(bob.store.messages(&g, None, 10).unwrap().len(), 2);
    // A message from before the Welcome cannot be decrypted by a joiner.
    let carol = Device::new("carol");
    alice.add(&ds, &g, &[&carol]);
    carol.sync(&ds);
    let before_join: Vec<GroupMessage> = ds
        .messages(&g, 0, 100)
        .unwrap()
        .into_iter()
        .flat_map(|d| common::to_events(Event::Message(d)))
        .filter_map(|e| match e {
            IncomingEvent::Message(m) if m.kind == MessageKind::Application => Some(m),
            _ => None,
        })
        .collect();
    assert!(carol
        .client
        .apply_history(&carol.store, &carol.engine, before_join)
        .unwrap()
        .is_empty());
}

#[test]
fn leaving_records_the_own_left_event() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    alice.create_chat(&ds, &g);
    alice.add(&ds, &g, &[&bob]);
    bob.sync(&ds);
    let last = alice.send_text(&ds, &g, "hi");
    bob.sync(&ds);
    let last_seq = bob.message(&last).seq.unwrap();

    // Bob proposes to leave; his device records it as others will.
    bob.propose_leave(&ds, &g);
    let changes = bob
        .client
        .leave_chat(&bob.store, &bob.engine, &g, NOW)
        .unwrap();
    let left_bob = event(last_seq + 1, "bob", "bob", Kind::Left);
    assert!(changes.iter().any(|c| matches!(
        c,
        StateChange::MembershipChanged(e) if e.kind == Kind::Left && e.seq == last_seq + 1
    )));
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.membership, Membership::Left);
    assert_eq!(events(&bob, &g).last(), Some(&left_bob));
    let has_group = bob
        .store
        .transaction(|txn| Ok(bob.engine.has_group(&*txn, &g)?))
        .unwrap();
    assert!(!has_group);

    // Leaving again changes nothing.
    let before = events(&bob, &g);
    let again = bob
        .client
        .leave_chat(&bob.store, &bob.engine, &g, NOW)
        .unwrap();
    assert!(again.is_empty());
    assert_eq!(events(&bob, &g), before);

    // Alice commits his proposal and records the same kind of event.
    alice.sync(&ds);
    let remove_bob = alice.commit_proposals(&ds, &g, vec![1]);
    assert_eq!(
        events(&alice, &g).last(),
        Some(&event(remove_bob, "bob", "alice", Kind::Left))
    );
}
