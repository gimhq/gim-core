//! Membership change items and back pagination through the server history.

mod common;

use std::pin::pin;

use common::{wait_until, Device};
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_sdk::testing::FakeTransport;
use gim_ui::{
    MembershipChangeKind as Kind, MessageContent, Timeline, TimelineItem, TimelineOptions, Vector,
};

/// Messages and membership changes, without date separators.
fn rows(items: &Vector<TimelineItem>) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            TimelineItem::Message(m) => match &m.content {
                MessageContent::Text { body } => Some(body.clone()),
                other => panic!("not a text: {other:?}"),
            },
            TimelineItem::MembershipChange {
                user_name, change, ..
            } => Some(format!("{change:?} {user_name}")),
            TimelineItem::DateSeparator { .. } => None,
        })
        .collect()
}

fn strings(rows: &[&str]) -> Vec<String> {
    rows.iter().map(|r| r.to_string()).collect()
}

#[tokio::test]
async fn add_and_remove_show_on_every_members_timeline() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice", "Alice").await;
    let bob = Device::register(&transport, "bob", "Bob").await;
    let carol = Device::register(&transport, "carol", "Carol").await;
    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    alice.send_text(&g, "ahoy").await;
    bob.sync().await;

    let alice_timeline = Timeline::new(&alice.client, g.clone()).await.unwrap();
    let bob_timeline = Timeline::new(&bob.client, g.clone()).await.unwrap();
    let (mut alice_items, alice_stream) = alice_timeline.items();
    let (mut bob_items, bob_stream) = bob_timeline.items();
    let (mut alice_stream, mut bob_stream) = (pin!(alice_stream), pin!(bob_stream));
    assert_eq!(rows(&alice_items), strings(&["Added Bob", "ahoy"]));
    assert_eq!(rows(&bob_items), strings(&["Added Bob", "ahoy"]));

    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    wait_until(&mut alice_stream, &mut alice_items, |items| {
        rows(items).contains(&"Added Carol".to_string())
    })
    .await;
    bob.sync().await;
    wait_until(&mut bob_stream, &mut bob_items, |items| {
        rows(items).contains(&"Added Carol".to_string())
    })
    .await;
    carol.sync().await;

    alice
        .client
        .remove_members(&g, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    carol.sync().await;
    let expected = strings(&["Added Bob", "ahoy", "Added Carol", "Removed Bob"]);
    wait_until(&mut alice_stream, &mut alice_items, |items| {
        rows(items) == expected
    })
    .await;
    wait_until(&mut bob_stream, &mut bob_items, |items| {
        rows(items) == expected
    })
    .await;
    let carol_timeline = Timeline::new(&carol.client, g.clone()).await.unwrap();
    assert_eq!(
        rows(&carol_timeline.items().0),
        strings(&["Added Carol", "Removed Bob"])
    );
    let change = carol_timeline.items().0.iter().find_map(|item| match item {
        TimelineItem::MembershipChange { change, .. } => Some(*change),
        _ => None,
    });
    assert_eq!(change, Some(Kind::Added));
}

#[tokio::test]
async fn late_joiner_pages_back_through_the_server_history() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice", "Alice").await;
    let bob = Device::register(&transport, "bob", "Bob").await;
    let carol = Device::register(&transport, "carol", "Carol").await;
    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    alice.send_text(&g, "before carol 1").await;
    alice.send_text(&g, "before carol 2").await;
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    carol.sync().await;
    for i in 1..=12 {
        alice.send_text(&g, &format!("m{i}")).await;
    }
    // Carol's device misses these events (as after a cursor reset): its
    // cursors move past them, its store and MLS state never saw them.
    let head = transport.service().events(&carol.device(), 0, usize::MAX).1;
    let last_seq = transport
        .service()
        .messages(&g, 0, usize::MAX)
        .unwrap()
        .last()
        .unwrap()
        .seq;
    carol
        .store
        .transaction(|txn| {
            txn.set_global_cursor(head)?;
            let mut cursor = txn.group_cursor(&g)?;
            cursor.advance_to(last_seq);
            Ok(txn.set_group_cursor(&g, &cursor)?)
        })
        .unwrap();
    assert!(carol.store.messages(&g, None, 100).unwrap().is_empty());

    let options = TimelineOptions {
        initial_page_size: 5,
        ..TimelineOptions::default()
    };
    let timeline = Timeline::with_options(&carol.client, g.clone(), options)
        .await
        .unwrap();
    let (mut items, stream) = timeline.items();
    let mut stream = pin!(stream);
    assert_eq!(rows(&items), strings(&["Added Carol"]));

    // The store has nothing older: the first page comes from the server.
    let mut more = timeline.paginate_backwards(5).await.unwrap();
    wait_until(&mut stream, &mut items, |items| {
        rows(items).iter().any(|r| r == "m12")
    })
    .await;
    assert_eq!(carol.store.messages(&g, None, 100).unwrap().len(), 12);
    for _ in 0..5 {
        if !more {
            break;
        }
        more = timeline.paginate_backwards(5).await.unwrap();
    }
    assert!(!more);
    let mut expected = strings(&["Added Carol"]);
    expected.extend((1..=12).map(|i| format!("m{i}")));
    wait_until(&mut stream, &mut items, |items| rows(items) == expected).await;
    assert_eq!(carol.store.chat(&g).unwrap().unwrap().unread_count, 0);

    // Nothing older remains: no further change.
    assert!(!timeline.paginate_backwards(20).await.unwrap());
    let reopened = Timeline::new(&carol.client, g.clone()).await.unwrap();
    assert!(!reopened.paginate_backwards(20).await.unwrap());
    assert_eq!(rows(&reopened.items().0), expected);
}
