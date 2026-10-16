//! Chat state on the chat list and the user ids of membership items.

mod common;

use std::pin::pin;

use common::{wait_until, Device};
use gim_common::{GroupId, UserId};
use gim_sdk::testing::FakeTransport;
use gim_ui::{
    ChatListItem, ChatListService, ChatState, MembershipChangeKind as Kind, Timeline, TimelineItem,
    Vector,
};

fn state(items: &Vector<ChatListItem>, g: &GroupId) -> Option<ChatState> {
    items.iter().find(|c| &c.chat_id == g).map(|c| c.state)
}

/// `(change, user_id, actor_user_id)` of the membership items.
fn changes(items: &Vector<TimelineItem>) -> Vec<(Kind, UserId, Option<UserId>)> {
    items
        .iter()
        .filter_map(|item| match item {
            TimelineItem::MembershipChange {
                change,
                user_id,
                actor_user_id,
                ..
            } => Some((*change, user_id.clone(), actor_user_id.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leave_moves_the_chat_to_leaving_then_left() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice", "Alice").await;
    let carol = Device::register(&transport, "carol", "Carol").await;
    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[carol.user_id()])
        .await
        .unwrap();
    carol.sync().await;

    let service = ChatListService::new(&carol.client).await.unwrap();
    let (mut items, stream) = service.entries();
    let mut stream = pin!(stream);
    assert_eq!(state(&items, &g), Some(ChatState::Active));

    carol.client.leave(&g).await.unwrap();
    wait_until(&mut stream, &mut items, |items| {
        state(items, &g) == Some(ChatState::Leaving)
    })
    .await;

    // Alice, the only other member, commits the leave.
    alice.sync().await;
    carol.sync().await;
    wait_until(&mut stream, &mut items, |items| {
        state(items, &g) == Some(ChatState::Left)
    })
    .await;

    // Both see Carol's own leave: the actor is Carol, not the committer.
    let left = (Kind::Left, carol.user_id(), Some(carol.user_id()));
    let carol_timeline = Timeline::new(&carol.client, g.clone()).await.unwrap();
    assert_eq!(carol_timeline.chat_state(), Some(ChatState::Left));
    assert_eq!(changes(&carol_timeline.items().0).last(), Some(&left));
    let alice_timeline = Timeline::new(&alice.client, g.clone()).await.unwrap();
    assert_eq!(changes(&alice_timeline.items().0).last(), Some(&left));

    // A restarted list reads the state from the store.
    drop(service);
    let service = ChatListService::new(&carol.client).await.unwrap();
    assert_eq!(state(&service.entries().0, &g), Some(ChatState::Left));
}

/// A leave the hub refuses for good leaves the chat active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_leave_returns_the_chat_to_active() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice", "Alice").await;
    let carol = Device::register(&transport, "carol", "Carol").await;
    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[carol.user_id()])
        .await
        .unwrap();
    carol.sync().await;
    let service = ChatListService::new(&carol.client).await.unwrap();
    let (mut items, stream) = service.entries();
    let mut stream = pin!(stream);

    // Removed hub-side (not yet seen by Carol): the hub answers 403.
    transport
        .service()
        .remove_member(&g, &carol.device())
        .unwrap();
    assert!(carol.client.leave(&g).await.is_err());
    let timeline = Timeline::new(&carol.client, g.clone()).await.unwrap();
    assert_eq!(timeline.chat_state(), Some(ChatState::Active));
    // The row ends active; a `Leaving` in between is not required.
    wait_until(&mut stream, &mut items, |items| {
        state(items, &g) == Some(ChatState::Active)
    })
    .await;
}

#[tokio::test]
async fn membership_items_carry_user_ids() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice", "Alice").await;
    let bob = Device::register(&transport, "bob", "Bob").await;
    let carol = Device::register(&transport, "carol", "Carol").await;
    // A user of another hub, unknown here: never added.
    let elsewhere = FakeTransport::new();
    let ghost = Device::register(&elsewhere, "ghost", "Ghost").await;

    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    let timeline = Timeline::new(&alice.client, g.clone()).await.unwrap();
    let (mut items, stream) = timeline.items();
    let mut stream = pin!(stream);
    alice
        .client
        .add_members(&g, &[carol.user_id(), ghost.user_id()])
        .await
        .unwrap();
    alice
        .client
        .remove_members(&g, &[bob.user_id()])
        .await
        .unwrap();
    let (a, b, c, x) = (
        alice.user_id(),
        bob.user_id(),
        carol.user_id(),
        ghost.user_id(),
    );
    let mut expected = vec![
        (Kind::Added, b.clone(), Some(a.clone())),
        (Kind::Added, c, Some(a.clone())),
        // The unresolvable invitee, reported as removed by the inviter.
        (Kind::Removed, x, Some(a.clone())),
        (Kind::Removed, b, Some(a)),
    ];
    wait_until(&mut stream, &mut items, |items| {
        changes(items).len() == expected.len()
    })
    .await;
    let mut got = changes(&items);
    let key = |row: &(Kind, UserId, Option<UserId>)| format!("{row:?}");
    got.sort_by_key(key);
    expected.sort_by_key(key);
    assert_eq!(got, expected);
}
