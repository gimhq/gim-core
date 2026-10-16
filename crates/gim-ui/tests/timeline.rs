mod common;

use std::pin::pin;
use std::sync::Arc;

use common::{apply, day_start, next, seed, wait_until, Device, DAY_MS, HOUR_MS, JAN_1_MS};
use gim_base::BaseClient;
use gim_common::{now_ms, GroupId};
use gim_proto::envelope::Content;
use gim_sdk::testing::FakeTransport;
use gim_ui::{
    FixedOffset, MessageContent, MessageItem, ReactionGroup, SendState, TimeZone, Timeline,
    TimelineItem, TimelineOptions, Vector, VectorDiff,
};

fn messages(items: &Vector<TimelineItem>) -> Vec<&MessageItem> {
    items.iter().filter_map(TimelineItem::as_message).collect()
}

fn body(item: &TimelineItem) -> &str {
    match &item.as_message().expect("a message").content {
        MessageContent::Text { body } => body,
        other => panic!("not a text: {other:?}"),
    }
}

fn separator(day_start_ms: u64) -> TimelineItem {
    TimelineItem::DateSeparator { day_start_ms }
}

async fn direct_chat(transport: &FakeTransport) -> (Device, Device, GroupId) {
    let alice = Device::register(transport, "alice", "Alice").await;
    let bob = Device::register(transport, "bob", "Bob").await;
    bob.client.find_user("alice").await.unwrap();
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    (alice, bob, g)
}

#[tokio::test]
async fn insert_edit_delete_and_reactions() {
    let transport = FakeTransport::new();
    let (alice, bob, g) = direct_chat(&transport).await;
    let one = alice.send_text(&g, "one").await;
    let two = alice.send_text(&g, "two").await;
    bob.sync().await;

    let timeline = Timeline::new(&bob.client, g.clone()).await.unwrap();
    let (mut items, stream) = timeline.items();
    let mut stream = pin!(stream);
    assert_eq!(items.len(), 3);
    assert!(matches!(items[0], TimelineItem::DateSeparator { .. }));
    assert_eq!((body(&items[1]), body(&items[2])), ("one", "two"));
    let first = items[1].as_message().unwrap();
    assert_eq!(first.sender.display_name, "Alice");
    assert_eq!(first.sender.handle, "alice");
    assert!(!first.is_own);
    assert_eq!(first.send_state, None);

    let three = alice.send_text(&g, "three").await;
    bob.sync().await;
    let diffs = next(&mut stream).await;
    let [VectorDiff::Insert { index: 3, value }] = diffs.as_slice() else {
        panic!("unexpected diffs {diffs:?}");
    };
    assert_eq!(body(value), "three");
    apply(&mut items, diffs);

    alice
        .send(
            &g,
            Content::Edit {
                target: two.clone(),
                new_body: "two!".into(),
            },
        )
        .await;
    bob.sync().await;
    let diffs = next(&mut stream).await;
    let [VectorDiff::Set { index: 2, value }] = diffs.as_slice() else {
        panic!("unexpected diffs {diffs:?}");
    };
    assert_eq!(body(value), "two!");
    assert!(value.as_message().unwrap().edited);
    apply(&mut items, diffs);

    // Own reaction: applied locally right away.
    let thumbs = |count, own| {
        vec![ReactionGroup {
            emoji: "👍".into(),
            count,
            own,
        }]
    };
    bob.send(
        &g,
        Content::Reaction {
            target: three.clone(),
            emoji: "👍".into(),
            remove: false,
        },
    )
    .await;
    let diffs = next(&mut stream).await;
    let [VectorDiff::Set { index: 3, value }] = diffs.as_slice() else {
        panic!("unexpected diffs {diffs:?}");
    };
    assert_eq!(value.as_message().unwrap().reactions, thumbs(1, true));
    apply(&mut items, diffs);

    alice
        .send(
            &g,
            Content::Reaction {
                target: three.clone(),
                emoji: "👍".into(),
                remove: false,
            },
        )
        .await;
    bob.sync().await;
    let diffs = next(&mut stream).await;
    let [VectorDiff::Set { index: 3, value }] = diffs.as_slice() else {
        panic!("unexpected diffs {diffs:?}");
    };
    assert_eq!(value.as_message().unwrap().reactions, thumbs(2, true));
    apply(&mut items, diffs);

    alice.send(&g, Content::Delete { target: one }).await;
    bob.sync().await;
    let diffs = next(&mut stream).await;
    let [VectorDiff::Set { index: 1, value }] = diffs.as_slice() else {
        panic!("unexpected diffs {diffs:?}");
    };
    assert_eq!(value.as_message().unwrap().content, MessageContent::Deleted);
    apply(&mut items, diffs);

    // Own message: local echo, then accepted by the server.
    bob.send_text(&g, "four").await;
    wait_until(&mut stream, &mut items, |items| {
        items.len() == 5
            && items[4]
                .as_message()
                .is_some_and(|m| m.is_own && m.send_state == Some(SendState::Sent))
    })
    .await;
    assert_eq!(body(&items[4]), "four");
    assert_eq!(items[4].as_message().unwrap().sender.display_name, "Bob");

    // The store holds what the stream built.
    let reopened = Timeline::new(&bob.client, g.clone()).await.unwrap();
    assert_eq!(reopened.items().0, items);
}

#[tokio::test]
async fn own_pending_failed_and_reply_preview() {
    let transport = FakeTransport::new();
    let (alice, bob, g) = direct_chat(&transport).await;
    let question = alice.send_text(&g, "lunch?").await;
    bob.sync().await;

    // Queued but never posted: stays pending.
    let base = BaseClient::new(bob.device());
    let enqueue = |body: &str, reply_to| {
        base.enqueue(
            &*bob.store,
            &g,
            Content::Text { body: body.into() },
            reply_to,
            now_ms(),
        )
        .unwrap()
        .0
    };
    let yes = enqueue("yes", Some(question.clone()));
    let failed = enqueue("see you", None);
    base.mark_failed(&*bob.store, &failed, "rejected", false, now_ms())
        .unwrap();

    let timeline = Timeline::new(&bob.client, g.clone()).await.unwrap();
    let (mut items, stream) = timeline.items();
    let mut stream = pin!(stream);
    let find = |items: &Vector<TimelineItem>, id| -> MessageItem {
        (*messages(items)
            .into_iter()
            .find(|m| &m.message_id == id)
            .unwrap())
        .clone()
    };
    let failed = find(&items, &failed);
    assert_eq!(
        failed.send_state,
        Some(SendState::Failed {
            reason: "rejected".into()
        })
    );
    let reply = find(&items, &yes);
    assert!(reply.is_own);
    assert_eq!(reply.send_state, Some(SendState::Pending));
    let preview = reply.reply_to.as_ref().unwrap();
    assert_eq!(preview.message_id, question);
    assert_eq!(preview.sender_name, "Alice");
    assert_eq!(preview.text, "lunch?");

    // Editing the quoted message refreshes the preview.
    alice
        .send(
            &g,
            Content::Edit {
                target: question.clone(),
                new_body: "lunch at 1?".into(),
            },
        )
        .await;
    bob.sync().await;
    wait_until(&mut stream, &mut items, |items| {
        find(items, &yes)
            .reply_to
            .is_some_and(|r| r.text == "lunch at 1?")
    })
    .await;

    // Removed from the server group: the hub rejects the post for good
    // (403 `not_member`), so the message fails with the rejection.
    transport
        .service()
        .remove_member(&g, &bob.device())
        .unwrap();
    bob.send_text(&g, "hello?").await;
    wait_until(&mut stream, &mut items, |items| {
        items.len() == 5
            && matches!(
                items[4].as_message().unwrap().send_state,
                Some(SendState::Failed { .. })
            )
    })
    .await;
    let last = items[4].as_message().unwrap();
    assert_eq!(body(&items[4]), "hello?");
    assert!(
        matches!(&last.send_state, Some(SendState::Failed { reason }) if reason.contains("403 not_member")),
        "{:?}",
        last.send_state
    );
}

#[tokio::test]
async fn date_separators() {
    let transport = FakeTransport::new();
    let (alice, bob, g) = direct_chat(&transport).await;
    let sender = alice.device();
    seed(&bob.store, &g, &sender, 1, JAN_1_MS + 10 * HOUR_MS, "jan 1");
    seed(
        &bob.store,
        &g,
        &sender,
        2,
        JAN_1_MS + DAY_MS + 9 * HOUR_MS,
        "jan 2",
    );

    let timeline = Timeline::new(&bob.client, g.clone()).await.unwrap();
    let (mut items, stream) = timeline.items();
    let mut stream = pin!(stream);
    assert_eq!(items.len(), 4);
    assert_eq!(items[0], separator(JAN_1_MS));
    assert_eq!(body(&items[1]), "jan 1");
    assert_eq!(items[2], separator(JAN_1_MS + DAY_MS));
    assert_eq!(body(&items[3]), "jan 2");

    alice.send_text(&g, "today").await;
    bob.sync().await;
    let diffs = next(&mut stream).await;
    let [VectorDiff::Insert {
        index: 4,
        value: sep,
    }, VectorDiff::Insert { index: 5, value }] = diffs.as_slice()
    else {
        panic!("unexpected diffs {diffs:?}");
    };
    assert_eq!(*sep, separator(day_start(now_ms())));
    assert_eq!(body(value), "today");
    apply(&mut items, diffs);

    // Same day: no new separator.
    alice.send_text(&g, "later today").await;
    bob.sync().await;
    let diffs = next(&mut stream).await;
    assert!(matches!(
        diffs.as_slice(),
        [VectorDiff::Insert { index: 6, .. }]
    ));
}

#[tokio::test]
async fn date_separators_follow_utc_offset() {
    let transport = FakeTransport::new();
    let (alice, bob, _) = direct_chat(&transport).await;
    let g = GroupId::new("local-only").unwrap();
    let sender = alice.device();
    // 22:30 UTC on Jan 1 is 01:30 on Jan 2 at UTC+3.
    seed(
        &bob.store,
        &g,
        &sender,
        1,
        JAN_1_MS + 22 * HOUR_MS + HOUR_MS / 2,
        "late",
    );
    seed(
        &bob.store,
        &g,
        &sender,
        2,
        JAN_1_MS + DAY_MS + 10 * HOUR_MS,
        "next",
    );

    let utc = Timeline::new(&bob.client, g.clone()).await.unwrap();
    assert_eq!(utc.items().0.len(), 4);

    let options = TimelineOptions {
        utc_offset_secs: 3 * 3600,
        ..TimelineOptions::default()
    };
    let local = Timeline::with_options(&bob.client, g.clone(), options)
        .await
        .unwrap();
    let items = local.items().0;
    assert_eq!(items.len(), 3);
    assert_eq!(items[0], separator(JAN_1_MS + DAY_MS - 3 * HOUR_MS));
}

/// UTC+1, and UTC+2 from `transition_ms` on.
struct Dst {
    transition_ms: i64,
}

impl TimeZone for Dst {
    fn utc_offset_secs(&self, at_ms: i64) -> i32 {
        if at_ms < self.transition_ms {
            3600
        } else {
            7200
        }
    }
}

#[tokio::test]
async fn date_separators_follow_dst_and_time_zone_changes() {
    let transport = FakeTransport::new();
    let (alice, bob, _) = direct_chat(&transport).await;
    let g = GroupId::new("dst").unwrap();
    let sender = alice.device();
    // Jan 11 00:00 UTC; the clocks go forward at 01:00 UTC.
    let d = JAN_1_MS + 10 * DAY_MS;
    let zone = Arc::new(Dst {
        transition_ms: (d + HOUR_MS) as i64,
    });
    // 23:30 local on Jan 10 (+1).
    seed(&bob.store, &g, &sender, 1, d - 3 * HOUR_MS / 2, "before");
    // 00:30 local on Jan 11 (+1), the transition day.
    seed(
        &bob.store,
        &g,
        &sender,
        2,
        d - HOUR_MS / 2,
        "transition day",
    );
    // 00:30 local on Jan 12 (+2).
    seed(
        &bob.store,
        &g,
        &sender,
        3,
        d + 22 * HOUR_MS + HOUR_MS / 2,
        "after",
    );

    let options = TimelineOptions {
        time_zone: Some(zone),
        ..TimelineOptions::default()
    };
    let timeline = Timeline::with_options(&bob.client, g.clone(), options)
        .await
        .unwrap();
    let (mut items, stream) = timeline.items();
    let mut stream = pin!(stream);
    assert_eq!(items.len(), 6);
    assert_eq!(items[0], separator(d - DAY_MS - HOUR_MS));
    assert_eq!(body(&items[1]), "before");
    assert_eq!(items[2], separator(d - HOUR_MS));
    assert_eq!(body(&items[3]), "transition day");
    assert_eq!(items[4], separator(d + DAY_MS - 2 * HOUR_MS));
    assert_eq!(body(&items[5]), "after");

    // Back to UTC: the first two share Jan 10.
    timeline.set_time_zone(Arc::new(FixedOffset(0)));
    let diffs = next(&mut stream).await;
    assert!(diffs
        .iter()
        .all(|d| !matches!(d, VectorDiff::Reset { .. } | VectorDiff::Set { .. })));
    apply(&mut items, diffs);
    let expected = timeline.items().0;
    assert_eq!(items, expected);
    assert_eq!(items.len(), 5);
    assert_eq!(items[0], separator(d - DAY_MS));
    assert_eq!(body(&items[1]), "before");
    assert_eq!(body(&items[2]), "transition day");
    assert_eq!(items[3], separator(d));
    assert_eq!(body(&items[4]), "after");
}

#[tokio::test]
async fn back_pagination() {
    let transport = FakeTransport::new();
    let (alice, bob, _) = direct_chat(&transport).await;
    let g = GroupId::new("paged").unwrap();
    let sender = alice.device();
    for seq in 1..=25 {
        seed(
            &bob.store,
            &g,
            &sender,
            seq,
            JAN_1_MS + seq * 1000,
            &format!("m{seq}"),
        );
    }

    let options = TimelineOptions {
        initial_page_size: 10,
        ..TimelineOptions::default()
    };
    let timeline = Timeline::with_options(&bob.client, g.clone(), options)
        .await
        .unwrap();
    let (mut items, stream) = timeline.items();
    let mut stream = pin!(stream);
    let bodies = |items: &Vector<TimelineItem>| -> Vec<String> {
        messages(items)
            .iter()
            .map(|m| match &m.content {
                MessageContent::Text { body } => body.clone(),
                _ => unreachable!(),
            })
            .collect()
    };
    let expected = |range: std::ops::RangeInclusive<u64>| -> Vec<String> {
        range.map(|seq| format!("m{seq}")).collect()
    };
    assert_eq!(items[0], separator(JAN_1_MS));
    assert_eq!(bodies(&items), expected(16..=25));

    assert!(timeline.paginate_backwards(10).await.unwrap());
    let diffs = next(&mut stream).await;
    assert_eq!(diffs.len(), 10);
    assert!(diffs
        .iter()
        .enumerate()
        .all(|(i, d)| matches!(d, VectorDiff::Insert { index, .. } if *index == i + 1)));
    apply(&mut items, diffs);
    assert_eq!(bodies(&items), expected(6..=25));

    assert!(!timeline.paginate_backwards(10).await.unwrap());
    apply(&mut items, next(&mut stream).await);
    assert_eq!(bodies(&items), expected(1..=25));
    assert_eq!(items[0], separator(JAN_1_MS));
    assert!(!timeline.paginate_backwards(10).await.unwrap());
}
