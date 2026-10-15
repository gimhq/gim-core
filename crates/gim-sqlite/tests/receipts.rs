//! Receipt aggregation and edit/delete/reaction folding.
//!
//! Ported from `crates/gim-base/tests/receipts.rs` to run against `SqliteStore`.

mod common;

use std::collections::BTreeSet;

use common::{group, setup, Device};
use gim_base::model::{MessageContent, OutboxKind, SendState};
use gim_base::StateReader;
use gim_proto::envelope::{Content, Envelope, ReceiptKind};
use gim_test::FakeDeliveryService;

fn receipt_ids(device: &Device, kind: ReceiptKind) -> Vec<Vec<gim_common::MessageId>> {
    device
        .store
        .outbox_entries()
        .unwrap()
        .into_iter()
        .filter_map(|e| match e.kind {
            OutboxKind::Envelope(Envelope {
                content:
                    Content::Receipt {
                        kind: k,
                        message_ids,
                    },
                ..
            }) if k == kind => Some(message_ids),
            _ => None,
        })
        .collect()
}

#[test]
fn receipts_aggregate_over_every_other_member_device() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob, &carol]);

    let first = alice.send_text(&ds, &g, "first");
    let second = alice.send_text(&ds, &g, "second");
    assert_eq!(alice.message(&first).send_state, Some(SendState::Sent));

    // Delivered receipts of one sync are coalesced into one envelope.
    bob.sync(&ds);
    assert_eq!(
        receipt_ids(&bob, ReceiptKind::Delivered),
        vec![vec![first.clone(), second.clone()]]
    );
    assert_eq!(bob.store.chat(&g).unwrap().unwrap().unread_count, 2);
    bob.flush(&ds);
    alice.sync(&ds);
    assert_eq!(alice.message(&first).send_state, Some(SendState::Sent));
    assert_eq!(
        alice.message(&first).receipts.get(&bob.me),
        Some(&ReceiptKind::Delivered)
    );

    carol.sync(&ds);
    carol.flush(&ds);
    alice.sync(&ds);
    assert_eq!(alice.message(&first).send_state, Some(SendState::Delivered));
    assert_eq!(
        alice.message(&second).send_state,
        Some(SendState::Delivered)
    );

    let (receipt, _) = bob.client.mark_read(&bob.store, &g, common::NOW).unwrap();
    assert!(receipt.is_some());
    assert_eq!(bob.store.chat(&g).unwrap().unwrap().unread_count, 0);
    assert_eq!(
        receipt_ids(&bob, ReceiptKind::Read),
        vec![vec![first.clone(), second.clone()]]
    );
    // Nothing new to read: no second receipt.
    assert_eq!(
        bob.client.mark_read(&bob.store, &g, common::NOW).unwrap().0,
        None
    );
    bob.flush(&ds);
    alice.sync(&ds);
    assert_eq!(alice.message(&first).send_state, Some(SendState::Delivered));

    carol
        .client
        .mark_read(&carol.store, &g, common::NOW)
        .unwrap();
    carol.flush(&ds);
    alice.sync(&ds);
    assert_eq!(alice.message(&first).send_state, Some(SendState::Read));

    // A late delivered receipt never downgrades.
    carol.send(
        &ds,
        &g,
        Content::Receipt {
            kind: ReceiptKind::Delivered,
            message_ids: vec![first.clone()],
        },
    );
    alice.sync(&ds);
    assert_eq!(alice.message(&first).send_state, Some(SendState::Read));
    assert_eq!(
        alice.message(&first).receipts.get(&carol.me),
        Some(&ReceiptKind::Read)
    );
    // Receipts never touch messages of other users.
    assert_eq!(bob.message(&first).send_state, None);
}

#[test]
fn edits_deletes_and_reactions_fold_into_the_target() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    setup(&ds, &g, &[&alice, &bob]);

    let id = alice.send_text(&ds, &g, "helo");
    alice.send(
        &ds,
        &g,
        Content::Edit {
            target: id.clone(),
            new_body: "hello".into(),
        },
    );
    // Own edits apply locally since own messages are never decrypted.
    for device in [&alice, &bob] {
        device.sync(&ds);
        let message = device.message(&id);
        assert_eq!(message.content, text_content("hello"));
        assert!(message.edited);
    }

    bob.send(
        &ds,
        &g,
        Content::Reaction {
            target: id.clone(),
            emoji: "+1".into(),
            remove: false,
        },
    );
    // Only the author may edit.
    bob.send(
        &ds,
        &g,
        Content::Edit {
            target: id.clone(),
            new_body: "hijacked".into(),
        },
    );
    alice.sync(&ds);
    let message = alice.message(&id);
    assert_eq!(message.content, text_content("hello"));
    assert_eq!(
        message.reactions.get(&bob.me.user_id),
        Some(&BTreeSet::from(["+1".to_string()]))
    );
    assert_eq!(bob.message(&id).reactions, message.reactions);

    bob.send(
        &ds,
        &g,
        Content::Reaction {
            target: id.clone(),
            emoji: "+1".into(),
            remove: true,
        },
    );
    alice.sync(&ds);
    assert!(alice.message(&id).reactions.is_empty());

    alice.send(&ds, &g, Content::Delete { target: id.clone() });
    bob.sync(&ds);
    for device in [&alice, &bob] {
        let message = device.message(&id);
        assert!(message.deleted);
        assert_eq!(message.content, text_content(""));
    }
    // A deleted message takes no further reactions.
    bob.send(
        &ds,
        &g,
        Content::Reaction {
            target: id.clone(),
            emoji: "+1".into(),
            remove: false,
        },
    );
    alice.sync(&ds);
    assert!(alice.message(&id).reactions.is_empty());
}

fn text_content(body: &str) -> MessageContent {
    MessageContent::Text { body: body.into() }
}
