//! Outbox transitions, backoff and re-preparation.
//!
//! Ported from `crates/gim-base/tests/outbox.rs` to run against `SqliteStore`.

mod common;

use common::{group, setup, text, Device, NOW};
use gim_base::model::{
    MessageContent, OutboxKind, OutboxState, PendingMedia, SendState, StateChange,
};
use gim_base::{BaseError, StateReader, MAX_SEND_ATTEMPTS};
use gim_proto::envelope::{Content, MediaInfo};
use gim_test::FakeDeliveryService;

#[test]
fn failures_back_off_then_fail_and_manual_retry_resets() {
    let ds = FakeDeliveryService::new();
    let g = group("solo");
    let alice = Device::new("alice");
    alice.create_chat(&ds, &g);

    let (id, changes) = alice
        .client
        .enqueue(&alice.store, &g, text("ahoy"), None, NOW)
        .unwrap();
    assert!(
        matches!(&changes[0], StateChange::MessageUpserted(m) if m.send_state == Some(SendState::Pending))
    );
    assert_eq!(alice.store.outbox_due(NOW - 1, 10).unwrap(), vec![]);
    assert_eq!(alice.store.outbox_due(NOW, 10).unwrap().len(), 1);

    let mut now = NOW;
    let mut previous_delay = 0;
    for attempt in 1..MAX_SEND_ATTEMPTS {
        alice
            .client
            .mark_failed(&alice.store, &id, "timeout", true, now)
            .unwrap();
        let entry = alice.store.outbox_entry(&id).unwrap().unwrap();
        assert_eq!(entry.attempts, attempt);
        assert_eq!(entry.state, OutboxState::Pending);
        assert_eq!(entry.last_error.as_deref(), Some("timeout"));
        let delay = entry.next_attempt_at_ms - now;
        assert!(delay > previous_delay, "attempt {attempt}: {delay}");
        assert!(delay <= 300_000);
        if attempt == 1 {
            assert!((750..=1_000).contains(&delay));
        }
        previous_delay = delay;
        assert!(alice
            .store
            .outbox_due(now + delay - 1, 10)
            .unwrap()
            .is_empty());
        now += delay;
        assert_eq!(alice.store.outbox_due(now, 10).unwrap().len(), 1);
    }
    let changes = alice
        .client
        .mark_failed(&alice.store, &id, "timeout", true, now)
        .unwrap();
    assert!(
        matches!(&changes[..], [StateChange::MessageUpserted(m)] if m.send_state == Some(SendState::Failed))
    );
    assert_eq!(
        alice.store.outbox_entry(&id).unwrap().unwrap().state,
        OutboxState::Failed
    );
    assert!(alice.store.outbox_due(u64::MAX, 10).unwrap().is_empty());
    assert!(matches!(
        alice.client.prepare(&alice.store, &alice.engine, &id),
        Err(BaseError::InvalidState(_))
    ));

    alice.client.retry(&alice.store, &id, now).unwrap();
    let entry = alice.store.outbox_entry(&id).unwrap().unwrap();
    assert_eq!(
        (entry.state, entry.attempts, entry.next_attempt_at_ms),
        (OutboxState::Pending, 0, now)
    );
    assert_eq!(alice.message(&id).send_state, Some(SendState::Pending));

    // A permanent error fails at once.
    alice
        .client
        .mark_failed(&alice.store, &id, "403", false, now)
        .unwrap();
    assert_eq!(alice.message(&id).send_state, Some(SendState::Failed));

    let changes = alice.client.cancel(&alice.store, &id).unwrap();
    assert!(changes.contains(&StateChange::MessageRemoved {
        group_id: g.clone(),
        message_id: id.clone(),
    }));
    assert!(alice.store.message(&id).unwrap().is_none());
    assert!(alice.store.outbox_entry(&id).unwrap().is_none());
    assert_eq!(alice.store.chat(&g).unwrap().unwrap().last_message_id, None);
}

#[test]
fn prepare_reuses_payload_and_reencrypts_after_epoch_change() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob]);

    let id = alice.enqueue(&g, text("to all hands"));
    let first = alice
        .client
        .prepare(&alice.store, &alice.engine, &id)
        .unwrap();
    let again = alice
        .client
        .prepare(&alice.store, &alice.engine, &id)
        .unwrap();
    assert_eq!(first, again);

    alice.add(&ds, &g, &[&carol]);
    bob.sync(&ds);
    carol.sync(&ds);
    let second = alice
        .client
        .prepare(&alice.store, &alice.engine, &id)
        .unwrap();
    assert_eq!(second.epoch, first.epoch + 1);
    assert_ne!(second.payload, first.payload);

    alice.flush(&ds);
    assert_eq!(alice.message(&id).send_state, Some(SendState::Sent));
    assert!(alice.message(&id).seq.is_some());
    for device in [&bob, &carol] {
        device.sync(&ds);
        assert_eq!(
            device.message(&id).content,
            MessageContent::Text {
                body: "to all hands".into()
            }
        );
    }
}

#[test]
fn media_is_sent_after_upload_completes() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    setup(&ds, &g, &[&alice, &bob]);

    let pending = PendingMedia {
        local_path: "/tmp/harbour.jpg".into(),
        mime: "image/jpeg".into(),
        caption: Some("Hvar harbour".into()),
    };
    let (id, _) = alice
        .client
        .enqueue_media(&alice.store, &g, pending.clone(), None, NOW)
        .unwrap();
    assert_eq!(
        alice.message(&id).content,
        MessageContent::PendingMedia(pending.clone())
    );
    assert!(matches!(
        alice.store.outbox_entry(&id).unwrap().unwrap().kind,
        OutboxKind::MediaUpload(_)
    ));
    assert!(matches!(
        alice.client.prepare(&alice.store, &alice.engine, &id),
        Err(BaseError::InvalidState(_))
    ));

    let media = MediaInfo {
        blob_id: "blob-1".into(),
        key: [7; 32],
        sha256: [9; 32],
        mime: "image/jpeg".into(),
        size: 1024,
        width: Some(800),
        height: Some(600),
        file_name: Some("harbour.jpg".into()),
        thumbnail: None,
    };
    alice
        .client
        .complete_media_upload(&alice.store, &id, media.clone())
        .unwrap();
    alice.flush(&ds);
    bob.sync(&ds);
    let expected = MessageContent::Media {
        media,
        caption: Some("Hvar harbour".into()),
    };
    assert_eq!(alice.message(&id).content, expected);
    assert_eq!(bob.message(&id).content, expected);
    assert!(matches!(
        alice.client.complete_media_upload(
            &alice.store,
            &id,
            match expected {
                MessageContent::Media { media, .. } => media,
                _ => unreachable!(),
            }
        ),
        Err(BaseError::NotFound(_))
    ));
}

#[test]
fn enqueue_validates_the_envelope_and_the_chat() {
    let ds = FakeDeliveryService::new();
    let g = group("solo");
    let alice = Device::new("alice");
    assert!(matches!(
        alice.client.enqueue(&alice.store, &g, text("x"), None, NOW),
        Err(BaseError::NotFound(_))
    ));
    alice.create_chat(&ds, &g);
    let target = alice.enqueue(&g, text("x"));
    let reply_on_reaction = alice.client.enqueue(
        &alice.store,
        &g,
        Content::Reaction {
            target: target.clone(),
            emoji: "+1".into(),
            remove: false,
        },
        Some(target),
        NOW,
    );
    assert!(matches!(reply_on_reaction, Err(BaseError::Proto(_))));
}
