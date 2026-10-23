//! Privacy settings, blocked users, chat settings and profile photos.

mod common;

use std::collections::BTreeSet;

use common::{group, setup, Device, NOW};
use gim_base::model::{ChatKind, Privacy, StateChange};
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_proto::envelope::{Content, MediaInfo, ReceiptKind};
use gim_test::FakeDeliveryService;

fn set_privacy(device: &Device, privacy: Privacy) {
    device
        .store
        .transaction(|txn| Ok(txn.set_privacy(&privacy)?))
        .unwrap();
}

fn blocking(blocked: &Device) -> Privacy {
    Privacy {
        blocked: BTreeSet::from([blocked.me.user_id.clone()]),
        ..Privacy::default()
    }
}

fn texts(device: &Device, g: &gim_common::GroupId) -> Vec<String> {
    device
        .store
        .messages(g, None, usize::MAX)
        .unwrap()
        .into_iter()
        .filter_map(|m| match m.content {
            gim_base::model::MessageContent::Text { body } => Some(body),
            _ => None,
        })
        .collect()
}

fn photo() -> MediaInfo {
    MediaInfo {
        blob_id: "avatar-1".into(),
        key: [1; 32],
        sha256: [2; 32],
        mime: "image/jpeg".into(),
        size: 10,
        width: None,
        height: None,
        file_name: None,
        thumbnail: None,
    }
}

#[test]
fn messages_of_a_blocked_user_are_dropped() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob, &carol]);
    set_privacy(&alice, blocking(&bob));

    bob.send_text(&ds, &g, "from bob");
    carol.send_text(&ds, &g, "from carol");
    bob.send(&ds, &g, Content::Typing { active: true });
    let changes = alice.sync(&ds);
    assert_eq!(texts(&alice, &g), ["from carol"]);
    assert!(!changes
        .iter()
        .any(|c| matches!(c, StateChange::Typing { .. })));

    // Unblocked, new messages are kept again.
    set_privacy(&alice, Privacy::default());
    bob.send_text(&ds, &g, "again");
    alice.sync(&ds);
    assert_eq!(texts(&alice, &g), ["from carol", "again"]);
}

#[test]
fn a_welcome_from_a_blocked_user_is_refused() {
    let ds = FakeDeliveryService::new();
    let g = group("lure");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    bob.register(&ds);
    set_privacy(&bob, blocking(&alice));

    alice.create_chat(&ds, &g);
    alice.add(&ds, &g, &[&bob]);
    bob.sync(&ds);
    assert!(bob.store.chat(&g).unwrap().is_none());
}

#[test]
fn read_receipts_and_typing_of_others_are_hidden_when_switched_off() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    setup(&ds, &g, &[&alice, &bob]);
    set_privacy(
        &alice,
        Privacy {
            read_receipts: false,
            typing: false,
            ..Privacy::default()
        },
    );

    let sent = alice.send_text(&ds, &g, "hello");
    bob.sync(&ds);
    bob.send(
        &ds,
        &g,
        Content::Receipt {
            kind: ReceiptKind::Read,
            message_ids: vec![sent.clone()],
        },
    );
    bob.send(&ds, &g, Content::Typing { active: true });
    let changes = alice.sync(&ds);
    assert_ne!(
        alice.message(&sent).receipts.get(&bob.me),
        Some(&ReceiptKind::Read)
    );
    assert!(!changes
        .iter()
        .any(|c| matches!(c, StateChange::Typing { .. })));
}

/// alice's two devices in their self group `g`.
fn own_devices(ds: &FakeDeliveryService, g: &gim_common::GroupId) -> (Device, Device) {
    let (phone, tablet) = (Device::new("alice"), Device::new_device("alice", 1));
    let user = &phone.me.user_id;
    let devices = [phone.me.device_id.clone(), tablet.me.device_id.clone()];
    ds.put_device_list(user, 1, b"alice".to_vec(), devices.into())
        .unwrap();
    ds.create_group(g, &phone.me).unwrap();
    phone
        .client
        .create_chat(&phone.store, &phone.engine, g, ChatKind::Group, None, NOW)
        .unwrap();
    phone.add(ds, g, &[&tablet]);
    tablet.sync(ds);
    (phone, tablet)
}

#[test]
fn the_latest_privacy_settings_of_the_own_devices_win() {
    let ds = FakeDeliveryService::new();
    let g = group("self");
    let (phone, tablet) = own_devices(&ds, &g);
    let mallory = gim_test::TestIdentity::new("mallory").device.user_id;
    let newer = Content::SelfPrivacy {
        read_receipts: false,
        typing: true,
        blocked: vec![mallory.clone()],
    };
    let older = Content::SelfPrivacy {
        read_receipts: true,
        typing: false,
        blocked: vec![],
    };
    phone
        .client
        .enqueue(&phone.store, &g, newer, None, NOW + 2)
        .unwrap();
    phone
        .client
        .enqueue(&phone.store, &g, older, None, NOW + 1)
        .unwrap();
    phone.flush(&ds);
    let changes = tablet.sync(&ds);

    let expected = Privacy {
        read_receipts: false,
        typing: true,
        blocked: BTreeSet::from([mallory]),
        updated_at_ms: NOW + 2,
    };
    assert_eq!(phone.store.privacy().unwrap(), expected);
    assert_eq!(tablet.store.privacy().unwrap(), expected);
    assert!(changes.contains(&StateChange::PrivacyChanged(expected)));
}

#[test]
fn chat_settings_follow_the_own_devices() {
    let ds = FakeDeliveryService::new();
    let (s, g) = (group("self"), group("crew"));
    let (phone, tablet) = own_devices(&ds, &s);
    let bob = Device::new("bob");
    setup(&ds, &g, &[&phone, &tablet, &bob]);

    let settings = Content::SelfChatSettings {
        group_id: g.clone(),
        muted_until_ms: u64::MAX,
        pinned: true,
        archived: false,
    };
    phone.send(&ds, &s, settings);
    tablet.sync(&ds);
    for device in [&phone, &tablet] {
        let chat = device.store.chat(&g).unwrap().unwrap();
        assert!(chat.pinned && !chat.archived && chat.is_muted(NOW));
    }

    // Settings of a chat this device is not in are ignored.
    phone.send(
        &ds,
        &s,
        Content::SelfChatSettings {
            group_id: group("elsewhere"),
            muted_until_ms: 0,
            pinned: true,
            archived: true,
        },
    );
    tablet.sync(&ds);
    assert!(tablet.store.chat(&group("elsewhere")).unwrap().is_none());
}

#[test]
fn a_profile_photo_is_stored_with_the_name() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    setup(&ds, &g, &[&alice, &bob]);

    alice.send(
        &ds,
        &g,
        Content::Profile {
            display_name: "Alice".into(),
            avatar: Some(photo()),
        },
    );
    bob.sync(&ds);
    let user = bob.store.user(&alice.me.user_id).unwrap().unwrap();
    assert_eq!(user.display_name, "Alice");
    assert_eq!(user.avatar, Some(photo()));

    // A later profile without a photo removes it.
    alice.send(
        &ds,
        &g,
        Content::Profile {
            display_name: "Alice".into(),
            avatar: None,
        },
    );
    bob.sync(&ds);
    assert_eq!(
        bob.store.user(&alice.me.user_id).unwrap().unwrap().avatar,
        None
    );
}
