//! Note-to-self chats: recognised by the MLS note marker, own devices only.

mod common;

use common::{group, Device, NOW};
use gim_base::model::ChatKind;
use gim_base::StateReader;
use gim_common::GroupId;
use gim_test::FakeDeliveryService;

/// alice's phone with a new note chat `g`, and her tablet, both registered.
fn note_chat(ds: &FakeDeliveryService, g: &GroupId) -> (Device, Device) {
    let (phone, tablet) = (Device::new("alice"), Device::new_device("alice", 1));
    let user = &phone.me.user_id;
    let devices = [phone.me.device_id.clone(), tablet.me.device_id.clone()];
    ds.put_device_list(user, 1, b"alice".to_vec(), devices.into())
        .unwrap();
    ds.create_group(g, &phone.me).unwrap();
    phone
        .client
        .create_chat(&phone.store, &phone.engine, g, ChatKind::Note, None, NOW)
        .unwrap();
    (phone, tablet)
}

fn kind(device: &Device, g: &GroupId) -> Option<ChatKind> {
    device.store.chat(g).unwrap().map(|chat| chat.kind)
}

#[test]
fn own_devices_recognise_the_note_chat_from_its_welcome() {
    let ds = FakeDeliveryService::new();
    let g = group("note");
    let (phone, tablet) = note_chat(&ds, &g);
    assert_eq!(kind(&phone, &g), Some(ChatKind::Note));
    assert!(phone.engine.is_note_group(&phone.store, &g).unwrap());

    phone.add(&ds, &g, &[&tablet]);
    tablet.sync(&ds);
    assert_eq!(kind(&tablet, &g), Some(ChatKind::Note));
    assert_eq!(kind(&phone, &g), Some(ChatKind::Note));

    // Notes sync across the own devices without unread counts.
    phone.send_text(&ds, &g, "milk");
    tablet.sync(&ds);
    let chat = tablet.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.unread_count, 0);
    assert!(chat.last_message_id.is_some());
}

#[test]
fn a_plain_group_of_own_devices_is_not_a_note_chat() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (phone, tablet) = note_chat(&ds, &group("note"));
    ds.create_group(&g, &phone.me).unwrap();
    phone
        .client
        .create_chat(&phone.store, &phone.engine, &g, ChatKind::Group, None, NOW)
        .unwrap();
    phone.add(&ds, &g, &[&tablet]);
    tablet.sync(&ds);
    assert_eq!(kind(&tablet, &g), Some(ChatKind::Group));
}

#[test]
fn another_user_never_joins_a_note_chat() {
    let ds = FakeDeliveryService::new();
    let g = group("note");
    let (phone, _tablet) = note_chat(&ds, &g);
    let bob = Device::new("bob");
    phone.add(&ds, &g, &[&bob]);

    // bob refuses the Welcome of another user's note group ...
    bob.sync(&ds);
    assert_eq!(kind(&bob, &g), None);
    assert!(!bob.engine.has_group(&bob.store, &g).unwrap());
    assert_eq!(bob.client.rejected(), 1);
    // ... and the chat with bob in it is no note chat any more.
    assert_eq!(kind(&phone, &g), Some(ChatKind::Group));
}
