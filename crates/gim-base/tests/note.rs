//! Note to self: the direct chat with yourself, of the own devices only.

mod common;

use common::{group, Device, NOW};
use gim_base::model::{ChatKind, StateChange};
use gim_base::{BaseError, StateReader, StateStore, StoreTxn};
use gim_common::GroupId;
use gim_proto::envelope::Content;
use gim_test::FakeDeliveryService;

/// alice's phone and tablet, both registered.
fn own_devices(ds: &FakeDeliveryService) -> (Device, Device) {
    let (phone, tablet) = (Device::new("alice"), Device::new_device("alice", 1));
    let user = &phone.me.user_id;
    let devices = [phone.me.device_id.clone(), tablet.me.device_id.clone()];
    ds.put_device_list(user, 1, b"alice".to_vec(), devices.into())
        .unwrap();
    (phone, tablet)
}

/// Creates the direct chat `g` on `device`, as gim-sdk does.
fn create_direct(ds: &FakeDeliveryService, device: &Device, g: &GroupId) {
    ds.create_group(g, &device.me).unwrap();
    device
        .client
        .create_chat(
            &device.store,
            &device.engine,
            g,
            ChatKind::Direct,
            None,
            NOW,
        )
        .unwrap();
}

/// Sets the hub's group kind after a Welcome, as gim-sdk does.
fn mark_direct(device: &Device, g: &GroupId) {
    device
        .store
        .transaction(|txn| {
            let mut chat = txn.chat(g)?.unwrap();
            chat.kind = ChatKind::Direct;
            txn.upsert_chat(&chat)?;
            Ok(())
        })
        .unwrap();
}

fn peer(device: &Device, g: &GroupId) -> Option<gim_common::UserId> {
    let chat = device.store.chat(g).unwrap().unwrap();
    device.client.direct_peer(&device.store, &chat).unwrap()
}

#[test]
fn the_direct_chat_with_yourself_syncs_across_the_own_devices() {
    let ds = FakeDeliveryService::new();
    let g = group("note");
    let (phone, tablet) = own_devices(&ds);
    let alice = phone.me.user_id.clone();
    create_direct(&ds, &phone, &g);
    assert_eq!(peer(&phone, &g), Some(alice.clone()));

    phone
        .client
        .check_add(&phone.store, &g, std::slice::from_ref(&alice))
        .unwrap();
    phone.add(&ds, &g, &[&tablet]);
    tablet.sync(&ds);
    mark_direct(&tablet, &g);
    assert_eq!(peer(&tablet, &g), Some(alice.clone()));
    let found = tablet
        .client
        .direct_chat_with(&tablet.store, &alice)
        .unwrap();
    assert_eq!(found.map(|c| c.group_id), Some(g.clone()));

    // Content flows as in any direct chat.
    let id = phone.send_text(&ds, &g, "milk");
    phone.send(&ds, &g, Content::Typing { active: true });
    let changes = tablet.sync(&ds);
    assert!(changes
        .iter()
        .any(|c| matches!(c, StateChange::Typing { .. })));
    assert!(tablet.store.message(&id).unwrap().is_some());
}

#[test]
fn the_direct_chat_with_yourself_admits_no_other_user() {
    let ds = FakeDeliveryService::new();
    let g = group("note");
    let (phone, _tablet) = own_devices(&ds);
    create_direct(&ds, &phone, &g);
    let bob = Device::new("bob").me.user_id;
    let err = phone
        .client
        .check_add(&phone.store, &g, &[bob])
        .unwrap_err();
    assert!(matches!(err, BaseError::InvalidState(_)));
}

#[test]
fn direct_chats_are_found_by_peer_and_the_lowest_group_id_wins() {
    let ds = FakeDeliveryService::new();
    let (phone, tablet) = own_devices(&ds);
    let alice = phone.me.user_id.clone();
    let bob = Device::new("bob");

    // Both own devices created a note to self at the same time.
    create_direct(&ds, &phone, &group("note-b"));
    create_direct(&ds, &tablet, &group("note-a"));
    phone.add(&ds, &group("note-b"), &[&tablet]);
    tablet.add(&ds, &group("note-a"), &[&phone]);
    phone.sync(&ds);
    tablet.sync(&ds);
    mark_direct(&phone, &group("note-a"));
    mark_direct(&tablet, &group("note-b"));
    for device in [&phone, &tablet] {
        let found = device
            .client
            .direct_chat_with(&device.store, &alice)
            .unwrap();
        assert_eq!(found.unwrap().group_id, group("note-a"));
    }

    // A direct chat with bob is not the note to self, even before bob joined
    // (pending invite) or after he left (membership events).
    let dm = group("dm");
    create_direct(&ds, &phone, &dm);
    phone.add(&ds, &dm, &[&bob]);
    assert_eq!(peer(&phone, &dm), Some(bob.me.user_id.clone()));
    let found = phone
        .client
        .direct_chat_with(&phone.store, &bob.me.user_id)
        .unwrap();
    assert_eq!(found.unwrap().group_id, dm);
    phone
        .client
        .check_add(&phone.store, &dm, std::slice::from_ref(&bob.me.user_id))
        .unwrap();
    let carol = Device::new("carol").me.user_id;
    assert!(phone.client.check_add(&phone.store, &dm, &[carol]).is_err());
    phone.remove(&ds, &dm, &[&bob]);
    assert_eq!(peer(&phone, &dm), Some(bob.me.user_id.clone()));
    let found = phone.client.direct_chat_with(&phone.store, &alice).unwrap();
    assert_eq!(found.unwrap().group_id, group("note-a"));
}
