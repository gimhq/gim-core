//! Group info sharing, member profiles and history backfill.

mod common;

use common::{server_messages, Device, FlakyTransport};
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_common::GroupId;
use gim_sdk::ClientError;

fn chat_name(device: &Device, g: &GroupId) -> Option<String> {
    device.store.chat(g).unwrap().unwrap().name
}

fn member_name(device: &Device, g: &GroupId, of: &Device) -> Option<String> {
    device
        .store
        .chat(g)
        .unwrap()
        .unwrap()
        .members
        .into_iter()
        .find(|m| m.device.user_id == of.user_id())
        .and_then(|m| m.display_name)
}

#[tokio::test]
async fn joiners_see_the_group_name() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let dave = Device::register(&transport, "dave").await;

    let g = alice
        .client
        .create_group_chat(Some("Aegean crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    assert_eq!(server_messages(&transport, &g, &alice.device()).len(), 1);
    bob.sync().await;
    assert_eq!(chat_name(&bob, &g).as_deref(), Some("Aegean crew"));

    // Members added later get the name again.
    alice
        .client
        .add_members(&g, &[dave.user_id()])
        .await
        .unwrap();
    dave.sync().await;
    assert_eq!(chat_name(&dave, &g).as_deref(), Some("Aegean crew"));

    // Nothing to share for direct chats and unnamed groups.
    let direct = alice
        .client
        .create_direct_chat(&carol.user_id())
        .await
        .unwrap();
    assert!(server_messages(&transport, &direct, &alice.device()).is_empty());
    let unnamed = alice
        .client
        .create_group_chat(None, &[carol.user_id()])
        .await
        .unwrap();
    assert!(server_messages(&transport, &unnamed, &alice.device()).is_empty());
}

#[tokio::test]
async fn set_group_info_renames_and_shares_the_avatar() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_group_chat(Some("Aegean crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;

    let avatar = alice.data_dir.path().join("boat.png");
    std::fs::write(&avatar, b"not really a png").unwrap();
    alice
        .client
        .set_group_info(
            &g,
            Some("Ionian crew".into()),
            Some((avatar, "image/png".into())),
        )
        .await
        .unwrap();
    // Applied locally right away.
    let chat = alice.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.name.as_deref(), Some("Ionian crew"));
    let media = chat.avatar.unwrap();
    assert_eq!(media.mime, "image/png");
    assert_eq!(media.size, 16);

    bob.sync().await;
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.name.as_deref(), Some("Ionian crew"));
    assert_eq!(chat.avatar.unwrap().blob_id, media.blob_id);

    // A rename alone keeps the avatar.
    alice
        .client
        .set_group_info(&g, Some("Adriatic crew".into()), None)
        .await
        .unwrap();
    bob.sync().await;
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.name.as_deref(), Some("Adriatic crew"));
    assert!(chat.avatar.is_some());

    let nothing = alice.client.set_group_info(&g, None, None).await;
    assert!(matches!(nothing, Err(ClientError::InvalidInput(_))));
    let direct = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let renamed = alice
        .client
        .set_group_info(&direct, Some("no".into()), None)
        .await;
    assert!(matches!(renamed, Err(ClientError::InvalidInput(_))));
}

#[tokio::test]
async fn member_profiles_resolve_without_find_user() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;

    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    assert_eq!(member_name(&alice, &g, &bob).as_deref(), Some("bob"));
    assert!(alice.store.user(&bob.user_id()).unwrap().is_some());

    let mut changes = bob.client.subscribe_changes();
    bob.sync().await;
    assert_eq!(member_name(&bob, &g, &alice).as_deref(), Some("alice"));
    let mut renamed = false;
    while let Ok(change) = changes.try_recv() {
        if let gim_base::model::StateChange::ChatUpserted(chat) = change {
            renamed |= chat
                .members
                .iter()
                .any(|m| m.display_name.as_deref() == Some("alice"));
        }
    }
    assert!(renamed, "the resolved name is broadcast");

    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    assert_eq!(member_name(&alice, &g, &carol).as_deref(), Some("carol"));
    bob.sync().await;
    assert_eq!(member_name(&bob, &g, &carol).as_deref(), Some("carol"));
}

#[tokio::test]
async fn backfill_skips_what_cannot_be_decrypted() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    for body in ["one", "two", "three"] {
        alice.client.send_text(&g, body, None).await.unwrap();
    }
    bob.sync().await;
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    carol.sync().await;
    alice.client.send_text(&g, "four", None).await.unwrap();
    bob.sync().await;
    carol.sync().await;
    assert_eq!(bob.messages(&g).len(), 4);
    assert_eq!(carol.messages(&g).len(), 1);

    // Bob clears his local history: the messages were decrypted before,
    // so their keys are gone and nothing comes back.
    let ids: Vec<_> = bob.messages(&g).into_iter().map(|m| m.message_id).collect();
    bob.store
        .transaction(|txn| {
            for id in &ids {
                txn.remove_message(id)?;
            }
            Ok(())
        })
        .unwrap();
    let head = bob.store.group_cursor(&g).unwrap().contiguous_seq;
    let backfill = bob
        .client
        .backfill_history(&g, head + 1, 100)
        .await
        .unwrap();
    assert_eq!(backfill.inserted, 0);
    assert!(!backfill.has_more);
    assert!(bob.messages(&g).is_empty());

    // Carol cannot read anything from before her Welcome, which directly
    // precedes her first message: nothing is requested.
    let oldest = carol.messages(&g)[0].seq.unwrap();
    for limit in [0, 100] {
        let backfill = carol
            .client
            .backfill_history(&g, oldest, limit)
            .await
            .unwrap();
        assert_eq!(backfill.inserted, 0);
        assert!(!backfill.has_more);
    }
    assert_eq!(carol.messages(&g).len(), 1);
}
