//! Several clients against one fake server.

use std::path::Path;
use std::sync::Arc;

use gim_base::model::{
    ChatKind, Membership, MembershipChangeKind, Message, MessageContent, SendState, StateChange,
};
use gim_base::{MemoryStore, StateReader};
use gim_common::{GroupId, MessageId, UserId};
use gim_proto::envelope::Content;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::{
    Client, ClientBuilder, ClientError, SecretStorage, KEY_PACKAGE_BATCH, SESSION_SECRET_KEY,
};
use gim_test::KEY_PACKAGES_LOW_THRESHOLD;
use tempfile::TempDir;

struct Device {
    client: Client<MemoryStore>,
    store: Arc<MemoryStore>,
    secrets: Arc<MemorySecretStorage>,
    data_dir: TempDir,
}

impl Device {
    async fn register(transport: &FakeTransport, handle: &str) -> Self {
        let store = Arc::new(MemoryStore::new());
        let secrets = Arc::new(MemorySecretStorage::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = build(transport, &store, &secrets, data_dir.path());
        client
            .register(handle, &handle.to_uppercase())
            .await
            .unwrap();
        Self {
            client,
            store,
            secrets,
            data_dir,
        }
    }

    fn user_id(&self) -> UserId {
        self.client.session().unwrap().device.user_id
    }

    async fn sync(&self) -> Vec<StateChange> {
        self.client.sync_once().await.unwrap()
    }

    async fn send_text(&self, group_id: &GroupId, body: &str) -> MessageId {
        self.client
            .send(
                group_id,
                Content::Text {
                    body: body.to_string(),
                },
            )
            .await
            .unwrap()
    }

    fn texts(&self, group_id: &GroupId) -> Vec<String> {
        self.store
            .messages(group_id, None, usize::MAX)
            .unwrap()
            .into_iter()
            .map(|m| text(&m))
            .collect()
    }

    fn members(&self, group_id: &GroupId) -> Vec<UserId> {
        let mut users: Vec<UserId> = self
            .store
            .chat(group_id)
            .unwrap()
            .unwrap()
            .members
            .into_iter()
            .map(|m| m.device.user_id)
            .collect();
        users.sort();
        users.dedup();
        users
    }
}

fn build(
    transport: &FakeTransport,
    store: &Arc<MemoryStore>,
    secrets: &Arc<MemorySecretStorage>,
    data_dir: &Path,
) -> Client<MemoryStore> {
    ClientBuilder::new(
        store.clone(),
        Arc::new(transport.clone()),
        secrets.clone() as Arc<dyn SecretStorage>,
    )
    .data_dir(data_dir)
    .build()
    .unwrap()
}

fn text(message: &Message) -> String {
    match &message.content {
        MessageContent::Text { body } => body.clone(),
        other => panic!("not a text: {other:?}"),
    }
}

async fn sync_all(devices: &[&Device]) {
    for device in devices {
        device.sync().await;
    }
}

fn sorted(mut users: Vec<UserId>) -> Vec<UserId> {
    users.sort();
    users
}

#[tokio::test]
async fn register_restore_and_find_user() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let session = alice.client.session().unwrap();
    assert_eq!(
        transport.service().key_package_count(&session.device),
        KEY_PACKAGE_BATCH as usize
    );
    assert!(matches!(
        alice.client.register("alice", "Alice").await,
        Err(ClientError::AlreadyLoggedIn)
    ));

    // A new client over the same store and secrets resumes the session.
    let restored = build(
        &transport,
        &alice.store,
        &alice.secrets,
        alice.data_dir.path(),
    );
    assert!(restored.session().is_none());
    assert!(restored.restore_session().await.unwrap());
    assert_eq!(restored.session(), Some(session.clone()));

    // A store with another identity does not accept the session.
    let other = build(
        &transport,
        &Device::register(&transport, "mallory").await.store,
        &alice.secrets,
        alice.data_dir.path(),
    );
    assert!(matches!(
        other.restore_session().await,
        Err(ClientError::InvalidSession(_))
    ));
    let fresh = build(
        &transport,
        &Arc::new(MemoryStore::new()),
        &Arc::new(MemorySecretStorage::new()),
        alice.data_dir.path(),
    );
    assert!(!fresh.restore_session().await.unwrap());
    assert!(matches!(
        fresh.find_user("alice").await,
        Err(ClientError::NotLoggedIn)
    ));

    let bob = Device::register(&transport, "bob").await;
    let found = bob.client.find_user("alice").await.unwrap().unwrap();
    assert_eq!(found.user_id, session.device.user_id);
    assert_eq!(found.display_name, "ALICE");
    assert_eq!(bob.store.user(&found.user_id).unwrap(), Some(found));
    assert_eq!(bob.client.find_user("nobody").await.unwrap(), None);
}

#[tokio::test]
async fn lost_store_identity_signs_out() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice").await;

    // The store was reset while the keystore kept the session secret.
    let reset = build(
        &transport,
        &Arc::new(MemoryStore::new()),
        &alice.secrets,
        alice.data_dir.path(),
    );
    assert!(!reset.restore_session().await.unwrap());
    assert!(reset.session().is_none());
    assert_eq!(alice.secrets.get(SESSION_SECRET_KEY).unwrap(), None);
    assert!(!reset.restore_session().await.unwrap());

    // Onboarding registers a new device.
    let session = reset.register("alice", "Alice").await.unwrap();
    assert_ne!(Some(session), alice.client.session());
}

#[tokio::test]
async fn direct_chat_between_two_clients() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let mut bob_changes = bob.client.subscribe_changes();

    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let hello = alice.send_text(&g, "hello bob").await;
    assert_eq!(
        alice.store.message(&hello).unwrap().unwrap().send_state,
        Some(SendState::Sent)
    );

    let changes = bob.sync().await;
    assert!(!changes.is_empty());
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert_eq!(chat.kind, ChatKind::Direct);
    assert_eq!(chat.membership, Membership::Joined);
    assert_eq!(chat.unread_count, 1);
    assert_eq!(bob.texts(&g), vec!["hello bob"]);
    assert_eq!(
        bob.members(&g),
        sorted(vec![alice.user_id(), bob.user_id()])
    );
    // Every applied change is broadcast too.
    for change in changes {
        assert_eq!(bob_changes.try_recv().unwrap(), change);
    }

    bob.send_text(&g, "hi alice").await;
    alice.sync().await;
    assert_eq!(alice.texts(&g), vec!["hello bob", "hi alice"]);
    assert_eq!(
        alice.store.chat(&g).unwrap().unwrap().kind,
        ChatKind::Direct
    );
    // Nothing new: the persisted cursor skips what was applied.
    assert!(alice.sync().await.is_empty());
    assert!(bob.sync().await.is_empty());
}

#[tokio::test]
async fn group_chat_and_second_device() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let bob_tablet = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    assert_eq!(bob.user_id(), bob_tablet.user_id());
    let all = [&alice, &bob, &bob_tablet, &carol];

    let g = alice
        .client
        .create_group_chat(Some("trip".into()), &[bob.user_id(), carol.user_id()])
        .await
        .unwrap();
    sync_all(&all).await;
    for device in &all[1..] {
        let chat = device.store.chat(&g).unwrap().unwrap();
        assert_eq!(chat.kind, ChatKind::Group);
        assert_eq!(chat.members.len(), 4);
    }

    alice.send_text(&g, "from alice").await;
    sync_all(&all).await;
    bob_tablet.send_text(&g, "from bob's tablet").await;
    sync_all(&all).await;
    carol.send_text(&g, "from carol").await;
    sync_all(&all).await;
    let expected = vec!["from alice", "from bob's tablet", "from carol"];
    for device in all {
        assert_eq!(device.texts(&g), expected);
    }
}

#[tokio::test]
async fn add_remove_and_leave() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;

    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    alice.send_text(&g, "before carol").await;
    sync_all(&[&bob]).await;

    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    // Sent by bob in the new epoch before carol processed her Welcome.
    bob.sync().await;
    bob.send_text(&g, "welcome carol").await;
    sync_all(&[&alice, &carol]).await;
    assert_eq!(carol.texts(&g), vec!["welcome carol"]);
    assert_eq!(
        carol.members(&g),
        sorted(vec![alice.user_id(), bob.user_id(), carol.user_id()])
    );
    assert!(matches!(
        alice.client.add_members(&g, &[carol.user_id()]).await,
        Err(ClientError::InvalidInput(_))
    ));

    alice
        .client
        .remove_members(&g, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    assert_eq!(
        bob.store.chat(&g).unwrap().unwrap().membership,
        Membership::Left
    );
    alice.send_text(&g, "without bob").await;
    carol.sync().await;
    bob.sync().await;
    assert_eq!(carol.texts(&g), vec!["welcome carol", "without bob"]);
    assert_eq!(bob.texts(&g), vec!["before carol", "welcome carol"]);
    assert_eq!(
        carol.members(&g),
        sorted(vec![alice.user_id(), carol.user_id()])
    );

    let mut changes = carol.client.subscribe_changes();
    carol.client.leave(&g).await.unwrap();
    assert_eq!(
        carol.store.chat(&g).unwrap().unwrap().membership,
        Membership::Left
    );
    // Carol's device records her own Left, like the other members do.
    let left = carol.store.membership_events(&g).unwrap().pop().unwrap();
    assert_eq!(
        (left.user_id.clone(), left.kind),
        (carol.user_id(), MembershipChangeKind::Left)
    );
    let mut emitted = Vec::new();
    while let Ok(change) = changes.try_recv() {
        emitted.push(change);
    }
    assert!(emitted.contains(&StateChange::MembershipChanged(left)));
    alice.send_text(&g, "after carol left").await;
    carol.sync().await;
    assert_eq!(carol.texts(&g), vec!["welcome carol", "without bob"]);
    assert!(carol
        .client
        .send(&g, Content::Text { body: "x".into() })
        .await
        .is_err());
}

#[tokio::test]
async fn competing_commits_are_retried() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let dave = Device::register(&transport, "dave").await;

    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;

    // Bob wins the epoch; alice has not seen his commit yet, so her first
    // post is rejected and she retries on top of it.
    bob.client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    assert_eq!(transport.service().epoch(&g), Ok(2));
    alice
        .client
        .add_members(&g, &[dave.user_id()])
        .await
        .unwrap();
    assert_eq!(transport.service().epoch(&g), Ok(3));
    let everyone = [&alice, &bob, &carol, &dave];
    sync_all(&everyone).await;

    let all_users = sorted(everyone.iter().map(|d| d.user_id()).collect());
    for device in everyone {
        assert_eq!(device.members(&g), all_users);
    }
    for device in everyone {
        device.send_text(&g, &device.user_id().to_string()).await;
        sync_all(&everyone).await;
    }
    let expected: Vec<String> = everyone.iter().map(|d| d.user_id().to_string()).collect();
    for device in everyone {
        assert_eq!(device.texts(&g), expected);
    }
}

#[tokio::test]
async fn key_packages_are_replenished_when_low() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let bob_device = bob.client.session().unwrap().device;
    let mut changes = bob.client.subscribe_changes();

    let claims = KEY_PACKAGE_BATCH as usize - KEY_PACKAGES_LOW_THRESHOLD + 1;
    for _ in 0..claims {
        transport.service().claim_key_package(&bob_device).unwrap();
    }
    let left = KEY_PACKAGE_BATCH as usize - claims;
    assert_eq!(transport.service().key_package_count(&bob_device), left);

    let applied = bob.sync().await;
    assert_eq!(applied, vec![StateChange::KeyPackagesLow]);
    assert_eq!(changes.try_recv().unwrap(), StateChange::KeyPackagesLow);
    assert_eq!(
        transport.service().key_package_count(&bob_device),
        left + KEY_PACKAGE_BATCH as usize
    );

    // The replenished packages are usable.
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    alice.send_text(&g, "fresh").await;
    bob.sync().await;
    assert_eq!(bob.texts(&g), vec!["fresh"]);
}
