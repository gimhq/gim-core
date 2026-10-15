//! Device linking, recovery restore, device management, the self group and
//! profiles against one fake hub.

use std::path::Path;
use std::sync::Arc;

use gim_base::model::{Membership, Message, MessageContent};
use gim_base::{MemoryStore, StateReader};
use gim_common::{DeviceRef, GroupId, UserId};
use gim_identity::link::LinkOffer;
use gim_identity::recovery::RecoveryCode;
use gim_proto::envelope::Content;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::{
    Client, ClientBuilder, ClientError, LinkSession, PendingApproval, SecretStorage,
    DEVICE_KEY_SECRET_KEY, ROOT_KEY_SECRET_KEY, SESSION_SECRET_KEY,
};
use tempfile::TempDir;

struct Device {
    client: Client<MemoryStore>,
    store: Arc<MemoryStore>,
    secrets: Arc<MemorySecretStorage>,
    _data_dir: TempDir,
}

impl Device {
    fn new(transport: &FakeTransport) -> Self {
        let store = Arc::new(MemoryStore::new());
        let secrets = Arc::new(MemorySecretStorage::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = build(transport, &store, &secrets, data_dir.path());
        Self {
            client,
            store,
            secrets,
            _data_dir: data_dir,
        }
    }

    async fn register(transport: &FakeTransport, handle: &str) -> (Self, RecoveryCode) {
        let device = Self::new(transport);
        let code = device
            .client
            .register(handle, &handle.to_uppercase())
            .await
            .unwrap();
        (device, code)
    }

    /// Starts a link on a new device and approves it on `old`.
    async fn start_link(
        transport: &FakeTransport,
        old: &Device,
    ) -> (Self, LinkSession, PendingApproval) {
        let new = Self::new(transport);
        let session = new.client.start_link(vec!["hub.example".into()]).unwrap();
        let approval = old.client.approve_link(&session.qr_string).await.unwrap();
        (new, session, approval)
    }

    /// A new device of `old`'s user, linked and confirmed on both.
    async fn link(transport: &FakeTransport, old: &Device) -> Self {
        let (new, session, approval) = Self::start_link(transport, old).await;
        let linked = new.client.wait_link(&session).await.unwrap();
        assert_eq!(linked.sas, approval.sas);
        new.client.confirm_link(true).await.unwrap();
        old.client.confirm_approval(&approval, true).await.unwrap();
        new.sync().await;
        new
    }

    fn device(&self) -> DeviceRef {
        self.client.session().unwrap().device
    }

    fn user_id(&self) -> UserId {
        self.device().user_id
    }

    async fn sync(&self) {
        self.client.sync_once().await.unwrap();
    }

    async fn send_text(&self, group_id: &GroupId, body: &str) {
        let content = Content::Text {
            body: body.to_string(),
        };
        self.client.send(group_id, content).await.unwrap();
    }

    fn texts(&self, group_id: &GroupId) -> Vec<String> {
        self.store
            .messages(group_id, None, usize::MAX)
            .unwrap()
            .iter()
            .map(text)
            .collect()
    }

    fn display_name(&self, user_id: &UserId) -> String {
        self.store.user(user_id).unwrap().unwrap().display_name
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

fn hub_members(transport: &FakeTransport, group_id: &GroupId) -> Vec<DeviceRef> {
    transport.service().group(group_id).unwrap().members
}

#[tokio::test]
async fn linked_device_joins_the_self_group_and_existing_chats() {
    let transport = FakeTransport::new();
    let (alice, _) = Device::register(&transport, "alice").await;
    let (bob, _) = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    bob.sync().await;
    alice.send_text(&g, "before").await;
    bob.sync().await;

    let tablet = Device::link(&transport, &alice).await;
    assert_eq!(tablet.user_id(), alice.user_id());
    assert_ne!(tablet.device(), alice.device());

    // The tablet is in the self group (hidden) and the existing chat.
    let self_groups = tablet.store.self_groups().unwrap();
    assert_eq!(self_groups, alice.store.self_groups().unwrap());
    assert!(hub_members(&transport, &self_groups[0]).contains(&tablet.device()));
    let chats = tablet.store.chats().unwrap();
    assert_eq!(chats.len(), 1);
    assert_eq!(chats[0].group_id, g);
    assert_eq!(chats[0].membership, Membership::Joined);
    // Name and DeviceList came through the self group.
    assert_eq!(tablet.display_name(&alice.user_id()), "ALICE");
    let devices = tablet.client.devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices.iter().filter(|d| d.is_current).count(), 1);
    assert!(devices.iter().all(|d| !d.revoked));

    // Messages after the add reach the tablet; its own reach bob.
    alice.send_text(&g, "after").await;
    tablet.sync().await;
    assert_eq!(tablet.texts(&g), ["after"]);
    tablet.send_text(&g, "from the tablet").await;
    bob.sync().await;
    assert_eq!(bob.texts(&g), ["before", "after", "from the tablet"]);
    let listed = bob.client.user_devices(&alice.user_id()).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|d| !d.is_current));
}

#[tokio::test]
async fn tampered_bundle_is_rejected() {
    let transport = FakeTransport::new();
    let (alice, _) = Device::register(&transport, "alice").await;
    let (tablet, session, _) = Device::start_link(&transport, &alice).await;

    // The relay flips a ciphertext byte.
    let offer = LinkOffer::from_qr_string(&session.qr_string).unwrap();
    let link_id: String = offer.link_id().iter().map(|b| format!("{b:02x}")).collect();
    let mut sealed = transport.service().take_link_bundle(&link_id).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    transport
        .service()
        .post_link_bundle(&link_id, sealed)
        .unwrap();

    let result = tablet.client.wait_link(&session).await;
    assert!(
        matches!(result, Err(ClientError::Identity(_))),
        "{result:?}"
    );
    assert!(tablet.client.session().is_none());
    assert_eq!(tablet.secrets.get(ROOT_KEY_SECRET_KEY).unwrap(), None);
    assert_eq!(tablet.secrets.get(DEVICE_KEY_SECRET_KEY).unwrap(), None);
    // A session takes a single bundle.
    assert!(matches!(
        tablet.client.wait_link(&session).await,
        Err(ClientError::InvalidInput(_))
    ));
    assert!(matches!(
        tablet.client.confirm_link(true).await,
        Err(ClientError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn sas_mismatch_wipes_the_new_device_and_revokes_it() {
    let transport = FakeTransport::new();
    let (alice, _) = Device::register(&transport, "alice").await;
    let (tablet, session, approval) = Device::start_link(&transport, &alice).await;
    let linked = tablet.client.wait_link(&session).await.unwrap();
    assert_eq!(linked.sas, approval.sas);
    let device = tablet.device();

    tablet.client.confirm_link(false).await.unwrap();
    assert!(tablet.client.session().is_none());
    for key in [
        SESSION_SECRET_KEY,
        ROOT_KEY_SECRET_KEY,
        DEVICE_KEY_SECRET_KEY,
    ] {
        assert_eq!(tablet.secrets.get(key).unwrap(), None, "{key}");
    }

    alice
        .client
        .confirm_approval(&approval, false)
        .await
        .unwrap();
    let devices = alice.client.devices().await.unwrap();
    let revoked = devices
        .iter()
        .find(|d| d.device_id == device.device_id)
        .unwrap();
    assert!(revoked.revoked);
    let active = transport.service().devices(&alice.user_id()).unwrap();
    assert_eq!(active, [alice.device()]);
}

#[tokio::test]
async fn restore_from_recovery_revokes_the_lost_devices() {
    let transport = FakeTransport::new();
    let (alice, code) = Device::register(&transport, "alice").await;
    let (bob, _) = Device::register(&transport, "bob").await;
    let g = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.sync().await;
    let lost = alice.device();

    // A wrong code does not open the backup; keeping unknown devices fails.
    let other = Device::new(&transport);
    let wrong = RecoveryCode::generate().unwrap();
    assert!(matches!(
        other
            .client
            .restore_from_recovery(&alice.user_id(), &wrong, true)
            .await,
        Err(ClientError::Identity(_))
    ));
    assert!(matches!(
        other
            .client
            .restore_from_recovery(&alice.user_id(), &code, false)
            .await,
        Err(ClientError::InvalidInput(_))
    ));
    assert!(other.client.session().is_none());

    let restored = Device::new(&transport);
    restored
        .client
        .restore_from_recovery(&alice.user_id(), &code, true)
        .await
        .unwrap();
    assert_eq!(restored.user_id(), alice.user_id());
    assert_ne!(restored.device(), lost);
    assert_eq!(restored.store.self_groups().unwrap().len(), 1);
    let devices = restored.client.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert!(devices[0].is_current);
    assert_eq!(
        transport.service().devices(&alice.user_id()).unwrap(),
        [restored.device()]
    );

    // The lost device is signed out; bob removes its leaf.
    let result = alice.client.sync_once().await;
    assert!(
        matches!(result, Err(ClientError::DeviceNotActive(_))),
        "{result:?}"
    );
    bob.sync().await;
    assert!(!hub_members(&transport, &g).contains(&lost));

    // Chats need re-adding by a member.
    bob.client
        .add_members(&g, &[restored.user_id()])
        .await
        .unwrap();
    restored.sync().await;
    bob.send_text(&g, "welcome back").await;
    restored.sync().await;
    assert_eq!(restored.texts(&g), ["welcome back"]);
}

#[tokio::test]
async fn revoked_device_is_removed_everywhere() {
    let transport = FakeTransport::new();
    let (alice, _) = Device::register(&transport, "alice").await;
    let tablet = Device::link(&transport, &alice).await;
    let (bob, _) = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_group_chat(Some("crew".into()), &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    tablet.sync().await;
    assert!(hub_members(&transport, &g).contains(&tablet.device()));

    assert!(matches!(
        alice.client.revoke_device(&alice.device().device_id).await,
        Err(ClientError::InvalidInput(_))
    ));
    alice
        .client
        .revoke_device(&tablet.device().device_id)
        .await
        .unwrap();
    let self_group = alice.store.self_groups().unwrap().pop().unwrap();
    assert!(!hub_members(&transport, &g).contains(&tablet.device()));
    assert!(!hub_members(&transport, &self_group).contains(&tablet.device()));

    // Peers see the revocation; the tablet is refused by the hub.
    bob.sync().await;
    let listed = bob.client.user_devices(&alice.user_id()).await.unwrap();
    assert!(listed
        .iter()
        .any(|d| d.device_id == tablet.device().device_id && d.revoked));
    alice.send_text(&g, "after").await;
    bob.sync().await;
    assert_eq!(bob.texts(&g), ["after"]);
    let result = tablet.client.sync_once().await;
    assert!(
        matches!(result, Err(ClientError::DeviceNotActive(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn self_group_syncs_profile_and_read_markers() {
    let transport = FakeTransport::new();
    let (alice, _) = Device::register(&transport, "alice").await;
    let tablet = Device::link(&transport, &alice).await;
    let (bob, _) = Device::register(&transport, "bob").await;
    let g = bob
        .client
        .create_direct_chat(&alice.user_id())
        .await
        .unwrap();
    alice.sync().await;
    tablet.sync().await;
    bob.send_text(&g, "one").await;
    bob.send_text(&g, "two").await;
    alice.sync().await;
    tablet.sync().await;
    assert_eq!(tablet.store.chat(&g).unwrap().unwrap().unread_count, 2);

    // Read on the phone, read on the tablet.
    alice.client.mark_read(&g).await.unwrap();
    tablet.sync().await;
    let (read, synced) = (
        alice.store.chat(&g).unwrap().unwrap(),
        tablet.store.chat(&g).unwrap().unwrap(),
    );
    assert_eq!(synced.unread_count, 0);
    assert_eq!(synced.last_read_seq, read.last_read_seq);
    assert!(read.last_read_seq > 0);

    // A new name reaches the tablet (self group) and bob (profile).
    alice
        .client
        .set_display_name("Captain Alice")
        .await
        .unwrap();
    tablet.sync().await;
    bob.sync().await;
    assert_eq!(tablet.display_name(&alice.user_id()), "Captain Alice");
    assert_eq!(bob.display_name(&alice.user_id()), "Captain Alice");
    let chat = bob.store.chat(&g).unwrap().unwrap();
    assert!(chat
        .members
        .iter()
        .filter(|m| m.device.user_id == alice.user_id())
        .all(|m| m.display_name.as_deref() == Some("Captain Alice")));

    // The self group stays out of the chat list.
    for device in [&alice, &tablet] {
        let chats: Vec<GroupId> = device
            .store
            .chats()
            .unwrap()
            .into_iter()
            .map(|c| c.group_id)
            .collect();
        assert_eq!(chats, std::slice::from_ref(&g));
    }
}

#[tokio::test]
async fn profile_is_announced_on_join() {
    let transport = FakeTransport::new();
    let (alice, _) = Device::register(&transport, "alice").await;
    let (bob, _) = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    bob.client
        .set_display_name("Bob the Skipper")
        .await
        .unwrap();
    alice.sync().await;
    assert_eq!(alice.display_name(&bob.user_id()), "Bob the Skipper");

    // A member added later learns the adder's name from its announcement,
    // and the adder learns the new member's from the join announcement.
    let (carol, _) = Device::register(&transport, "carol").await;
    carol.client.set_display_name("Carol at sea").await.unwrap();
    alice
        .client
        .add_members(&g, &[carol.user_id()])
        .await
        .unwrap();
    carol.sync().await;
    alice.sync().await;
    assert_eq!(carol.display_name(&alice.user_id()), "ALICE");
    assert_eq!(alice.display_name(&carol.user_id()), "Carol at sea");
}
