//! Restarts (a new `Client` over the reopened `SqliteStore`) in the middle
//! of group changes and media sends.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use gim_base::model::{
    Membership, MessageContent, MessageKind, PendingCommit, PendingMedia, SendState,
};
use gim_base::{BaseClient, BaseError, StateReader, StateStore, StoreTxn};
use gim_common::{now_ms, ClientId, GroupId};
use gim_crypto::MlsEngine;
use gim_sdk::testing::MemorySecretStorage;
use gim_sdk::{
    Client, ClientBuilder, ClientError, SecretStorage, COMMIT_POST_ATTEMPTS, SESSION_SECRET_KEY,
};
use gim_sqlite::{DbKey, SqliteStore};
use tempfile::TempDir;

use common::{server_handshakes, Device, FlakyTransport};

/// A device on SQLite whose client can be restarted.
struct Persistent {
    transport: FlakyTransport,
    secrets: Arc<MemorySecretStorage>,
    dir: TempDir,
}

impl Persistent {
    fn new(transport: &FlakyTransport) -> Self {
        Self {
            transport: transport.clone(),
            secrets: Arc::new(MemorySecretStorage::new()),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn open(&self) -> Client<SqliteStore> {
        ClientBuilder::open(
            Arc::new(self.transport.clone()),
            self.secrets.clone(),
            |key, new_key| {
                SqliteStore::open_or_reset(self.dir.path(), &DbKey::new(*key), new_key)
                    .map_err(BaseError::from)
            },
        )
        .unwrap()
        .data_dir(self.dir.path())
        .build()
        .unwrap()
    }

    async fn register(&self, handle: &str) -> Client<SqliteStore> {
        let client = self.open();
        client.register(handle, handle).await.unwrap();
        client
    }

    /// Drops `client` and starts a new one over the same database.
    async fn restart(&self, client: Client<SqliteStore>) -> Client<SqliteStore> {
        drop(client);
        let client = self.open();
        assert!(client.restore_session().await.unwrap());
        client
    }
}

fn server_messages(
    transport: &FlakyTransport,
    g: &GroupId,
    client: &Client<SqliteStore>,
    kind: gim_test::MessageKind,
) -> Vec<gim_test::Delivered> {
    let sender = client.session().unwrap().device;
    transport
        .inner
        .service()
        .messages(g, 0, usize::MAX)
        .unwrap()
        .into_iter()
        .filter(|m| m.sender == sender && m.kind == kind)
        .collect()
}

async fn commit_of_unknown_outcome_is_reposted_after_restart(lose_reply: bool) {
    let transport = FlakyTransport::new();
    let node = Persistent::new(&transport);
    let alice = node.register("alice").await;
    let bob = Device::register(&transport, "bob").await;
    let carol = Device::register(&transport, "carol").await;
    let g = alice
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    let service = transport.inner.service();

    transport.faults.fail_posts(
        MessageKind::Commit,
        lose_reply,
        COMMIT_POST_ATTEMPTS as usize,
    );
    assert!(alice.add_members(&g, &[carol.user_id()]).await.is_err());
    let pending = alice.store().pending_commit(&g).unwrap().unwrap();
    assert_eq!(
        pending.welcome.as_ref().unwrap().recipients,
        vec![carol.device()]
    );
    let reached = if lose_reply { 2 } else { 1 };
    assert_eq!(service.epoch(&g), Ok(reached));

    let alice = node.restart(alice).await;
    // Re-posted once with the same client_id (with its Welcome), merged.
    assert_eq!(alice.store().pending_commit(&g).unwrap(), None);
    assert_eq!(service.epoch(&g), Ok(2));
    let commits = server_messages(&transport, &g, &alice, gim_test::MessageKind::Commit);
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[1].client_id, pending.client_id);
    let welcomes = service.pending_welcomes(&carol.device(), 10);
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0].seq, commits[1].seq);
    assert_eq!(alice.store().chat(&g).unwrap().unwrap().members.len(), 3);

    alice.send_text(&g, "after restart", None).await.unwrap();
    for device in [&bob, &carol] {
        device.sync().await;
        assert_eq!(device.messages(&g).len(), 1);
        assert_eq!(device.store.chat(&g).unwrap().unwrap().members.len(), 3);
    }
}

#[tokio::test]
async fn accepted_commit_with_lost_reply_is_reposted_after_restart() {
    commit_of_unknown_outcome_is_reposted_after_restart(true).await;
}

#[tokio::test]
async fn commit_that_never_arrived_is_posted_after_restart() {
    commit_of_unknown_outcome_is_reposted_after_restart(false).await;
}

#[tokio::test]
async fn a_leave_proposal_left_uncommitted_is_committed_after_restart() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let node = Persistent::new(&transport);
    let bob = node.register("bob").await;
    let bob_id = bob.session().unwrap().device.user_id;
    let g = alice
        .client
        .create_group_chat(None, &[bob_id])
        .await
        .unwrap();
    bob.sync_once().await.unwrap();
    let service = transport.inner.service();

    // Bob, the only member left, commits alice's leave; the posts fail.
    alice.client.leave(&g).await.unwrap();
    transport
        .faults
        .fail_posts(MessageKind::Commit, false, COMMIT_POST_ATTEMPTS as usize);
    assert!(bob.sync_once().await.is_err());
    assert_eq!(service.epoch(&g), Ok(1));

    // The commit of unknown outcome is re-posted on restore.
    let bob = node.restart(bob).await;
    assert_eq!(service.epoch(&g), Ok(2));
    assert_eq!(bob.store().pending_commit(&g).unwrap(), None);
    let members = bob.store().chat(&g).unwrap().unwrap().members;
    assert_eq!(members.len(), 1);
    alice.sync().await;
    assert_eq!(
        alice.store.chat(&g).unwrap().unwrap().membership,
        Membership::Left
    );
}

#[tokio::test]
async fn leaving_survives_a_restart() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let node = Persistent::new(&transport);
    let bob = node.register("bob").await;
    let bob_id = bob.session().unwrap().device.user_id;
    let g = alice
        .client
        .create_group_chat(None, &[bob_id])
        .await
        .unwrap();
    bob.sync_once().await.unwrap();
    let service = transport.inner.service();

    // The proposal never reaches the hub.
    transport
        .faults
        .fail_posts(MessageKind::Commit, false, COMMIT_POST_ATTEMPTS as usize);
    assert!(bob.leave(&g).await.is_err());
    let leave = bob.store().pending_leave(&g).unwrap().unwrap();
    assert!(!leave.accepted);
    assert_eq!(server_handshakes(&transport, &g), 1);

    let bob = node.restart(bob).await;
    assert_eq!(
        bob.store().chat(&g).unwrap().unwrap().membership,
        Membership::Leaving
    );
    assert!(matches!(
        bob.send_text(&g, "still here?", None).await,
        Err(ClientError::Base(BaseError::InvalidState(_)))
    ));
    // Re-submitted on restore with the same client_id.
    let resent = bob.store().pending_leave(&g).unwrap().unwrap();
    assert!(resent.accepted);
    assert_eq!(resent.client_id, leave.client_id);
    assert_eq!(server_handshakes(&transport, &g), 2);

    alice.sync().await;
    assert_eq!(service.epoch(&g), Ok(2));
    bob.sync_once().await.unwrap();
    assert_eq!(
        bob.store().chat(&g).unwrap().unwrap().membership,
        Membership::Left
    );
    assert_eq!(bob.store().pending_leave(&g).unwrap(), None);
}

#[tokio::test]
async fn store_reset_signs_out_instead_of_failing() {
    let transport = FlakyTransport::new();
    let node = Persistent::new(&transport);
    let alice = node.register("alice").await;
    drop(alice);

    // Losing the database key resets the database; the keystore still
    // holds the session.
    node.secrets
        .delete(ClientBuilder::<SqliteStore>::DB_KEY_SECRET_KEY)
        .unwrap();
    let alice = node.open();
    assert!(!alice.restore_session().await.unwrap());
    assert_eq!(node.secrets.get(SESSION_SECRET_KEY).unwrap(), None);
    alice.create_identity("alice").await.unwrap();
    node.restart(alice).await;
}

#[tokio::test]
async fn dangling_pending_commits_are_reconciled_after_restart() {
    let transport = FlakyTransport::new();
    let node = Persistent::new(&transport);
    let alice = node.register("alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    let commits = server_messages(&transport, &g, &alice, gim_test::MessageKind::Commit).len();

    // An MLS pending commit without its record (it blocks sending), and a
    // record of a group whose MLS state is gone.
    let gone = GroupId::new("gone").unwrap();
    let engine = MlsEngine::new();
    let bob_device = bob.device();
    alice
        .store()
        .transaction(|txn| {
            engine.remove_members(&*txn, &g, &[bob_device])?;
            txn.upsert_pending_commit(&PendingCommit {
                group_id: gone.clone(),
                client_id: ClientId::new("dangling-commit").unwrap(),
                epoch: 1,
                payload: vec![1],
                welcome: None,
            })?;
            Ok(())
        })
        .unwrap();

    let alice = node.restart(alice).await;
    assert!(alice.store().pending_commits().unwrap().is_empty());
    assert_eq!(
        server_messages(&transport, &g, &alice, gim_test::MessageKind::Commit).len(),
        commits
    );
    alice.send_text(&g, "after restart", None).await.unwrap();
    bob.sync().await;
    assert_eq!(bob.messages(&g).len(), 1);
    assert_eq!(alice.store().chat(&g).unwrap().unwrap().members.len(), 2);

    // Idempotent.
    let alice = node.restart(alice).await;
    assert!(alice.store().pending_commits().unwrap().is_empty());
}

fn write_outgoing(client: &Client<SqliteStore>, dir: &str) -> String {
    let dir = client.outgoing_dir().join(dir);
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("photo.jpg");
    fs::write(&file, b"not really a jpeg").unwrap();
    file.to_str().unwrap().to_string()
}

fn outgoing_entries(client: &Client<SqliteStore>) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(client.outgoing_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn queue_upload(
    client: &Client<SqliteStore>,
    g: &GroupId,
    local_path: String,
) -> gim_common::MessageId {
    let base = BaseClient::new(client.session().unwrap().device);
    let media = PendingMedia {
        local_path,
        mime: "image/jpeg".into(),
        caption: None,
    };
    base.enqueue_media(&**client.store(), g, media, None, now_ms())
        .unwrap()
        .0
}

#[tokio::test]
async fn outgoing_copies_are_deleted_once_sent_cancelled_or_orphaned() {
    let transport = FlakyTransport::new();
    let node = Persistent::new(&transport);
    let alice = node.register("alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice.create_direct_chat(&bob.user_id()).await.unwrap();

    // Uploaded: the copy and its directory go.
    let sent = write_outgoing(&alice, "sent");
    let id = alice
        .send_media(&g, &sent, "image/jpeg", None, None)
        .await
        .unwrap();
    let message = alice.store().message(&id).unwrap().unwrap();
    assert_eq!(message.send_state, Some(SendState::Sent));
    assert!(matches!(message.content, MessageContent::Media { .. }));
    assert!(!Path::new(&sent).parent().unwrap().exists());

    // Cancelled before the upload.
    let cancelled = write_outgoing(&alice, "cancelled");
    let id = queue_upload(&alice, &g, cancelled.clone());
    alice.cancel_send(&id).await.unwrap();
    assert!(!Path::new(&cancelled).parent().unwrap().exists());

    // A file outside the outgoing directory belongs to the app.
    let own = node.dir.path().join("own.jpg");
    fs::write(&own, b"app file").unwrap();
    let id = queue_upload(&alice, &g, own.to_str().unwrap().to_string());
    alice.cancel_send(&id).await.unwrap();
    assert!(own.exists());

    // On start, only copies of queued uploads are kept.
    let queued = write_outgoing(&alice, "queued");
    queue_upload(&alice, &g, queued);
    write_outgoing(&alice, "orphan");
    fs::write(alice.outgoing_dir().join("stray"), b"").unwrap();
    let alice = node.restart(alice).await;
    assert_eq!(outgoing_entries(&alice), vec!["queued"]);
}
