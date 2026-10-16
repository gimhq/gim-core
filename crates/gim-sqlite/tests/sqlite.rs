//! SqliteStore specifics: persistence across reopen, atomicity of MLS state
//! and rows, and read semantics compared with gim-base's MemoryStore.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{group, key, setup, text, Device, NOW};
use gim_base::model::{
    Chat, ChatKind, ChatMember, DepartedMember, GroupCursor, GroupMessage, HubRecord, HubState,
    KeyPackageRecord, MediaCacheEntry, Membership, MembershipChangeKind, MembershipEvent, Message,
    MessageContent, MessageKind, OutboxEntry, OutboxKind, OutboxState, PendingCommit,
    PendingInvite, PendingLeave, PendingMedia, PendingWelcome, PreparedPayload, SendState,
    UserInfo,
};
use gim_base::{
    BaseError, MemoryStore, StateReader, StateStore, StoreError, StoreTxn, WriteTarget,
};
use gim_common::{ClientId, DeviceRef, MessageId, UserId};
use gim_crypto::CryptoStore;
use gim_proto::envelope::{Envelope, MediaInfo, ReceiptKind};
use gim_sqlite::{SqliteStore, DATABASE_FILE_NAME};
use gim_test::FakeDeliveryService;

#[test]
fn state_and_mls_groups_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let alice = Device::new("alice");
    let bob = Device::with_store("bob", SqliteStore::open(dir.path(), &key()).unwrap());
    assert!(dir.path().join(DATABASE_FILE_NAME).is_file());
    setup(&ds, &g, &[&alice, &bob]);
    let hi = alice.send_text(&ds, &g, "hi");
    bob.sync(&ds);
    let pending = bob.enqueue(&g, text("queued before restart"));

    let epoch = bob.epoch(&g);
    let chat = bob.store.chat(&g).unwrap().unwrap();
    let timeline = bob.store.messages(&g, None, 10).unwrap();
    let outbox = bob.store.outbox_entries().unwrap();
    let cursor = bob.store.group_cursor(&g).unwrap();
    let identity = bob
        .store
        .transaction(|txn| Ok(txn.load_identity()?))
        .unwrap();
    drop(bob);

    let bob = Device::with_store("bob", SqliteStore::open(dir.path(), &key()).unwrap());
    assert_eq!(bob.store.chat(&g).unwrap().unwrap(), chat);
    assert_eq!(bob.store.messages(&g, None, 10).unwrap(), timeline);
    assert_eq!(bob.message(&hi).content, text_content("hi"));
    assert_eq!(bob.store.outbox_entries().unwrap(), outbox);
    assert_eq!(bob.store.group_cursor(&g).unwrap(), cursor);
    assert_eq!(
        bob.store
            .transaction(|txn| Ok(txn.load_identity()?))
            .unwrap(),
        identity
    );
    assert_eq!(bob.epoch(&g), epoch);

    // The MLS group still works both ways after the restart.
    bob.flush(&ds);
    alice.sync(&ds);
    assert_eq!(
        alice.message(&pending).content,
        text_content("queued before restart")
    );
    let reply = alice.send_text(&ds, &g, "welcome back");
    bob.sync(&ds);
    assert_eq!(bob.message(&reply).content, text_content("welcome back"));

    // So does a commit processed after the restart.
    let carol = Device::new("carol");
    alice.add(&ds, &g, &[&carol]);
    bob.sync(&ds);
    carol.sync(&ds);
    assert_eq!(bob.epoch(&g), alice.epoch(&g));
    let hey = carol.send_text(&ds, &g, "hey");
    bob.sync(&ds);
    assert_eq!(bob.message(&hey).content, text_content("hey"));
}

#[cfg(unix)]
#[test]
fn creates_missing_data_dir_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("device").join("data");
    SqliteStore::open(&data_dir, &key()).unwrap();
    assert!(data_dir.join(DATABASE_FILE_NAME).is_file());
    let mode = std::fs::metadata(&data_dir).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[test]
fn failure_after_mls_processing_rolls_back_epoch_and_rows() {
    let dir = tempfile::tempdir().unwrap();
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, carol) = (Device::new("alice"), Device::new("carol"));
    let bob = Device::with_store("bob", SqliteStore::open(dir.path(), &key()).unwrap());
    setup(&ds, &g, &[&alice, &bob]);

    // Commit: MLS merges the new epoch, then the chat write fails.
    alice.add(&ds, &g, &[&carol]);
    let commit = bob.pull(&ds).remove(0);
    let epoch = bob.epoch(&g);
    let chat = bob.store.chat(&g).unwrap();
    bob.store.fail_writes(Some(WriteTarget::Chat));
    assert!(bob
        .client
        .apply(&bob.store, &bob.engine, commit.clone())
        .is_err());
    bob.store.fail_writes(None);
    assert_eq!(bob.epoch(&g), epoch);
    assert_eq!(bob.store.chat(&g).unwrap(), chat);

    // Application message: decrypted (ratchet advanced), then the message
    // row write fails.
    let bob = reopen(bob, dir.path());
    assert_eq!(bob.epoch(&g), epoch);
    assert!(!bob.apply(commit).is_empty());
    carol.sync(&ds);
    let id = alice.send_text(&ds, &g, "fair winds");
    let message = bob.pull(&ds).remove(0);
    let timeline = bob.store.messages(&g, None, usize::MAX).unwrap();
    bob.store.fail_writes(Some(WriteTarget::Message));
    assert!(bob
        .client
        .apply(&bob.store, &bob.engine, message.clone())
        .is_err());
    bob.store.fail_writes(None);
    let bob = reopen(bob, dir.path());
    assert_eq!(bob.store.messages(&g, None, usize::MAX).unwrap(), timeline);
    assert!(bob.store.message(&id).unwrap().is_none());
    // The ratchet was not consumed, so the message still decrypts.
    bob.apply(message);
    assert_eq!(bob.message(&id).content, text_content("fair winds"));
}

#[test]
fn error_in_transaction_rolls_back_mls_group_creation() {
    let dir = tempfile::tempdir().unwrap();
    let g = group("crew");
    let alice = Device::with_store("alice", SqliteStore::open(dir.path(), &key()).unwrap());
    let result: Result<(), BaseError> = alice.store.transaction(|txn| {
        alice.engine.create_group(&*txn, &g)?;
        txn.upsert_chat(&Chat::new(g.clone(), ChatKind::Group, NOW))?;
        assert!(alice.engine.has_group(&*txn, &g)?);
        assert!(txn.chat(&g)?.is_some());
        Err(BaseError::InvalidState("abort".into()))
    });
    assert!(result.is_err());
    let alice = reopen(alice, dir.path());
    assert!(!alice.has_group(&g));
    assert!(alice.store.chat(&g).unwrap().is_none());
    // The group id is free: no MLS state was left behind.
    alice
        .store
        .transaction(|txn| Ok(alice.engine.create_group(&*txn, &g)?))
        .unwrap();
    assert_eq!(alice.epoch(&g), 0);
}

#[test]
fn reads_match_memory_store() {
    let memory = MemoryStore::new();
    let sqlite = SqliteStore::open_in_memory().unwrap();
    memory.transaction(|txn| Ok(write_rows(txn)?)).unwrap();
    sqlite.transaction(|txn| Ok(write_rows(txn)?)).unwrap();
    assert_same_reads(&memory, &sqlite);
    assert_eq!(sqlite.pending_commits().unwrap().len(), 3);
    assert_eq!(sqlite.pending_leaves().unwrap().len(), 2);
    let invites = sqlite.pending_invites().unwrap();
    let order: Vec<(&str, &str)> = invites
        .iter()
        .map(|i| (i.group_id.as_str(), i.user_id.as_str()))
        .collect();
    assert_eq!(
        order,
        [("anchor", "erin"), ("crew", "dave"), ("crew", "erin")]
    );
    assert_eq!(
        sqlite.chat(&group("anchor")).unwrap().unwrap().membership,
        Membership::Leaving
    );
    assert_eq!(sqlite.departed_members().unwrap().len(), 3);
    assert_eq!(sqlite.device_lists().unwrap().len(), 2);
    let hubs: Vec<String> = sqlite
        .hubs()
        .unwrap()
        .into_iter()
        .map(|h| h.hub_id)
        .collect();
    assert_eq!(hubs, ["ha", "hb"]);
    let ledger = sqlite.key_package_records().unwrap();
    assert_eq!(ledger.len(), 2);
    assert!(ledger[1].last_resort);
    // A KeyPackage belongs to one hub, ever.
    let mut moved = ledger[0].clone();
    moved.hub_id = "hc".into();
    assert!(sqlite
        .transaction(|txn| Ok(txn.add_key_package_record(&moved)?))
        .is_err());
    assert!(memory
        .transaction(|txn| Ok(txn.add_key_package_record(&moved)?))
        .is_err());
    let crew = sqlite.membership_events(&group("crew")).unwrap();
    let order: Vec<(u64, &str)> = crew.iter().map(|e| (e.seq, e.user_id.as_str())).collect();
    assert_eq!(order, [(3, "bob"), (3, "carol"), (9, "bob")]);
    assert_eq!(crew[2].kind, MembershipChangeKind::Removed);
    memory.transaction(|txn| Ok(update_rows(txn)?)).unwrap();
    sqlite.transaction(|txn| Ok(update_rows(txn)?)).unwrap();
    assert_same_reads(&memory, &sqlite);
    // Reads inside a transaction see its own writes.
    memory.transaction(|txn| Ok(remove_rows(txn)?)).unwrap();
    sqlite
        .transaction(|txn| {
            remove_rows(txn)?;
            assert_same_reads(&memory, &*txn);
            Ok(())
        })
        .unwrap();
    assert_same_reads(&memory, &sqlite);
    // Removing the chat removes its pending leave and invites.
    assert_eq!(sqlite.pending_leave(&group("crew")).unwrap(), None);
    assert!(sqlite.pending_leave(&group("anchor")).unwrap().is_some());
    let invites = sqlite.pending_invites().unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].group_id, group("anchor"));
    assert_eq!(invites[0].attempts, 1);
}

fn reopen(device: Device, dir: &std::path::Path) -> Device {
    let name = device.name.clone();
    drop(device);
    Device::with_store(&name, SqliteStore::open(dir, &key()).unwrap())
}

fn text_content(body: &str) -> MessageContent {
    MessageContent::Text { body: body.into() }
}

fn device(user: &str, device: &str) -> DeviceRef {
    DeviceRef::parse(user, device).unwrap()
}

fn id(value: &str) -> MessageId {
    MessageId::new(value).unwrap()
}

fn media(blob_id: &str) -> MediaInfo {
    MediaInfo {
        blob_id: blob_id.into(),
        key: [1; 32],
        sha256: [2; 32],
        mime: "image/jpeg".into(),
        size: 4096,
        width: Some(640),
        height: Some(480),
        file_name: Some("harbour.jpg".into()),
        thumbnail: Some(vec![3, 4, 5]),
    }
}

fn message(group_id: &str, message_id: &str, seq: Option<u64>, sent_at_ms: u64) -> Message {
    Message {
        message_id: id(message_id),
        group_id: group(group_id),
        seq,
        sender: device("alice", "phone"),
        sent_at_ms,
        content: text_content(message_id),
        reply_to: None,
        edited: false,
        deleted: false,
        reactions: BTreeMap::new(),
        send_state: None,
        receipts: BTreeMap::new(),
    }
}

fn outbox(message_id: &str, state: OutboxState, next: u64, created: u64) -> OutboxEntry {
    OutboxEntry {
        message_id: id(message_id),
        group_id: group("crew"),
        kind: OutboxKind::Envelope(Envelope::new(id(message_id), created, text("ahoy"))),
        state,
        attempts: 0,
        next_attempt_at_ms: next,
        last_error: None,
        prepared: None,
        created_at_ms: created,
    }
}

fn write_rows(txn: &mut impl StoreTxn) -> Result<(), StoreError> {
    let mut crew = Chat::new(group("crew"), ChatKind::Group, NOW);
    crew.name = Some("Crew".into());
    crew.avatar = Some(media("avatar"));
    crew.members = vec![
        ChatMember {
            device: device("alice", "phone"),
            display_name: Some("Alice".into()),
        },
        ChatMember {
            device: device("bob", "phone"),
            display_name: None,
        },
    ];
    crew.unread_count = 2;
    crew.last_message_id = Some(id("m3"));
    crew.last_seq = 3;
    crew.last_read_seq = 1;
    txn.upsert_chat(&crew)?;
    let mut dm = Chat::new(group("dm"), ChatKind::Direct, NOW + 5);
    dm.membership = Membership::Left;
    txn.upsert_chat(&dm)?;
    // Same updated_at as crew: ties are ordered by group id.
    let mut anchor = Chat::new(group("anchor"), ChatKind::Group, NOW);
    anchor.membership = Membership::Leaving;
    txn.upsert_chat(&anchor)?;

    // Inserted out of order; two unsent own messages.
    for (message_id, seq, sent_at) in [
        ("m3", Some(3), NOW + 3),
        ("m1", Some(1), NOW + 1),
        ("u2", None, NOW + 9),
        ("u1", None, NOW + 8),
        ("m2", Some(2), NOW + 2),
    ] {
        txn.upsert_message(&message("crew", message_id, seq, sent_at))?;
    }
    let mut rich = message("crew", "m4", Some(4), NOW + 4);
    rich.content = MessageContent::Media {
        media: media("photo"),
        caption: Some("Hydra".into()),
    };
    rich.reply_to = Some(id("m1"));
    rich.edited = true;
    rich.reactions = BTreeMap::from([(
        UserId::new("bob").unwrap(),
        BTreeSet::from(["+1".to_owned(), "sun".to_owned()]),
    )]);
    rich.send_state = Some(SendState::Delivered);
    rich.receipts = BTreeMap::from([
        (device("bob", "phone"), ReceiptKind::Read),
        (device("bob", "tablet"), ReceiptKind::Delivered),
    ]);
    txn.upsert_message(&rich)?;
    let mut pending = message("crew", "u3", None, NOW + 10);
    pending.content = MessageContent::PendingMedia(PendingMedia {
        local_path: "/tmp/chart.png".into(),
        mime: "image/png".into(),
        caption: None,
    });
    pending.send_state = Some(SendState::Pending);
    txn.upsert_message(&pending)?;
    txn.upsert_message(&message("dm", "d1", Some(1), NOW))?;

    txn.upsert_outbox(&outbox("o2", OutboxState::Pending, NOW + 100, NOW + 2))?;
    txn.upsert_outbox(&outbox("o1", OutboxState::Pending, NOW, NOW + 1))?;
    txn.upsert_outbox(&outbox("o3", OutboxState::Failed, NOW, NOW))?;
    let mut upload = outbox("o4", OutboxState::Pending, NOW, NOW + 1);
    upload.kind = OutboxKind::MediaUpload(PendingMedia {
        local_path: "/tmp/chart.png".into(),
        mime: "image/png".into(),
        caption: Some("route".into()),
    });
    upload.attempts = 2;
    upload.last_error = Some("timeout".into());
    upload.prepared = Some(PreparedPayload {
        epoch: 7,
        payload: vec![9, 8, 7],
    });
    txn.upsert_outbox(&upload)?;

    txn.set_global_cursor(42)?;
    txn.set_group_cursor(
        &group("crew"),
        &GroupCursor {
            contiguous_seq: 3,
            ahead: BTreeSet::from([5, 7]),
        },
    )?;
    for seq in [9, 6] {
        txn.park_message(&GroupMessage {
            group_id: group("crew"),
            seq,
            sender: device("carol", "laptop"),
            kind: MessageKind::Application,
            payload: vec![seq as u8; 3],
            client_id: Some(ClientId::new(format!("c{seq}")).unwrap()),
        })?;
    }
    txn.park_message(&GroupMessage {
        group_id: group("unknown"),
        seq: 1,
        sender: device("dave", "phone"),
        kind: MessageKind::Welcome,
        payload: vec![1],
        client_id: None,
    })?;

    for (blob_id, last_access_ms) in [("b2", NOW), ("b1", NOW), ("b0", NOW + 1)] {
        txn.upsert_media(&MediaCacheEntry {
            blob_id: blob_id.into(),
            local_path: format!("/cache/{blob_id}"),
            size: 1024,
            last_access_ms,
        })?;
    }
    txn.upsert_user(&UserInfo {
        user_id: UserId::new("alice").unwrap(),
        handle: "alice".into(),
        display_name: "Alice".into(),
    })?;

    let commit = |g: &str, welcome| PendingCommit {
        group_id: group(g),
        client_id: ClientId::new(format!("commit-{g}")).unwrap(),
        epoch: 4,
        payload: vec![4, 2],
        welcome,
    };
    txn.upsert_pending_commit(&commit(
        "crew",
        Some(PendingWelcome {
            payload: vec![5],
            recipients: vec![device("carol", "laptop"), device("dave", "phone")],
        }),
    ))?;
    txn.upsert_pending_commit(&commit("dm", None))?;
    txn.upsert_pending_commit(&commit("anchor", None))?;
    for g in ["crew", "anchor"] {
        txn.upsert_pending_leave(&PendingLeave {
            group_id: group(g),
            client_id: ClientId::new(format!("leave-{g}")).unwrap(),
            epoch: 4,
            payload: vec![7, 1],
            attempts: 1,
            accepted: false,
        })?;
    }
    for (g, user) in [("crew", "erin"), ("anchor", "erin"), ("crew", "dave")] {
        txn.upsert_pending_invite(&invite(g, user))?;
    }
    for (user, data) in [("bob", vec![1, 2]), ("alice", vec![3])] {
        txn.upsert_device_list(&UserId::new(user).unwrap(), &data)?;
    }
    txn.upsert_hub(&HubRecord {
        hub_id: "hb".into(),
        url: None,
        priority: 1,
        verified_root_pubkey: None,
        last_seen_ms: None,
        state: HubState::Unverified,
    })?;
    txn.upsert_hub(&HubRecord {
        hub_id: "ha".into(),
        url: Some("https://a.example".into()),
        priority: 0,
        verified_root_pubkey: Some(vec![7; 32]),
        last_seen_ms: Some(NOW),
        state: HubState::Verified,
    })?;
    for (kp_ref, hub_id, last_resort) in [(vec![2, 2], "hb", true), (vec![1], "ha", false)] {
        txn.add_key_package_record(&KeyPackageRecord {
            kp_ref,
            hub_id: hub_id.into(),
            last_resort,
            created_at_ms: NOW,
        })?;
    }
    for (g, user, dev) in [
        ("crew", "dave", "phone"),
        ("crew", "carol", "laptop"),
        ("dm", "bob", "tablet"),
        ("crew", "carol", "laptop"),
    ] {
        txn.add_departed_member(&DepartedMember {
            group_id: group(g),
            device: device(user, dev),
        })?;
    }
    for (g, seq, user, actor, kind) in [
        ("crew", 9, "bob", "bob", MembershipChangeKind::Left),
        ("crew", 3, "carol", "alice", MembershipChangeKind::Added),
        ("crew", 3, "bob", "alice", MembershipChangeKind::Added),
        ("dm", 2, "bob", "alice", MembershipChangeKind::Removed),
        // Replaces the first row.
        ("crew", 9, "bob", "alice", MembershipChangeKind::Removed),
    ] {
        txn.add_membership_event(&membership(g, seq, user, actor, kind))?;
    }
    Ok(())
}

fn invite(g: &str, user: &str) -> PendingInvite {
    PendingInvite {
        group_id: group(g),
        user_id: UserId::new(user).unwrap(),
        created_at_ms: NOW,
        next_retry_at_ms: NOW + 5,
        attempts: 0,
    }
}

fn membership(
    g: &str,
    seq: u64,
    user: &str,
    actor: &str,
    kind: MembershipChangeKind,
) -> MembershipEvent {
    MembershipEvent {
        group_id: group(g),
        seq,
        user_id: UserId::new(user).unwrap(),
        actor: UserId::new(actor).unwrap(),
        kind,
        at_ms: NOW + seq,
    }
}

fn update_rows(txn: &mut impl StoreTxn) -> Result<(), StoreError> {
    let mut crew = txn.chat(&group("crew"))?.unwrap();
    crew.updated_at_ms = NOW + 20;
    crew.unread_count = 0;
    txn.upsert_chat(&crew)?;
    let mut sent = txn.message(&id("u1"))?.unwrap();
    sent.seq = Some(5);
    sent.send_state = Some(SendState::Sent);
    txn.upsert_message(&sent)?;
    txn.remove_message(&id("m2"))?;
    let mut failed = txn.outbox_entry(&id("o1"))?.unwrap();
    failed.state = OutboxState::Failed;
    txn.upsert_outbox(&failed)?;
    txn.remove_outbox(&id("o2"))?;
    txn.set_global_cursor(43)?;
    txn.unpark_message(&group("crew"), 6)?;
    txn.remove_media("b1")?;
    txn.upsert_user(&UserInfo {
        user_id: UserId::new("alice").unwrap(),
        handle: "alice".into(),
        display_name: "Alice M.".into(),
    })?;
    let mut retried = txn.pending_commit(&group("crew"))?.unwrap();
    retried.epoch = 5;
    txn.upsert_pending_commit(&retried)?;
    txn.upsert_device_list(&UserId::new("bob").unwrap(), &[4])?;
    txn.remove_pending_commit(&group("anchor"))?;
    let mut renewed = txn.pending_leave(&group("anchor"))?.unwrap();
    renewed.epoch = 5;
    renewed.attempts = 2;
    renewed.accepted = true;
    txn.upsert_pending_leave(&renewed)?;
    txn.remove_departed_member(&DepartedMember {
        group_id: group("crew"),
        device: device("dave", "phone"),
    })?;
    let mut retried = invite("anchor", "erin");
    retried.attempts = 1;
    retried.next_retry_at_ms = NOW + 30;
    txn.upsert_pending_invite(&retried)?;
    txn.remove_pending_invite(&group("crew"), &UserId::new("dave").unwrap())?;
    let mut removed = txn.hubs()?.remove(0);
    removed.state = HubState::Removed;
    txn.upsert_hub(&removed)?;
    txn.upsert_hub(&HubRecord {
        hub_id: "hc".into(),
        url: Some("https://c.example".into()),
        priority: 255,
        verified_root_pubkey: None,
        last_seen_ms: None,
        state: HubState::Unverified,
    })?;
    txn.remove_hub("hb")?;
    txn.add_membership_event(&membership(
        "crew",
        12,
        "dave",
        "carol",
        MembershipChangeKind::Added,
    ))?;
    Ok(())
}

fn remove_rows(txn: &mut impl StoreTxn) -> Result<(), StoreError> {
    txn.remove_chat(&group("crew"))
}

fn assert_same_reads(expected: &impl StateReader, actual: &impl StateReader) {
    assert_eq!(actual.chats().unwrap(), expected.chats().unwrap());
    for g in ["crew", "dm", "anchor", "unknown"].map(group) {
        assert_eq!(actual.chat(&g).unwrap(), expected.chat(&g).unwrap());
        for before_seq in [None, Some(0), Some(2), Some(3), Some(u64::MAX)] {
            for limit in [0, 1, 2, 3, usize::MAX] {
                assert_eq!(
                    actual.messages(&g, before_seq, limit).unwrap(),
                    expected.messages(&g, before_seq, limit).unwrap(),
                    "{g} before {before_seq:?} limit {limit}"
                );
            }
        }
        for after_seq in [0, 1, 4, u64::MAX] {
            assert_eq!(
                actual.messages_after(&g, after_seq).unwrap(),
                expected.messages_after(&g, after_seq).unwrap()
            );
        }
        assert_eq!(
            actual.group_cursor(&g).unwrap(),
            expected.group_cursor(&g).unwrap()
        );
        assert_eq!(
            actual.parked_messages(&g).unwrap(),
            expected.parked_messages(&g).unwrap()
        );
        assert_eq!(
            actual.pending_commit(&g).unwrap(),
            expected.pending_commit(&g).unwrap()
        );
        assert_eq!(
            actual.pending_leave(&g).unwrap(),
            expected.pending_leave(&g).unwrap()
        );
        assert_eq!(
            actual.membership_events(&g).unwrap(),
            expected.membership_events(&g).unwrap()
        );
    }
    assert_eq!(
        actual.pending_commits().unwrap(),
        expected.pending_commits().unwrap()
    );
    assert_eq!(
        actual.pending_leaves().unwrap(),
        expected.pending_leaves().unwrap()
    );
    assert_eq!(
        actual.pending_invites().unwrap(),
        expected.pending_invites().unwrap()
    );
    assert_eq!(
        actual.departed_members().unwrap(),
        expected.departed_members().unwrap()
    );
    assert_eq!(
        actual.device_lists().unwrap(),
        expected.device_lists().unwrap()
    );
    assert_eq!(actual.hubs().unwrap(), expected.hubs().unwrap());
    assert_eq!(
        actual.key_package_records().unwrap(),
        expected.key_package_records().unwrap()
    );
    for message_id in ["m1", "m2", "m4", "u1", "u3", "d1", "none"].map(id) {
        assert_eq!(
            actual.message(&message_id).unwrap(),
            expected.message(&message_id).unwrap()
        );
    }
    assert_eq!(
        actual.outbox_entries().unwrap(),
        expected.outbox_entries().unwrap()
    );
    for message_id in ["o1", "o2", "o4"].map(id) {
        assert_eq!(
            actual.outbox_entry(&message_id).unwrap(),
            expected.outbox_entry(&message_id).unwrap()
        );
    }
    for now in [0, NOW, NOW + 100, u64::MAX] {
        for limit in [1, usize::MAX] {
            assert_eq!(
                actual.outbox_due(now, limit).unwrap(),
                expected.outbox_due(now, limit).unwrap()
            );
        }
    }
    assert_eq!(
        actual.global_cursor().unwrap(),
        expected.global_cursor().unwrap()
    );
    assert_eq!(
        actual.media_entries().unwrap(),
        expected.media_entries().unwrap()
    );
    for blob_id in ["b0", "b1", "none"] {
        assert_eq!(
            actual.media(blob_id).unwrap(),
            expected.media(blob_id).unwrap()
        );
    }
    for user in ["alice", "bob"] {
        let user = UserId::new(user).unwrap();
        assert_eq!(actual.user(&user).unwrap(), expected.user(&user).unwrap());
    }
}
