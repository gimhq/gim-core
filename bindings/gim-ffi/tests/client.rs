//! GimClients over one fake server, driven through the FFI surface only.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gim_core::{
    create_client_with_fake_transport, ChatKind, ChatListDiff, ChatListListener, ChatSummary,
    ClientConfig, ConnectionState, ConnectionStateListener, GimClient, GimError, MessageContent,
    MessageItem, PlatformHooks, SendState, TaskHandle, TimelineDiff, TimelineItem,
    TimelineListener, TypingListener,
};
use gim_sdk::testing::FakeTransport;
use tempfile::TempDir;

/// In-memory keystore and a temporary data directory.
struct MemoryHooks {
    dir: TempDir,
    secrets: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryHooks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            dir: tempfile::tempdir().unwrap(),
            secrets: Mutex::default(),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

impl PlatformHooks for MemoryHooks {
    fn secure_store_get(&self, key: String) -> Option<Vec<u8>> {
        self.secrets.lock().unwrap().get(&key).cloned()
    }
    fn secure_store_set(&self, key: String, value: Vec<u8>) -> Result<(), GimError> {
        self.secrets.lock().unwrap().insert(key, value);
        Ok(())
    }
    fn secure_store_delete(&self, key: String) {
        self.secrets.lock().unwrap().remove(&key);
    }
    fn data_dir(&self) -> String {
        self.dir.path().to_str().unwrap().to_string()
    }
    fn is_network_reachable(&self) -> bool {
        true
    }
}

/// A native-side copy of a list, kept up to date by applying the diffs.
struct Mirror<T>(Mutex<Vec<T>>);

impl<T: Clone> Mirror<T> {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Vec::new())))
    }

    fn get(&self) -> Vec<T> {
        self.0.lock().unwrap().clone()
    }

    /// Waits until `check` holds for the list.
    async fn wait(&self, what: &str, check: impl Fn(&[T]) -> bool) -> Vec<T> {
        for _ in 0..500 {
            let items = self.get();
            if check(&items) {
                return items;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {what}");
    }
}

macro_rules! apply_diffs {
    ($items:expr, $diffs:expr, $ty:ident) => {
        for diff in $diffs {
            match diff {
                $ty::Append { values } => $items.extend(values),
                $ty::Clear => $items.clear(),
                $ty::PushFront { value } => $items.insert(0, value),
                $ty::PushBack { value } => $items.push(value),
                $ty::PopFront => {
                    $items.remove(0);
                }
                $ty::PopBack => {
                    $items.pop();
                }
                $ty::Insert { index, value } => $items.insert(index as usize, value),
                $ty::Set { index, value } => $items[index as usize] = value,
                $ty::Remove { index } => {
                    $items.remove(index as usize);
                }
                $ty::Truncate { length } => $items.truncate(length as usize),
                $ty::Reset { values } => *$items = values,
            }
        }
    };
}

impl ChatListListener for Mirror<ChatSummary> {
    fn on_update(&self, diffs: Vec<ChatListDiff>) {
        let items = &mut *self.0.lock().unwrap();
        apply_diffs!(items, diffs, ChatListDiff);
    }
}

impl TimelineListener for Mirror<TimelineItem> {
    fn on_update(&self, diffs: Vec<TimelineDiff>) {
        let items = &mut *self.0.lock().unwrap();
        apply_diffs!(items, diffs, TimelineDiff);
    }
}

/// Records every value it is given.
struct Recorder<T>(Mutex<Vec<T>>);

impl<T: Clone> Recorder<T> {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Vec::new())))
    }

    async fn wait(&self, what: &str, check: impl Fn(&T) -> bool) {
        for _ in 0..500 {
            if self.0.lock().unwrap().last().is_some_and(&check) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {what}");
    }
}

impl ConnectionStateListener for Recorder<ConnectionState> {
    fn on_change(&self, state: ConnectionState) {
        self.0.lock().unwrap().push(state);
    }
}

impl TypingListener for Recorder<Vec<String>> {
    fn on_update(&self, user_ids: Vec<String>) {
        self.0.lock().unwrap().push(user_ids);
    }
}

async fn open(transport: &FakeTransport, hooks: &Arc<MemoryHooks>) -> Arc<GimClient> {
    let config = ClientConfig {
        server_url: "https://gim.example.org".to_string(),
    };
    create_client_with_fake_transport(config, hooks.clone(), transport.clone())
        .await
        .unwrap()
}

struct User {
    client: Arc<GimClient>,
    hooks: Arc<MemoryHooks>,
    user_id: String,
}

impl User {
    async fn register(transport: &FakeTransport, handle: &str, name: &str) -> Self {
        let hooks = MemoryHooks::new();
        let client = open(transport, &hooks).await;
        assert_eq!(client.session().await.unwrap(), None);
        let code = client.create_identity(name.to_string()).await.unwrap();
        assert!(!code.is_empty());
        let session = client.session().await.unwrap().unwrap();
        assert_eq!(session.display_name, name);
        // Handles are claimed through the directory; the FFI does not
        // expose it yet.
        let user_id = gim_common::UserId::new(session.user_id.clone()).unwrap();
        transport.service().claim_handle(&user_id, handle).unwrap();
        Self {
            client,
            hooks,
            user_id: session.user_id,
        }
    }

    async fn timeline(&self, chat_id: &str) -> (Arc<Mirror<TimelineItem>>, Arc<TaskHandle>) {
        let mirror = Mirror::new();
        let handle = self
            .client
            .timeline(chat_id.to_string())
            .await
            .unwrap()
            .add_listener(mirror.clone())
            .await;
        (mirror, handle)
    }

    async fn chat_list(&self) -> (Arc<Mirror<ChatSummary>>, Arc<TaskHandle>) {
        let mirror = Mirror::new();
        let handle = self.client.chat_list(mirror.clone()).await.unwrap();
        (mirror, handle)
    }
}

fn messages(items: &[TimelineItem]) -> Vec<MessageItem> {
    items
        .iter()
        .filter_map(|item| match item {
            TimelineItem::Message { item } => Some(item.clone()),
            _ => None,
        })
        .collect()
}

fn message(items: &[TimelineItem], id: &str) -> Option<MessageItem> {
    messages(items).into_iter().find(|m| m.message_id == id)
}

fn text(item: &MessageItem) -> &str {
    match &item.content {
        MessageContent::Text { body } => body,
        other => panic!("not a text: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_chat_text_receipts_typing_and_restart() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let bob = User::register(&transport, "bob", "Bob").await;

    let found = alice
        .client
        .find_user("bob".to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (found.user_id.as_str(), found.display_name.as_str()),
        (bob.user_id.as_str(), "Bob")
    );
    assert_eq!(
        alice.client.find_user("nobody".to_string()).await.unwrap(),
        None
    );

    let chat = alice
        .client
        .create_direct_chat(bob.user_id.clone())
        .await
        .unwrap();
    assert_eq!(
        alice
            .client
            .create_direct_chat(bob.user_id.clone())
            .await
            .unwrap(),
        chat,
        "the existing direct chat is reused"
    );

    bob.client.find_user("alice".to_string()).await.unwrap();
    let connection = Recorder::new();
    let _connection_handle = bob
        .client
        .connection_state(connection.clone())
        .await
        .unwrap();
    // The first callback is the current state.
    connection
        .wait("bob offline", |s| *s == ConnectionState::Offline)
        .await;
    for user in [&alice, &bob] {
        user.client.start_sync().await.unwrap();
    }
    connection
        .wait("bob connected", |s| *s == ConnectionState::Connected)
        .await;

    let (alice_timeline, _alice_timeline_handle) = alice.timeline(&chat).await;
    let (bob_chats, _bob_chats_handle) = bob.chat_list().await;
    let typing = Recorder::new();
    let _typing_handle = bob
        .client
        .typing(chat.clone(), typing.clone())
        .await
        .unwrap();

    let id = alice
        .client
        .send_text(chat.clone(), "hello".to_string(), None)
        .await
        .unwrap();
    let items = alice_timeline
        .wait("local echo", |items| message(items, &id).is_some())
        .await;
    let sent = message(&items, &id).unwrap();
    assert_eq!(text(&sent), "hello");
    assert!(sent.is_own);

    // Bob receives it through his chat list; the direct chat is named
    // after Alice.
    let chats = bob_chats
        .wait("chat at bob", |c| {
            c.first()
                .and_then(|c| c.last_message.as_ref())
                .is_some_and(|m| m.text == "hello")
        })
        .await;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats[0].chat_id, chat);
    assert_eq!(chats[0].kind, ChatKind::Direct);
    assert_eq!(chats[0].name, "Alice");
    assert_eq!(chats[0].unread_count, 1);
    assert_eq!(chats[0].member_count, 2);

    let (bob_timeline, _bob_timeline_handle) = bob.timeline(&chat).await;
    let items = bob_timeline
        .wait("bob timeline", |items| message(items, &id).is_some())
        .await;
    let received = message(&items, &id).unwrap();
    assert_eq!(received.sender.display_name, "Alice");
    assert!(!received.is_own);
    assert_eq!(received.send_state, None);
    assert!(matches!(items[0], TimelineItem::DateSeparator { .. }));

    // Delivered, then read.
    alice_timeline
        .wait("delivered", |items| {
            message(items, &id).is_some_and(|m| m.send_state == Some(SendState::Delivered))
        })
        .await;
    bob.client
        .mark_read(chat.clone(), id.clone())
        .await
        .unwrap();
    bob_chats
        .wait("unread cleared", |c| c[0].unread_count == 0)
        .await;
    alice_timeline
        .wait("read", |items| {
            message(items, &id).is_some_and(|m| m.send_state == Some(SendState::Read))
        })
        .await;

    // Typing.
    typing.wait("nobody typing", |users| users.is_empty()).await;
    alice.client.set_typing(chat.clone(), true).await.unwrap();
    typing
        .wait("alice typing", |users| {
            users == std::slice::from_ref(&alice.user_id)
        })
        .await;

    // A reply from Bob, then Alice restarts from her data directory.
    let reply = bob
        .client
        .send_text(chat.clone(), "hi alice".to_string(), Some(id.clone()))
        .await
        .unwrap();
    alice_timeline
        .wait("reply", |items| message(items, &reply).is_some())
        .await;
    let session = alice.client.session().await.unwrap().unwrap();
    alice.client.stop_sync().await.unwrap();
    drop((_alice_timeline_handle, alice_timeline));
    let hooks = alice.hooks.clone();
    drop(alice.client);

    let restarted = open(&transport, &hooks).await;
    assert_eq!(restarted.session().await.unwrap(), Some(session));
    let timeline = Mirror::new();
    let _handle = restarted
        .timeline(chat.clone())
        .await
        .unwrap()
        .add_listener(timeline.clone())
        .await;
    let history = timeline.wait("history", |items| !items.is_empty()).await;
    let history = messages(&history);
    assert_eq!(
        history.iter().map(text).collect::<Vec<_>>(),
        ["hello", "hi alice"]
    );
    assert_eq!(history[0].send_state, Some(SendState::Read));
    assert_eq!(
        history[1].reply_to.as_ref().map(|r| r.text.as_str()),
        Some("hello")
    );

    // The restarted client still sends.
    restarted.start_sync().await.unwrap();
    let again = restarted
        .send_text(chat.clone(), "back".to_string(), None)
        .await
        .unwrap();
    bob_timeline
        .wait("message after restart", |items| {
            message(items, &again).is_some()
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn media_send_and_fetch() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let bob = User::register(&transport, "bob", "Bob").await;
    let chat = alice
        .client
        .create_direct_chat(bob.user_id.clone())
        .await
        .unwrap();
    bob.client.start_sync().await.unwrap();
    let (bob_timeline, _handle) = bob.timeline(&chat).await;

    let source = alice.hooks.path("report.pdf");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    fs::write(&source, &data).unwrap();
    let id = alice
        .client
        .send_media(
            chat.clone(),
            source.to_str().unwrap().to_string(),
            "application/pdf".to_string(),
            Some("q3".to_string()),
            None,
        )
        .await
        .unwrap();
    // The file was copied: the app may delete it right away.
    fs::remove_file(&source).unwrap();

    let items = bob_timeline
        .wait("media at bob", |items| message(items, &id).is_some())
        .await;
    let MessageContent::File {
        media,
        file_name,
        caption,
    } = message(&items, &id).unwrap().content
    else {
        panic!("not a file");
    };
    assert_eq!(file_name.as_deref(), Some("report.pdf"));
    assert_eq!(caption.as_deref(), Some("q3"));
    assert_eq!(media.message_id, id);
    assert_eq!(media.size, data.len() as u64);
    assert!(!media.has_thumbnail);

    let dest = bob.hooks.path("downloaded.pdf");
    let dest = dest.to_str().unwrap().to_string();
    let path = bob
        .client
        .fetch_media(
            media.chat_id.clone(),
            media.message_id.clone(),
            dest.clone(),
        )
        .await
        .unwrap();
    assert_eq!(path, dest);
    assert_eq!(fs::read(&path).unwrap(), data);
    assert_eq!(
        bob.client
            .fetch_thumbnail(
                chat.clone(),
                id.clone(),
                bob.hooks.path("t").to_str().unwrap().to_string()
            )
            .await,
        Ok(None)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_members() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let bob = User::register(&transport, "bob", "Bob").await;
    let carol = User::register(&transport, "carol", "Carol").await;
    // Display names come from the directory cache, filled by lookups.
    for handle in ["bob", "carol"] {
        alice.client.find_user(handle.to_string()).await.unwrap();
    }
    let chat = alice
        .client
        .create_group_chat(
            "Crew".to_string(),
            vec![bob.user_id.clone(), carol.user_id.clone()],
        )
        .await
        .unwrap();

    let mut names: Vec<String> = alice
        .client
        .chat_members(chat.clone())
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.display_name)
        .collect();
    names.sort();
    assert_eq!(names, ["Alice", "Bob", "Carol"]);

    alice
        .client
        .remove_member(chat.clone(), carol.user_id.clone())
        .await
        .unwrap();
    let members = alice.client.chat_members(chat.clone()).await.unwrap();
    let mut ids: Vec<&str> = members.iter().map(|p| p.user_id.as_str()).collect();
    ids.sort();
    let mut expected = vec![alice.user_id.as_str(), bob.user_id.as_str()];
    expected.sort();
    assert_eq!(ids, expected);

    assert!(matches!(
        alice.client.chat_members("unknown".to_string()).await,
        Err(GimError::NotFound { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_info_and_member_names_reach_joiners() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let bob = User::register(&transport, "bob", "Bob").await;
    // No find_user: member names are looked up by the clients.
    let chat = alice
        .client
        .create_group_chat("Crew".to_string(), vec![bob.user_id.clone()])
        .await
        .unwrap();
    let (list, _list_handle) = bob.chat_list().await;
    bob.client.start_sync().await.unwrap();
    list.wait("the shared group name", |items| {
        items.iter().any(|c| c.chat_id == chat && c.name == "Crew")
    })
    .await;
    // Profiles are resolved in the background after the chat shows up.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut names: Vec<String> = bob
            .client
            .chat_members(chat.clone())
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.display_name)
            .collect();
        names.sort();
        if names == ["Alice", "Bob"] {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "names: {names:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let avatar = alice.hooks.path("boat.png");
    std::fs::write(&avatar, b"png bytes").unwrap();
    alice
        .client
        .set_group_info(
            chat.clone(),
            Some("Ionian crew".to_string()),
            Some(avatar.to_str().unwrap().to_string()),
        )
        .await
        .unwrap();
    let rows = list
        .wait("the new name and avatar", |items| {
            items
                .iter()
                .any(|c| c.chat_id == chat && c.name == "Ionian crew" && c.avatar.is_some())
        })
        .await;
    let row = rows.iter().find(|c| c.chat_id == chat).unwrap();
    let avatar = row.avatar.as_ref().unwrap();
    assert_eq!(avatar.mime, "image/png");
    assert_eq!(avatar.message_id, "");

    assert!(matches!(
        alice.client.set_group_info(chat.clone(), None, None).await,
        Err(GimError::InvalidInput { .. })
    ));
    bob.client.stop_sync().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_deletes_local_state() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    alice.client.sign_out().await.unwrap();
    assert!(alice.hooks.secrets.lock().unwrap().is_empty());
    assert!(!alice.hooks.path("gim.sqlite3").exists());
    assert_eq!(alice.client.session().await, Err(GimError::NotRegistered));

    let fresh = open(&transport, &alice.hooks).await;
    assert_eq!(fresh.session().await.unwrap(), None);
}
