//! GimClients over one fake server, driven through the FFI surface only.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gim_core::{
    create_client_with_fake_transport, ChatKind, ChatListDiff, ChatListListener, ChatState,
    ChatSummary, ClientConfig, ConnectionState, ConnectionStateListener, GimClient, GimError,
    HubInfo, HubListListener, HubState, LocalTimeZone, MembershipChangeKind, MessageContent,
    MessageItem, NotificationKind, PlatformHooks, PushRegistration, SendState, TaskHandle,
    TimelineDiff, TimelineItem, TimelineListener, TypingListener,
};
use gim_sdk::testing::FakeTransport;
use tempfile::TempDir;

/// In-memory keystore and a temporary data directory.
struct MemoryHooks {
    dir: TempDir,
    secrets: Mutex<HashMap<String, Vec<u8>>>,
    /// Reads fail, like a keystore locked before the first unlock.
    locked: AtomicBool,
}

impl MemoryHooks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            dir: tempfile::tempdir().unwrap(),
            secrets: Mutex::default(),
            locked: AtomicBool::new(false),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

impl PlatformHooks for MemoryHooks {
    fn secure_store_get(&self, key: String) -> Result<Option<Vec<u8>>, GimError> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(GimError::Storage {
                reason: "keystore locked".to_string(),
            });
        }
        Ok(self.secrets.lock().unwrap().get(&key).cloned())
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

impl HubListListener for Recorder<Vec<HubInfo>> {
    fn on_update(&self, hubs: Vec<HubInfo>) {
        self.0.lock().unwrap().push(hubs);
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
        assert_eq!(session.handle, "");
        assert_eq!(client.user_id(), Some(session.user_id.clone()));
        client.claim_handle(handle.to_string()).await.unwrap();
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

/// A time zone without DST, implemented on the "native" side.
struct Offset(i32);

impl LocalTimeZone for Offset {
    fn utc_offset_secs(&self, _at_ms: i64) -> i32 {
        self.0
    }
}

fn separators(items: &[TimelineItem]) -> Vec<u64> {
    items
        .iter()
        .filter_map(|item| match item {
            TimelineItem::DateSeparator { day_start_ms } => Some(*day_start_ms),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn date_separators_follow_the_local_time_zone() {
    const HOUR_MS: i64 = 3_600_000;
    const DAY_MS: i64 = 24 * HOUR_MS;
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let chat = alice
        .client
        .create_group_chat("Crew".to_string(), Vec::new())
        .await
        .unwrap();
    alice
        .client
        .send_text(chat.clone(), "late".to_string(), None)
        .await
        .unwrap();
    let (timeline, _handle) = alice.timeline(&chat).await;
    let items = timeline
        .wait("the message", |items| messages(items).len() == 1)
        .await;
    let sent = messages(&items)[0].sent_at_ms as i64;
    // UTC by default.
    let utc_day = sent - sent.rem_euclid(DAY_MS);
    assert_eq!(separators(&items), vec![utc_day as u64]);

    // +2 h re-buckets the open timeline.
    alice
        .client
        .set_local_time_zone(Some(Arc::new(Offset(7200))));
    let local = sent + 2 * HOUR_MS;
    let plus_two_day = local - local.rem_euclid(DAY_MS) - 2 * HOUR_MS;
    timeline
        .wait("the +2 h day", |items| {
            separators(items) == vec![plus_two_day as u64]
        })
        .await;

    // The clock is not under test control: pick the offset that makes the
    // message 00:54 local (between +1 h and +25 h, so its UTC day is the
    // day before).
    let mut offset = (54 * 60_000 - sent).rem_euclid(DAY_MS);
    if offset < HOUR_MS {
        offset += DAY_MS;
    }
    // Whole seconds, rounded up: 00:54:00.xxx local.
    let offset = (offset + 999) / 1000 * 1000;
    let local = sent + offset;
    let local_midnight = local - local.rem_euclid(DAY_MS) - offset;
    assert_ne!(local_midnight, utc_day);
    alice
        .client
        .set_local_time_zone(Some(Arc::new(Offset((offset / 1000) as i32))));
    let items = timeline
        .wait("the 00:54 local day", |items| {
            separators(items) == vec![local_midnight as u64]
        })
        .await;
    assert!(matches!(items[0], TimelineItem::DateSeparator { .. }));
    assert_eq!(messages(&items).len(), 1);

    // A timeline opened later uses the zone too.
    let (later, _later_handle) = alice.timeline(&chat).await;
    later
        .wait("the 00:54 local day", |items| {
            separators(items) == vec![local_midnight as u64]
        })
        .await;

    // None is UTC again.
    alice.client.set_local_time_zone(None);
    timeline
        .wait("the UTC day", |items| {
            separators(items) == vec![utc_day as u64]
        })
        .await;
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
    alice.client.stop_typing(chat.clone()).await.unwrap();
    typing
        .wait("alice stopped typing", |users| users.is_empty())
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

fn chat_state(rows: &[ChatSummary], chat: &str) -> Option<ChatState> {
    rows.iter().find(|c| c.chat_id == chat).map(|c| c.state)
}

/// `(change, user_id, actor_user_id)` of the membership items.
fn membership(items: &[TimelineItem]) -> Vec<(MembershipChangeKind, String, Option<String>)> {
    items
        .iter()
        .filter_map(|item| match item {
            TimelineItem::MembershipChange {
                change,
                user_id,
                actor_user_id,
                ..
            } => Some((*change, user_id.clone(), actor_user_id.clone())),
            _ => None,
        })
        .collect()
}

fn not_active(result: Result<impl std::fmt::Debug, GimError>, chat: &str, state: ChatState) {
    match result {
        Err(GimError::ChatNotActive { chat_id, state: s }) if chat_id == chat && s == state => {}
        other => panic!("expected ChatNotActive {state:?}, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_and_left_chat_state() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let carol = User::register(&transport, "carol", "Carol").await;
    let chat = alice
        .client
        .create_group_chat("Crew".to_string(), vec![carol.user_id.clone()])
        .await
        .unwrap();
    let (list, list_handle) = carol.chat_list().await;
    carol.client.start_sync().await.unwrap();
    list.wait("the chat, active", |rows| {
        chat_state(rows, &chat) == Some(ChatState::Active)
    })
    .await;
    let (timeline, _timeline_handle) = carol.timeline(&chat).await;
    let added = (
        MembershipChangeKind::Added,
        carol.user_id.clone(),
        Some(alice.user_id.clone()),
    );
    timeline
        .wait("carol added by alice", |items| {
            membership(items).contains(&added)
        })
        .await;

    // Alice does not sync yet: the leave stays pending.
    carol.client.leave_chat(chat.clone()).await.unwrap();
    list.wait("leaving", |rows| {
        chat_state(rows, &chat) == Some(ChatState::Leaving)
    })
    .await;
    assert_eq!(
        carol.client.chat_state(chat.clone()).await.unwrap(),
        ChatState::Leaving
    );
    not_active(
        carol
            .client
            .send_text(chat.clone(), "hi".to_string(), None)
            .await,
        &chat,
        ChatState::Leaving,
    );

    // After a restart the state is there before any call fails.
    carol.client.stop_sync().await.unwrap();
    drop((list_handle, list, _timeline_handle, timeline));
    let hooks = carol.hooks.clone();
    drop(carol.client);
    let restarted = open(&transport, &hooks).await;
    assert_eq!(
        restarted.chat_state(chat.clone()).await.unwrap(),
        ChatState::Leaving
    );
    let opened = restarted.timeline(chat.clone()).await.unwrap();
    assert_eq!(opened.chat_state(), Some(ChatState::Leaving));
    let list = Mirror::new();
    let _list_handle = restarted.chat_list(list.clone()).await.unwrap();
    list.wait("leaving after restart", |rows| {
        chat_state(rows, &chat) == Some(ChatState::Leaving)
    })
    .await;
    let timeline = Mirror::new();
    let _timeline_handle = opened.add_listener(timeline.clone()).await;

    // Alice commits the leave; Carol applies it.
    alice.client.start_sync().await.unwrap();
    restarted.start_sync().await.unwrap();
    list.wait("left", |rows| {
        chat_state(rows, &chat) == Some(ChatState::Left)
    })
    .await;
    let left = (
        MembershipChangeKind::Left,
        carol.user_id.clone(),
        Some(carol.user_id.clone()),
    );
    timeline
        .wait("own left", |items| membership(items).last() == Some(&left))
        .await;
    assert_eq!(opened.chat_state(), Some(ChatState::Left));
    not_active(
        restarted
            .send_text(chat.clone(), "hi".to_string(), None)
            .await,
        &chat,
        ChatState::Left,
    );
    not_active(
        restarted.leave_chat(chat.clone()).await,
        &chat,
        ChatState::Left,
    );
    let (alice_timeline, _alice_handle) = alice.timeline(&chat).await;
    alice_timeline
        .wait("carol left", |items| {
            membership(items).last() == Some(&left)
        })
        .await;
    assert!(matches!(
        restarted.chat_state("unknown".to_string()).await,
        Err(GimError::NotFound { .. })
    ));
    for client in [&alice.client, &restarted] {
        client.stop_sync().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_leave_keeps_the_chat_active() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let carol = User::register(&transport, "carol", "Carol").await;
    let chat = alice
        .client
        .create_group_chat("Crew".to_string(), vec![carol.user_id.clone()])
        .await
        .unwrap();
    let (list, _list_handle) = carol.chat_list().await;
    carol.client.start_sync().await.unwrap();
    list.wait("the chat", |rows| chat_state(rows, &chat).is_some())
        .await;
    carol.client.stop_sync().await.unwrap();

    // Removed hub-side, unseen by Carol: the hub refuses the leave (403).
    let session = carol.client.session().await.unwrap().unwrap();
    let device = gim_common::DeviceRef::parse(&session.user_id, &session.device_id).unwrap();
    let group = gim_common::GroupId::new(chat.clone()).unwrap();
    transport.service().remove_member(&group, &device).unwrap();
    assert!(matches!(
        carol.client.leave_chat(chat.clone()).await,
        Err(GimError::Server { status: 403, .. })
    ));
    assert_eq!(
        carol.client.chat_state(chat.clone()).await.unwrap(),
        ChatState::Active
    );
    list.wait("active again", |rows| {
        chat_state(rows, &chat) == Some(ChatState::Active)
    })
    .await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_registration_processing_and_sign_out() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let registration = PushRegistration {
        provider: "fcm".to_string(),
        token: "fcm-token".to_string(),
        app_id: Some("im.g.apps".to_string()),
        sandbox: None,
        p256dh: None,
        auth: None,
    };
    let bad = PushRegistration {
        provider: String::new(),
        ..registration.clone()
    };
    assert!(matches!(
        alice.client.register_push(bad).await,
        Err(GimError::InvalidInput { .. })
    ));
    alice.client.register_push(registration).await.unwrap();
    let requests = transport.push_requests();
    assert!(
        matches!(requests.as_slice(), [(_, Some(r))] if r.token == "fcm-token"),
        "{requests:?}"
    );

    assert!(matches!(
        alice.client.process_push("not json".to_string()).await,
        Err(GimError::InvalidInput { .. })
    ));
    let content = alice
        .client
        .process_push(r#"{"v":1,"type":"wake","collapse_id":"c1"}"#.to_string())
        .await
        .unwrap();
    assert_eq!(content.kind, NotificationKind::Generic);
    assert!(!content.should_display);
    assert_eq!(content.collapse_id.as_deref(), Some("c1"));

    // Signing out removes the registration from the hub first.
    alice.client.sign_out().await.unwrap();
    let requests = transport.push_requests();
    assert!(matches!(requests.last(), Some((_, None))), "{requests:?}");
    assert!(alice.hooks.secrets.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handles_and_display_name() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let bob = User::register(&transport, "bob", "Bob").await;
    let session = alice.client.session().await.unwrap().unwrap();
    assert_eq!(session.handle, "alice");

    alice
        .client
        .set_display_name("Alice B.".to_string())
        .await
        .unwrap();
    let session = alice.client.session().await.unwrap().unwrap();
    assert_eq!(session.display_name, "Alice B.");
    assert!(matches!(
        alice.client.set_display_name(String::new()).await,
        Err(GimError::InvalidInput { .. })
    ));

    alice.client.release_handle().await.unwrap();
    assert_eq!(alice.client.session().await.unwrap().unwrap().handle, "");
    assert_eq!(bob.client.find_user("alice".to_string()).await, Ok(None));
    assert!(matches!(
        alice.client.release_handle().await,
        Err(GimError::InvalidInput { .. })
    ));
    alice
        .client
        .claim_handle("skipper".to_string())
        .await
        .unwrap();
    let found = bob
        .client
        .find_user("skipper".to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.user_id, alice.user_id);
    assert!(matches!(
        bob.client.claim_handle("skipper".to_string()).await,
        Err(GimError::Server { status: 409, .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_device_and_manage_devices() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let bob = User::register(&transport, "bob", "Bob").await;

    let tablet_hooks = MemoryHooks::new();
    let tablet = open(&transport, &tablet_hooks).await;
    assert_eq!(tablet.user_id(), None);
    let link = tablet.start_link(vec!["hub.example".to_string()]).unwrap();
    assert!(!link.qr_string().is_empty());
    let approval = alice.client.approve_link(link.qr_string()).await.unwrap();
    let sas = tablet.wait_link(link.clone()).await.unwrap();
    assert_eq!(sas, approval.sas());
    assert_eq!(sas.len(), 7);
    // A link session accepts a single bundle.
    assert!(matches!(
        tablet.wait_link(link).await,
        Err(GimError::InvalidInput { .. })
    ));
    tablet.confirm_link(true).await.unwrap();
    alice
        .client
        .confirm_approval(approval.clone(), true)
        .await
        .unwrap();
    assert_eq!(tablet.user_id(), Some(alice.user_id.clone()));
    let tablet_device = tablet.session().await.unwrap().unwrap().device_id;
    assert_eq!(approval.device_id(), tablet_device);

    let devices = alice.client.devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().all(|d| !d.revoked && d.created_at_ms > 0));
    let current: Vec<_> = devices.iter().filter(|d| d.is_current).collect();
    assert_eq!(current.len(), 1);
    assert_ne!(current[0].device_id, tablet_device);
    let seen_by_bob = bob
        .client
        .user_devices(alice.user_id.clone())
        .await
        .unwrap();
    assert_eq!(seen_by_bob.len(), 2);
    assert!(seen_by_bob.iter().all(|d| !d.is_current));

    assert!(matches!(
        alice
            .client
            .revoke_device(current[0].device_id.clone())
            .await,
        Err(GimError::InvalidInput { .. })
    ));
    alice
        .client
        .revoke_device(tablet_device.clone())
        .await
        .unwrap();
    let devices = alice.client.devices().await.unwrap();
    let revoked = devices
        .iter()
        .find(|d| d.device_id == tablet_device)
        .unwrap();
    assert!(revoked.revoked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_link_wipes_the_new_device() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let hooks = MemoryHooks::new();
    let phone = open(&transport, &hooks).await;
    let link = phone.start_link(vec!["hub.example".to_string()]).unwrap();
    let approval = alice.client.approve_link(link.qr_string()).await.unwrap();
    phone.wait_link(link).await.unwrap();
    phone.confirm_link(false).await.unwrap();
    assert_eq!(phone.session().await, Err(GimError::NotRegistered));
    assert!(hooks.secrets.lock().unwrap().is_empty());
    assert!(!hooks.path("gim.sqlite3").exists());

    alice
        .client
        .confirm_approval(approval.clone(), false)
        .await
        .unwrap();
    let devices = alice.client.devices().await.unwrap();
    assert!(devices
        .iter()
        .any(|d| d.device_id == approval.device_id() && d.revoked));
    assert!(matches!(
        alice.client.confirm_link(true).await,
        Err(GimError::InvalidInput { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_from_recovery_code() {
    let transport = FakeTransport::new();
    let hooks = MemoryHooks::new();
    let lost = open(&transport, &hooks).await;
    let code = lost.create_identity("Alice".to_string()).await.unwrap();
    let user_id = lost.user_id().unwrap();
    drop(lost);

    let fresh = open(&transport, &MemoryHooks::new()).await;
    assert!(matches!(
        fresh
            .restore_from_recovery(user_id.clone(), "not a code".to_string(), true)
            .await,
        Err(GimError::InvalidInput { .. })
    ));
    fresh
        .restore_from_recovery(user_id.clone(), code.clone(), true)
        .await
        .unwrap();
    assert_eq!(fresh.user_id(), Some(user_id.clone()));
    // The lost device is listed as revoked.
    let devices = fresh.devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|d| d.is_current && !d.revoked));
    assert!(devices.iter().any(|d| !d.is_current && d.revoked));
    assert!(matches!(
        fresh.restore_from_recovery(user_id, code, true).await,
        Err(GimError::InvalidInput { .. })
    ));
}

#[tokio::test]
async fn locked_keystore_fails_without_replacing_the_database_key() {
    let transport = FakeTransport::new();
    let hooks = MemoryHooks::new();
    let client = open(&transport, &hooks).await;
    assert!(!client.local_state_reset());
    drop(client);
    let keys = hooks.secrets.lock().unwrap().clone();

    hooks.locked.store(true, Ordering::SeqCst);
    let config = ClientConfig {
        server_url: "https://gim.example.org".to_string(),
    };
    let result = create_client_with_fake_transport(config, hooks.clone(), transport.clone()).await;
    assert!(matches!(result, Err(GimError::Storage { .. })));
    assert_eq!(*hooks.secrets.lock().unwrap(), keys);

    hooks.locked.store(false, Ordering::SeqCst);
    let reopened = open(&transport, &hooks).await;
    assert!(!reopened.local_state_reset());
}

#[tokio::test]
async fn lost_database_key_reports_a_local_state_reset() {
    let transport = FakeTransport::new();
    let hooks = MemoryHooks::new();
    let client = open(&transport, &hooks).await;
    client.create_identity("Alice".to_string()).await.unwrap();
    drop(client);

    // The keystore lost the database key, e.g. after a device restore.
    hooks.secrets.lock().unwrap().remove("gim.db_key.v1");
    let reopened = open(&transport, &hooks).await;
    assert!(reopened.local_state_reset());
    assert_eq!(reopened.session().await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_hub_management() {
    let transport = FakeTransport::new();
    let alice = User::register(&transport, "alice", "Alice").await;
    let home = transport.service().hub_id().to_string();
    let hubs = alice.client.hubs().await.unwrap();
    assert_eq!(
        hubs,
        [HubInfo {
            hub_id: home.clone(),
            url: None,
            state: HubState::Verified,
            priority: 0,
            is_primary: true,
            is_home: true,
            signed_in: true,
        }]
    );

    let updates = Recorder::new();
    let _handle = alice.client.hub_list(updates.clone()).await.unwrap();
    updates.wait("the current hubs", |h| *h == hubs).await;
    // The sync loop refreshes the registry.
    alice.client.start_sync().await.unwrap();
    for _ in 0..500 {
        if updates.0.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(updates.0.lock().unwrap().len() >= 2);
    assert_eq!(updates.0.lock().unwrap().last(), Some(&hubs));
    alice.client.stop_sync().await.unwrap();

    assert_eq!(
        alice.client.remove_hub(home.clone(), true).await,
        Err(GimError::HomeHub {
            hub_id: home.clone()
        })
    );
    assert!(matches!(
        alice.client.remove_hub("hnotlisted".into(), true).await,
        Err(GimError::InvalidInput { .. })
    ));
    alice.client.set_primary_hub(home).await.unwrap();
    assert!(matches!(
        alice.client.set_primary_hub("hnotlisted".into()).await,
        Err(GimError::InvalidInput { .. })
    ));
    assert!(matches!(
        alice.client.add_hub("ftp://hub.example.org".into()).await,
        Err(GimError::InvalidInput { .. })
    ));
    // Nothing listens on the discard port.
    assert!(matches!(
        alice.client.add_hub("http://127.0.0.1:9".into()).await,
        Err(GimError::Network { .. })
    ));
    assert_eq!(alice.client.hubs().await.unwrap(), hubs);
}
