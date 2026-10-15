//! The timeline of one chat: a window of its latest messages, grown with
//! [`Timeline::paginate_backwards`], with date separators.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use eyeball_im::{ObservableVector, Vector, VectorDiff};
use futures_core::Stream;
use futures_util::StreamExt;
use gim_base::model::{Chat, Message, StateChange};
use gim_base::{BaseError, StateReader, StateStore};
use gim_common::{GroupId, MessageId, UserId};
use gim_sdk::Client;
use tokio::task::JoinHandle;

use crate::diff;
use crate::items::{
    message_content, preview_text, profile, reaction_groups, send_state, MessageItem,
    ReplyPreview, TimelineItem, UserProfile,
};
use crate::listener::{lock, own_user, recv_batch, with_state, Received};
use crate::Result;

/// Messages loaded when a timeline opens.
pub const DEFAULT_PAGE_SIZE: usize = 50;

const DAY_MS: i64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimelineOptions {
    /// Offset of the local time zone from UTC; date separators split local
    /// calendar days.
    pub utc_offset_secs: i32,
    /// Messages loaded when the timeline opens.
    pub initial_page_size: usize,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        Self {
            utc_offset_secs: 0,
            initial_page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

type Reader = dyn StateReader + Send + Sync;

/// Keeps the timeline of one chat in sync with the client's state changes.
/// Edits, deletes, reactions and receipts update their message in place.
/// Dropping the timeline ends its streams.
pub struct Timeline {
    group_id: GroupId,
    store: Arc<Reader>,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Timeline {
    /// Opens the timeline with [`TimelineOptions::default`] (UTC days).
    pub async fn new<S: StateStore + 'static>(client: &Client<S>, group_id: GroupId) -> Result<Self> {
        Self::with_options(client, group_id, TimelineOptions::default()).await
    }

    pub async fn with_options<S: StateStore + 'static>(
        client: &Client<S>,
        group_id: GroupId,
        options: TimelineOptions,
    ) -> Result<Self> {
        let own = own_user(client)?;
        let mut changes = client.subscribe_changes();
        let store: Arc<Reader> = client.store().clone();
        let state = Arc::new(Mutex::new(State {
            group_id: group_id.clone(),
            own,
            utc_offset_ms: i64::from(options.utc_offset_secs) * 1000,
            page_size: options.initial_page_size,
            chat: None,
            messages: Vec::new(),
            rendered: HashMap::new(),
            profiles: HashMap::new(),
            has_more: false,
            items: ObservableVector::new(),
        }));
        with_state(&store, &state, move |store, state| {
            state.load(store, options.initial_page_size)
        })
        .await?;
        let (task_store, task_state) = (store.clone(), state.clone());
        let task = tokio::spawn(async move {
            loop {
                let received = recv_batch(&mut changes).await;
                if matches!(received, Received::Closed) {
                    break;
                }
                let _ = with_state(&task_store, &task_state, move |store, state| {
                    match received {
                        Received::Changes(changes) => state
                            .apply(store, &changes)
                            .or_else(|_| state.reload(store)),
                        _ => state.reload(store),
                    }
                })
                .await;
            }
        });
        Ok(Self {
            group_id,
            store,
            state,
            task,
        })
    }

    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// The current items, oldest first, and their diffs from then on. A
    /// `Reset` means the timeline was rebuilt from the store.
    pub fn items(
        &self,
    ) -> (
        Vector<TimelineItem>,
        impl Stream<Item = Vec<VectorDiff<TimelineItem>>>,
    ) {
        let (values, stream) = lock(&self.state)
            .items
            .subscribe()
            .into_values_and_batched_stream();
        (values, stream.map(diff::collapse_reset))
    }

    /// Loads up to `count` older messages from the store (delivered through
    /// the item streams). Returns whether older messages remain.
    ///
    /// Only the store is paged: gim-sdk exposes no history backfill yet, so
    /// a hole in the stored history is skipped over.
    pub async fn paginate_backwards(&self, count: u16) -> Result<bool> {
        with_state(&self.store, &self.state, move |store, state| {
            state.paginate(store, usize::from(count))
        })
        .await
    }
}

impl Drop for Timeline {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(PartialEq, Eq, Hash)]
enum ItemKey {
    Day(u64),
    Message(MessageId),
    Membership(u64, String),
}

struct State {
    group_id: GroupId,
    own: UserId,
    utc_offset_ms: i64,
    page_size: usize,
    chat: Option<Chat>,
    /// Loaded messages in timeline order.
    messages: Vec<Message>,
    rendered: HashMap<MessageId, MessageItem>,
    profiles: HashMap<UserId, UserProfile>,
    /// Whether the store has messages older than the loaded ones.
    has_more: bool,
    items: ObservableVector<TimelineItem>,
}

impl State {
    /// Loads the latest `limit` messages and resets the items.
    fn load(&mut self, store: &Reader, limit: usize) -> Result<(), BaseError> {
        self.chat = store.chat(&self.group_id)?;
        let (messages, has_more) = self.fetch(store, None, limit)?;
        self.messages = messages;
        self.has_more = has_more;
        self.rendered.clear();
        self.profiles.clear();
        self.render_where(store, |_| true)?;
        let items = self.build();
        diff::reset(&mut self.items, items.into_iter().collect());
        Ok(())
    }

    /// Rebuilds the loaded window from the store.
    fn reload(&mut self, store: &Reader) -> Result<(), BaseError> {
        self.load(store, self.messages.len().max(self.page_size))
    }

    fn paginate(&mut self, store: &Reader, count: usize) -> Result<bool, BaseError> {
        if !self.has_more || count == 0 {
            return Ok(self.has_more);
        }
        // Everything loaded may be unsent: then page from the newest sent.
        let before = self.oldest_seq().unwrap_or(u64::MAX);
        let (older, has_more) = self.fetch(store, Some(before), count)?;
        for message in older {
            if self.position(&message.message_id).is_none() {
                self.messages.push(message);
            }
        }
        self.has_more = has_more;
        self.messages.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
        self.render_where(store, |_| false)?;
        self.publish();
        Ok(has_more)
    }

    fn apply(&mut self, store: &Reader, changes: &[StateChange]) -> Result<(), BaseError> {
        let mut touched: HashSet<MessageId> = HashSet::new();
        let mut rerender_all = false;
        let mut changed = false;
        for change in changes {
            match change {
                StateChange::ChatUpserted(chat) if chat.group_id == self.group_id => {
                    // Member names feed the sender profiles.
                    if self.chat.as_ref().map(|c| &c.members) != Some(&chat.members) {
                        self.profiles.clear();
                        rerender_all = true;
                    }
                    self.chat = Some(chat.clone());
                }
                StateChange::ChatRemoved(group_id) if *group_id == self.group_id => {
                    self.messages.clear();
                    self.rendered.clear();
                    self.has_more = false;
                    changed = true;
                }
                StateChange::MessageUpserted(message) if message.group_id == self.group_id => {
                    match self.position(&message.message_id) {
                        Some(i) => self.messages[i] = message.clone(),
                        None if self.in_window(message) => self.messages.push(message.clone()),
                        // Older than the window: it is loaded when paged in,
                        // but replies to it still need a fresh preview.
                        None => {}
                    }
                    touched.insert(message.message_id.clone());
                }
                StateChange::MessageRemoved {
                    group_id,
                    message_id,
                } if *group_id == self.group_id => {
                    self.messages.retain(|m| &m.message_id != message_id);
                    self.rendered.remove(message_id);
                    touched.insert(message_id.clone());
                }
                _ => {}
            }
        }
        if touched.is_empty() && !rerender_all && !changed {
            return Ok(());
        }
        self.messages.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
        self.render_where(store, |m| {
            rerender_all
                || touched.contains(&m.message_id)
                || m.reply_to.as_ref().is_some_and(|id| touched.contains(id))
        })?;
        self.publish();
        Ok(())
    }

    /// Up to `limit` messages before `before_seq`, and whether there are
    /// more.
    fn fetch(
        &self,
        store: &Reader,
        before_seq: Option<u64>,
        limit: usize,
    ) -> Result<(Vec<Message>, bool), BaseError> {
        let mut page = store.messages(&self.group_id, before_seq, limit.saturating_add(1))?;
        let has_more = page.len() > limit;
        if has_more {
            page.remove(0);
        }
        Ok((page, has_more))
    }

    fn oldest_seq(&self) -> Option<u64> {
        self.messages.iter().filter_map(|m| m.seq).min()
    }

    fn position(&self, message_id: &MessageId) -> Option<usize> {
        self.messages
            .iter()
            .position(|m| &m.message_id == message_id)
    }

    fn in_window(&self, message: &Message) -> bool {
        if !self.has_more {
            return true;
        }
        match (message.seq, self.oldest_seq()) {
            (Some(seq), Some(oldest)) => seq > oldest,
            _ => true,
        }
    }

    /// Renders the messages matching `stale`, and those never rendered.
    fn render_where(
        &mut self,
        store: &Reader,
        stale: impl Fn(&Message) -> bool,
    ) -> Result<(), BaseError> {
        for i in 0..self.messages.len() {
            let message = &self.messages[i];
            if self.rendered.contains_key(&message.message_id) && !stale(message) {
                continue;
            }
            let message = message.clone();
            let item = self.render(store, &message)?;
            self.rendered.insert(message.message_id, item);
        }
        Ok(())
    }

    fn render(&mut self, store: &Reader, message: &Message) -> Result<MessageItem, BaseError> {
        let reply_to = match &message.reply_to {
            Some(id) => {
                let target = match self.position(id) {
                    Some(i) => Some(self.messages[i].clone()),
                    None => store.message(id)?,
                };
                match target {
                    Some(target) => Some(ReplyPreview {
                        message_id: target.message_id.clone(),
                        sender_name: self.profile(store, &target.sender.user_id)?.display_name,
                        text: preview_text(&target),
                    }),
                    None => None,
                }
            }
            None => None,
        };
        Ok(MessageItem {
            message_id: message.message_id.clone(),
            chat_id: message.group_id.clone(),
            sender: self.profile(store, &message.sender.user_id)?,
            is_own: message.sender.user_id == self.own,
            sent_at_ms: message.sent_at_ms,
            content: message_content(message),
            reply_to,
            reactions: reaction_groups(message, &self.own),
            edited: message.edited,
            send_state: send_state(store, message)?,
        })
    }

    fn profile(&mut self, store: &Reader, user_id: &UserId) -> Result<UserProfile, BaseError> {
        if let Some(profile) = self.profiles.get(user_id) {
            return Ok(profile.clone());
        }
        let profile = profile(store, self.chat.as_ref(), user_id)?;
        self.profiles.insert(user_id.clone(), profile.clone());
        Ok(profile)
    }

    /// The items for the loaded messages: a date separator before the first
    /// message of each local day. A message whose clock is behind the one
    /// before it stays under that day, so separators only move forward.
    fn build(&self) -> Vec<TimelineItem> {
        let mut items = Vec::with_capacity(self.messages.len() + 1);
        let mut last_day = None;
        for message in &self.messages {
            let local = message.sent_at_ms as i64 + self.utc_offset_ms;
            let day = local.div_euclid(DAY_MS);
            if last_day.is_none_or(|last| day > last) {
                last_day = Some(day);
                let day_start_ms = (day * DAY_MS - self.utc_offset_ms).max(0) as u64;
                items.push(TimelineItem::DateSeparator { day_start_ms });
            }
            if let Some(item) = self.rendered.get(&message.message_id) {
                items.push(TimelineItem::Message(item.clone()));
            }
        }
        items
    }

    fn publish(&mut self) {
        let items = self.build();
        diff::update(&mut self.items, &items, |item| match item {
            TimelineItem::Message(m) => ItemKey::Message(m.message_id.clone()),
            TimelineItem::DateSeparator { day_start_ms } => ItemKey::Day(*day_start_ms),
            TimelineItem::MembershipChange {
                user_name, at_ms, ..
            } => ItemKey::Membership(*at_ms, user_name.clone()),
        });
    }
}

/// The store's timeline order: by seq, unsent messages last.
fn order_key(message: &Message) -> (u64, u64, &MessageId) {
    (
        message.seq.unwrap_or(u64::MAX),
        message.sent_at_ms,
        &message.message_id,
    )
}
