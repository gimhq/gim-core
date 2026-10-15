//! The timeline of one chat: a window of its latest messages, grown with
//! [`Timeline::paginate_backwards`] (from the store, then from the server
//! history), with date separators and membership changes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use eyeball_im::{ObservableVector, Vector, VectorDiff};
use futures_core::Stream;
use futures_util::future::BoxFuture;
use futures_util::StreamExt;
use gim_base::model::{Chat, ChatKind, MembershipEvent, Message, StateChange};
use gim_base::{BaseError, StateReader, StateStore};
use gim_common::{GroupId, MessageId, UserId};
use gim_sdk::{Backfill, Client, BACKFILL_PAGE};
use tokio::task::JoinHandle;

use crate::diff;
use crate::items::{
    membership_change_kind, message_content, preview_text, profile, reaction_groups, send_state,
    MessageItem, ReplyPreview, TimelineItem, UserProfile,
};
use crate::listener::{lock, own_user, recv_batch, with_state, Received};
use crate::Result;

/// Messages loaded when a timeline opens.
pub const DEFAULT_PAGE_SIZE: usize = 50;

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// The local time zone that date separators split calendar days in.
pub trait TimeZone: Send + Sync {
    /// Offset from UTC in effect at `at_ms` (Unix milliseconds), DST
    /// included. Asked once per UTC hour of the items' timestamps (at the
    /// start of that hour) and cached until the zone is replaced.
    fn utc_offset_secs(&self, at_ms: i64) -> i32;
}

/// A time zone without DST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedOffset(pub i32);

impl TimeZone for FixedOffset {
    fn utc_offset_secs(&self, _at_ms: i64) -> i32 {
        self.0
    }
}

#[derive(Clone)]
pub struct TimelineOptions {
    /// Offset of the local time zone from UTC, used when `time_zone` is
    /// `None`; date separators split local calendar days.
    pub utc_offset_secs: i32,
    /// The local time zone, with an offset per timestamp (DST-safe).
    /// Overrides `utc_offset_secs`.
    pub time_zone: Option<Arc<dyn TimeZone>>,
    /// Messages loaded when the timeline opens.
    pub initial_page_size: usize,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        Self {
            utc_offset_secs: 0,
            time_zone: None,
            initial_page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl std::fmt::Debug for TimelineOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimelineOptions")
            .field("utc_offset_secs", &self.utc_offset_secs)
            .field("time_zone", &self.time_zone.as_ref().map(|_| ".."))
            .field("initial_page_size", &self.initial_page_size)
            .finish()
    }
}

type Reader = dyn StateReader + Send + Sync;

/// [`Client::backfill_history`] of the timeline's chat.
type Backfiller =
    Box<dyn Fn(u64, u32) -> BoxFuture<'static, gim_sdk::Result<Backfill>> + Send + Sync>;

/// Keeps the timeline of one chat in sync with the client's state changes.
/// Edits, deletes, reactions and receipts update their message in place.
/// Dropping the timeline ends its streams.
pub struct Timeline {
    group_id: GroupId,
    store: Arc<Reader>,
    state: Arc<Mutex<State>>,
    backfill: Backfiller,
    task: JoinHandle<()>,
}

impl Timeline {
    /// Opens the timeline with [`TimelineOptions::default`] (UTC days).
    pub async fn new<S: StateStore + 'static>(
        client: &Client<S>,
        group_id: GroupId,
    ) -> Result<Self> {
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
        let zone = options
            .time_zone
            .unwrap_or_else(|| Arc::new(FixedOffset(options.utc_offset_secs)));
        let state = Arc::new(Mutex::new(State {
            group_id: group_id.clone(),
            own,
            days: LocalDays::new(zone),
            page_size: options.initial_page_size,
            chat: None,
            messages: Vec::new(),
            rendered: HashMap::new(),
            profiles: HashMap::new(),
            membership: Vec::new(),
            has_more: false,
            history_from: None,
            history_more: true,
            items: ObservableVector::new(),
            keys: Vec::new(),
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
                let _ = with_state(
                    &task_store,
                    &task_state,
                    move |store, state| match received {
                        Received::Changes(changes) => state
                            .apply(store, &changes)
                            .or_else(|_| state.reload(store)),
                        _ => state.reload(store),
                    },
                )
                .await;
            }
        });
        let (sdk, gid) = (client.clone(), group_id.clone());
        let backfill: Backfiller = Box::new(move |before_seq, limit| {
            let (sdk, gid) = (sdk.clone(), gid.clone());
            Box::pin(async move { sdk.backfill_history(&gid, before_seq, limit).await })
        });
        Ok(Self {
            group_id,
            store,
            state,
            backfill,
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

    /// Replaces the local time zone and moves the date separators to the
    /// new local days, delivered as diffs through the item streams (only
    /// separators are removed and inserted; messages stay). Call it when
    /// the system time zone changes.
    pub fn set_time_zone(&self, zone: Arc<dyn TimeZone>) {
        let mut state = lock(&self.state);
        state.days = LocalDays::new(zone);
        state.publish();
    }

    /// Loads up to `count` older messages (delivered through the item
    /// streams): from the store, and once it has nothing older, from the
    /// server history ([`Client::backfill_history`]), skipping what this
    /// device cannot decrypt. Returns whether older messages remain.
    pub async fn paginate_backwards(&self, count: u16) -> Result<bool> {
        let count = usize::from(count);
        let (mut loaded, store_more) = with_state(&self.store, &self.state, move |store, state| {
            state.paginate(store, count)
        })
        .await?;
        if store_more {
            return Ok(true);
        }
        loop {
            let before = with_state(&self.store, &self.state, |store, state| {
                state.history_before(store)
            })
            .await?;
            let Some(before) = before else {
                return Ok(false);
            };
            if loaded >= count {
                // Only whether there is more; no request.
                return Ok((self.backfill)(before, 0).await?.has_more);
            }
            let backfill = (self.backfill)(before, BACKFILL_PAGE).await?;
            let wanted = count - loaded;
            let (added, store_more) = with_state(&self.store, &self.state, move |store, state| {
                state.history_from = Some(backfill.from_seq);
                state.history_more = backfill.has_more;
                // The backfilled messages are older than the window.
                state.has_more = true;
                state.paginate(store, wanted)
            })
            .await?;
            loaded += added;
            if store_more {
                return Ok(true);
            }
            if !backfill.has_more {
                return Ok(false);
            }
        }
    }
}

impl Drop for Timeline {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum ItemKey {
    Day(u64),
    Message(MessageId),
    Membership(u64, UserId),
}

struct State {
    group_id: GroupId,
    own: UserId,
    days: LocalDays,
    page_size: usize,
    chat: Option<Chat>,
    /// Loaded messages in timeline order.
    messages: Vec<Message>,
    rendered: HashMap<MessageId, MessageItem>,
    profiles: HashMap<UserId, UserProfile>,
    /// All membership events of the chat, ascending.
    membership: Vec<MembershipEvent>,
    /// Whether the store has messages older than the loaded ones.
    has_more: bool,
    /// Lowest seq the server history was backfilled from.
    history_from: Option<u64>,
    /// Whether the server history may hold older readable messages.
    history_more: bool,
    items: ObservableVector<TimelineItem>,
    /// Keys of `items`.
    keys: Vec<ItemKey>,
}

impl State {
    /// Loads the latest `limit` messages and resets the items.
    fn load(&mut self, store: &Reader, limit: usize) -> Result<(), BaseError> {
        self.chat = store.chat(&self.group_id)?;
        let (messages, has_more) = self.fetch(store, None, limit)?;
        self.messages = messages;
        self.has_more = has_more;
        self.membership = store.membership_events(&self.group_id)?;
        self.rendered.clear();
        self.profiles.clear();
        self.render_where(store, |_| true)?;
        let (keys, items): (Vec<_>, Vec<_>) = self.build().into_iter().unzip();
        self.keys = keys;
        diff::reset(&mut self.items, items.into_iter().collect());
        Ok(())
    }

    /// Rebuilds the loaded window from the store.
    fn reload(&mut self, store: &Reader) -> Result<(), BaseError> {
        self.load(store, self.messages.len().max(self.page_size))
    }

    /// Loads up to `count` older messages from the store. Returns how many
    /// were added and whether the store has more.
    fn paginate(&mut self, store: &Reader, count: usize) -> Result<(usize, bool), BaseError> {
        if !self.has_more || count == 0 {
            return Ok((0, self.has_more));
        }
        // Everything loaded may be unsent: then page from the newest sent.
        let before = self.oldest_seq().unwrap_or(u64::MAX);
        let (older, has_more) = self.fetch(store, Some(before), count)?;
        let mut added = 0;
        for message in older {
            if self.position(&message.message_id).is_none() {
                self.messages.push(message);
                added += 1;
            }
        }
        self.has_more = has_more;
        self.messages
            .sort_by(|a, b| order_key(a).cmp(&order_key(b)));
        self.render_where(store, |_| false)?;
        self.publish();
        Ok((added, has_more))
    }

    /// The `before_seq` of the next server history backfill, if the server
    /// may have older messages: below the oldest loaded message, or below
    /// every applied seq when there is none.
    fn history_before(&self, store: &Reader) -> Result<Option<u64>, BaseError> {
        if !self.history_more {
            return Ok(None);
        }
        let below = match self.oldest_seq() {
            Some(oldest) => oldest,
            None => store.group_cursor(&self.group_id)?.contiguous_seq + 1,
        };
        let before = self.history_from.map_or(below, |from| from.min(below));
        Ok((before > 1).then_some(before))
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
                    // The kind decides whether membership changes show.
                    if self.chat.as_ref().map(|c| c.kind) != Some(chat.kind) {
                        changed = true;
                    }
                    self.chat = Some(chat.clone());
                }
                StateChange::ChatRemoved(group_id) if *group_id == self.group_id => {
                    self.messages.clear();
                    self.rendered.clear();
                    self.membership.clear();
                    self.has_more = false;
                    self.history_more = false;
                    changed = true;
                }
                StateChange::MembershipChanged(event) if event.group_id == self.group_id => {
                    let key = |e: &MembershipEvent| (e.seq, e.user_id.clone());
                    match self.membership.binary_search_by_key(&key(event), key) {
                        Ok(i) => self.membership[i] = event.clone(),
                        Err(i) => self.membership.insert(i, event.clone()),
                    }
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
        self.messages
            .sort_by(|a, b| order_key(a).cmp(&order_key(b)));
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

    /// Renders the messages matching `stale`, and those never rendered,
    /// and resolves the names of the users in membership events.
    fn render_where(
        &mut self,
        store: &Reader,
        stale: impl Fn(&Message) -> bool,
    ) -> Result<(), BaseError> {
        let users: Vec<UserId> = self.membership.iter().map(|e| e.user_id.clone()).collect();
        for user_id in &users {
            self.profile(store, user_id)?;
        }
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

    /// The items for the loaded messages and the membership events among
    /// them, in seq order (unsent messages last), with their keys: a date
    /// separator before the first item of each local day. An item whose
    /// clock is behind the one before it stays under that day, so
    /// separators only move forward. While older messages are not loaded,
    /// membership events older than the window are left out too; direct
    /// chats show none.
    fn build(&mut self) -> Vec<(ItemKey, TimelineItem)> {
        let lowest = match (self.has_more, self.oldest_seq()) {
            (true, Some(oldest)) => oldest,
            _ => 0,
        };
        // Direct chats only ever have their two users.
        let group = self
            .chat
            .as_ref()
            .is_some_and(|c| c.kind == ChatKind::Group);
        let mut events = self
            .membership
            .iter()
            .filter(|e| group && e.seq >= lowest)
            .peekable();
        // (time, key, item) in seq order.
        let mut entries = Vec::with_capacity(self.messages.len() + self.membership.len());
        let event_entry = |event: &MembershipEvent| {
            let user_name = self
                .profiles
                .get(&event.user_id)
                .map_or_else(|| event.user_id.to_string(), |p| p.display_name.clone());
            let item = TimelineItem::MembershipChange {
                user_name,
                change: membership_change_kind(event.kind),
                at_ms: event.at_ms,
            };
            (
                event.at_ms,
                ItemKey::Membership(event.seq, event.user_id.clone()),
                item,
            )
        };
        for message in &self.messages {
            let seq = message.seq.unwrap_or(u64::MAX);
            while let Some(event) = events.next_if(|e| e.seq < seq) {
                entries.push(event_entry(event));
            }
            if let Some(item) = self.rendered.get(&message.message_id) {
                entries.push((
                    message.sent_at_ms,
                    ItemKey::Message(message.message_id.clone()),
                    TimelineItem::Message(item.clone()),
                ));
            }
        }
        entries.extend(events.map(event_entry));

        let mut items = Vec::with_capacity(entries.len() + 1);
        let mut last_day = None;
        for (at_ms, key, item) in entries {
            let day = self.days.day(at_ms as i64);
            if last_day.is_none_or(|last| day > last) {
                last_day = Some(day);
                let day_start_ms = self.days.day_start_ms(day).max(0) as u64;
                items.push((
                    ItemKey::Day(day_start_ms),
                    TimelineItem::DateSeparator { day_start_ms },
                ));
            }
            items.push((key, item));
        }
        items
    }

    fn publish(&mut self) {
        let (keys, items): (Vec<_>, Vec<_>) = self.build().into_iter().unzip();
        let old_keys = std::mem::replace(&mut self.keys, keys);
        diff::update_keyed(&mut self.items, old_keys, &items, &self.keys);
    }
}

/// Local calendar days of a [`TimeZone`], with its offsets cached per UTC
/// hour.
struct LocalDays {
    zone: Arc<dyn TimeZone>,
    /// Offset in ms by UTC hour.
    offsets: HashMap<i64, i64>,
}

impl LocalDays {
    fn new(zone: Arc<dyn TimeZone>) -> Self {
        Self {
            zone,
            offsets: HashMap::new(),
        }
    }

    fn offset_ms(&mut self, at_ms: i64) -> i64 {
        let hour = at_ms.div_euclid(HOUR_MS);
        let zone = &self.zone;
        *self
            .offsets
            .entry(hour)
            .or_insert_with(|| i64::from(zone.utc_offset_secs(hour * HOUR_MS)) * 1000)
    }

    /// The local day number of `at_ms`.
    fn day(&mut self, at_ms: i64) -> i64 {
        (at_ms + self.offset_ms(at_ms)).div_euclid(DAY_MS)
    }

    /// When local `day` starts, in UTC ms: local midnight with the offset
    /// in effect at midnight, which differs from the one later that day on
    /// a DST transition day.
    fn day_start_ms(&mut self, day: i64) -> i64 {
        let midnight = day * DAY_MS;
        let guess = midnight - self.offset_ms(midnight);
        midnight - self.offset_ms(guess)
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
