//! The chat list: every chat, most recently updated first.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use eyeball_im::{ObservableVector, Vector, VectorDiff};
use futures_core::Stream;
use futures_util::StreamExt;
use gim_base::model::StateChange;
use gim_base::{BaseError, StateReader, StateStore};
use gim_common::{GroupId, UserId};
use gim_sdk::Client;
use tokio::task::JoinHandle;

use crate::diff;
use crate::items::{chat_list_item, ChatListItem};
use crate::listener::{lock, own_user, recv_batch, with_state, Received};
use crate::Result;

/// Keeps the chat list in sync with the client's state changes. Dropping
/// the service ends its streams.
pub struct ChatListService {
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

struct State {
    own: UserId,
    items: ObservableVector<ChatListItem>,
}

impl ChatListService {
    /// Loads the chat list from the store and starts following the client.
    pub async fn new<S: StateStore + 'static>(client: &Client<S>) -> Result<Self> {
        let own = own_user(client)?;
        // Subscribe first: a change racing the initial load is applied again,
        // which is harmless since items are rebuilt from the store.
        let mut changes = client.subscribe_changes();
        let state = Arc::new(Mutex::new(State {
            own,
            items: ObservableVector::new(),
        }));
        let store = client.store().clone();
        with_state(&store, &state, |store, state| state.reload(store)).await?;
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let received = recv_batch(&mut changes).await;
                if matches!(received, Received::Closed) {
                    break;
                }
                // A failed update is repaired by rebuilding from the store;
                // if that fails too, the next change tries again.
                let _ = with_state(&store, &task_state, move |store, state| match received {
                    Received::Changes(changes) => state
                        .apply(store, &changes)
                        .or_else(|_| state.reload(store)),
                    _ => state.reload(store),
                })
                .await;
            }
        });
        Ok(Self { state, task })
    }

    /// The current list and its diffs from then on. A `Reset` means the list
    /// was rebuilt from the store.
    pub fn entries(
        &self,
    ) -> (
        Vector<ChatListItem>,
        impl Stream<Item = Vec<VectorDiff<ChatListItem>>>,
    ) {
        let (values, stream) = lock(&self.state)
            .items
            .subscribe()
            .into_values_and_batched_stream();
        (values, stream.map(diff::collapse_reset))
    }
}

impl Drop for ChatListService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl State {
    fn reload<R: StateReader + ?Sized>(&mut self, store: &R) -> Result<(), BaseError> {
        let mut items = store
            .chats()?
            .iter()
            .map(|chat| chat_list_item(store, &self.own, chat))
            .collect::<Result<Vec<_>, _>>()?;
        sort(&mut items);
        diff::reset(&mut self.items, items.into_iter().collect());
        Ok(())
    }

    fn apply<R: StateReader + ?Sized>(
        &mut self,
        store: &R,
        changes: &[StateChange],
    ) -> Result<(), BaseError> {
        let touched: BTreeSet<&GroupId> = changes
            .iter()
            .filter_map(|change| match change {
                StateChange::ChatUpserted(chat) => Some(&chat.group_id),
                StateChange::ChatRemoved(group_id) => Some(group_id),
                // The last message preview may have changed.
                StateChange::MessageUpserted(message) => Some(&message.group_id),
                StateChange::MessageRemoved { group_id, .. } => Some(group_id),
                StateChange::Typing { .. } | StateChange::KeyPackagesLow => None,
            })
            .collect();
        if touched.is_empty() {
            return Ok(());
        }
        let mut items: Vec<ChatListItem> = self
            .items
            .iter()
            .filter(|item| !touched.contains(&item.chat_id))
            .cloned()
            .collect();
        for group_id in touched {
            if let Some(chat) = store.chat(group_id)? {
                items.push(chat_list_item(store, &self.own, &chat)?);
            }
        }
        sort(&mut items);
        diff::update(&mut self.items, &items, |item| item.chat_id.clone());
        Ok(())
    }
}

fn sort(items: &mut [ChatListItem]) {
    items.sort_by(|a, b| {
        (Reverse(a.updated_at_ms), &a.chat_id).cmp(&(Reverse(b.updated_at_ms), &b.chat_id))
    });
}
