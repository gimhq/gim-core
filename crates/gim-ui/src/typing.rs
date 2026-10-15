//! Who is typing in one chat.

use std::collections::HashMap;
use std::time::Duration;

use eyeball::SharedObservable;
use futures_core::Stream;
use gim_base::model::StateChange;
use gim_base::StateStore;
use gim_common::{GroupId, UserId};
use gim_sdk::Client;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::listener::{own_user, recv_batch, Received};
use crate::Result;

/// A user stops being shown as typing this long after their last typing
/// event.
pub const TYPING_TIMEOUT: Duration = Duration::from_secs(6);

/// Aggregates the typing events of one chat. This user's own devices are
/// ignored. Dropping it ends its streams.
pub struct TypingNotifications {
    users: SharedObservable<Vec<UserId>>,
    task: JoinHandle<()>,
}

impl TypingNotifications {
    pub fn new<S: StateStore + 'static>(client: &Client<S>, group_id: GroupId) -> Result<Self> {
        let own = own_user(client)?;
        let mut changes = client.subscribe_changes();
        let users = SharedObservable::new(Vec::new());
        let observable = users.clone();
        let task = tokio::spawn(async move {
            let mut expiry: HashMap<UserId, Instant> = HashMap::new();
            loop {
                let next = expiry.values().min().copied();
                tokio::select! {
                    received = recv_batch(&mut changes) => match received {
                        Received::Changes(changes) => {
                            for change in changes {
                                match change {
                                    StateChange::Typing { group_id: g, user_id, active }
                                        if g == group_id && user_id != own =>
                                    {
                                        if active {
                                            expiry.insert(user_id, Instant::now() + TYPING_TIMEOUT);
                                        } else {
                                            expiry.remove(&user_id);
                                        }
                                    }
                                    // A message ends the sender's typing.
                                    StateChange::MessageUpserted(message)
                                        if message.group_id == group_id
                                            && message.seq.is_some() =>
                                    {
                                        expiry.remove(&message.sender.user_id);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        // Typing is transient; nothing to rebuild.
                        Received::Lagged => {}
                        Received::Closed => break,
                    },
                    _ = tokio::time::sleep_until(next.unwrap_or_else(Instant::now)), if next.is_some() => {}
                }
                let now = Instant::now();
                expiry.retain(|_, at| *at > now);
                let mut typing: Vec<UserId> = expiry.keys().cloned().collect();
                typing.sort();
                observable.set_if_not_eq(typing);
            }
        });
        Ok(Self { users, task })
    }

    /// The users typing now, sorted, and every later change of that list.
    pub fn subscribe(&self) -> (Vec<UserId>, impl Stream<Item = Vec<UserId>>) {
        let subscriber = self.users.subscribe();
        (subscriber.get(), subscriber)
    }
}

impl Drop for TypingNotifications {
    fn drop(&mut self) {
        self.task.abort();
    }
}
