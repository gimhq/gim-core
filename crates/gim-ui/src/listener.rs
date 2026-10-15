//! Plumbing shared by the services: batched change reception and store work
//! off the async runtime.

use std::sync::{Arc, Mutex, MutexGuard};

use gim_base::model::StateChange;
use gim_base::BaseError;
use gim_sdk::{Client, ClientError};
use tokio::sync::broadcast::{self, error::RecvError, error::TryRecvError};

use crate::{Result, UiError};

pub(crate) enum Received {
    Changes(Vec<StateChange>),
    /// Changes were dropped; the receiver must rebuild from the store.
    Lagged,
    Closed,
}

/// Waits for the next change and takes every change already queued behind
/// it, so one client operation becomes one diff batch. Cancel safe.
pub(crate) async fn recv_batch(rx: &mut broadcast::Receiver<StateChange>) -> Received {
    let mut changes = match rx.recv().await {
        Ok(change) => vec![change],
        Err(RecvError::Lagged(_)) => return Received::Lagged,
        Err(RecvError::Closed) => return Received::Closed,
    };
    loop {
        match rx.try_recv() {
            Ok(change) => changes.push(change),
            Err(TryRecvError::Lagged(_)) => return Received::Lagged,
            Err(TryRecvError::Empty | TryRecvError::Closed) => return Received::Changes(changes),
        }
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn own_user<S: gim_base::StateStore + 'static>(
    client: &Client<S>,
) -> Result<gim_common::UserId> {
    client
        .session()
        .map(|s| s.device.user_id)
        .ok_or(UiError::Client(ClientError::NotLoggedIn))
}

/// Runs `f` on the service state with the store, on a blocking thread.
pub(crate) async fn with_state<S, T, R, F>(store: &Arc<S>, state: &Arc<Mutex<T>>, f: F) -> Result<R>
where
    S: ?Sized + Send + Sync + 'static,
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(&S, &mut T) -> Result<R, BaseError> + Send + 'static,
{
    let (store, state) = (store.clone(), state.clone());
    tokio::task::spawn_blocking(move || f(&store, &mut lock(&state)))
        .await
        .map_err(|e| UiError::Task(e.to_string()))?
        .map_err(Into::into)
}
