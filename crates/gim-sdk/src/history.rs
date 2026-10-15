//! History backfill: messages older than the stored timeline, read from the
//! group's hub history by seq windows.

use gim_base::model::{MembershipChangeKind, StateChange};
use gim_base::{BaseClient, StateReader, StateStore, StoreError};
use gim_common::{GroupId, UserId};

use crate::{Client, Result};

/// Result of [`Client::backfill_history`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backfill {
    /// Messages added to or updated in the store.
    pub inserted: usize,
    /// Lowest seq the window covered; the `before_seq` of the next call.
    pub from_seq: u64,
    /// Whether the hub history may hold older messages this device can
    /// read.
    pub has_more: bool,
}

impl<S: StateStore + 'static> Client<S> {
    /// Reads the up to `limit` seqs of the group's hub history below
    /// `before_seq` and applies them through gim-base (see
    /// [`BaseClient::apply_history`]): messages already stored are kept,
    /// and messages this device cannot decrypt are skipped. Seqs at or
    /// below the Welcome that last added this user are never read: nothing
    /// before it was encrypted for this device.
    pub async fn backfill_history(
        &self,
        group_id: &GroupId,
        before_seq: u64,
        limit: u32,
    ) -> Result<Backfill> {
        let session = self.require_session()?;
        let (gid, own) = (group_id.clone(), session.device.user_id.clone());
        let floor = self
            .run(move |store, _| Ok(history_floor(store, &gid, &own)?))
            .await?;
        let end = before_seq.saturating_sub(1);
        if end <= floor || limit == 0 {
            return Ok(Backfill {
                inserted: 0,
                from_seq: before_seq,
                has_more: end > floor,
            });
        }
        let after = end.saturating_sub(u64::from(limit)).max(floor);
        let Some(history) = self
            .group_history(&session, group_id, after, Some(end))
            .await?
        else {
            // Not readable (any more): nothing older can be loaded.
            return Ok(Backfill {
                inserted: 0,
                from_seq: before_seq,
                has_more: false,
            });
        };
        let window: Vec<_> = history
            .into_iter()
            .filter(|m| m.seq > after && m.seq <= end)
            .collect();
        let base = BaseClient::new(session.device.clone());
        let changes = {
            let _guard = self.inner.group_lock.lock().await;
            self.run(move |store, engine| base.apply_history(store, engine, window))
                .await?
        };
        self.emit(&changes);
        let senders = changes
            .iter()
            .filter_map(|change| match change {
                StateChange::MessageUpserted(m) => Some(m.sender.user_id.clone()),
                _ => None,
            })
            .collect();
        self.resolve_users(&session, senders).await;
        let inserted = changes
            .iter()
            .filter(|c| matches!(c, StateChange::MessageUpserted(_)))
            .count();
        Ok(Backfill {
            inserted,
            from_seq: after + 1,
            has_more: after > floor,
        })
    }
}

/// Seq of the Welcome that last added `own` to the group (0 for its
/// creator): the hub history at or below it is not readable.
fn history_floor<R: StateReader + ?Sized>(
    store: &R,
    group_id: &GroupId,
    own: &UserId,
) -> std::result::Result<u64, StoreError> {
    Ok(store
        .membership_events(group_id)?
        .iter()
        .filter(|e| &e.user_id == own && e.kind == MembershipChangeKind::Added)
        .map(|e| e.seq)
        .max()
        .unwrap_or(0))
}
