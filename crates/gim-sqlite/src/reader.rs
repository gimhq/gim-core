//! [`StateReader`] over a connection; shared by the store (committed state)
//! and a transaction (its own uncommitted writes included).

use std::collections::BTreeSet;

use gim_base::model::{
    Chat, DepartedMember, GroupCursor, GroupMessage, HubRecord, HubState, KeyPackageRecord,
    MediaCacheEntry, MembershipChangeKind, MembershipEvent, Message, OutboxEntry, OutboxState,
    PendingCommit, PendingInvite, PendingLeave, UserInfo,
};
use gim_base::{StateReader, StoreError};
use gim_common::{DeviceRef, GroupId, MessageId, UserId};
use rusqlite::{params, Connection, Params, Row};

use crate::rows::{
    decode, ChatData, MessageData, OutboxData, ParkedData, PendingCommitData, PendingLeaveData,
};

type StoreResult<T> = Result<T, StoreError>;

pub(crate) struct Reader<'c>(pub &'c Connection);

const MESSAGE_COLUMNS: &str = "message_id, group_id, seq, sent_at_ms, data";
const OUTBOX_COLUMNS: &str = "message_id, group_id, state, next_attempt_at_ms, created_at_ms, data";

/// A query bound that fits SQLite's signed 64-bit integers.
pub(crate) fn bound(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn sql_limit(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(crate) fn sql_err(err: rusqlite::Error) -> StoreError {
    StoreError::new(err)
}

pub(crate) fn membership_kind_str(kind: MembershipChangeKind) -> &'static str {
    match kind {
        MembershipChangeKind::Added => "added",
        MembershipChangeKind::Removed => "removed",
        MembershipChangeKind::Left => "left",
    }
}

fn membership_kind(value: &str) -> StoreResult<MembershipChangeKind> {
    match value {
        "added" => Ok(MembershipChangeKind::Added),
        "removed" => Ok(MembershipChangeKind::Removed),
        "left" => Ok(MembershipChangeKind::Left),
        other => Err(StoreError::new(format!(
            "unknown membership kind '{other}'"
        ))),
    }
}

pub(crate) fn hub_state_str(state: HubState) -> &'static str {
    match state {
        HubState::Unverified => "unverified",
        HubState::Verified => "verified",
        HubState::Removed => "removed",
    }
}

fn hub_state(value: &str) -> StoreResult<HubState> {
    match value {
        "unverified" => Ok(HubState::Unverified),
        "verified" => Ok(HubState::Verified),
        "removed" => Ok(HubState::Removed),
        other => Err(StoreError::new(format!("unknown hub state '{other}'"))),
    }
}

fn user_id(value: String) -> StoreResult<UserId> {
    UserId::new(value).map_err(StoreError::new)
}

pub(crate) fn outbox_state_str(state: OutboxState) -> &'static str {
    match state {
        OutboxState::Pending => "pending",
        OutboxState::Failed => "failed",
    }
}

fn get<T: rusqlite::types::FromSql>(row: &Row<'_>, idx: usize) -> StoreResult<T> {
    row.get(idx).map_err(sql_err)
}

fn group_id(value: String) -> StoreResult<GroupId> {
    GroupId::new(value).map_err(StoreError::new)
}

fn message_id(value: String) -> StoreResult<MessageId> {
    MessageId::new(value).map_err(StoreError::new)
}

impl Reader<'_> {
    fn query<T>(
        &self,
        sql: &str,
        params: impl Params,
        mut map: impl FnMut(&Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<Vec<T>> {
        let mut stmt = self.0.prepare_cached(sql).map_err(sql_err)?;
        let mut rows = stmt.query(params).map_err(sql_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(sql_err)? {
            out.push(map(row)?);
        }
        Ok(out)
    }

    fn query_one<T>(
        &self,
        sql: &str,
        params: impl Params,
        map: impl FnMut(&Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<Option<T>> {
        Ok(self.query(sql, params, map)?.pop())
    }

    fn chats_where(&self, sql: &str, params: impl Params) -> StoreResult<Vec<Chat>> {
        self.query(sql, params, |row| {
            let data: ChatData = decode(&get::<Vec<u8>>(row, 2)?)?;
            Ok(Chat {
                group_id: group_id(get(row, 0)?)?,
                kind: data.kind.into(),
                name: data.name,
                avatar: data.avatar.map(TryInto::try_into).transpose()?,
                members: data.members.into_iter().map(Into::into).collect(),
                unread_count: data.unread_count,
                last_message_id: data.last_message_id,
                last_seq: data.last_seq,
                last_read_seq: data.last_read_seq,
                updated_at_ms: get(row, 1)?,
                membership: data.membership.into(),
            })
        })
    }

    fn messages_where(&self, sql: &str, params: impl Params) -> StoreResult<Vec<Message>> {
        self.query(sql, params, |row| {
            let data: MessageData = decode(&get::<Vec<u8>>(row, 4)?)?;
            Ok(Message {
                message_id: message_id(get(row, 0)?)?,
                group_id: group_id(get(row, 1)?)?,
                seq: get(row, 2)?,
                sender: data.sender,
                sent_at_ms: get(row, 3)?,
                content: data.content.try_into()?,
                reply_to: data.reply_to,
                edited: data.edited,
                deleted: data.deleted,
                reactions: data.reactions,
                send_state: data.send_state.map(Into::into),
                receipts: data.receipts.into_iter().collect(),
            })
        })
    }

    fn outbox_where(&self, sql: &str, params: impl Params) -> StoreResult<Vec<OutboxEntry>> {
        self.query(sql, params, |row| {
            let data: OutboxData = decode(&get::<Vec<u8>>(row, 5)?)?;
            let state = match get::<String>(row, 2)?.as_str() {
                "pending" => OutboxState::Pending,
                "failed" => OutboxState::Failed,
                other => return Err(StoreError::new(format!("unknown outbox state {other}"))),
            };
            Ok(OutboxEntry {
                message_id: message_id(get(row, 0)?)?,
                group_id: group_id(get(row, 1)?)?,
                kind: data.kind.try_into()?,
                state,
                attempts: data.attempts,
                next_attempt_at_ms: get(row, 3)?,
                last_error: data.last_error,
                prepared: data.prepared.map(Into::into),
                created_at_ms: get(row, 4)?,
            })
        })
    }

    fn pending_commits_where(
        &self,
        sql: &str,
        params: impl Params,
    ) -> StoreResult<Vec<PendingCommit>> {
        self.query(sql, params, |row| {
            let data: PendingCommitData = decode(&get::<Vec<u8>>(row, 1)?)?;
            Ok(data.into_model(group_id(get(row, 0)?)?))
        })
    }

    fn pending_leaves_where(
        &self,
        sql: &str,
        params: impl Params,
    ) -> StoreResult<Vec<PendingLeave>> {
        self.query(sql, params, |row| {
            let data: PendingLeaveData = decode(&get::<Vec<u8>>(row, 1)?)?;
            Ok(data.into_model(group_id(get(row, 0)?)?))
        })
    }

    fn media_where(&self, sql: &str, params: impl Params) -> StoreResult<Vec<MediaCacheEntry>> {
        self.query(sql, params, |row| {
            Ok(MediaCacheEntry {
                blob_id: get(row, 0)?,
                local_path: get(row, 1)?,
                size: get(row, 2)?,
                last_access_ms: get(row, 3)?,
            })
        })
    }
}

impl StateReader for Reader<'_> {
    fn chats(&self) -> StoreResult<Vec<Chat>> {
        self.chats_where(
            "SELECT group_id, updated_at_ms, data FROM chats \
             WHERE group_id NOT IN (SELECT group_id FROM self_groups) \
             ORDER BY updated_at_ms DESC, group_id",
            [],
        )
    }

    fn chat(&self, group_id: &GroupId) -> StoreResult<Option<Chat>> {
        Ok(self
            .chats_where(
                "SELECT group_id, updated_at_ms, data FROM chats WHERE group_id = ?1",
                [group_id.as_str()],
            )?
            .pop())
    }

    fn messages(
        &self,
        group_id: &GroupId,
        before_seq: Option<u64>,
        limit: usize,
    ) -> StoreResult<Vec<Message>> {
        // Newest first, then reversed into timeline order.
        let mut messages = match before_seq {
            None => self.messages_where(
                &format!(
                    "SELECT {MESSAGE_COLUMNS} FROM messages WHERE group_id = ?1 \
                     ORDER BY seq IS NULL DESC, seq DESC, sent_at_ms DESC, message_id DESC \
                     LIMIT ?2"
                ),
                params![group_id.as_str(), sql_limit(limit)],
            )?,
            Some(before) => self.messages_where(
                &format!(
                    "SELECT {MESSAGE_COLUMNS} FROM messages WHERE group_id = ?1 AND seq < ?2 \
                     ORDER BY seq DESC, sent_at_ms DESC, message_id DESC LIMIT ?3"
                ),
                params![group_id.as_str(), bound(before), sql_limit(limit)],
            )?,
        };
        messages.reverse();
        Ok(messages)
    }

    fn messages_after(&self, group_id: &GroupId, after_seq: u64) -> StoreResult<Vec<Message>> {
        self.messages_where(
            &format!(
                "SELECT {MESSAGE_COLUMNS} FROM messages WHERE group_id = ?1 AND seq > ?2 \
                 ORDER BY seq, sent_at_ms, message_id"
            ),
            params![group_id.as_str(), bound(after_seq)],
        )
    }

    fn message(&self, message_id: &MessageId) -> StoreResult<Option<Message>> {
        Ok(self
            .messages_where(
                &format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE message_id = ?1"),
                [message_id.as_str()],
            )?
            .pop())
    }

    fn outbox_entry(&self, message_id: &MessageId) -> StoreResult<Option<OutboxEntry>> {
        Ok(self
            .outbox_where(
                &format!("SELECT {OUTBOX_COLUMNS} FROM outbox WHERE message_id = ?1"),
                [message_id.as_str()],
            )?
            .pop())
    }

    fn outbox_entries(&self) -> StoreResult<Vec<OutboxEntry>> {
        self.outbox_where(
            &format!("SELECT {OUTBOX_COLUMNS} FROM outbox ORDER BY created_at_ms, message_id"),
            [],
        )
    }

    fn outbox_due(&self, now_ms: u64, limit: usize) -> StoreResult<Vec<OutboxEntry>> {
        self.outbox_where(
            &format!(
                "SELECT {OUTBOX_COLUMNS} FROM outbox \
                 WHERE state = ?1 AND next_attempt_at_ms <= ?2 \
                 ORDER BY created_at_ms, message_id LIMIT ?3"
            ),
            params![
                outbox_state_str(OutboxState::Pending),
                bound(now_ms),
                sql_limit(limit)
            ],
        )
    }

    fn global_cursor(&self) -> StoreResult<Option<u64>> {
        self.query_one(
            "SELECT global_cursor FROM sync_state WHERE id = 1",
            [],
            |row| get(row, 0),
        )
    }

    fn hub_cursor(&self, hub_id: &str) -> StoreResult<Option<u64>> {
        self.query_one(
            "SELECT cursor FROM hub_cursors WHERE hub_id = ?1",
            [hub_id],
            |row| get(row, 0),
        )
    }

    fn group_cursor(&self, group_id: &GroupId) -> StoreResult<GroupCursor> {
        Ok(self
            .query_one(
                "SELECT contiguous_seq, ahead FROM group_cursors WHERE group_id = ?1",
                [group_id.as_str()],
                |row| {
                    Ok(GroupCursor {
                        contiguous_seq: get(row, 0)?,
                        ahead: decode::<BTreeSet<u64>>(&get::<Vec<u8>>(row, 1)?)?,
                    })
                },
            )?
            .unwrap_or_default())
    }

    fn parked_messages(&self, group_id: &GroupId) -> StoreResult<Vec<GroupMessage>> {
        self.query(
            "SELECT seq, data FROM parked_messages WHERE group_id = ?1 ORDER BY seq",
            [group_id.as_str()],
            |row| {
                let data: ParkedData = decode(&get::<Vec<u8>>(row, 1)?)?;
                Ok(GroupMessage {
                    group_id: group_id.clone(),
                    seq: get(row, 0)?,
                    sender: data.sender,
                    kind: data.kind.into(),
                    payload: data.payload.into_vec(),
                    client_id: data.client_id,
                })
            },
        )
    }

    fn media(&self, blob_id: &str) -> StoreResult<Option<MediaCacheEntry>> {
        Ok(self
            .media_where(
                "SELECT blob_id, local_path, size, last_access_ms FROM media_cache \
                 WHERE blob_id = ?1",
                [blob_id],
            )?
            .pop())
    }

    fn media_entries(&self) -> StoreResult<Vec<MediaCacheEntry>> {
        self.media_where(
            "SELECT blob_id, local_path, size, last_access_ms FROM media_cache \
             ORDER BY last_access_ms, blob_id",
            [],
        )
    }

    fn user(&self, user_id: &UserId) -> StoreResult<Option<UserInfo>> {
        self.query_one(
            "SELECT user_id, handle, display_name FROM users WHERE user_id = ?1",
            [user_id.as_str()],
            |row| {
                Ok(UserInfo {
                    user_id: UserId::new(get::<String>(row, 0)?).map_err(StoreError::new)?,
                    handle: get(row, 1)?,
                    display_name: get(row, 2)?,
                })
            },
        )
    }

    fn pending_commit(&self, group_id: &GroupId) -> StoreResult<Option<PendingCommit>> {
        Ok(self
            .pending_commits_where(
                "SELECT group_id, data FROM pending_commits WHERE group_id = ?1",
                [group_id.as_str()],
            )?
            .pop())
    }

    fn pending_commits(&self) -> StoreResult<Vec<PendingCommit>> {
        self.pending_commits_where(
            "SELECT group_id, data FROM pending_commits ORDER BY group_id",
            [],
        )
    }

    fn pending_leave(&self, group_id: &GroupId) -> StoreResult<Option<PendingLeave>> {
        Ok(self
            .pending_leaves_where(
                "SELECT group_id, data FROM pending_leaves WHERE group_id = ?1",
                [group_id.as_str()],
            )?
            .pop())
    }

    fn pending_leaves(&self) -> StoreResult<Vec<PendingLeave>> {
        self.pending_leaves_where(
            "SELECT group_id, data FROM pending_leaves ORDER BY group_id",
            [],
        )
    }

    fn pending_invites(&self) -> StoreResult<Vec<PendingInvite>> {
        self.query(
            "SELECT group_id, user_id, created_at_ms, next_retry_at_ms, attempts \
             FROM pending_invites ORDER BY group_id, user_id",
            [],
            |row| {
                Ok(PendingInvite {
                    group_id: group_id(get(row, 0)?)?,
                    user_id: user_id(get(row, 1)?)?,
                    created_at_ms: get(row, 2)?,
                    next_retry_at_ms: get(row, 3)?,
                    attempts: get(row, 4)?,
                })
            },
        )
    }

    fn departed_members(&self) -> StoreResult<Vec<DepartedMember>> {
        self.query(
            "SELECT group_id, user_id, device_id FROM departed_members \
             ORDER BY group_id, user_id, device_id",
            [],
            |row| {
                Ok(DepartedMember {
                    group_id: group_id(get(row, 0)?)?,
                    device: DeviceRef::parse(&get::<String>(row, 1)?, &get::<String>(row, 2)?)
                        .map_err(StoreError::new)?,
                })
            },
        )
    }

    fn membership_events(&self, group_id: &GroupId) -> StoreResult<Vec<MembershipEvent>> {
        self.query(
            "SELECT group_id, seq, user_id, actor, kind, at_ms FROM membership_events \
             WHERE group_id = ?1 ORDER BY seq, user_id",
            [group_id.as_str()],
            |row| {
                Ok(MembershipEvent {
                    group_id: self::group_id(get(row, 0)?)?,
                    seq: get(row, 1)?,
                    user_id: user_id(get(row, 2)?)?,
                    actor: user_id(get(row, 3)?)?,
                    kind: membership_kind(&get::<String>(row, 4)?)?,
                    at_ms: get(row, 5)?,
                })
            },
        )
    }
    fn device_lists(&self) -> StoreResult<Vec<(UserId, Vec<u8>)>> {
        self.query(
            "SELECT user_id, data FROM device_lists ORDER BY user_id",
            [],
            |row| Ok((user_id(get(row, 0)?)?, get(row, 1)?)),
        )
    }
    fn self_groups(&self) -> StoreResult<Vec<GroupId>> {
        self.query("SELECT group_id FROM self_groups ORDER BY n", [], |row| {
            group_id(get(row, 0)?)
        })
    }

    fn hubs(&self) -> StoreResult<Vec<HubRecord>> {
        self.query(
            "SELECT hub_id, url, priority, verified_root_pubkey, last_seen_ms, state, url_shared \
             FROM hubs ORDER BY hub_id",
            [],
            |row| {
                Ok(HubRecord {
                    hub_id: get(row, 0)?,
                    url: get(row, 1)?,
                    priority: get(row, 2)?,
                    verified_root_pubkey: get(row, 3)?,
                    last_seen_ms: get(row, 4)?,
                    state: hub_state(&get::<String>(row, 5)?)?,
                    url_shared: get(row, 6)?,
                })
            },
        )
    }

    fn key_package_records(&self) -> StoreResult<Vec<KeyPackageRecord>> {
        self.query(
            "SELECT kp_ref, hub_id, last_resort, created_at_ms \
             FROM key_package_ledger ORDER BY kp_ref",
            [],
            |row| {
                Ok(KeyPackageRecord {
                    kp_ref: get(row, 0)?,
                    hub_id: get(row, 1)?,
                    last_resort: get(row, 2)?,
                    created_at_ms: get(row, 3)?,
                })
            },
        )
    }
}
