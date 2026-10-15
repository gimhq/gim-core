//! [`StateReader`] over a connection; shared by the store (committed state)
//! and a transaction (its own uncommitted writes included).

use std::collections::BTreeSet;

use gim_base::model::{
    Chat, GroupCursor, GroupMessage, MediaCacheEntry, Message, OutboxEntry, OutboxState, UserInfo,
};
use gim_base::{StateReader, StoreError};
use gim_common::{GroupId, MessageId, UserId};
use rusqlite::{params, Connection, Params, Row};

use crate::rows::{decode, ChatData, MessageData, OutboxData, ParkedData};

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
}
