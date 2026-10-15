//! Send API: messages, edits, deletes, reactions, read receipts and typing
//! notifications.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gim_base::model::{ChatKind, PendingMedia};
use gim_base::{new_message_id, BaseClient, BaseError, StateStore};
use gim_common::{now_ms, GroupId, MessageId};
use gim_crypto::encrypt_envelope;
use gim_proto::envelope::{Content, Envelope};

use crate::client::new_client_id;
use crate::{Client, ClientError, Result};

/// Minimum interval between two "typing" notifications of a chat while the
/// user keeps typing.
pub const TYPING_INTERVAL: Duration = Duration::from_secs(3);

/// Last typing notification sent for a chat.
pub(crate) struct TypingState {
    active: bool,
    sent_at: Instant,
}

impl<S: StateStore + 'static> Client<S> {
    pub async fn send_text(
        &self,
        group_id: &GroupId,
        body: impl Into<String>,
        reply_to: Option<MessageId>,
    ) -> Result<MessageId> {
        let content = Content::Text { body: body.into() };
        self.send_with_reply(group_id, content, reply_to).await
    }

    /// Sends a file: the outbox encrypts it to a temporary file under the
    /// data directory, uploads the blob and then posts the message. The
    /// file must stay readable until the message is sent.
    pub async fn send_media(
        &self,
        group_id: &GroupId,
        path: impl AsRef<Path>,
        mime: impl Into<String>,
        caption: Option<String>,
        reply_to: Option<MessageId>,
    ) -> Result<MessageId> {
        let session = self.require_session()?;
        let local_path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| ClientError::InvalidInput("path is not UTF-8".into()))?
            .to_string();
        let media = PendingMedia {
            local_path,
            mime: mime.into(),
            caption,
        };
        let (gid, base) = (group_id.clone(), BaseClient::new(session.device));
        let (message_id, changes) = self
            .run(move |store, _| base.enqueue_media(store, &gid, media, reply_to, now_ms()))
            .await?;
        self.emit(&changes);
        self.flush_outbox().await?;
        Ok(message_id)
    }

    /// Renames the group chat and/or replaces its avatar (`None` leaves a
    /// field unchanged) and shares it with the members in a group info
    /// message. The avatar file (path, MIME type) is encrypted and uploaded
    /// before this returns.
    pub async fn set_group_info(
        &self,
        group_id: &GroupId,
        name: Option<String>,
        avatar: Option<(PathBuf, String)>,
    ) -> Result<MessageId> {
        self.require_session()?;
        if name.is_none() && avatar.is_none() {
            return Err(ClientError::InvalidInput("nothing to change".into()));
        }
        let gid = group_id.clone();
        let chat = self
            .run(move |store, _| {
                store
                    .chat(&gid)?
                    .ok_or_else(|| BaseError::NotFound(format!("chat {gid}")))
            })
            .await?;
        if chat.kind != ChatKind::Group {
            return Err(ClientError::InvalidInput(
                "direct chats have no group info".into(),
            ));
        }
        let avatar = match avatar {
            Some((path, mime)) => {
                let local_path = path
                    .to_str()
                    .ok_or_else(|| ClientError::InvalidInput("path is not UTF-8".into()))?
                    .to_string();
                let pending = PendingMedia {
                    local_path,
                    mime,
                    caption: None,
                };
                Some(self.upload_media(&new_message_id()?, pending).await?)
            }
            None => None,
        };
        self.send(group_id, Content::GroupInfo { name, avatar })
            .await
    }

    /// Replaces the text of an own message, or the caption of own media.
    pub async fn edit(
        &self,
        group_id: &GroupId,
        target: &MessageId,
        new_body: impl Into<String>,
    ) -> Result<MessageId> {
        let content = Content::Edit {
            target: target.clone(),
            new_body: new_body.into(),
        };
        self.send(group_id, content).await
    }

    pub async fn delete(&self, group_id: &GroupId, target: &MessageId) -> Result<MessageId> {
        let content = Content::Delete {
            target: target.clone(),
        };
        self.send(group_id, content).await
    }

    pub async fn react(
        &self,
        group_id: &GroupId,
        target: &MessageId,
        emoji: impl Into<String>,
    ) -> Result<MessageId> {
        self.reaction(group_id, target, emoji.into(), false).await
    }

    pub async fn unreact(
        &self,
        group_id: &GroupId,
        target: &MessageId,
        emoji: impl Into<String>,
    ) -> Result<MessageId> {
        self.reaction(group_id, target, emoji.into(), true).await
    }

    /// Marks the chat read and sends a read receipt for the other users'
    /// new messages.
    pub async fn mark_read(&self, group_id: &GroupId) -> Result<()> {
        let session = self.require_session()?;
        let (gid, base) = (group_id.clone(), BaseClient::new(session.device));
        let (receipt, changes) = self
            .run(move |store, _| base.mark_read(store, &gid, now_ms()))
            .await?;
        self.emit(&changes);
        if receipt.is_some() {
            self.flush_outbox().await?;
        }
        Ok(())
    }

    /// Tells the chat whether the user is typing. Sent directly, never
    /// queued; while active, repeated calls send at most one notification
    /// per [`TYPING_INTERVAL`], and an inactive call only follows an
    /// active one.
    pub async fn set_typing(&self, group_id: &GroupId, active: bool) -> Result<()> {
        let session = self.require_session()?;
        {
            let mut typing = self.inner.typing.lock().unwrap_or_else(|e| e.into_inner());
            let due = match typing.get(group_id) {
                Some(last) if active => !last.active || last.sent_at.elapsed() >= TYPING_INTERVAL,
                Some(last) => last.active,
                None => active,
            };
            if !due {
                return Ok(());
            }
            typing.insert(
                group_id.clone(),
                TypingState {
                    active,
                    sent_at: Instant::now(),
                },
            );
        }
        let sent = self.post_typing(&session, group_id, active).await;
        if sent.is_err() {
            // Let the next call try again.
            self.inner
                .typing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(group_id);
        }
        sent
    }

    pub(crate) async fn send_with_reply(
        &self,
        group_id: &GroupId,
        content: Content,
        reply_to: Option<MessageId>,
    ) -> Result<MessageId> {
        let session = self.require_session()?;
        let (gid, base) = (group_id.clone(), BaseClient::new(session.device));
        let (message_id, changes) = self
            .run(move |store, _| base.enqueue(store, &gid, content, reply_to, now_ms()))
            .await?;
        self.emit(&changes);
        self.flush_outbox().await?;
        Ok(message_id)
    }

    async fn reaction(
        &self,
        group_id: &GroupId,
        target: &MessageId,
        emoji: String,
        remove: bool,
    ) -> Result<MessageId> {
        let content = Content::Reaction {
            target: target.clone(),
            emoji,
            remove,
        };
        self.send(group_id, content).await
    }

    async fn post_typing(
        &self,
        session: &crate::Session,
        group_id: &GroupId,
        active: bool,
    ) -> Result<()> {
        let _guard = self.inner.group_lock.lock().await;
        self.settle_commit(session, group_id).await?;
        let envelope = Envelope::new(new_message_id()?, now_ms(), Content::Typing { active });
        let gid = group_id.clone();
        let payload = self
            .run(move |store, engine| {
                if store.chat(&gid)?.is_none() {
                    return Err(BaseError::NotFound(format!("chat {gid}")));
                }
                store.transaction(|txn| Ok(encrypt_envelope(engine, &*txn, &gid, &envelope)?))
            })
            .await?;
        let client_id = new_client_id()?;
        let seq = self
            .authed(|t| {
                let (client_id, payload) = (client_id.clone(), payload.clone());
                async move {
                    self.inner
                        .transport
                        .post_message(&t, group_id, client_id, payload)
                        .await
                }
            })
            .await?;
        self.mark_applied(group_id, seq).await
    }
}
