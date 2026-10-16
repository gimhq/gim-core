//! Push (contract `push.md`): the device's push registration on every
//! listed hub, and [`Client::process_push`], which turns a pushed payload
//! into the content of a notification.
//!
//! The hub never talks to a push platform: it posts a signed webhook to an
//! external push server, which owns APNs, FCM and the rest. The client only
//! stores its opaque registration on its hubs (`PUT /v2/push/registration`)
//! and parses what arrives. A push is a wake-up hint: pushes may be
//! coalesced, dropped or duplicated, and the event stream stays the source
//! of truth.
//!
//! Registration: [`Client::register_push`] stores the registration in
//! [`crate::SecretStorage`] ([`PUSH_REGISTRATION_SECRET_KEY`]) and puts it
//! on every verified hub this device can reach. A hub where that failed is
//! retried by the sync loop, which also puts it on a hub whenever this
//! device signs in there again (a new hub, a renewal after a 401, a new
//! enrollment) and on every (re)connect of a hub's event loop until it
//! succeeded in this run. With multi-homing only the primary hub pushes
//! (hub-side gate); duplicates from several hubs share the `collapse_id`.
//!
//! [`Client::process_push`] does one bounded unit of work: it applies the
//! pushed message (fetched by `from_seq`), joins the pushed
//! Welcome, catches up one group, or reads one page of events, always
//! through the same apply path as sync, so a message applied from a push is
//! skipped when the stream delivers it (and the other way round, per
//! `(gid, seq)`). It never moves event cursors, never commits, never tops
//! up KeyPackages and never downloads media: the app's sync does all that.
//!
//! The inline `mls_message` of a push is ignored. The push server and the
//! platform only relay the payload, and nothing in an MLS ciphertext binds
//! it to the hub-assigned seq; decrypting it would consume its ratchet
//! secret, and a failure would mark the seq applied, so a relay could
//! suppress or replay messages. The message is always fetched from the
//! hub, the same copy the stream delivers.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Duration;

use gim_base::model::{
    Chat, ChatKind, GroupCursor, GroupMessage, IncomingEvent, Membership, MembershipChangeKind,
    Message, MessageContent, MessageKind, StateChange,
};
use gim_base::{BaseError, StateReader, StateStore};
use gim_common::{now_ms, GroupId, MessageId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::Session;
use crate::routing::HubTarget;
use crate::sync::{Fetched, HubLink};
use crate::transport::{HubEvent, TransportError};
use crate::{Client, ClientError, Result, BACKFILL_PAGE};

/// [`crate::SecretStorage`] key of the device's [`PushRegistration`], as
/// JSON.
pub const PUSH_REGISTRATION_SECRET_KEY: &str = "gim.push_registration.v1";
/// Default time budget of [`Client::process_push`]; an iOS Notification
/// Service Extension has about 30 s.
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(15);
/// Body of a notification whose content is unknown (not decryptable, not
/// fetched in time, minimal mode with nothing new).
pub const GENERIC_BODY: &str = "New message";
/// Messages of the pushed group read before applying, to tell a new
/// reaction from other changes of an earlier message.
const SNAPSHOT_MESSAGES: usize = 100;
/// A pushed seq further than this past the group's applied history is not
/// caught up from a push (the stream backfills it).
const MAX_CATCH_UP: u64 = BACKFILL_PAGE as u64;

/// The device's push registration (contract `push.md` §1). Every field is
/// opaque to the hub, which passes it to the push server.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistration {
    /// Push platform name for the push server (`apns`, `fcm`,
    /// `unifiedpush`, ...): 1-64 characters of `a-z 0-9 . _ -`. `log` is
    /// the hub's test provider.
    pub provider: String,
    /// Platform token: 1-4096 bytes without control characters.
    pub token: String,
    /// App identifier (e.g. a bundle ID): 1-255 characters of
    /// `A-Z a-z 0-9 . - _ :`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Platform sandbox flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<bool>,
    /// Opaque key for the push server (e.g. a Web Push `p256dh`): 1-256
    /// characters of base64url, padding optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p256dh: Option<String>,
    /// Opaque secret for the push server (e.g. a Web Push `auth`), like
    /// `p256dh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

impl std::fmt::Debug for PushRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRegistration")
            .field("provider", &self.provider)
            .field("app_id", &self.app_id)
            .field("sandbox", &self.sandbox)
            .finish_non_exhaustive()
    }
}

impl PushRegistration {
    /// Checks the shape rules of `push.md` §1, as the hub does;
    /// [`ClientError::InvalidInput`] naming the first bad field.
    pub fn validate(&self) -> Result<()> {
        let invalid = |field: &str, rule: &str| {
            Err(ClientError::InvalidInput(format!(
                "push registration {field}: {rule}"
            )))
        };
        let provider = &self.provider;
        if !(1..=64).contains(&provider.len())
            || !provider
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
        {
            return invalid("provider", "1-64 characters of a-z 0-9 . _ -");
        }
        if !(1..=4096).contains(&self.token.len()) || self.token.chars().any(char::is_control) {
            return invalid("token", "1-4096 bytes without control characters");
        }
        if let Some(app_id) = &self.app_id {
            if !(1..=255).contains(&app_id.len())
                || !app_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
            {
                return invalid("app_id", "1-255 characters of A-Z a-z 0-9 . - _ :");
            }
        }
        for (field, value) in [("p256dh", &self.p256dh), ("auth", &self.auth)] {
            if value.as_deref().is_some_and(|v| !is_base64url(v)) {
                return invalid(field, "1-256 characters of base64url");
            }
        }
        Ok(())
    }
}

/// 1-256 characters of base64url, with optional `=` padding.
fn is_base64url(value: &str) -> bool {
    let data = value.trim_end_matches('=');
    let padding = value.len() - data.len();
    (1..=256).contains(&value.len())
        && !data.is_empty()
        && padding <= 2
        && data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// What a notification is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationKind {
    /// A text or media message (also the silent edit or delete of one).
    Message,
    /// A reaction to a message.
    Reaction,
    /// This device joined a chat (a Welcome).
    Invite,
    /// A member was added to or removed from a chat.
    Membership,
    /// Unknown content: not decryptable or not fetched in time, or nothing
    /// to show.
    Generic,
}

/// The content of a notification, from [`Client::process_push`].
///
/// When the push cannot be decrypted or processed in time, the content is
/// generic: [`NotificationKind::Generic`] with the body [`GENERIC_BODY`]
/// and `should_display` set (never an error that drops the notification);
/// the chat is named if the push names one this device knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationContent {
    pub chat_id: Option<GroupId>,
    /// Group name, or the other user's name for a direct chat.
    pub chat_title: Option<String>,
    pub sender_user_id: Option<UserId>,
    pub sender_display_name: Option<String>,
    /// Text preview: the text, the media caption, `Photo` or
    /// `File: <name>`; `reacted <emoji>` for a reaction.
    pub body: String,
    /// The message (or the reacted-to message), if known.
    pub message_id: Option<MessageId>,
    /// The payload's `collapse_id`: platforms collapse notifications with
    /// the same one (the same message pushed by several hubs).
    pub collapse_id: Option<String>,
    pub kind: NotificationKind,
    /// `false`: show nothing (own messages, edits, deletes, receipts,
    /// membership events, something the stream already showed as read).
    pub should_display: bool,
    /// Unix milliseconds: when the message was sent, or now.
    pub timestamp_ms: u64,
}

/// Which hubs hold the current registration, in this run.
#[derive(Debug, Default)]
pub(crate) struct PushState {
    /// `None` is the home hub.
    registered: HashSet<Option<String>>,
}

/// A parsed push payload (contract `push.md` §3).
#[derive(Debug, Clone)]
struct Push {
    kind: PushKind,
    collapse_id: Option<String>,
}

#[derive(Debug, Clone)]
enum PushKind {
    Message {
        group_id: GroupId,
        seq: u64,
    },
    Welcome {
        group_id: GroupId,
        seq: u64,
    },
    Membership {
        group_id: GroupId,
        seq: u64,
    },
    /// Minimal mode, an unknown type or version, or fields missing.
    Wake,
}

impl Push {
    /// [`ClientError::InvalidInput`] unless `payload` is a JSON object.
    /// Unknown fields are ignored; a known type without its fields is read
    /// as a wake-up.
    fn parse(payload: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(payload)
            .map_err(|e| ClientError::InvalidInput(format!("push payload: {e}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| ClientError::InvalidInput("push payload is not a JSON object".into()))?;
        let text = |key: &str| object.get(key).and_then(Value::as_str);
        let target = || {
            let group_id = GroupId::new(text("gid")?).ok()?;
            Some((group_id, object.get("seq")?.as_u64()?))
        };
        let version = object.get("v").and_then(Value::as_u64);
        let kind = match (version, text("type")) {
            (Some(1), Some("message")) => {
                target().map(|(group_id, seq)| PushKind::Message { group_id, seq })
            }
            (Some(1), Some("welcome")) => {
                target().map(|(group_id, seq)| PushKind::Welcome { group_id, seq })
            }
            (Some(1), Some("group.member_added" | "group.member_removed")) => {
                target().map(|(group_id, seq)| PushKind::Membership { group_id, seq })
            }
            _ => None,
        };
        Ok(Self {
            kind: kind.unwrap_or(PushKind::Wake),
            collapse_id: text("collapse_id").map(str::to_string),
        })
    }

    fn group_id(&self) -> Option<&GroupId> {
        match &self.kind {
            PushKind::Message { group_id, .. }
            | PushKind::Welcome { group_id, .. }
            | PushKind::Membership { group_id, .. } => Some(group_id),
            PushKind::Wake => None,
        }
    }
}

/// Plain-text rendering of a message for a notification.
fn preview(message: &Message) -> String {
    let media = |mime: &str, file_name: Option<&str>, caption: Option<&str>| match (
        caption.filter(|c| !c.is_empty()),
        file_name,
    ) {
        (Some(caption), _) => caption.to_string(),
        (None, _) if mime.starts_with("image/") => "Photo".to_string(),
        (None, Some(name)) => format!("File: {name}"),
        (None, None) => "File".to_string(),
    };
    match &message.content {
        MessageContent::Text { body } => body.clone(),
        MessageContent::Media {
            media: info,
            caption,
        } => media(&info.mime, info.file_name.as_deref(), caption.as_deref()),
        MessageContent::PendingMedia(pending) => {
            media(&pending.mime, None, pending.caption.as_deref())
        }
    }
}

/// The user's name: directory cache, else the chat's member list, else the
/// user id.
fn user_name<R: StateReader + ?Sized>(
    store: &R,
    chat: Option<&Chat>,
    user_id: &UserId,
) -> Result<String, BaseError> {
    if let Some(user) = store.user(user_id)?.filter(|u| !u.display_name.is_empty()) {
        return Ok(user.display_name);
    }
    let member = chat.and_then(|chat| {
        chat.members
            .iter()
            .filter(|m| &m.device.user_id == user_id)
            .find_map(|m| m.display_name.clone())
    });
    Ok(member.unwrap_or_else(|| user_id.to_string()))
}

/// The chat's title: its name, or the other users' names.
fn chat_title<R: StateReader + ?Sized>(
    store: &R,
    own: Option<&UserId>,
    chat: &Chat,
) -> Result<String, BaseError> {
    let users: BTreeSet<&UserId> = chat
        .members
        .iter()
        .map(|m| &m.device.user_id)
        .filter(|u| Some(*u) != own)
        .collect();
    let mut others = Vec::with_capacity(users.len());
    for user_id in users {
        others.push(user_name(store, Some(chat), user_id)?);
    }
    Ok(match (chat.kind, &chat.name) {
        (ChatKind::Direct, _) if !others.is_empty() => others[0].clone(),
        (_, Some(name)) => name.clone(),
        (_, None) => others.join(", "),
    })
}

/// Builds notification contents from the store.
struct Describe<'a, R: ?Sized> {
    store: &'a R,
    /// The signed-in user, if any.
    own: Option<&'a UserId>,
    collapse_id: Option<String>,
}

impl<R: StateReader + ?Sized> Describe<'_, R> {
    fn base(
        &self,
        group_id: Option<&GroupId>,
        kind: NotificationKind,
        should_display: bool,
    ) -> Result<NotificationContent, BaseError> {
        let chat = match group_id {
            Some(group_id) => self.store.chat(group_id)?,
            None => None,
        };
        Ok(NotificationContent {
            chat_id: group_id.cloned(),
            chat_title: chat
                .as_ref()
                .map(|chat| chat_title(self.store, self.own, chat))
                .transpose()?,
            sender_user_id: None,
            sender_display_name: None,
            body: GENERIC_BODY.to_string(),
            message_id: None,
            collapse_id: self.collapse_id.clone(),
            kind,
            should_display,
            timestamp_ms: now_ms(),
        })
    }

    fn sender(
        &self,
        mut content: NotificationContent,
        user_id: &UserId,
    ) -> Result<NotificationContent, BaseError> {
        let chat = match &content.chat_id {
            Some(group_id) => self.store.chat(group_id)?,
            None => None,
        };
        content.sender_display_name = Some(user_name(self.store, chat.as_ref(), user_id)?);
        content.sender_user_id = Some(user_id.clone());
        Ok(content)
    }

    /// A text or media message; shown unless own, deleted or read.
    fn message(&self, message: &Message) -> Result<NotificationContent, BaseError> {
        let read = self
            .store
            .chat(&message.group_id)?
            .is_some_and(|chat| message.seq.is_some_and(|seq| seq <= chat.last_read_seq));
        let display = Some(&message.sender.user_id) != self.own && !message.deleted && !read;
        let mut content = self.base(Some(&message.group_id), NotificationKind::Message, display)?;
        content.body = preview(message);
        content.message_id = Some(message.message_id.clone());
        content.timestamp_ms = message.sent_at_ms;
        self.sender(content, &message.sender.user_id)
    }

    /// `reactor` reacted with `emoji` to `message`.
    fn reaction(
        &self,
        message: &Message,
        reactor: &UserId,
        emoji: &str,
    ) -> Result<NotificationContent, BaseError> {
        let display = Some(reactor) != self.own;
        let mut content =
            self.base(Some(&message.group_id), NotificationKind::Reaction, display)?;
        content.body = format!("reacted {emoji}");
        content.message_id = Some(message.message_id.clone());
        self.sender(content, reactor)
    }

    /// This device joined the chat; `actor` added it, if known.
    fn invite(
        &self,
        group_id: &GroupId,
        actor: Option<&UserId>,
    ) -> Result<NotificationContent, BaseError> {
        let mut content = self.base(Some(group_id), NotificationKind::Invite, true)?;
        content.body = "Added you to the chat".to_string();
        match actor.filter(|a| Some(*a) != self.own) {
            Some(actor) => self.sender(content, actor),
            None => Ok(content),
        }
    }

    /// What applying the message of `kind` at `(group_id, seq)` changed: a
    /// new message at that seq, a reaction to an earlier message (compared
    /// with `before`), or else something silent (edit, delete, receipt,
    /// typing, group info, a commit, anything in a self group). An
    /// application message that changed nothing could not be decrypted:
    /// generic content.
    fn applied(
        &self,
        group_id: &GroupId,
        seq: u64,
        kind: MessageKind,
        changes: &[StateChange],
        before: &[Message],
    ) -> Result<NotificationContent, BaseError> {
        if self.store.self_groups()?.contains(group_id) {
            return self.base(None, NotificationKind::Generic, false);
        }
        if changes.is_empty() && kind == MessageKind::Application {
            return self.base(Some(group_id), NotificationKind::Generic, true);
        }
        let upserted = changes.iter().filter_map(|change| match change {
            StateChange::MessageUpserted(m) if &m.group_id == group_id => Some(m),
            _ => None,
        });
        if let Some(message) = upserted.clone().find(|m| m.seq == Some(seq)) {
            return self.message(message);
        }
        // An earlier message changed.
        if let Some(message) = upserted.into_iter().next() {
            if message.deleted {
                return self.base(Some(group_id), NotificationKind::Message, false);
            }
            let previous = before.iter().find(|b| b.message_id == message.message_id);
            let added = previous.and_then(|previous| {
                message.reactions.iter().find_map(|(user_id, emojis)| {
                    let had = previous.reactions.get(user_id);
                    emojis
                        .iter()
                        .find(|e| !had.is_some_and(|had| had.contains(*e)))
                        .map(|emoji| (user_id, emoji))
                })
            });
            if let Some((reactor, emoji)) = added {
                return self.reaction(message, reactor, emoji);
            }
            return self.base(Some(group_id), NotificationKind::Message, false);
        }
        let membership = changes.iter().any(
            |change| matches!(change, StateChange::MembershipChanged(e) if &e.group_id == group_id),
        );
        let kind = if membership {
            NotificationKind::Membership
        } else {
            NotificationKind::Generic
        };
        self.base(Some(group_id), kind, false)
    }
}

impl<S: StateStore + 'static> Client<S> {
    /// Validates `registration` (contract `push.md` §1), stores it on this
    /// device and puts it on every verified hub this device can reach
    /// (`PUT /v2/push/registration`), replacing the previous one. Without a
    /// session it is only stored, and put on the hubs once this device
    /// signs in. A hub that cannot be reached now gets it on the sync
    /// loop's next connect. Fails with [`ClientError::InvalidInput`] for a
    /// malformed registration (nothing stored), or with a hub's definite
    /// rejection after trying every hub. Does nothing in
    /// [`crate::ClientMode::Extension`]: the app owns the registration.
    pub async fn register_push(&self, registration: PushRegistration) -> Result<()> {
        registration.validate()?;
        if self.is_extension() {
            return Ok(());
        }
        let _guard = self.inner.push_lock.lock().await;
        let encoded = serde_json::to_vec(&registration).expect("a registration serializes");
        self.inner
            .secrets
            .set(PUSH_REGISTRATION_SECRET_KEY, &encoded)?;
        self.push_state().registered.clear();
        if self.session().is_none() {
            return Ok(());
        }
        let mut rejected = None;
        for hub in self.submission_hubs().await {
            match self.put_push_on(&hub, &registration).await {
                Ok(()) => {}
                Err(err @ TransportError::Rejected { .. }) => {
                    tracing::warn!(hub_id = %hub.hub_id, error = %err, "hub refused the push registration");
                    rejected.get_or_insert(err);
                }
                Err(err) => {
                    tracing::info!(hub_id = %hub.hub_id, error = %err, "push registration deferred to the next connect");
                }
            }
        }
        rejected.map_or(Ok(()), |err| Err(err.into()))
    }

    /// Removes the push registration from every verified hub this device
    /// can reach (`DELETE /v2/push/registration`), then deletes the local
    /// copy. The local copy is deleted even if a hub failed; the first
    /// failure is returned after trying every hub. Hubs that could not be
    /// reached keep pushing until the push server reports the token
    /// invalid. Does nothing in [`crate::ClientMode::Extension`].
    pub async fn unregister_push(&self) -> Result<()> {
        if self.is_extension() {
            return Ok(());
        }
        let _guard = self.inner.push_lock.lock().await;
        let mut failed = None;
        if self.session().is_some() {
            for hub in self.submission_hubs().await {
                let deleted = self
                    .authed_on(&hub, |t, token| async move {
                        t.delete_push_registration(&token).await
                    })
                    .await;
                if let Err(err) = deleted {
                    tracing::warn!(hub_id = %hub.hub_id, error = %err, "cannot remove the push registration");
                    failed.get_or_insert(err);
                }
            }
        }
        self.inner.secrets.delete(PUSH_REGISTRATION_SECRET_KEY)?;
        self.push_state().registered.clear();
        failed.map_or(Ok(()), |err| Err(err.into()))
    }

    /// The stored push registration, if any.
    pub fn push_registration(&self) -> Result<Option<PushRegistration>> {
        let Some(encoded) = self.inner.secrets.get(PUSH_REGISTRATION_SECRET_KEY)? else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(&encoded)
            .inspect_err(|err| tracing::warn!(error = %err, "unreadable push registration"))
            .ok())
    }

    /// This device signed in (again) on a hub (`None`: the home hub), or
    /// the hub's event loop connected: the sync loop puts the registration
    /// there unless it already did in this run. A new sign-in may follow a
    /// hub losing the registration (a 401), so it is put again.
    /// Never in [`crate::ClientMode::Extension`], which has no sync loop.
    pub(crate) fn push_hub_changed(&self, hub_id: Option<&str>, signed_in: bool) {
        if self.is_extension() {
            return;
        }
        if signed_in {
            self.push_state()
                .registered
                .remove(&hub_id.map(str::to_string));
        }
        self.inner.push_wake.notify_one();
    }

    /// Puts the stored registration on every verified hub this device can
    /// reach that does not hold it in this run, at start, whenever
    /// [`Client::push_hub_changed`] asks and whenever the hub registry
    /// changed (a hub verified). Failures are retried then.
    pub(crate) async fn maintain_push_registration(&self) -> std::convert::Infallible {
        let mut registry = self.subscribe_hub_changes();
        loop {
            self.put_push_where_missing().await;
            tokio::select! {
                () = self.inner.push_wake.notified() => {}
                // Lagging only merges notifications; the sender lives as
                // long as the client.
                _ = registry.recv() => {}
            }
        }
    }

    async fn put_push_where_missing(&self) {
        let _guard = self.inner.push_lock.lock().await;
        let registration = match self.push_registration() {
            Ok(Some(registration)) => registration,
            Ok(None) => return,
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the push registration");
                return;
            }
        };
        if self.session().is_none() {
            return;
        }
        for hub in self.submission_hubs().await {
            if self.push_state().registered.contains(&push_key(&hub)) {
                continue;
            }
            if let Err(err) = self.put_push_on(&hub, &registration).await {
                tracing::info!(hub_id = %hub.hub_id, error = %err, "cannot put the push registration; retrying on the next connect");
            }
        }
    }

    async fn put_push_on(
        &self,
        hub: &HubTarget,
        registration: &PushRegistration,
    ) -> Result<(), TransportError> {
        self.authed_on(hub, |t, token| async move {
            t.put_push_registration(&token, registration).await
        })
        .await?;
        tracing::debug!(hub_id = %hub.hub_id, "push registration stored on the hub");
        self.push_state().registered.insert(push_key(hub));
        Ok(())
    }

    fn push_state(&self) -> std::sync::MutexGuard<'_, PushState> {
        self.inner.push.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// [`Client::process_push_within`] with [`PUSH_TIMEOUT`].
    pub async fn process_push(&self, payload: &str) -> Result<NotificationContent> {
        self.process_push_within(payload, PUSH_TIMEOUT).await
    }

    /// Processes a push payload (contract `push.md` §3, the JSON object the
    /// push server delivered) within `timeout`, and returns what to show:
    ///
    /// - `message`: the message at `(gid, seq)`, fetched with `GET
    ///   /v2/groups/{gid}/messages?from_seq={seq}` (the inline
    ///   `mls_message` is ignored, see the module docs), and applied like
    ///   sync applies it. If it was applied before (the stream
    ///   or another push), the stored message is described and nothing is
    ///   applied again. New text and media are shown (not own ones, nor
    ///   read ones), a new reaction as `reacted <emoji>`; edits, deletes,
    ///   receipts and other content show nothing by themselves. A pushed
    ///   Proposal is applied like any message. In a chat not joined yet
    ///   (the hub replaced the Welcome's push with this one) it joins
    ///   through the pending Welcomes first.
    /// - `welcome`: joins through the pending Welcomes (`GET
    ///   /v2/welcomes/pending`, then the acknowledgement) and shows the
    ///   invite. The inline Welcome is not used: it does not name who
    ///   added this device.
    /// - `group.member_added` / `group.member_removed`: catches the group
    ///   up to the pushed seq (joining it first through the pending
    ///   Welcomes if the change added this device); silent by itself.
    /// - `wake` (minimal mode), an unknown type or version: joins the
    ///   pending Welcomes and reads one page of events from every reachable
    ///   hub (without moving the cursors: the app's stream reads them
    ///   again).
    ///
    /// The hub keeps one pending push per device, with the highest
    /// priority and the newest payload, so an alert push may carry a
    /// receipt, an announcement or a member change that followed a text.
    /// The payload carries no priority: every type is handled the same at
    /// any priority. When the pushed message shows nothing (and for member
    /// changes and wake-ups), the
    /// group is caught up to the pushed seq and the newest unread text or
    /// media from someone else obtained in this call is shown, else the
    /// invite of a chat joined in this call, else nothing. Only the stored
    /// read state decides what is unread.
    ///
    /// Groups with an own commit not settled yet are left to the stream.
    /// Fails only with [`ClientError::InvalidInput`] if `payload` is not a
    /// JSON object; any other failure, and running out of time, give the
    /// generic content (see [`NotificationContent`]), silent for
    /// membership pushes.
    pub async fn process_push_within(
        &self,
        payload: &str,
        timeout: Duration,
    ) -> Result<NotificationContent> {
        let push = Push::parse(payload)?;
        let failure = match tokio::time::timeout(timeout, self.handle_push(&push)).await {
            Ok(Ok(content)) => return Ok(content),
            Ok(Err(err)) => err.to_string(),
            Err(_) => format!("not done within {timeout:?}"),
        };
        tracing::warn!(kind = ?push.kind, error = %failure, "push not processed; generic notification");
        let display = !matches!(push.kind, PushKind::Membership { .. });
        Ok(self.generic(&push, display).await)
    }

    async fn handle_push(&self, push: &Push) -> Result<NotificationContent> {
        let session = self.require_session()?;
        match &push.kind {
            PushKind::Message { group_id, seq } => {
                self.push_message(&session, push, group_id, *seq).await
            }
            PushKind::Welcome { group_id, seq } => {
                self.push_welcome(&session, push, group_id, *seq).await
            }
            PushKind::Membership { group_id, seq } => {
                self.push_membership(&session, push, group_id, *seq).await
            }
            PushKind::Wake => self.push_wake(&session, push).await,
        }
    }

    /// Runs `describe` over the store.
    async fn describe<T, F>(&self, session: Option<&Session>, push: &Push, describe: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Describe<'_, S>) -> Result<T, BaseError> + Send + 'static,
    {
        let own = session
            .map(|s| s.device.user_id.clone())
            .or_else(|| self.session().map(|s| s.device.user_id));
        let collapse_id = push.collapse_id.clone();
        self.read(move |store, _| {
            describe(&Describe {
                store,
                own: own.as_ref(),
                collapse_id,
            })
        })
        .await
    }

    /// The generic content: the push's chat if known locally, nothing else.
    async fn generic(&self, push: &Push, display: bool) -> NotificationContent {
        let group_id = push.group_id().cloned();
        let described = self
            .describe(None, push, move |d| {
                d.base(group_id.as_ref(), NotificationKind::Generic, display)
            })
            .await;
        described.unwrap_or_else(|err| {
            tracing::debug!(error = %err, "cannot name the chat of a push");
            NotificationContent {
                chat_id: push.group_id().cloned(),
                chat_title: None,
                sender_user_id: None,
                sender_display_name: None,
                body: GENERIC_BODY.to_string(),
                message_id: None,
                collapse_id: push.collapse_id.clone(),
                kind: NotificationKind::Generic,
                should_display: display,
                timestamp_ms: now_ms(),
            }
        })
    }

    /// Whether `(group_id, seq)` was applied, and the group's last
    /// contiguous applied seq.
    async fn applied_seq(&self, group_id: &GroupId, seq: u64) -> Result<(bool, u64)> {
        let gid = group_id.clone();
        self.read(move |store, _| {
            let cursor = store.group_cursor(&gid)?;
            Ok((cursor.contains(seq), cursor.contiguous_seq))
        })
        .await
    }

    /// A message push. For a chat this device has not joined (the hub
    /// keeps one pending push per device, so the Welcome's push may have
    /// been replaced by this one) it joins through the pending Welcomes
    /// first. If the pushed message itself shows nothing (a receipt, an
    /// announcement, an edit; the hub may have replaced an earlier push of
    /// a text with this one), the group is caught up to the pushed seq and
    /// the newest unread message from someone else obtained in this wake
    /// is shown, else the invite of a chat joined in this wake.
    async fn push_message(
        &self,
        session: &Session,
        push: &Push,
        group_id: &GroupId,
        seq: u64,
    ) -> Result<NotificationContent> {
        let before = self.cursors([group_id.clone()]).await?;
        let mut joined_now = None;
        if !self.is_joined(group_id).await? {
            self.join_pending(session, group_id, None).await?;
            joined_now = self.joined_actor(session, group_id, None).await?;
        }
        let content = self
            .push_joined_message(session, push, group_id, seq)
            .await?;
        // After applying: the pushed message may be the inviter's profile.
        if let Some(actor) = &joined_now {
            self.joined(session, group_id, actor.as_ref()).await;
        }
        if content.should_display {
            return Ok(content);
        }
        if let Err(err) = self.catch_up(session, group_id, seq).await {
            tracing::info!(%group_id, error = %err, "cannot catch up the pushed group");
        }
        if let Some(newest) = self.newest_obtained(session, push, before).await? {
            return Ok(newest);
        }
        match joined_now {
            Some(actor) => self.describe_invite(session, push, group_id, actor).await,
            None => Ok(content),
        }
    }

    async fn push_joined_message(
        &self,
        session: &Session,
        push: &Push,
        group_id: &GroupId,
        seq: u64,
    ) -> Result<NotificationContent> {
        let (applied, contiguous) = self.applied_seq(group_id, seq).await?;
        if applied {
            return self.applied_before(session, push, group_id, seq).await;
        }
        if seq > contiguous.saturating_add(MAX_CATCH_UP) {
            tracing::info!(%group_id, seq, contiguous, "pushed message too far ahead; left to the stream");
            return Ok(self.generic(push, true).await);
        }
        let Some(message) = self.fetch_message(group_id, seq).await? else {
            tracing::info!(%group_id, seq, "pushed message not found");
            return Ok(self.generic(push, true).await);
        };
        let kind = message.kind;
        let events = vec![IncomingEvent::Message(message)];
        let link = self.home_link();
        let Some((changes, before)) = self
            .apply_pushed(session, &link, events, Some(group_id))
            .await?
        else {
            return Ok(self.generic(push, true).await);
        };
        if !self.applied_seq(group_id, seq).await?.0 {
            // Parked: an earlier commit is missing.
            return Ok(self.generic(push, true).await);
        }
        let gid = group_id.clone();
        self.describe(Some(session), push, move |d| {
            d.applied(&gid, seq, kind, &changes, &before)
        })
        .await
    }

    /// The message at `(group_id, seq)`, applied before: described as
    /// stored (silent if it is not a text or media message, e.g. an edit).
    async fn applied_before(
        &self,
        session: &Session,
        push: &Push,
        group_id: &GroupId,
        seq: u64,
    ) -> Result<NotificationContent> {
        let gid = group_id.clone();
        self.describe(Some(session), push, move |d| {
            let stored = d
                .store
                .messages(&gid, Some(seq + 1), 1)?
                .into_iter()
                .find(|m| m.seq == Some(seq));
            match stored {
                Some(message) => d.message(&message),
                None => d.base(Some(&gid), NotificationKind::Generic, false),
            }
        })
        .await
    }

    /// The message at `(group_id, seq)` from the hubs (the home hub first,
    /// then the other reachable listed hubs).
    async fn fetch_message(&self, group_id: &GroupId, seq: u64) -> Result<Option<GroupMessage>> {
        let history = self
            .group_history_from(
                &self.home_link(),
                group_id,
                seq.saturating_sub(1),
                Some(seq),
            )
            .await?;
        Ok(history.and_then(|messages| messages.into_iter().find(|m| m.seq == seq)))
    }

    /// Applies `events` of the hub of `link` through the sync apply path,
    /// under the group lock, leaving out the groups with an own commit not
    /// settled yet (which only the stream may resolve). Returns the changes
    /// and the latest messages of `snapshot` before applying; `None` if
    /// every event was left out.
    async fn apply_pushed(
        &self,
        session: &Session,
        link: &HubLink,
        events: Vec<IncomingEvent>,
        snapshot: Option<&GroupId>,
    ) -> Result<Option<(Vec<StateChange>, Vec<Message>)>> {
        let _guard = self.inner.group_lock.lock().await;
        let snapshot = snapshot.cloned();
        let (pending, before) = self
            .read(move |store, _| {
                let pending: BTreeSet<GroupId> = store
                    .pending_commits()?
                    .into_iter()
                    .map(|c| c.group_id)
                    .collect();
                let before = match snapshot {
                    Some(gid) => store.messages(&gid, None, SNAPSHOT_MESSAGES)?,
                    None => vec![],
                };
                Ok((pending, before))
            })
            .await?;
        let events: Vec<IncomingEvent> = events
            .into_iter()
            .filter(|event| match event {
                IncomingEvent::Message(m) => !pending.contains(&m.group_id),
                IncomingEvent::MemberAdded { group_id, .. }
                | IncomingEvent::MemberRemoved { group_id, .. } => !pending.contains(group_id),
                // Left to the stream: the app tops up the KeyPackages.
                IncomingEvent::KeyPackagesLow => false,
            })
            .collect();
        if events.is_empty() {
            return Ok(None);
        }
        let changes = self.apply_group_events(session, link, events).await?;
        Ok(Some((changes, before)))
    }

    async fn push_welcome(
        &self,
        session: &Session,
        push: &Push,
        group_id: &GroupId,
        seq: u64,
    ) -> Result<NotificationContent> {
        if !self.applied_seq(group_id, seq).await?.0 {
            self.join_pending(session, group_id, Some(seq)).await?;
        }
        let Some(actor) = self.joined_actor(session, group_id, Some(seq)).await? else {
            return Ok(self.generic(push, true).await);
        };
        self.invite(session, push, group_id, actor).await
    }

    /// Joins the pending Welcomes of every reachable hub, the home hub
    /// first, until `group_id` is joined (at `seq`, the Welcome's Commit,
    /// if given).
    async fn join_pending(
        &self,
        session: &Session,
        group_id: &GroupId,
        seq: Option<u64>,
    ) -> Result<()> {
        let _guard = self.inner.group_lock.lock().await;
        for link in std::iter::once(self.home_link()).chain(self.hub_links()) {
            match self.join_pending_welcomes(session, &link).await {
                Ok(_) => {
                    let done = match seq {
                        Some(seq) => self.applied_seq(group_id, seq).await?.0,
                        None => self.is_joined(group_id).await?,
                    };
                    if done {
                        break;
                    }
                }
                Err(err) => {
                    tracing::info!(%group_id, error = %err, "cannot read the pending Welcomes")
                }
            }
        }
        Ok(())
    }

    async fn is_joined(&self, group_id: &GroupId) -> Result<bool> {
        let gid = group_id.clone();
        self.read(move |store, _| {
            Ok(store
                .chat(&gid)?
                .is_some_and(|c| c.membership == Membership::Joined))
        })
        .await
    }

    /// `None` unless `group_id` is joined; else who added this device (at
    /// `seq` if given, else the latest addition), if known.
    async fn joined_actor(
        &self,
        session: &Session,
        group_id: &GroupId,
        seq: Option<u64>,
    ) -> Result<Option<Option<UserId>>> {
        let (gid, own) = (group_id.clone(), session.device.user_id.clone());
        self.run(move |store, _| {
            let joined = store
                .chat(&gid)?
                .is_some_and(|c| c.membership == Membership::Joined);
            let actor = store
                .membership_events(&gid)?
                .into_iter()
                .filter(|e| {
                    seq.is_none_or(|seq| e.seq == seq)
                        && e.user_id == own
                        && e.kind == MembershipChangeKind::Added
                })
                .max_by_key(|e| e.seq)
                .map(|e| e.actor);
            Ok(joined.then_some(actor))
        })
        .await
    }

    /// What the sync loop does for a chat it joined.
    async fn joined(&self, session: &Session, group_id: &GroupId, actor: Option<&UserId>) {
        if let Some(actor) = actor {
            self.resolve_users(session, BTreeSet::from([actor.clone()]))
                .await;
        }
        self.announce_profile(group_id).await;
    }

    /// The invite to the joined `group_id` by `actor`, after doing what the
    /// sync loop does for a chat it joined.
    async fn invite(
        &self,
        session: &Session,
        push: &Push,
        group_id: &GroupId,
        actor: Option<UserId>,
    ) -> Result<NotificationContent> {
        self.joined(session, group_id, actor.as_ref()).await;
        self.describe_invite(session, push, group_id, actor).await
    }

    async fn describe_invite(
        &self,
        session: &Session,
        push: &Push,
        group_id: &GroupId,
        actor: Option<UserId>,
    ) -> Result<NotificationContent> {
        let gid = group_id.clone();
        self.describe(Some(session), push, move |d| d.invite(&gid, actor.as_ref()))
            .await
    }

    /// A member change: joins the group first if the change added this
    /// device, then catches the group up to the pushed seq; shows a message
    /// that brought, else the invite of a group joined now, else nothing.
    async fn push_membership(
        &self,
        session: &Session,
        push: &Push,
        group_id: &GroupId,
        seq: u64,
    ) -> Result<NotificationContent> {
        let before = self.cursors([group_id.clone()]).await?;
        // The Commit may have added this device: its Welcome push coalesced
        // into this one.
        let mut joined_now = None;
        if !self.is_joined(group_id).await? {
            self.join_pending(session, group_id, Some(seq)).await?;
            joined_now = self.joined_actor(session, group_id, Some(seq)).await?;
        }
        self.catch_up(session, group_id, seq).await?;
        if let Some(actor) = &joined_now {
            self.joined(session, group_id, actor.as_ref()).await;
        }
        if let Some(newest) = self.newest_obtained(session, push, before).await? {
            return Ok(newest);
        }
        if let Some(actor) = joined_now {
            return self.describe_invite(session, push, group_id, actor).await;
        }
        let gid = group_id.clone();
        self.describe(Some(session), push, move |d| {
            d.base(Some(&gid), NotificationKind::Membership, false)
        })
        .await
    }

    /// Applies the group's messages up to `seq` that are missing, unless
    /// `seq` is more than [`MAX_CATCH_UP`] past the applied history (the
    /// stream backfills that).
    async fn catch_up(&self, session: &Session, group_id: &GroupId, seq: u64) -> Result<()> {
        let (_, contiguous) = self.applied_seq(group_id, seq).await?;
        if seq <= contiguous || seq > contiguous.saturating_add(MAX_CATCH_UP) {
            return Ok(());
        }
        let history = self
            .group_history_from(&self.home_link(), group_id, contiguous, Some(seq))
            .await?
            .unwrap_or_default();
        let events = history
            .into_iter()
            .filter(|m| m.seq <= seq)
            .map(IncomingEvent::Message)
            .collect();
        self.apply_pushed(session, &self.home_link(), events, None)
            .await?;
        Ok(())
    }

    /// The applied seqs of `groups` now.
    async fn cursors(
        &self,
        groups: impl IntoIterator<Item = GroupId>,
    ) -> Result<BTreeMap<GroupId, GroupCursor>> {
        let groups: Vec<GroupId> = groups.into_iter().collect();
        self.read(move |store, _| {
            groups
                .into_iter()
                .map(|gid| Ok((gid.clone(), store.group_cursor(&gid)?)))
                .collect()
        })
        .await
    }

    /// The newest message to show among those applied since `before` was
    /// read (their seq was not applied then): text or media from someone
    /// else, not deleted and not read, outside the self groups. Reads only
    /// the stored unread state.
    async fn newest_obtained(
        &self,
        session: &Session,
        push: &Push,
        before: BTreeMap<GroupId, GroupCursor>,
    ) -> Result<Option<NotificationContent>> {
        self.describe(Some(session), push, move |d| {
            let hidden = d.store.self_groups()?;
            let mut newest: Option<NotificationContent> = None;
            for (gid, cursor) in &before {
                if hidden.contains(gid) {
                    continue;
                }
                for message in d.store.messages(gid, None, SNAPSHOT_MESSAGES)? {
                    if !message.seq.is_some_and(|seq| !cursor.contains(seq)) {
                        continue;
                    }
                    let content = d.message(&message)?;
                    if content.should_display
                        && newest
                            .as_ref()
                            .is_none_or(|n| content.timestamp_ms > n.timestamp_ms)
                    {
                        newest = Some(content);
                    }
                }
            }
            Ok(newest)
        })
        .await
    }

    /// A wake-up (minimal mode, unknown type): joins the pending Welcomes
    /// and reads one page of events of every reachable hub, then shows the
    /// newest unread message from someone else obtained, else the invite
    /// of a chat joined, else nothing (generic content if a hub could not
    /// be read).
    async fn push_wake(&self, session: &Session, push: &Push) -> Result<NotificationContent> {
        let own = session.device.user_id.clone();
        let mut joined = Vec::new();
        let mut complete = true;
        {
            let _guard = self.inner.group_lock.lock().await;
            for link in std::iter::once(self.home_link()).chain(self.hub_links()) {
                match self.join_pending_welcomes(session, &link).await {
                    Ok(changes) => {
                        joined.extend(changes.into_iter().filter_map(|change| match change {
                            StateChange::MembershipChanged(e)
                                if e.user_id == own && e.kind == MembershipChangeKind::Added =>
                            {
                                Some(e.group_id)
                            }
                            _ => None,
                        }))
                    }
                    Err(err) => {
                        tracing::info!(error = %err, "cannot read the pending Welcomes for a push");
                        complete = false;
                    }
                }
            }
        }
        let mut before = self.cursors(joined.iter().cloned()).await?;
        for link in std::iter::once(self.home_link()).chain(self.hub_links()) {
            match self.wake_hub(session, &link).await {
                Ok(cursors) => {
                    for (gid, cursor) in cursors {
                        before.entry(gid).or_insert(cursor);
                    }
                }
                Err(err) => {
                    tracing::info!(error = %err, "cannot read a hub's events for a push");
                    complete = false;
                }
            }
        }
        if let Some(newest) = self.newest_obtained(session, push, before).await? {
            return Ok(newest);
        }
        let hidden = self.read(|store, _| Ok(store.self_groups()?)).await?;
        if let Some(group_id) = joined.iter().rev().find(|g| !hidden.contains(*g)) {
            if let Some(actor) = self.joined_actor(session, group_id, None).await? {
                return self.invite(session, push, group_id, actor).await;
            }
        }
        self.describe(Some(session), push, move |d| {
            d.base(None, NotificationKind::Generic, !complete)
        })
        .await
    }

    /// Reads one page of events of the hub of `link` (without moving its
    /// cursor) and applies its DeviceList updates and group events. Returns
    /// the applied seqs of the groups of those events before applying.
    async fn wake_hub(
        &self,
        session: &Session,
        link: &HubLink,
    ) -> Result<BTreeMap<GroupId, GroupCursor>> {
        let Fetched::Batch(batch) = self.fetch(link, Duration::ZERO).await? else {
            return Err(ClientError::Transport(TransportError::Gone { cursor: 0 }));
        };
        let mut revoked = Vec::new();
        let mut events = Vec::new();
        for event in batch.events {
            match event {
                HubEvent::Group(event) => events.push(event),
                HubEvent::DeviceListUpdated {
                    user_id,
                    device_list,
                } => match self.accept_device_list(&user_id, &device_list).await {
                    Ok(newly) => revoked.extend(newly),
                    Err(ClientError::Identity(reason)) => {
                        tracing::warn!(%user_id, %reason, "ignoring a device list update");
                    }
                    Err(err) => return Err(err),
                },
                // Left to the stream.
                HubEvent::HostingRecordExpiring { .. } | HubEvent::HostingRecordUpdated { .. } => {}
            }
        }
        self.record_revoked(session, revoked).await?;
        let groups: BTreeSet<GroupId> = events
            .iter()
            .filter_map(|event| match event {
                IncomingEvent::Message(m) => Some(m.group_id.clone()),
                IncomingEvent::MemberAdded { group_id, .. }
                | IncomingEvent::MemberRemoved { group_id, .. } => Some(group_id.clone()),
                IncomingEvent::KeyPackagesLow => None,
            })
            .collect();
        let before = self.cursors(groups).await?;
        self.apply_pushed(session, link, events, None).await?;
        Ok(before)
    }
}

/// The registry key of a hub: `None` for the home hub.
fn push_key(hub: &HubTarget) -> Option<String> {
    (!hub.home).then(|| hub.hub_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> PushRegistration {
        PushRegistration {
            provider: "apns".into(),
            token: "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad".into(),
            app_id: Some("im.g.apps".into()),
            sandbox: Some(false),
            p256dh: None,
            auth: None,
        }
    }

    #[test]
    fn registrations_follow_the_shape_rules() {
        assert!(registration().validate().is_ok());
        let web = PushRegistration {
            provider: "unifiedpush".into(),
            token: "https://push.example.eu/x".into(),
            app_id: None,
            sandbox: None,
            p256dh: Some("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4".into()),
            auth: Some("BTBZMqHH6r4Tts7J_aSIgg==".into()),
        };
        assert!(web.validate().is_ok());
        let bad = [
            PushRegistration {
                provider: "".into(),
                ..registration()
            },
            PushRegistration {
                provider: "APNS".into(),
                ..registration()
            },
            PushRegistration {
                provider: "a".repeat(65),
                ..registration()
            },
            PushRegistration {
                token: "".into(),
                ..registration()
            },
            PushRegistration {
                token: "a\nb".into(),
                ..registration()
            },
            PushRegistration {
                token: "a".repeat(4097),
                ..registration()
            },
            PushRegistration {
                app_id: Some("".into()),
                ..registration()
            },
            PushRegistration {
                app_id: Some("im g".into()),
                ..registration()
            },
            PushRegistration {
                p256dh: Some("a+b".into()),
                ..registration()
            },
            PushRegistration {
                auth: Some("=".into()),
                ..registration()
            },
            PushRegistration {
                auth: Some("a".repeat(257)),
                ..registration()
            },
        ];
        for registration in bad {
            assert!(
                matches!(registration.validate(), Err(ClientError::InvalidInput(_))),
                "{registration:?} accepted"
            );
        }
    }

    #[test]
    fn debug_hides_the_token_and_keys() {
        let printed = format!("{:?}", registration());
        assert!(!printed.contains("740f4707"), "{printed}");
    }

    #[test]
    fn payloads_parse_by_type_and_fall_back_to_a_wake_up() {
        let gid = "hubexample/g_1";
        let message = format!(
            r#"{{"v":1,"type":"message","gid":"{gid}","seq":42,"message_id":"m1","collapse_id":"m1","mls_message":"AAEAAg==","extra":true}}"#
        );
        let push = Push::parse(&message).unwrap();
        assert_eq!(push.collapse_id.as_deref(), Some("m1"));
        match push.kind {
            PushKind::Message { group_id, seq } => {
                assert_eq!(group_id.as_str(), gid);
                assert_eq!(seq, 42);
            }
            kind => panic!("{kind:?}"),
        }
        let welcome = format!(r#"{{"v":1,"type":"welcome","gid":"{gid}","seq":3}}"#);
        assert!(matches!(
            Push::parse(&welcome).unwrap().kind,
            PushKind::Welcome { seq: 3, .. }
        ));
        let removed = format!(r#"{{"v":1,"type":"group.member_removed","gid":"{gid}","seq":4}}"#);
        assert!(matches!(
            Push::parse(&removed).unwrap().kind,
            PushKind::Membership { seq: 4, .. }
        ));
        for wake in [
            r#"{"v": 1, "type": "wake", "collapse_id": "m1"}"#.to_string(),
            r#"{"v":2,"type":"message","gid":"g","seq":1}"#.to_string(),
            r#"{"v":1,"type":"poke"}"#.to_string(),
            r#"{"v":1,"type":"message","seq":"1"}"#.to_string(),
            "{}".to_string(),
        ] {
            assert!(
                matches!(Push::parse(&wake).unwrap().kind, PushKind::Wake),
                "{wake}"
            );
        }
        for garbage in ["", "not json", "[1,2]", "\"text\"", "{\"v\":"] {
            assert!(
                matches!(Push::parse(garbage), Err(ClientError::InvalidInput(_))),
                "{garbage:?}"
            );
        }
    }
}
