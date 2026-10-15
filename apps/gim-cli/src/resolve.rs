//! Resolution of `<chat>`, `<msg>` and `<handle>` arguments against the
//! store (after `sync_once`) and the user directory.

use std::collections::HashMap;

use gim_base::model::{Chat, ChatKind, Membership, Message, UserInfo};
use gim_base::StateReader;
use gim_common::{MessageId, UserId};

use crate::error::{CliError, Result};
use crate::profile::Ctx;

/// Cached user directory entries of some users.
#[derive(Debug, Default)]
pub struct Directory(HashMap<UserId, UserInfo>);

impl Directory {
    pub fn load<'a>(
        store: &impl StateReader,
        ids: impl IntoIterator<Item = &'a UserId>,
    ) -> Result<Self> {
        let mut users = HashMap::new();
        for id in ids {
            if users.contains_key(id) {
                continue;
            }
            if let Some(user) = store.user(id)? {
                users.insert(id.clone(), user);
            }
        }
        Ok(Self(users))
    }

    #[cfg(test)]
    pub fn from_users(users: impl IntoIterator<Item = UserInfo>) -> Self {
        Self(users.into_iter().map(|u| (u.user_id.clone(), u)).collect())
    }

    pub fn get(&self, id: &UserId) -> Option<&UserInfo> {
        self.0.get(id)
    }

    pub fn handle(&self, id: &UserId) -> Option<&str> {
        self.get(id).map(|u| u.handle.as_str())
    }

    /// Handle if known, else the user id.
    pub fn label(&self, id: &UserId) -> String {
        self.handle(id)
            .map(str::to_string)
            .unwrap_or_else(|| id.to_string())
    }
}

/// The other user of a direct chat.
pub fn peer_of<'a>(chat: &'a Chat, me: &UserId) -> Option<&'a UserId> {
    chat.members
        .iter()
        .map(|m| &m.device.user_id)
        .find(|id| *id != me)
}

/// Every user of a chat, in member order, without duplicates.
pub fn users_of(chat: &Chat) -> Vec<&UserId> {
    let mut users: Vec<&UserId> = Vec::new();
    for member in &chat.members {
        if !users.contains(&&member.device.user_id) {
            users.push(&member.device.user_id);
        }
    }
    users
}

/// The joined direct chat with `user`, most recently updated first.
pub fn find_direct<'a>(chats: &'a [Chat], me: &UserId, user: &UserId) -> Option<&'a Chat> {
    chats.iter().find(|c| {
        c.kind == ChatKind::Direct
            && c.membership == Membership::Joined
            && peer_of(c, me) == Some(user)
    })
}

/// `<chat>`: an exact group id; else the unique chat with that name; else
/// the joined direct chat with the user of that handle (leading `@`
/// optional). `None` when no chat matches; ambiguous is an error.
pub fn lookup_chat<'a>(
    chats: &'a [Chat],
    me: &UserId,
    directory: &Directory,
    arg: &str,
) -> Result<Option<&'a Chat>> {
    if let Some(chat) = chats.iter().find(|c| c.group_id.as_str() == arg) {
        return Ok(Some(chat));
    }
    let unique = |found: Vec<&'a Chat>, what: &str| match found.as_slice() {
        [chat] => Ok(Some(*chat)),
        [] => Ok(None),
        _ => Err(CliError::not_found(format!(
            "{what} {arg:?} is ambiguous ({} chats); use the chat id",
            found.len()
        ))),
    };
    let named = chats
        .iter()
        .filter(|c| c.name.as_deref() == Some(arg))
        .collect();
    if let Some(chat) = unique(named, "chat name")? {
        return Ok(Some(chat));
    }
    let handle = arg.strip_prefix('@').unwrap_or(arg);
    let direct = chats
        .iter()
        .filter(|c| c.kind == ChatKind::Direct && c.membership == Membership::Joined)
        .filter(|c| peer_of(c, me).and_then(|p| directory.handle(p)) == Some(handle))
        .collect();
    unique(direct, "direct chat with")
}

impl Ctx {
    pub fn resolve_chat(&self, arg: &str) -> Result<Chat> {
        self.lookup_chat(arg)?
            .ok_or_else(|| CliError::not_found(format!("unknown chat {arg:?}")))
    }

    /// Like [`Ctx::resolve_chat`], but `None` when no chat matches yet.
    pub fn lookup_chat(&self, arg: &str) -> Result<Option<Chat>> {
        let chats = self.store().chats()?;
        let me = &self.session.device.user_id;
        let peers = chats.iter().filter_map(|c| peer_of(c, me));
        let directory = Directory::load(self.store(), peers)?;
        Ok(lookup_chat(&chats, me, &directory, arg)?.cloned())
    }

    pub fn resolve_message(&self, arg: &str) -> Result<Message> {
        let unknown = || CliError::not_found(format!("unknown message {arg:?}"));
        let id = MessageId::new(arg).map_err(|_| unknown())?;
        self.store().message(&id)?.ok_or_else(unknown)
    }

    pub async fn resolve_user(&self, handle: &str) -> Result<UserInfo> {
        let handle = handle.strip_prefix('@').unwrap_or(handle);
        self.client
            .find_user(handle)
            .await?
            .ok_or_else(|| CliError::not_found(format!("unknown user @{handle}")))
    }

    pub async fn resolve_users(&self, handles: &[String]) -> Result<Vec<UserId>> {
        let mut users = Vec::with_capacity(handles.len());
        for handle in handles {
            users.push(self.resolve_user(handle).await?.user_id);
        }
        Ok(users)
    }
}

#[cfg(test)]
mod tests {
    use gim_base::model::ChatMember;
    use gim_common::{DeviceRef, GroupId};

    use super::*;
    use crate::error::ErrorKind;

    fn uid(id: &str) -> UserId {
        UserId::new(id).unwrap()
    }

    fn chat(id: &str, kind: ChatKind, name: Option<&str>, users: &[&str]) -> Chat {
        let mut chat = Chat::new(GroupId::new(id).unwrap(), kind, 0);
        chat.name = name.map(str::to_string);
        chat.members = users
            .iter()
            .map(|u| ChatMember {
                device: DeviceRef::parse(u, "d1").unwrap(),
                display_name: None,
            })
            .collect();
        chat
    }

    fn user(id: &str, handle: &str) -> UserInfo {
        UserInfo {
            user_id: uid(id),
            handle: handle.into(),
            display_name: handle.to_uppercase(),
        }
    }

    fn fixture() -> (Vec<Chat>, Directory) {
        let mut left = chat("g-left", ChatKind::Direct, None, &["me", "u-carol"]);
        left.membership = Membership::Left;
        let chats = vec![
            chat("g-bob", ChatKind::Direct, None, &["me", "u-bob"]),
            chat(
                "g-crew",
                ChatKind::Group,
                Some("crew"),
                &["me", "u-bob", "u-carol"],
            ),
            chat("g-dup1", ChatKind::Group, Some("dup"), &["me"]),
            chat("g-dup2", ChatKind::Group, Some("dup"), &["me"]),
            chat("g-named", ChatKind::Group, Some("bob"), &["me"]),
            left,
        ];
        let directory = Directory::from_users([user("u-bob", "bob"), user("u-carol", "carol")]);
        (chats, directory)
    }

    fn resolve(arg: &str) -> Result<String> {
        let (chats, directory) = fixture();
        lookup_chat(&chats, &uid("me"), &directory, arg)?
            .map(|c| c.group_id.to_string())
            .ok_or_else(|| CliError::not_found(format!("unknown chat {arg:?}")))
    }

    #[test]
    fn chat_resolves_by_id_then_name_then_peer_handle() {
        assert_eq!(resolve("g-crew").unwrap(), "g-crew");
        assert_eq!(resolve("crew").unwrap(), "g-crew");
        // A chat name beats a peer handle.
        assert_eq!(resolve("bob").unwrap(), "g-named");
        assert_eq!(resolve("@bob").unwrap(), "g-bob");
    }

    #[test]
    fn chat_resolution_fails_on_ambiguous_or_unknown() {
        let err = resolve("dup").unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound);
        assert!(err.message.contains("ambiguous"), "{}", err.message);
        assert_eq!(resolve("nobody").unwrap_err().kind, ErrorKind::NotFound);
        // Left direct chats only resolve by id.
        assert_eq!(resolve("@carol").unwrap_err().kind, ErrorKind::NotFound);
        assert_eq!(resolve("g-left").unwrap(), "g-left");
    }

    #[test]
    fn chat_lookup_is_none_when_unknown_and_fails_when_ambiguous() {
        let (chats, directory) = fixture();
        let lookup = |arg| lookup_chat(&chats, &uid("me"), &directory, arg);
        assert!(lookup("nobody").unwrap().is_none());
        assert!(lookup("@carol").unwrap().is_none());
        assert_eq!(lookup("dup").unwrap_err().kind.exit_code(), 4);
        assert_eq!(lookup("crew").unwrap().unwrap().group_id.as_str(), "g-crew");
    }

    #[test]
    fn direct_chat_lookup_skips_groups_and_left_chats() {
        let (chats, _) = fixture();
        let me = uid("me");
        let found = find_direct(&chats, &me, &uid("u-bob")).map(|c| c.group_id.as_str());
        assert_eq!(found, Some("g-bob"));
        assert!(find_direct(&chats, &me, &uid("u-carol")).is_none());
        assert!(find_direct(&chats, &me, &me).is_none());
    }

    #[test]
    fn users_of_deduplicates_devices() {
        let mut c = chat("g", ChatKind::Group, None, &["me", "u-bob"]);
        c.members.push(ChatMember {
            device: DeviceRef::parse("u-bob", "d2").unwrap(),
            display_name: None,
        });
        assert_eq!(users_of(&c), [&uid("me"), &uid("u-bob")]);
    }
}
