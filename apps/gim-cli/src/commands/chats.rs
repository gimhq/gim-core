//! `chats list`, `dm`, `group ...`, `members`, `read`, `typing`.

use gim_base::StateReader;

use super::chat_id_output;
use crate::error::Result;
use crate::output::{chat_summary, ChatsOut, MemberOut, MembersOut, Output};
use crate::profile::Ctx;
use crate::resolve::{find_direct, peer_of, users_of, Directory};

pub fn list(ctx: &Ctx) -> Result<Output> {
    let store = ctx.store();
    let me = &ctx.session.device.user_id;
    let chats = store.chats()?;
    let directory = Directory::load(store, chats.iter().filter_map(|c| peer_of(c, me)))?;
    let mut out = Vec::with_capacity(chats.len());
    for chat in &chats {
        let last = match &chat.last_message_id {
            Some(id) => store.message(id)?,
            None => None,
        };
        out.push(chat_summary(chat, me, &directory, last.as_ref()));
    }
    let human = out
        .iter()
        .map(|c| {
            let mut line = format!(
                "{}\t{}\t{}\t{} members\t{} unread",
                c.id,
                c.kind,
                c.name.as_deref().unwrap_or("-"),
                c.members,
                c.unread_count
            );
            if c.membership != "joined" {
                line.push_str(&format!("\t({})", c.membership));
            }
            if let Some(last) = &c.last_message {
                line.push_str(&format!("\t{}", last.summary));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Output::new(&ChatsOut { chats: out }, human))
}

/// The joined direct chat with the user, created if there is none.
pub async fn dm(ctx: &Ctx, handle: &str) -> Result<Output> {
    let user_id = ctx.resolve_user(handle).await?;
    let chats = ctx.store().chats()?;
    let existing = find_direct(&chats, &ctx.session.device.user_id, &user_id);
    let chat_id = match existing {
        Some(chat) => chat.group_id.clone(),
        None => ctx.client.create_direct_chat(&user_id).await?,
    };
    Ok(chat_id_output(&chat_id))
}

pub async fn group_create(ctx: &Ctx, name: &str, handles: &[String]) -> Result<Output> {
    let users = ctx.resolve_users(handles).await?;
    let chat_id = ctx
        .client
        .create_group_chat(Some(name.to_string()), &users)
        .await?;
    Ok(chat_id_output(&chat_id))
}

pub async fn group_add(ctx: &Ctx, chat: &str, handles: &[String]) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    let users = ctx.resolve_users(handles).await?;
    ctx.client.add_members(&chat.group_id, &users).await?;
    Ok(chat_id_output(&chat.group_id))
}

pub async fn group_remove(ctx: &Ctx, chat: &str, handles: &[String]) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    let users = ctx.resolve_users(handles).await?;
    ctx.client.remove_members(&chat.group_id, &users).await?;
    Ok(chat_id_output(&chat.group_id))
}

pub async fn group_rename(ctx: &Ctx, chat: &str, name: &str) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    ctx.client
        .set_group_info(&chat.group_id, Some(name.to_string()), None)
        .await?;
    Ok(chat_id_output(&chat.group_id))
}

pub async fn group_leave(ctx: &Ctx, chat: &str) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    ctx.client.leave(&chat.group_id).await?;
    Ok(chat_id_output(&chat.group_id))
}

pub fn members(ctx: &Ctx, chat: &str) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    let users = users_of(&chat);
    let directory = Directory::load(ctx.store(), users.iter().copied())?;
    let members: Vec<MemberOut> = users
        .into_iter()
        .map(|user_id| {
            let info = directory.get(user_id);
            let devices = chat.members.iter().filter(|m| &m.device.user_id == user_id);
            MemberOut {
                user_id: user_id.to_string(),
                handle: info.map(|u| u.handle.clone()),
                display_name: info
                    .map(|u| u.display_name.clone())
                    .or_else(|| devices.clone().find_map(|m| m.display_name.clone())),
                devices: devices.map(|m| m.device.device_id.to_string()).collect(),
            }
        })
        .collect();
    let human = members
        .iter()
        .map(|m| {
            format!(
                "{}\t{}\t{}\t{}",
                m.handle
                    .as_deref()
                    .map_or("-".to_string(), |h| format!("@{h}")),
                m.display_name.as_deref().unwrap_or("-"),
                m.user_id,
                m.devices.join(",")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Output::new(&MembersOut { members }, human))
}

pub async fn read(ctx: &Ctx, chat: &str) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    ctx.client.mark_read(&chat.group_id).await?;
    Ok(chat_id_output(&chat.group_id))
}

pub async fn typing(ctx: &Ctx, chat: &str, stop: bool) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    ctx.client.set_typing(&chat.group_id, !stop).await?;
    Ok(chat_id_output(&chat.group_id))
}
