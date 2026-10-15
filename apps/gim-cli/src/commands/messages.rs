//! `send`, `react`, `edit`, `delete`, `history`.

use gim_base::model::Message;
use gim_base::StateReader;
use gim_common::{GroupId, MessageId};

use super::sent_output;
use crate::error::{CliError, Result};
use crate::output::{message_line, message_out, MessageWrapOut, MessagesOut, Output};
use crate::profile::Ctx;
use crate::resolve::Directory;

/// Directory of the senders, reacting users and receipt users of messages.
pub fn message_directory(ctx: &Ctx, messages: &[Message]) -> Result<Directory> {
    let users = messages
        .iter()
        .flat_map(|m| std::iter::once(&m.sender.user_id).chain(m.reactions.keys()))
        .chain(
            messages
                .iter()
                .flat_map(|m| m.receipts.keys().map(|d| &d.user_id)),
        );
    Directory::load(ctx.store(), users)
}

/// `{"message": Message}`, printed as its history line.
pub fn message_output(ctx: &Ctx, message: &Message) -> Result<Output> {
    let directory = message_directory(ctx, std::slice::from_ref(message))?;
    let message = message_out(message, &directory);
    let human = message_line(&message);
    Ok(Output::new(&MessageWrapOut { message }, human))
}

/// `--reply <msg>`: a message of the same chat.
pub fn resolve_reply(
    ctx: &Ctx,
    chat_id: &GroupId,
    reply: Option<&str>,
) -> Result<Option<MessageId>> {
    let Some(reply) = reply else {
        return Ok(None);
    };
    let message = ctx.resolve_message(reply)?;
    if &message.group_id != chat_id {
        return Err(CliError::usage(format!(
            "message {reply} is not in chat {chat_id}"
        )));
    }
    Ok(Some(message.message_id))
}

pub async fn send(ctx: &Ctx, chat: &str, text: &str, reply: Option<&str>) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    let reply_to = resolve_reply(ctx, &chat.group_id, reply)?;
    let id = ctx.client.send_text(&chat.group_id, text, reply_to).await?;
    sent_output(ctx, &chat.group_id, &id)
}

pub async fn react(ctx: &Ctx, msg: &str, emoji: &str, remove: bool) -> Result<Output> {
    let target = ctx.resolve_message(msg)?;
    let (chat_id, target_id) = (&target.group_id, &target.message_id);
    let id = if remove {
        ctx.client.unreact(chat_id, target_id, emoji).await?
    } else {
        ctx.client.react(chat_id, target_id, emoji).await?
    };
    sent_output(ctx, chat_id, &id)
}

pub async fn edit(ctx: &Ctx, msg: &str, text: &str) -> Result<Output> {
    let target = ctx.resolve_message(msg)?;
    let id = ctx
        .client
        .edit(&target.group_id, &target.message_id, text)
        .await?;
    sent_output(ctx, &target.group_id, &id)
}

pub async fn delete(ctx: &Ctx, msg: &str) -> Result<Output> {
    let target = ctx.resolve_message(msg)?;
    let id = ctx
        .client
        .delete(&target.group_id, &target.message_id)
        .await?;
    sent_output(ctx, &target.group_id, &id)
}

pub fn history(ctx: &Ctx, chat: &str, limit: usize) -> Result<Output> {
    let chat = ctx.resolve_chat(chat)?;
    let messages: Vec<Message> = ctx.store().messages(&chat.group_id, None, limit)?;
    let directory = message_directory(ctx, &messages)?;
    let messages: Vec<_> = messages
        .iter()
        .map(|m| message_out(m, &directory))
        .collect();
    let human = messages
        .iter()
        .map(message_line)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Output::new(&MessagesOut { messages }, human))
}
