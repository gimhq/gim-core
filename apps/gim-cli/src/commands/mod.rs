//! Command implementations. Each takes a connected [`Ctx`] (except
//! `register`) and returns what to print.

pub mod account;
pub mod chats;
pub mod media;
pub mod messages;

use gim_base::StateReader;
use gim_common::{GroupId, MessageId};

use crate::error::Result;
use crate::output::{send_state_name, ChatIdOut, Output, SentOut};
use crate::profile::Ctx;

/// `{"chat_id"}`, printed as the bare id.
pub fn chat_id_output(chat_id: &GroupId) -> Output {
    let out = ChatIdOut {
        chat_id: chat_id.to_string(),
    };
    Output::new(&out, chat_id.to_string())
}

/// A message just queued: its id and current send state.
pub fn sent_output(ctx: &Ctx, chat_id: &GroupId, message_id: &MessageId) -> Result<Output> {
    let state = ctx
        .store()
        .message(message_id)?
        .and_then(|m| m.send_state)
        .map(send_state_name);
    let out = SentOut {
        message_id: message_id.to_string(),
        chat_id: chat_id.to_string(),
        send_state: state,
    };
    let human = format!("{message_id}\t{}", state.unwrap_or("sent"));
    Ok(Output::new(&out, human))
}
