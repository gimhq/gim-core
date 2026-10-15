//! `listen`: prints state changes as the sync loop applies them.

use std::io::{self, Write};
use std::time::Duration;

use gim_base::model::{Message, StateChange};
use gim_base::StateReader;
use gim_common::{GroupId, UserId};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{interval, sleep_until, Instant, MissedTickBehavior};

use super::{check_sync, stop_sync};
use crate::error::{CliError, Result};
use crate::output::{connection_output, event_output, text_of, Output};
use crate::profile::Ctx;
use crate::resolve::{peer_of, Directory};

pub const HELP: &str = "\
Prints one line per event: new or updated messages (edits, reactions, \
receipts), removed messages, chats, membership changes, typing and \
connection states. With --json, one JSON object per line (JSON lines), \
flushed per line:
  {\"event\":\"message\",\"message\":{...}}
  {\"event\":\"message_removed\",\"chat_id\":..,\"message_id\":..}
  {\"event\":\"chat\",\"chat\":{...}}  {\"event\":\"chat_removed\",\"chat_id\":..}
  {\"event\":\"membership\",\"chat_id\":..,\"seq\":..,\"user\":..,\"actor\":..,\"change\":..,\"at_ms\":..}
  {\"event\":\"typing\",\"chat_id\":..,\"user\":..,\"active\":..}
  {\"event\":\"connection\",\"state\":\"offline|connecting|syncing|connected\"}
Changes already applied by the initial sync are not printed.

Exit codes:
  0  stopped by Ctrl-C, --count or --until, or --timeout without --until/--count
  3  --timeout elapsed before --until or --count was reached
  (other errors: see `gim --help`)";

#[derive(Debug, clap::Args)]
pub struct ListenArgs {
    /// Only events of this chat (connection events are always printed).
    #[arg(long)]
    pub chat: Option<String>,
    /// Stop after this many seconds.
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,
    /// Stop after a message whose text or caption contains TEXT.
    #[arg(long, value_name = "TEXT")]
    pub until: Option<String>,
    /// Stop after N events (connection events are not counted).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
    pub count: Option<u64>,
}

/// Why `listen` stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Interrupted,
    Count,
    Until,
    Timeout,
    /// Nobody reads stdout any more.
    Closed,
}

/// A timeout fails only when --until or --count was still waiting.
fn outcome(stop: Stop, waiting: bool) -> Result<()> {
    match stop {
        Stop::Timeout if waiting => Err(CliError::timeout(
            "timed out before --until or --count was reached",
        )),
        Stop::Interrupted | Stop::Count | Stop::Until | Stop::Timeout | Stop::Closed => Ok(()),
    }
}

pub async fn listen(ctx: &Ctx, args: &ListenArgs, json: bool) -> Result<Output> {
    let chat = match &args.chat {
        Some(chat) => Some(ctx.resolve_chat(chat)?.group_id),
        None => None,
    };
    let mut changes = ctx.client.subscribe_changes();
    let mut states = ctx.client.subscribe_connection_state();
    ctx.client.start_sync()?;
    let result = follow(ctx, args, chat.as_ref(), json, &mut changes, &mut states).await;
    let stopped = stop_sync(ctx).await;
    let stop = result?;
    stopped?;
    outcome(stop, args.until.is_some() || args.count.is_some())?;
    Ok(Output::empty())
}

async fn follow(
    ctx: &Ctx,
    args: &ListenArgs,
    chat: Option<&GroupId>,
    json: bool,
    changes: &mut tokio::sync::broadcast::Receiver<StateChange>,
    states: &mut tokio::sync::broadcast::Receiver<gim_sdk::ConnectionState>,
) -> Result<Stop> {
    let deadline = args
        .timeout
        .map(|secs| Instant::now() + Duration::from_secs(secs));
    let timeout = async move {
        match deadline {
            Some(deadline) => sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(timeout);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut printed = 0;
    loop {
        tokio::select! {
            _ = &mut ctrl_c => return Ok(Stop::Interrupted),
            () = &mut timeout => return Ok(Stop::Timeout),
            _ = tick.tick() => check_sync(ctx)?,
            state = states.recv() => match state {
                Ok(state) => {
                    if !emit(&connection_output(state), json)? {
                        return Ok(Stop::Closed);
                    }
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return Err(CliError::other("connection stream closed")),
            },
            change = changes.recv() => {
                let change = match change {
                    Ok(change) => change,
                    Err(RecvError::Lagged(n)) => {
                        eprintln!("gim: skipped {n} events");
                        continue;
                    }
                    Err(RecvError::Closed) => return Err(CliError::other("change stream closed")),
                };
                if change == StateChange::KeyPackagesLow {
                    if let Err(err) = ctx.client.replenish_key_packages().await {
                        eprintln!("gim: replenishing KeyPackages failed: {err}");
                    }
                    continue;
                }
                if chat.is_some_and(|chat| chat_of(&change) != Some(chat)) {
                    continue;
                }
                let Some(event) = event_for(ctx, &change)? else {
                    continue;
                };
                if !emit(&event, json)? {
                    return Ok(Stop::Closed);
                }
                printed += 1;
                if args.until.as_deref().is_some_and(|until| until_reached(&change, until)) {
                    return Ok(Stop::Until);
                }
                if args.count.is_some_and(|count| printed >= count) {
                    return Ok(Stop::Count);
                }
            }
        }
    }
}

/// Prints one event line and flushes it; `false` once stdout is closed.
fn emit(event: &Output, json: bool) -> Result<bool> {
    let line = if json {
        event.json.to_string()
    } else {
        event.human.clone()
    };
    let mut out = io::stdout().lock();
    match writeln!(out, "{line}").and_then(|()| out.flush()) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// The chat a change is about.
fn chat_of(change: &StateChange) -> Option<&GroupId> {
    match change {
        StateChange::ChatUpserted(chat) => Some(&chat.group_id),
        StateChange::ChatRemoved(group_id)
        | StateChange::MessageRemoved { group_id, .. }
        | StateChange::Typing { group_id, .. } => Some(group_id),
        StateChange::MessageUpserted(message) => Some(&message.group_id),
        StateChange::MembershipChanged(event) => Some(&event.group_id),
        StateChange::KeyPackagesLow => None,
    }
}

/// Whether a change is a message whose text or caption contains `until`.
fn until_reached(change: &StateChange, until: &str) -> bool {
    matches!(change, StateChange::MessageUpserted(message)
        if text_of(message).is_some_and(|text| text.contains(until)))
}

/// Users a change names, for the directory of its line.
fn users_of_change<'a>(change: &'a StateChange, me: &'a UserId) -> Vec<&'a UserId> {
    match change {
        StateChange::MessageUpserted(m) => std::iter::once(&m.sender.user_id)
            .chain(m.reactions.keys())
            .chain(m.receipts.keys().map(|d| &d.user_id))
            .collect(),
        StateChange::ChatUpserted(chat) => peer_of(chat, me).into_iter().collect(),
        StateChange::MembershipChanged(event) => vec![&event.user_id, &event.actor],
        StateChange::Typing { user_id, .. } => vec![user_id],
        StateChange::ChatRemoved(_)
        | StateChange::MessageRemoved { .. }
        | StateChange::KeyPackagesLow => Vec::new(),
    }
}

fn event_for(ctx: &Ctx, change: &StateChange) -> Result<Option<Output>> {
    let me = &ctx.session.device.user_id;
    let store = ctx.store();
    let directory = Directory::load(store, users_of_change(change, me))?;
    let last: Option<Message> = match change {
        StateChange::ChatUpserted(chat) => match &chat.last_message_id {
            Some(id) => store.message(id)?,
            None => None,
        },
        _ => None,
    };
    Ok(event_output(change, me, &directory, last.as_ref()))
}

#[cfg(test)]
mod tests {
    use gim_base::model::MessageContent;
    use gim_common::{DeviceRef, MessageId};

    use super::*;
    use crate::error::{ErrorKind, EXIT_TIMEOUT};

    fn message(text: &str) -> StateChange {
        StateChange::MessageUpserted(Message {
            message_id: MessageId::new("m-1").unwrap(),
            group_id: GroupId::new("g-1").unwrap(),
            seq: Some(1),
            sender: DeviceRef::parse("u-bob", "d-b1").unwrap(),
            sent_at_ms: 1,
            content: MessageContent::Text { body: text.into() },
            reply_to: None,
            edited: false,
            deleted: false,
            reactions: Default::default(),
            send_state: None,
            receipts: Default::default(),
        })
    }

    #[test]
    fn timeout_fails_only_while_waiting() {
        let err = outcome(Stop::Timeout, true).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Timeout);
        assert_eq!(err.kind.exit_code(), EXIT_TIMEOUT);
        assert_eq!(err.kind.name(), "timeout");
        assert!(outcome(Stop::Timeout, false).is_ok());
        for stop in [Stop::Interrupted, Stop::Count, Stop::Until, Stop::Closed] {
            assert!(outcome(stop, true).is_ok(), "{stop:?}");
        }
    }

    #[test]
    fn until_matches_message_text_only() {
        assert!(until_reached(&message("Moored in Split"), "Split"));
        assert!(!until_reached(&message("Moored in Split"), "Hvar"));
        let typing = StateChange::Typing {
            group_id: GroupId::new("g-1").unwrap(),
            user_id: UserId::new("u-bob").unwrap(),
            active: true,
        };
        assert!(!until_reached(&typing, "Split"));
    }

    #[test]
    fn changes_belong_to_their_chat() {
        assert_eq!(chat_of(&message("x")).map(GroupId::as_str), Some("g-1"));
        let removed = StateChange::ChatRemoved(GroupId::new("g-2").unwrap());
        assert_eq!(chat_of(&removed).map(GroupId::as_str), Some("g-2"));
        assert_eq!(chat_of(&StateChange::KeyPackagesLow), None);
    }
}
