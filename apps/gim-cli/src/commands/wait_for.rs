//! `wait-for`: waits until a message of a chat matches filters, or until a
//! given message reaches some states.

use std::time::Duration;

use gim_base::model::{Message, StateChange};
use gim_base::StateReader;
use gim_common::{GroupId, MessageId, UserId};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{interval, sleep, MissedTickBehavior};

use super::messages::message_output;
use super::{check_sync, stop_sync};
use crate::error::{CliError, Result};
use crate::output::{serde_name, text_of, Output};
use crate::profile::Ctx;

pub const HELP: &str = "\
Without --msg, waits for a message of the chat matching all of --text and \
--from; messages already in the store count. With --msg, waits until that \
message has all of the given states (--from then names who must have \
reacted with --reaction). Prints the message ({\"message\":{...}} with \
--json).

Exit codes:
  0  matched
  2  no filter given, or an invalid combination
  3  --timeout elapsed first
  (other errors: see `gim --help`)";

/// Messages per store page when searching a chat.
const PAGE: usize = 200;

#[derive(Debug, clap::Args)]
#[command(group(
    clap::ArgGroup::new("filter")
        .required(true)
        .multiple(true)
        .args(["text", "from", "reaction", "read_by", "delivered_to", "edited", "deleted"]),
))]
pub struct WaitForArgs {
    pub chat: String,
    /// The text or caption contains TEXT.
    #[arg(long)]
    pub text: Option<String>,
    /// Sent by this user; with --msg, the user of --reaction.
    #[arg(long, value_name = "HANDLE")]
    pub from: Option<String>,
    /// Wait for states of this message of the chat.
    #[arg(long, value_name = "MSG")]
    pub msg: Option<String>,
    /// Has this reaction.
    #[arg(long, value_name = "EMOJI", requires = "msg")]
    pub reaction: Option<String>,
    /// Read by this user.
    #[arg(long, value_name = "HANDLE", requires = "msg")]
    pub read_by: Option<String>,
    /// Delivered to (or read by) this user.
    #[arg(long, value_name = "HANDLE", requires = "msg")]
    pub delivered_to: Option<String>,
    /// Edited.
    #[arg(long, requires = "msg")]
    pub edited: bool,
    /// Deleted.
    #[arg(long, requires = "msg")]
    pub deleted: bool,
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    pub timeout: u64,
}

/// What the message must satisfy; every given part must hold.
#[derive(Debug, Default)]
pub struct Filter {
    pub text: Option<String>,
    pub sender: Option<UserId>,
    /// An emoji, and who must have reacted with it (`None`: anyone).
    pub reaction: Option<(String, Option<UserId>)>,
    pub read_by: Option<UserId>,
    pub delivered_to: Option<UserId>,
    pub edited: bool,
    pub deleted: bool,
}

impl Filter {
    pub fn matches(&self, m: &Message) -> bool {
        self.text
            .as_deref()
            .is_none_or(|text| text_of(m).is_some_and(|t| t.contains(text)))
            && self.sender.as_ref().is_none_or(|u| &m.sender.user_id == u)
            && self.reaction.as_ref().is_none_or(|(emoji, by)| {
                m.reactions.iter().any(|(user, emojis)| {
                    by.as_ref().is_none_or(|by| by == user) && emojis.contains(emoji)
                })
            })
            && self
                .read_by
                .as_ref()
                .is_none_or(|u| has_receipt(m, u, &["read"]))
            && self
                .delivered_to
                .as_ref()
                .is_none_or(|u| has_receipt(m, u, &["delivered", "read"]))
            && (!self.edited || m.edited)
            && (!self.deleted || m.deleted)
    }
}

/// Whether a device of `user` reported one of these receipt kinds.
fn has_receipt(m: &Message, user: &UserId, kinds: &[&str]) -> bool {
    m.receipts
        .iter()
        .any(|(device, kind)| &device.user_id == user && kinds.contains(&serde_name(kind).as_str()))
}

/// Combinations clap cannot express.
fn check_args(args: &WaitForArgs) -> Result<()> {
    if args.msg.is_some() && args.from.is_some() && args.reaction.is_none() {
        return Err(CliError::usage("--from with --msg requires --reaction"));
    }
    if args.msg.is_none() && args.text.is_none() && args.from.is_none() {
        return Err(CliError::usage(
            "--text or --from is required without --msg",
        ));
    }
    Ok(())
}

async fn resolve(ctx: &Ctx, handle: Option<&str>) -> Result<Option<UserId>> {
    Ok(match handle {
        Some(handle) => Some(ctx.resolve_user(handle).await?.user_id),
        None => None,
    })
}

async fn filter(ctx: &Ctx, args: &WaitForArgs) -> Result<Filter> {
    let from = resolve(ctx, args.from.as_deref()).await?;
    let (sender, reactor) = match args.msg {
        Some(_) => (None, from),
        None => (from, None),
    };
    Ok(Filter {
        text: args.text.clone(),
        sender,
        reaction: args.reaction.clone().map(|emoji| (emoji, reactor)),
        read_by: resolve(ctx, args.read_by.as_deref()).await?,
        delivered_to: resolve(ctx, args.delivered_to.as_deref()).await?,
        edited: args.edited,
        deleted: args.deleted,
    })
}

/// What to wait for, in which chat.
struct Target {
    chat: GroupId,
    msg: Option<MessageId>,
    filter: Filter,
}

impl Target {
    /// The matching message in the store: the given one, else the newest
    /// match among the latest `pages` pages of the chat (all if `None`).
    fn find(&self, store: &impl StateReader, pages: Option<usize>) -> Result<Option<Message>> {
        if let Some(id) = &self.msg {
            return Ok(store.message(id)?.filter(|m| self.filter.matches(m)));
        }
        let mut before = None;
        let mut pages = pages;
        loop {
            let page = store.messages(&self.chat, before, PAGE)?;
            let full = page.len() == PAGE;
            let oldest = page.first().and_then(|m| m.seq);
            if let Some(m) = page.into_iter().rev().find(|m| self.filter.matches(m)) {
                return Ok(Some(m));
            }
            pages = pages.map(|p| p.saturating_sub(1));
            match oldest {
                Some(seq) if full && pages != Some(0) => before = Some(seq),
                _ => return Ok(None),
            }
        }
    }

    /// Whether a change may make the target match.
    fn concerns(&self, change: &StateChange) -> bool {
        match change {
            StateChange::MessageUpserted(m) => match &self.msg {
                Some(id) => &m.message_id == id,
                None => m.group_id == self.chat,
            },
            StateChange::MessageRemoved { message_id, .. } => self.msg.as_ref() == Some(message_id),
            _ => false,
        }
    }
}

pub async fn wait_for(ctx: &Ctx, args: &WaitForArgs) -> Result<Output> {
    check_args(args)?;
    let chat = ctx.resolve_chat(&args.chat)?.group_id;
    let msg = match &args.msg {
        Some(arg) => {
            let message = ctx.resolve_message(arg)?;
            if message.group_id != chat {
                return Err(CliError::usage(format!(
                    "message {arg} is not in chat {chat}"
                )));
            }
            Some(message.message_id)
        }
        None => None,
    };
    let target = Target {
        chat,
        msg,
        filter: filter(ctx, args).await?,
    };
    if let Some(message) = target.find(ctx.store(), None)? {
        return message_output(ctx, &message);
    }
    let mut changes = ctx.client.subscribe_changes();
    ctx.client.start_sync()?;
    let result = wait(ctx, &target, args.timeout, &mut changes).await;
    let stopped = stop_sync(ctx).await;
    let message = result?;
    stopped?;
    message_output(ctx, &message)
}

async fn wait(
    ctx: &Ctx,
    target: &Target,
    secs: u64,
    changes: &mut tokio::sync::broadcast::Receiver<StateChange>,
) -> Result<Message> {
    let timeout = sleep(Duration::from_secs(secs));
    tokio::pin!(timeout);
    // Safety net besides the change stream.
    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let found = tokio::select! {
            () = &mut timeout => {
                return Err(CliError::timeout(format!("no match within {secs} s")));
            }
            _ = tick.tick() => {
                check_sync(ctx)?;
                target.find(ctx.store(), Some(1))?
            }
            change = changes.recv() => match change {
                Ok(change) if target.concerns(&change) => target.find(ctx.store(), Some(1))?,
                Ok(_) => None,
                Err(RecvError::Lagged(_)) => target.find(ctx.store(), None)?,
                Err(RecvError::Closed) => return Err(CliError::other("change stream closed")),
            },
        };
        if let Some(message) = found {
            return Ok(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use clap::Parser;
    use gim_base::model::MessageContent;
    use gim_common::DeviceRef;

    use super::*;
    use crate::error::ErrorKind;

    fn uid(id: &str) -> UserId {
        UserId::new(id).unwrap()
    }

    /// Own message to bob and carol: bob reacted ⛵, bob's phone read it,
    /// carol's device got it.
    fn message() -> Message {
        let receipt = |kind: &str| serde_json::from_value(serde_json::json!(kind)).unwrap();
        Message {
            message_id: MessageId::new("m-1").unwrap(),
            group_id: GroupId::new("g-1").unwrap(),
            seq: Some(3),
            sender: DeviceRef::parse("u-alice", "d-a1").unwrap(),
            sent_at_ms: 1,
            content: MessageContent::Text {
                body: "Leaving Dubrovnik at 06:00".into(),
            },
            reply_to: None,
            edited: false,
            deleted: false,
            reactions: BTreeMap::from([(uid("u-bob"), BTreeSet::from(["⛵".to_string()]))]),
            send_state: None,
            receipts: BTreeMap::from([
                (
                    DeviceRef::parse("u-bob", "d-b1").unwrap(),
                    receipt("delivered"),
                ),
                (DeviceRef::parse("u-bob", "d-b2").unwrap(), receipt("read")),
                (
                    DeviceRef::parse("u-carol", "d-c1").unwrap(),
                    receipt("delivered"),
                ),
            ]),
        }
    }

    #[test]
    fn text_and_sender_filters() {
        let m = message();
        let f = |text: Option<&str>, sender: Option<&str>| Filter {
            text: text.map(str::to_string),
            sender: sender.map(uid),
            ..Filter::default()
        };
        assert!(f(Some("Dubrovnik"), None).matches(&m));
        assert!(f(Some("Dubrovnik"), Some("u-alice")).matches(&m));
        assert!(!f(Some("Dubrovnik"), Some("u-bob")).matches(&m));
        assert!(!f(Some("Kotor"), Some("u-alice")).matches(&m));
        assert!(f(None, None).matches(&m));
        let mut empty = m.clone();
        empty.content = MessageContent::Text {
            body: String::new(),
        };
        assert!(!f(Some("Dubrovnik"), None).matches(&empty));
    }

    #[test]
    fn reaction_filter_by_anyone_or_one_user() {
        let m = message();
        let f = |emoji: &str, by: Option<&str>| Filter {
            reaction: Some((emoji.to_string(), by.map(uid))),
            ..Filter::default()
        };
        assert!(f("⛵", None).matches(&m));
        assert!(f("⛵", Some("u-bob")).matches(&m));
        assert!(!f("⛵", Some("u-carol")).matches(&m));
        assert!(!f("👍", None).matches(&m));
    }

    #[test]
    fn receipt_filters() {
        let m = message();
        let read = |u: &str| Filter {
            read_by: Some(uid(u)),
            ..Filter::default()
        };
        let delivered = |u: &str| Filter {
            delivered_to: Some(uid(u)),
            ..Filter::default()
        };
        // Any device of the user counts.
        assert!(read("u-bob").matches(&m));
        assert!(!read("u-carol").matches(&m));
        assert!(delivered("u-bob").matches(&m));
        assert!(delivered("u-carol").matches(&m));
        assert!(!delivered("u-dave").matches(&m));
        // Read implies delivered.
        let mut only_read = m.clone();
        only_read
            .receipts
            .retain(|d, _| d.device_id.as_str() == "d-b2");
        assert!(delivered("u-bob").matches(&only_read));
    }

    #[test]
    fn edited_deleted_and_combined_filters() {
        let mut m = message();
        let f = Filter {
            text: Some("Dubrovnik".into()),
            reaction: Some(("⛵".into(), None)),
            read_by: Some(uid("u-bob")),
            edited: true,
            ..Filter::default()
        };
        assert!(!f.matches(&m));
        m.edited = true;
        assert!(f.matches(&m));
        let deleted = Filter {
            deleted: true,
            ..Filter::default()
        };
        assert!(!deleted.matches(&m));
        m.deleted = true;
        assert!(deleted.matches(&m));
    }

    #[derive(Debug, Parser)]
    struct Cmd {
        #[command(flatten)]
        args: WaitForArgs,
    }

    fn parse(args: &[&str]) -> std::result::Result<WaitForArgs, clap::Error> {
        Cmd::try_parse_from(std::iter::once("wait-for").chain(args.iter().copied())).map(|c| c.args)
    }

    #[test]
    fn filters_are_required_and_checked() {
        let usage = |args: &[&str]| match parse(args) {
            Err(err) => err.exit_code() == 2,
            Ok(args) => check_args(&args).unwrap_err().kind == ErrorKind::Usage,
        };
        assert!(usage(&["crew"]));
        assert!(usage(&["crew", "--timeout", "5"]));
        // State filters need --msg.
        assert!(usage(&["crew", "--edited"]));
        assert!(usage(&["crew", "--read-by", "bob"]));
        // --msg needs a state (or --text) filter; --from qualifies --reaction.
        assert!(usage(&["crew", "--msg", "m-1", "--from", "bob"]));
        assert!(usage(&["crew", "--msg", "m-1"]));
        for ok in [
            &["crew", "--text", "Split"][..],
            &["crew", "--from", "bob"],
            &["crew", "--msg", "m-1", "--deleted"],
            &["crew", "--msg", "m-1", "--reaction", "⛵", "--from", "bob"],
        ] {
            let args = parse(ok).unwrap();
            check_args(&args).unwrap();
            assert_eq!(args.timeout, 30);
        }
    }

    #[test]
    fn timeout_maps_to_exit_code_3() {
        let err = CliError::timeout("no match within 30 s");
        assert_eq!(err.kind.exit_code(), 3);
        assert_eq!(err.kind.name(), "timeout");
    }
}
