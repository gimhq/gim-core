//! `gim`: command-line client of gim, built on the public gim-sdk API.
//!
//! Every command is one-shot: it opens the profile directory (SQLite store,
//! `secrets.json`, `config.json`), restores the session, catches up with
//! one `sync_once`, runs, and flushes the outbox before exiting. Only
//! `listen` and `wait-for` run the background sync loop, stopped before
//! exiting.
//!
//! A profile must never be used by two `gim` processes at the same time
//! (nor by anything else): there is no locking beyond SQLite's own, and
//! concurrent syncs or sends of one device would corrupt its MLS state.

#![forbid(unsafe_code)]

mod commands;
mod error;
mod output;
mod profile;
mod resolve;
mod secrets;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::commands::{account, chats, listen, media, messages, wait_for};
use crate::error::{exit_codes_help, CliError, Result, EXIT_OK, EXIT_USAGE};
use crate::output::{print_error, Output};
use crate::profile::Ctx;

#[derive(Debug, Parser)]
#[command(
    name = "gim",
    version,
    about = "Command-line gim client",
    long_about = long_about(),
)]
struct Cli {
    /// Profile directory (store, session, config). Required.
    #[arg(long, env = "GIM_PROFILE", global = true, value_name = "DIR")]
    profile: Option<PathBuf>,
    /// Server base URL; saved to the profile by `register`, read from it
    /// otherwise.
    #[arg(long, env = "GIM_SERVER", global = true, value_name = "URL")]
    server: Option<String>,
    /// Print exactly one JSON object on stdout (errors included).
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

fn long_about() -> String {
    format!(
        "Command-line gim client. Each command restores the profile's session, \
         syncs once, runs and sends what it queued before exiting. Never use one \
         profile from two processes at once.\n\n{}",
        exit_codes_help()
    )
}

const MEMBERS_ABOUT: &str = "Lists devices known from chat membership only.";

const TYPING_ABOUT: &str = "Typing indicators expire on their own; --stop only takes effect \
     within the same process that sent the start (gim-sdk keeps typing state in memory), \
     so from a fresh process it is a no-op.";

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new identity with this device and claim a handle
    /// (requires --server); prints the recovery code once.
    Register {
        handle: String,
        display_name: String,
    },
    /// Show this profile's user and device.
    Whoami,
    /// Look up users.
    #[command(subcommand)]
    Users(UsersCommand),
    /// List chats.
    #[command(subcommand)]
    Chats(ChatsCommand),
    /// Open (or create) the direct chat with a user; prints the chat id.
    Dm { handle: String },
    /// Manage group chats.
    #[command(subcommand)]
    Group(GroupCommand),
    /// List the members of a chat.
    #[command(long_about = MEMBERS_ABOUT)]
    Members { chat: String },
    /// Send a text message.
    Send {
        chat: String,
        text: String,
        /// Message to reply to.
        #[arg(long, value_name = "MSG")]
        reply: Option<String>,
    },
    /// Send an image.
    SendImage {
        chat: String,
        path: PathBuf,
        #[arg(long)]
        caption: Option<String>,
        /// Message to reply to.
        #[arg(long, value_name = "MSG")]
        reply: Option<String>,
    },
    /// Send a file.
    SendFile {
        chat: String,
        path: PathBuf,
        #[arg(long)]
        caption: Option<String>,
        /// Message to reply to.
        #[arg(long, value_name = "MSG")]
        reply: Option<String>,
    },
    /// React to a message.
    React {
        msg: String,
        emoji: String,
        /// Remove the reaction instead.
        #[arg(long)]
        remove: bool,
    },
    /// Edit an own message.
    Edit { msg: String, text: String },
    /// Delete an own message.
    Delete { msg: String },
    /// Mark a chat read.
    Read { chat: String },
    /// Show a chat's latest messages, oldest first.
    History {
        chat: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Send a typing notification.
    #[command(long_about = TYPING_ABOUT)]
    Typing {
        chat: String,
        /// Stop typing instead.
        #[arg(long)]
        stop: bool,
    },
    /// Download the media of a message.
    Download { msg: String, path: PathBuf },
    /// Print events as they arrive until Ctrl-C, --timeout, --count or
    /// --until.
    #[command(after_help = listen::HELP)]
    Listen(listen::ListenArgs),
    /// Wait until a message matches filters, or a message reaches states.
    #[command(after_help = wait_for::HELP)]
    WaitFor(wait_for::WaitForArgs),
}

#[derive(Debug, Subcommand)]
enum UsersCommand {
    /// Find a user by exact handle (0 or 1 result).
    ///
    /// Exact handle lookup; substring search is not available yet.
    Search {
        /// Handle, with or without a leading '@'.
        query: String,
    },
}

#[derive(Debug, Subcommand)]
enum ChatsCommand {
    /// List all chats, most recent first.
    List,
}

#[derive(Debug, Subcommand)]
enum GroupCommand {
    /// Create a group chat; prints the chat id.
    Create {
        name: String,
        #[arg(required = true)]
        handles: Vec<String>,
    },
    /// Add users to a group.
    Add {
        chat: String,
        #[arg(required = true)]
        handles: Vec<String>,
    },
    /// Remove users from a group.
    Remove {
        chat: String,
        #[arg(required = true)]
        handles: Vec<String>,
    },
    /// Rename a group.
    Rename { chat: String, name: String },
    /// Leave a group.
    Leave { chat: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) if !err.use_stderr() => {
            // --help / --version.
            let _ = err.print();
            return ExitCode::from(EXIT_OK);
        }
        Err(err) if std::env::args_os().any(|a| a == "--json") => {
            let message = err.render().to_string();
            print_error(&CliError::usage(message.trim()), true);
            return ExitCode::from(EXIT_USAGE);
        }
        Err(err) => err.exit(),
    };
    let json = cli.json;
    match run(cli).await {
        Ok(output) => {
            output.print(json);
            ExitCode::from(EXIT_OK)
        }
        Err(err) => {
            print_error(&err, json);
            ExitCode::from(err.kind.exit_code())
        }
    }
}

async fn run(cli: Cli) -> Result<Output> {
    let dir = cli
        .profile
        .ok_or_else(|| CliError::usage("--profile (or GIM_PROFILE) is required"))?;
    let server = cli.server.as_deref();
    if let Command::Register {
        handle,
        display_name,
    } = &cli.command
    {
        return account::register(&dir, server, handle, display_name).await;
    }
    let ctx = Ctx::connect(&dir, server).await?;
    let output = dispatch(&ctx, cli.command, cli.json).await?;
    ctx.client.flush_outbox().await?;
    Ok(output)
}

async fn dispatch(ctx: &Ctx, command: Command, json: bool) -> Result<Output> {
    match command {
        Command::Register { .. } => unreachable!("handled before connecting"),
        Command::Whoami => account::whoami(ctx),
        Command::Users(UsersCommand::Search { query }) => account::search_users(ctx, &query).await,
        Command::Chats(ChatsCommand::List) => chats::list(ctx),
        Command::Dm { handle } => chats::dm(ctx, &handle).await,
        Command::Group(GroupCommand::Create { name, handles }) => {
            chats::group_create(ctx, &name, &handles).await
        }
        Command::Group(GroupCommand::Add { chat, handles }) => {
            chats::group_add(ctx, &chat, &handles).await
        }
        Command::Group(GroupCommand::Remove { chat, handles }) => {
            chats::group_remove(ctx, &chat, &handles).await
        }
        Command::Group(GroupCommand::Rename { chat, name }) => {
            chats::group_rename(ctx, &chat, &name).await
        }
        Command::Group(GroupCommand::Leave { chat }) => chats::group_leave(ctx, &chat).await,
        Command::Members { chat } => chats::members(ctx, &chat),
        Command::Send { chat, text, reply } => {
            messages::send(ctx, &chat, &text, reply.as_deref()).await
        }
        Command::SendImage {
            chat,
            path,
            caption,
            reply,
        } => media::send_media(ctx, &chat, &path, caption, reply.as_deref(), true).await,
        Command::SendFile {
            chat,
            path,
            caption,
            reply,
        } => media::send_media(ctx, &chat, &path, caption, reply.as_deref(), false).await,
        Command::React { msg, emoji, remove } => messages::react(ctx, &msg, &emoji, remove).await,
        Command::Edit { msg, text } => messages::edit(ctx, &msg, &text).await,
        Command::Delete { msg } => messages::delete(ctx, &msg).await,
        Command::Read { chat } => chats::read(ctx, &chat).await,
        Command::History { chat, limit } => messages::history(ctx, &chat, limit),
        Command::Typing { chat, stop } => chats::typing(ctx, &chat, stop).await,
        Command::Download { msg, path } => media::download(ctx, &msg, &path).await,
        Command::Listen(args) => listen::listen(ctx, &args, json).await,
        Command::WaitFor(args) => wait_for::wait_for(ctx, &args).await,
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_lists_commands_and_exit_codes() {
        let help = Cli::command().render_long_help().to_string();
        for name in [
            "register",
            "whoami",
            "users",
            "chats",
            "dm",
            "group",
            "members",
            "send",
            "send-image",
            "send-file",
            "react",
            "edit",
            "delete",
            "read",
            "history",
            "typing",
            "download",
            "listen",
            "wait-for",
        ] {
            assert!(
                help.contains(&format!("  {name} ")),
                "{name} missing:\n{help}"
            );
        }
        assert!(help.contains("5  server, network or transport error"));
    }

    #[test]
    fn typing_and_members_help_state_their_limits() {
        let mut cli = Cli::command();
        for (name, about) in [("typing", TYPING_ABOUT), ("members", MEMBERS_ABOUT)] {
            let help = cli
                .find_subcommand_mut(name)
                .unwrap()
                .render_long_help()
                .to_string();
            assert!(help.contains(about), "{name}:\n{help}");
        }
        assert!(TYPING_ABOUT.contains("from a fresh process it is a no-op."));
        assert_eq!(
            MEMBERS_ABOUT,
            "Lists devices known from chat membership only."
        );
    }

    #[test]
    fn users_search_help_says_exact_handle_lookup() {
        let mut cli = Cli::command();
        let search = cli
            .find_subcommand_mut("users")
            .and_then(|users| users.find_subcommand_mut("search"))
            .unwrap();
        let help = search.render_long_help().to_string();
        assert!(
            help.contains("Exact handle lookup; substring search is not available yet."),
            "{help}"
        );
    }

    #[test]
    fn listen_and_wait_for_help_document_options_and_exit_codes() {
        let mut cli = Cli::command();
        for (name, options) in [
            ("listen", &["--chat", "--timeout", "--until", "--count"][..]),
            (
                "wait-for",
                &[
                    "--text",
                    "--from",
                    "--msg",
                    "--reaction",
                    "--read-by",
                    "--delivered-to",
                    "--edited",
                    "--deleted",
                    "--timeout",
                ],
            ),
        ] {
            let help = cli
                .find_subcommand_mut(name)
                .unwrap()
                .render_long_help()
                .to_string();
            for option in options {
                assert!(help.contains(option), "{name} {option}:\n{help}");
            }
            assert!(help.contains("Exit codes:"), "{name}:\n{help}");
            assert!(help.contains("3  "), "{name}:\n{help}");
        }
    }

    #[test]
    fn parses_listen_and_wait_for() {
        let cli =
            Cli::try_parse_from(["gim", "listen", "--chat", "crew", "--until", "ok", "--json"])
                .unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Command::Listen(listen::ListenArgs {
                count: None,
                timeout: None,
                ..
            })
        ));
        let err = Cli::try_parse_from(["gim", "listen", "--count", "0"]).unwrap_err();
        assert_eq!(err.exit_code(), i32::from(EXIT_USAGE));
        let err = Cli::try_parse_from(["gim", "wait-for", "crew"]).unwrap_err();
        assert_eq!(err.exit_code(), i32::from(EXIT_USAGE));
        let cli = Cli::try_parse_from(["gim", "wait-for", "crew", "--text", "Split"]).unwrap();
        assert!(matches!(cli.command, Command::WaitFor(ref a) if a.timeout == 30));
    }

    #[test]
    fn parses_global_options_after_the_command() {
        let cli = Cli::try_parse_from([
            "gim",
            "history",
            "crew",
            "--limit",
            "5",
            "--json",
            "--profile",
            "/p",
        ])
        .unwrap();
        assert!(cli.json);
        assert_eq!(cli.profile, Some(PathBuf::from("/p")));
        assert!(matches!(cli.command, Command::History { limit: 5, .. }));
        let err = Cli::try_parse_from(["gim", "group", "create", "crew"]).unwrap_err();
        assert_eq!(err.exit_code(), i32::from(EXIT_USAGE));
    }
}
