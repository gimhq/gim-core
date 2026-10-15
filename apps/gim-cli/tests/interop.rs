//! CLI-to-CLI interop: three `gim` profiles (alice, bob, carol) talk to each
//! other through the real binary against the server named by
//! `GIM_SERVER_URL` (see `testing/gim-cli-interop.sh`). Without it the test
//! prints a notice and passes, so the default `cargo test` stays offline.
//!
//! Black box: only the CLI's `--json` output and exit codes are checked.
//! Profiles synchronise with `gim wait-for` only, never with sleeps.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tempfile::TempDir;

const GIM: &str = env!("CARGO_BIN_EXE_gim");
const WAIT_SECS: &str = "30";
const EXIT_TIMEOUT: i32 = 3;
const EXIT_NOT_FOUND: i32 = 4;

/// A valid 2x2 RGB PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a,
    0x73, 0x00, 0x00, 0x00, 0x11, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0x00, 0x04,
    0x50, 0xe2, 0xff, 0xff, 0xff, 0x00, 0x23, 0xec, 0x05, 0xfb, 0xd5, 0xaa, 0x1e, 0x66, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

fn server_url(test: &str) -> Option<String> {
    match std::env::var("GIM_SERVER_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipping {test}: GIM_SERVER_URL is not set");
            None
        }
    }
}

/// A handle unique to this run: the server keeps users across runs.
fn unique_handle(prefix: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{prefix}_{:x}_{:x}_{n}",
        nanos % (1 << 40),
        std::process::id()
    )
}

fn describe(args: &[&str], out: &Output) -> String {
    format!(
        "gim {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn parse(args: &[&str], out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON object ({e}):\n{}",
            describe(args, out)
        )
    })
}

/// One profile, in its own temp dir.
struct Gim {
    handle: String,
    dir: TempDir,
}

impl Gim {
    fn register(server: &str, name: &str) -> Self {
        let gim = Self {
            handle: unique_handle(name),
            dir: TempDir::new().unwrap(),
        };
        let handle = gim.handle.clone();
        let out = gim.ok(&["--server", server, "register", &handle, name]);
        assert_eq!(out["handle"], handle.as_str(), "{out}");
        gim
    }

    fn profile(&self) -> PathBuf {
        self.dir.path().join("profile")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(GIM);
        cmd.arg("--json")
            .arg("--profile")
            .arg(self.profile())
            .args(args)
            .env_remove("GIM_PROFILE")
            .env_remove("GIM_SERVER");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("gim runs")
    }

    /// Runs a command that must succeed; its JSON output.
    fn ok(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(out.status.success(), "{}", describe(args, &out));
        parse(args, &out)
    }

    /// Runs a command that must exit with `code`; its JSON error.
    fn fail(&self, args: &[&str], code: i32) -> Value {
        let out = self.run(args);
        assert_eq!(out.status.code(), Some(code), "{}", describe(args, &out));
        let value = parse(args, &out);
        assert!(
            value["error"]["code"].is_string(),
            "{}",
            describe(args, &out)
        );
        value
    }

    /// `wait-for` with the default test timeout; the matched message.
    fn wait_for(&self, chat: &str, filters: &[&str]) -> Value {
        let mut args = vec!["wait-for", chat, "--timeout", WAIT_SECS];
        args.extend_from_slice(filters);
        self.ok(&args)["message"].clone()
    }

    fn send(&self, chat: &str, text: &str) -> String {
        id_of(&self.ok(&["send", chat, text]))
    }

    fn history(&self, chat: &str) -> Vec<Value> {
        let out = self.ok(&["history", chat]);
        out["messages"].as_array().unwrap().clone()
    }

    fn chat_name(&self, chat: &str) -> Value {
        let out = self.ok(&["chats", "list"]);
        let chats = out["chats"].as_array().unwrap();
        let found = chats.iter().find(|c| c["id"] == chat);
        found.unwrap_or_else(|| panic!("{chat} not in {out}"))["name"].clone()
    }

    fn member_handles(&self, chat: &str) -> Vec<String> {
        let out = self.ok(&["members", chat]);
        let mut handles: Vec<String> = out["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["handle"].as_str().unwrap_or("?").to_string())
            .collect();
        handles.sort();
        handles
    }
}

fn id_of(sent: &Value) -> String {
    sent["message_id"].as_str().expect("message_id").to_string()
}

fn chat_of(out: &Value) -> String {
    out["chat_id"].as_str().expect("chat_id").to_string()
}

fn find<'a>(messages: &'a [Value], id: &str) -> &'a Value {
    messages
        .iter()
        .find(|m| m["id"] == id)
        .unwrap_or_else(|| panic!("{id} not in history {messages:?}"))
}

fn sorted(mut handles: Vec<&str>) -> Vec<String> {
    handles.sort();
    handles.into_iter().map(str::to_string).collect()
}

#[test]
fn cli_to_cli_interop() {
    let Some(server) = server_url("cli_to_cli_interop") else {
        return;
    };
    let alice = Gim::register(&server, "alice");
    let bob = Gim::register(&server, "bob");
    let carol = Gim::register(&server, "carol");

    let me = alice.ok(&["whoami"]);
    assert_eq!(me["handle"], alice.handle.as_str(), "{me}");
    assert_eq!(me["server"], server.as_str(), "{me}");
    let found = alice.ok(&["users", "search", &bob.handle]);
    assert_eq!(found["users"][0]["handle"], bob.handle.as_str(), "{found}");

    direct_chat(&alice, &bob);
    group_chat(&alice, &bob, &carol);
    listen(&bob, &carol);
    exit_codes(&alice);
}

/// Text, reply, reaction, edit, delete, read receipt and image in a DM.
fn direct_chat(alice: &Gim, bob: &Gim) {
    let chat = chat_of(&alice.ok(&["dm", &bob.handle]));
    let hello = alice.send(&chat, "Leaving Split at 06:00");
    let got = bob.wait_for(&chat, &["--text", "Leaving Split", "--from", &alice.handle]);
    assert_eq!(got["id"], hello.as_str(), "{got}");
    assert_eq!(got["sender"]["handle"], alice.handle.as_str(), "{got}");

    let reply = id_of(&bob.ok(&["send", &chat, "See you in Hvar", "--reply", &hello]));
    let got = alice.wait_for(&chat, &["--text", "See you in Hvar", "--from", &bob.handle]);
    assert_eq!(got["id"], reply.as_str(), "{got}");
    assert_eq!(
        find(&alice.history(&chat), &reply)["reply_to"],
        hello.as_str()
    );

    bob.ok(&["react", &hello, "👍"]);
    let got = alice.wait_for(
        &chat,
        &["--msg", &hello, "--reaction", "👍", "--from", &bob.handle],
    );
    assert_eq!(
        got["reactions"][&bob.handle],
        serde_json::json!(["👍"]),
        "{got}"
    );

    alice.ok(&["edit", &hello, "Leaving Split at 07:00"]);
    bob.wait_for(&chat, &["--msg", &hello, "--edited"]);
    let edited = find(&bob.history(&chat), &hello).clone();
    assert_eq!(edited["text"], "Leaving Split at 07:00", "{edited}");
    assert_eq!(edited["edited"], true, "{edited}");
    alice.ok(&["delete", &hello]);
    let got = bob.wait_for(&chat, &["--msg", &hello, "--deleted"]);
    assert_eq!(got["deleted"], true, "{got}");

    let tick = alice.send(&chat, "Anchored off Vis");
    bob.wait_for(&chat, &["--text", "Anchored off Vis"]);
    bob.ok(&["read", &chat]);
    let got = alice.wait_for(&chat, &["--msg", &tick, "--read-by", &bob.handle]);
    assert_eq!(got["receipts"][&bob.handle], "read", "{got}");

    let png = alice.dir.path().join("bay.png");
    std::fs::write(&png, PNG).unwrap();
    let image = id_of(&alice.ok(&[
        "send-image",
        &chat,
        path_str(&png),
        "--caption",
        "Stiniva bay",
    ]));
    let got = bob.wait_for(&chat, &["--text", "Stiniva bay", "--from", &alice.handle]);
    assert_eq!(got["id"], image.as_str(), "{got}");
    assert_eq!(got["kind"], "media", "{got}");
    assert_eq!(got["media"]["mime"], "image/png", "{got}");
    let saved = bob.dir.path().join("bay-download.png");
    let out = bob.ok(&["download", &image, path_str(&saved)]);
    assert_eq!(out["size"], PNG.len(), "{out}");
    assert_eq!(std::fs::read(&saved).unwrap(), PNG);
}

/// Create, add, rename and remove in a group of three.
fn group_chat(alice: &Gim, bob: &Gim, carol: &Gim) {
    let chat = chat_of(&alice.ok(&["group", "create", "Crew Adriatic", &bob.handle]));
    alice.ok(&["group", "add", &chat, &carol.handle]);
    alice.send(&chat, "Welcome aboard");
    carol.wait_for(
        &chat,
        &["--text", "Welcome aboard", "--from", &alice.handle],
    );
    let hi = carol.send(&chat, "Carol here, ready to sail");
    for gim in [alice, bob] {
        let got = gim.wait_for(&chat, &["--text", "Carol here", "--from", &carol.handle]);
        assert_eq!(got["id"], hi.as_str(), "{got}");
    }

    alice.ok(&["group", "rename", &chat, "Crew Ionian"]);
    for gim in [bob, carol] {
        assert_eq!(gim.chat_name(&chat), "Crew Ionian", "@{}", gim.handle);
    }

    let all = sorted(vec![&alice.handle, &bob.handle, &carol.handle]);
    assert_eq!(alice.member_handles(&chat), all);
    alice.ok(&["group", "remove", &chat, &carol.handle]);
    assert_eq!(
        alice.member_handles(&chat),
        sorted(vec![&alice.handle, &bob.handle])
    );
    alice.send(&chat, "Secret course to Corfu");
    bob.wait_for(&chat, &["--text", "Secret course", "--from", &alice.handle]);
    carol.fail(
        &[
            "wait-for",
            &chat,
            "--text",
            "Secret course",
            "--timeout",
            "3",
        ],
        EXIT_TIMEOUT,
    );
}

/// `listen` in a child process receives a message sent by another profile.
fn listen(bob: &Gim, carol: &Gim) {
    let chat = chat_of(&carol.ok(&["dm", &bob.handle]));
    let args = [
        "listen",
        "--chat",
        &chat,
        "--count",
        "1",
        "--timeout",
        WAIT_SECS,
    ];
    let mut child = bob
        .command(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("gim listen runs");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    // The first (connection) line comes after `listen` subscribed and
    // caught up, so the message below is printed as an event.
    let first = lines.next().expect("listen prints").unwrap();
    assert!(first.contains("\"connection\""), "{first}");
    let sent = carol.send(&chat, "Wind NW 4, leaving Corfu");
    let rest: Vec<String> = lines.map(Result::unwrap).collect();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}\n{rest:?}\n{stderr}", out.status);
    let events: Vec<Value> = rest
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|e: &Value| e["event"] != "connection")
        .collect();
    assert_eq!(events.len(), 1, "{rest:?}\n{stderr}");
    assert_eq!(events[0]["event"], "message", "{rest:?}");
    assert_eq!(events[0]["message"]["id"], sent.as_str(), "{rest:?}");
    assert_eq!(events[0]["message"]["text"], "Wind NW 4, leaving Corfu");
}

fn exit_codes(alice: &Gim) {
    let err = alice.fail(&["send", "no-such-chat", "hello"], EXIT_NOT_FOUND);
    assert_eq!(err["error"]["code"], "not_found", "{err}");
    let chats = alice.ok(&["chats", "list"]);
    let chat = chats["chats"][0]["id"].as_str().unwrap().to_string();
    let err = alice.fail(
        &["wait-for", &chat, "--text", "never sent", "--timeout", "1"],
        EXIT_TIMEOUT,
    );
    assert_eq!(err["error"]["code"], "timeout", "{err}");
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}
