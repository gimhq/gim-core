# gim-core

Rust core shared by the gim native clients (iOS, Android): MLS end-to-end
encryption (OpenMLS), and — as later work lands — storage, networking, sync,
outbox and UI-facing services, exposed to Swift and Kotlin through UniFFI.

The workspace is modelled on matrix-rust-sdk: one role per crate, dependencies
point downwards only
(`common ← proto ← crypto ← base ← sqlite`, `base + crypto + proto ← sdk ← ui ← ffi`).

| Crate | Role |
|---|---|
| `crates/gim-common` | ids (`UserId`, `DeviceId`, `GroupId`, `ClientId`, `MessageId`, `DeviceRef`), error helpers, time; no I/O |
| `crates/gim-proto` | gim-server v1 REST/stream DTOs, gim-hub API v2 DTOs (`v2`, vendored contract in `contract/hub-v2/`) and the versioned CBOR envelope schema |
| `crates/gim-crypto` | OpenMLS wrapper (`MlsEngine`), `CryptoStore` trait + `MemoryCryptoStore`; no networking |
| `crates/gim-identity` | root and device Ed25519 keys, `user_id`/`device_id` derivation, signed `DeviceCert` and `DeviceList` (spec: `docs/identity.md`); no I/O |
| `crates/gim-base` | client state machine without networking, `StateStore` trait (skeleton) |
| `crates/gim-sqlite` | rusqlite `StateStore` + `CryptoStore` on one database (skeleton) |
| `crates/gim-sdk` | async `Client`: HTTP, WebSocket/long-poll, sync, outbox, media (skeleton) |
| `crates/gim-ui` | chat list and timeline `VectorDiff` streams (skeleton) |
| `bindings/gim-ffi` | the only UniFFI crate; builds `libgim_core.{so,a,dylib}` |
| `bindings/android`, `bindings/apple` | packaging scripts |
| `uniffi-bindgen` | `uniffi-bindgen` binary used by the packaging scripts |
| `testing/gim-test` | fixtures and `FakeDeliveryService` (in-memory gim-server delivery) |
| `testing/gim-integration-testing` | tests against a real gim-server container (skeleton) |

MLS ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, pure-Rust
crypto (RustCrypto provider), no C toolchain needed.

## Checks

Builds run in a container:

```sh
mkdir -p /srv/.tmp/cache/cargo
docker run --rm --label ai-agent=true -v "$PWD:$PWD" -w "$PWD" \
  -v /srv/.tmp/cache/cargo:/cache/cargo -e CARGO_HOME=/cache/cargo rust:1 \
  sh -c 'rustup component add rustfmt clippy && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test'
```

## CLI (gim)

`apps/gim-cli` builds `gim`, a command-line client on the public gim-sdk
API, for scripted interop runs against gim-server and the mobile apps.

```sh
cargo build -p gim-cli          # -> target/debug/gim
```

### Profiles

Every command needs a profile directory: `--profile DIR` (or `GIM_PROFILE`).
It holds the SQLite store (`gim.sqlite3`), the session (`secrets.json`, mode
0600; refused if group/other bits are set) and `config.json` (server URL).
`register` creates the profile and needs `--server URL` (or `GIM_SERVER`); later
commands read the URL from the profile. One profile is one device: never use it
from two `gim` processes at once (concurrent syncs or sends corrupt its MLS
state); use one profile per simulated user.

Each command restores the session, syncs once, runs and sends what it queued
before exiting. Only `listen` and `wait-for` keep syncing while they run.

### Commands

`<chat>` is a chat id, a unique chat name, or the handle of a direct-chat peer
(`@bob`); `<msg>` is a message id.

| Command | What it does |
|---|---|
| `register <handle> <display_name>` | Register a new user and device |
| `whoami` | This profile's user, device and server |
| `users search <handle>` | Exact-handle lookup returning 0 or 1 users (substring search is not available yet) |
| `chats list` | All chats, most recent first |
| `dm <handle>` | Open (or create) the direct chat; prints the chat id |
| `group create <name> <handle>...` | Create a group; prints the chat id |
| `group add\|remove <chat> <handle>...` | Add or remove members |
| `group rename <chat> <name>`, `group leave <chat>` | Rename or leave a group |
| `members <chat>` | Members and their devices; lists devices known from chat membership only |
| `send <chat> <text> [--reply <msg>]` | Send text |
| `send-image\|send-file <chat> <path> [--caption T] [--reply <msg>]` | Send media |
| `react <msg> <emoji> [--remove]` | Add or remove a reaction |
| `edit <msg> <text>`, `delete <msg>` | Edit or delete an own message |
| `read <chat>` | Mark a chat read (sends read receipts) |
| `history <chat> [--limit N]` | Latest messages, oldest first |
| `typing <chat> [--stop]` | Typing notification |
| `download <msg> <path>` | Save a message's media |
| `listen [--chat C] [--timeout S] [--until T] [--count N]` | Print events as they arrive |
| `wait-for <chat> ...` | Block until a message matches (see below) |

Typing indicators expire on their own. `typing <chat> --stop` from a fresh
process is a no-op: gim-sdk keeps typing state in memory, so only the process
that started typing can stop it.

`wait-for` waits for the chat (DM peer handle, chat name or id) to appear if
the profile has not joined it yet.

### Output and exit codes

With `--json` every command prints exactly one JSON object on stdout, errors
included (`{"error": {"code", "message"}}`); ids are strings, timestamps are
milliseconds. `listen --json` prints JSON lines instead, one event per line,
flushed per line. The shapes are documented in `apps/gim-cli/src/output.rs`
and in `gim <command> --help`.

| Exit code | Meaning |
|---|---|
| 0 | ok |
| 1 | other error |
| 2 | usage error or invalid input |
| 3 | timeout (`wait-for`, `listen --until/--count`) |
| 4 | not found (profile not registered, unknown user, chat or message) |
| 5 | server, network or transport error |

### Scripting with wait-for

Synchronise scripts with `wait-for` (default `--timeout 30`), not sleeps:

```sh
gim wait-for @alice --text "Leaving Split" --from alice     # a new message
gim wait-for "$chat" --msg "$id" --reaction 👍 --from bob   # a reaction
gim wait-for "$chat" --msg "$id" --edited                   # or --deleted
gim wait-for "$chat" --msg "$id" --read-by bob              # or --delivered-to
gim --json wait-for "$chat" --text hi | jq -r .message.id   # exit 3 on timeout
gim --json listen --chat "$chat" --count 1 --timeout 30     # one JSON line
```

### Dev server and interop test

`scripts/gim-server-dev.sh` builds gim-server from `GIM_SERVER_SRC` (default
`/srv/gimhq/im-client/server`) and runs it on the `traefik` network:

```sh
url=$(scripts/gim-server-dev.sh start)    # prints http://<ip>:8080
scripts/gim-server-dev.sh stop
```

`testing/gim-cli-interop.sh` starts a server, runs
`apps/gim-cli/tests/interop.rs` (alice, bob and carol through the real binary:
DM, reply, reaction, edit, delete, read receipt, image, group of three,
`listen`, exit codes) in a `rust:1` container and stops the server. Without
`GIM_SERVER_URL` the test is skipped, so `cargo test` stays offline.

```sh
testing/gim-cli-interop.sh
```

### Two-client walkthrough

Two terminals, alice and bob. For an Android interop run, replace either side
with the app (registered against the same server) and use its handle.

```sh
scripts/gim-server-dev.sh start           # once; prints the URL
url=$(scripts/gim-server-dev.sh url)      # in each terminal

# terminal 1: alice
export GIM_PROFILE=/tmp/alice
gim --server "$url" register alice "Alice"
# terminal 2: bob
export GIM_PROFILE=/tmp/bob
gim --server "$url" register bob "Bob"

# alice
gim dm bob                                # prints the chat id
gim send @bob "Leaving Split at 06:00"
# bob
gim wait-for @alice --text "Leaving Split"   # prints the message and its id
gim send @alice "See you in Hvar" --reply <msg>
gim react <msg> 👍
gim read @alice
gim listen --chat @alice                  # live events until Ctrl-C
# alice (bob sees the edit, the image and later messages live)
gim history @bob
gim edit <msg> "Leaving Split at 07:00"
gim send-image @bob bay.png --caption "Stiniva bay"
# bob: Ctrl-C the listen first (one process per profile), then
gim wait-for @alice --text "Stiniva bay"
gim download <msg> /tmp/bay.png
```

## Bindings

```sh
cargo build -p gim-ffi
cargo run -p uniffi-bindgen -- generate --library target/debug/libgim_core.so --language kotlin --out-dir out/kotlin
cargo run -p uniffi-bindgen -- generate --library target/debug/libgim_core.so --language swift --out-dir out/swift
```

Kotlin package `im.g.gimcore`; Swift module `GIMCore` (FFI module `GIMCoreFFI`).

## Envelope and media formats

**Envelope** (`gim_proto::envelope`, carried inside MLS application messages):
one CBOR map with short keys — `v` version (`1`), `id` message id, `ts` sent
time in Unix ms, optional `re` reply-to id (text and media only), `c` content
tagged by `t`: `text`, `media`, `edit`, `delete`, `reaction`, `receipt`
(`delivered` | `read`), `typing`, `group_info`. Unknown keys are ignored;
version 0, newer versions and unknown content tags are rejected. The full key
table is in the module docs. `gim_crypto::{encrypt_envelope,
decrypt_to_envelope}` wrap encoding plus MLS application encryption.

**Media** (`gim_crypto::media`): chunked AES-256-GCM with a fresh random key
per blob.

```text
header  = "GIM1" || chunk_size (u32 BE, default 65536) || nonce_prefix (8 random bytes)
blob    = header || chunk_0 || ... || chunk_n
chunk_i = AES-256-GCM(key, nonce = nonce_prefix || i (u32 BE),
                      aad = header || last_flag (1 byte), plaintext_i) with 16-byte tag
```

All chunks but the last carry exactly `chunk_size` plaintext bytes; empty
media is one empty final chunk. The key and the SHA-256 of the whole blob
travel in the envelope's media map, never to gim-server. `encrypt_media` /
`decrypt_media` work on buffers (digest checked in constant time before
decrypting); `MediaEncryptor` / `MediaDecryptor` stream over
`std::io::Read`/`Write`.

## iOS packaging

```sh
bash scripts/generate-swift.sh      # Linux or macOS: out/swift (Swift sources, header, module.modulemap)
bash scripts/build-xcframework.sh   # macOS + Xcode: out/ios/GIMCore.xcframework{,.zip,.zip.sha256}
```

The xcframework holds arm64 device and arm64 simulator slices only (no Intel-Mac
simulator), built with the size-tuned `release-apple` profile, with embedded
bitcode removed from the prebuilt `compiler_builtins` members, so the zip stays
below 50 MB. See `bindings/apple/README.md` for the output layout, size,
bitcode and link-test notes. `out/` is never committed.

## CI

`.github/workflows/ci.yml`:

- `rust` (every push, pull request, manual run): `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test`, a `scripts/generate-swift.sh` smoke
  run, and a check that `scripts/generate-bindings.sh` leaves the committed
  bindings unchanged.
- `xcframework` (pushes to `main` and manual runs, macOS): runs
  `scripts/build-xcframework.sh` and uploads `gim-core-ios-<sha>` with the zip,
  its checksum, the Swift sources and `GIM_CORE_VERSION`.

## Android packaging

```sh
scripts/build-android.sh
```

Builds `libgim_core.so` for `arm64-v8a` and `x86_64` plus the Kotlin bindings
into `out/android/` inside a Docker container; see
[bindings/android/README.md](bindings/android/README.md).
