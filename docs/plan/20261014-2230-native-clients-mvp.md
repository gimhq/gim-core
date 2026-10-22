# Native IM Clients — Research and MVP Plan

Status: v3 2026-10-14 (auto mode; decision event m306kdc5: everything except UI moves into Rust). v1 assumed chat-bridge; replaced by a first-party mock server with MLS end-to-end encryption (user decision).
Scope: `gim-ios` (`im-client/ios`), `gim-android` (`im-client/android`), `gim-server` (`im-client/server`), `gim-core` (`im-client/core`). mac / win / web are out of scope.

## 1. Goal

A native chat client with a Telegram / WhatsApp-grade experience: instant chat list, smooth
message timeline, optimistic sending, offline reading, media, replies, reactions.
Client-first: the server is a lightweight mock delivery service; all message content is end-to-end encrypted with MLS (RFC 9420) via OpenMLS.

## 2. Research: open-source clients

Surveyed 2026-10-14 via the GitHub API (license, activity, module layout).

| Repo | Lang | License | What is worth studying |
|---|---|---|---|
| TelegramMessenger/Telegram-iOS | Swift | no LICENSE file at root; README demands publishing derived code (historically GPLv2) | `Postbox` (local store: `MessageHistoryTable`, `ChatListTable`, `SqliteValueBox`, `MediaBox`), `TelegramCore/State` (`AccountStateManager`, `PendingMessageManager`, `Holes`), `Display` (`ListView`, `TextNode` — async layout on top of an AsyncDisplayKit fork) |
| DrKLO/Telegram | Java | GPL-2.0 | `MessagesController` / `MessagesStorage` / `SendMessagesHelper` (god objects, 0.7–1.3 MB each), `ChatMessageCell` (one 1.6 MB custom-drawn cell), `ChatActivity` (2.6 MB) — study techniques, not structure |
| TGX-Android/Telegram-X | Java | GPL-3.0 | native UI over TDLib: proof that "shared core + native UI" works |
| tdlib/td | C++ | BSL-1.0 | client-side sync model; MTProto-only, unusable with a non-Telegram server |
| signalapp/Signal-iOS / Signal-Android | Swift / Kotlin | AGPL-3.0 | iOS timeline = `UICollectionView` + custom `ConversationViewLayout` + precomputed `CVCell` renderers |
| element-hq/element-x-ios / -android | Swift / Kotlin | AGPL-3.0 | closest modern reference: SwiftUI app with a **UIKit** `TimelineTableViewController` for the timeline; Android = Compose `LazyColumn(reverseLayout)`; clean feature/library modularisation (`features/*`, `libraries/*`) |
| matrix-org/matrix-rust-sdk | Rust | Apache-2.0 | timeline/sync engine design, UniFFI bindings |
| MessageKit/MessageKit, exyte/Chat | Swift | MIT | permissive iOS chat UI components (code may be reused) |
| wireapp/wire-ios / -android | Swift / Kotlin | GPL-3.0 | — |

**Primary references (user directive, 2026-10-14): Telegram and Signal.** Study Telegram for
local store, sync, list performance, and interaction details; Signal for a modern, well-factored
native codebase (Signal-iOS `ConversationView` renderers and layout, Signal-Android modules,
message send job queue). Element X is secondary only.

### Licensing decision

Every full-featured client (Telegram, Signal, Element, Wire) is GPL/AGPL or unlicensed.
Copying code makes the whole client GPL/AGPL, and GPL conflicts with App Store terms.
**Rule: study, do not copy.** Reimplement patterns from scratch; no code, assets, stickers,
icons, animations, or the "Telegram"/"WhatsApp" names. Only MIT/Apache code may be vendored,
with its license file kept.

### Patterns to adopt

1. **Local-first.** The UI reads only from the local DB; network writes into the DB; views observe
   DB queries (Telegram `Postbox` views, Element timeline).
2. **Event cursor sync with gap repair.** Persist the last event cursor; on reconnect resume from it;
   when the cursor has expired, mark a "hole" per chat and backfill pages on demand (Telegram `Holes`).
3. **Outbox with client ids.** Every send gets a local `client_id`, appears instantly as `pending`,
   retries with the same id (server is idempotent on `client_id`), transitions
   `pending → sent → delivered → read | failed`.
4. **Timeline performance.** iOS: UIKit list (`UICollectionView`) with precomputed text layout and
   cell sizes off the main thread; SwiftUI elsewhere. Android: Compose `LazyColumn(reverseLayout)`
   with stable keys, `contentType`, immutable UI models, precomputed text layout.
5. **Chunked, resumable media** with a content-addressed cache (`sha256`) and thumbnails first.

## 3. Decisions (2026-10-14)

1. **Backend: not chat-bridge.** chat-bridge is a single-tenant bridge, not a multi-user IM server.
   M1 uses `gim-server`, a lightweight mock delivery service built for these clients.
2. **E2EE in M1: MLS (RFC 9420) through OpenMLS** (MIT). The server only ever sees opaque bytes.
3. **Rust core owns everything below the UI** (v3, decision m306kdc5). `gim-core` owns local storage,
   networking, sync, outbox, MLS, and media crypto, bound to Swift and Kotlin with UniFFI — the shape of
   matrix-rust-sdk (Element X) and TDLib-based clients; Signal likewise keeps libsignal in Rust under
   both apps. Native code owns UI, ViewModels, and platform integration only.
4. **Private GitHub repos** `gimhq/gim-ios`, `gim-android`, `gim-server`, `gim-core`, with GitHub Actions;
   iOS / xcframework builds run on macOS runners.
5. **Auto mode** with the decision system: L1 reviews and merges; hard stops become decision events.

## 4. Component contracts

### 4.1 gim-server (mock delivery + authentication service)

Bun + Hono + `@hono/zod-openapi` + SQLite (`bun:sqlite`), one process, Docker image. The OpenAPI
document is committed as `openapi.json` at the repo root and is the client contract.

- **Auth (mock):** `POST /v1/devices` registers `{handle, display_name}` and returns `{user_id, device_id, token}`.
  No passwords or OTP; bearer token on every other route. A user may own several devices.
- **Directory:** look up users by handle; list a user's devices.
- **KeyPackages:** devices upload batches of MLS KeyPackages (opaque bytes); claiming one for a
  device consumes it (one-time), with a last-resort package that is never consumed.
- **Groups:** a conversation is an MLS group with a server-side id and a member-device list kept only
  for fan-out. `direct` and `group` kinds; group metadata (name, avatar) travels encrypted.
- **Messages:** `POST /v1/groups/{id}/messages` takes `{client_id, epoch, kind: commit|welcome|application, payload(base64), recipients?}`.
  The server assigns a per-group monotonically increasing `seq`, is idempotent on `client_id`,
  and rejects a commit whose `epoch` is not the current one (409) so commits are totally ordered.
  Welcomes are delivered only to the listed recipient devices.
- **Events:** one per-device stream with a global monotonic cursor: WebSocket `/v1/stream?cursor=`
  plus `GET /v1/events?cursor=&wait=` long-poll fallback. Events: `message` (group id, seq, sender
  device, kind, payload), `group.member_added|removed`, `keypackages.low`. Retention ≥ 7 days;
  a stale cursor returns `410` and the client backfills per group by `seq`.
- **Media:** `POST /v1/blobs` uploads an already-encrypted blob, returns `{blob_id}`; `GET /v1/blobs/{id}`
  supports `Range`. Keys and digests travel inside the encrypted message, never to the server.
- **Health:** `/healthz`. A seed script creates demo users and groups for manual testing.

### 4.2 gim-core (Rust: storage, network, sync, outbox, MLS, media; UniFFI)

- **MLS** (OpenMLS): identity/credential bound to `user_id/device_id`, KeyPackages (upload, replenish on
  `keypackages.low`), create group, add/remove members, Welcome, commits (epoch ordering via the server's 409),
  application messages. Ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- **Envelope** (inside MLS application messages), versioned CBOR: `text`, `media` (blob_id, key, sha256, mime,
  size, dimensions, thumbnail), `reply_to`, `edit`, `delete`, `reaction`, `receipt(delivered|read)`, `typing`,
  `group_info(name, avatar)`.
- **Storage**: one SQLite database (rusqlite, bundled) holding MLS state, chats, messages, outbox, cursors,
  media cache index, with migrations. MLS state changes and the resulting message rows commit in one
  transaction. At-rest encryption is deferred (iOS Data Protection / Android file-based encryption in M1).
- **Network**: tokio runtime, reqwest (rustls) for the §4.1 REST API, tokio-tungstenite WebSocket stream with
  long-poll fallback, reconnect with backoff; DTOs generated or hand-written from gim-server `openapi.json`.
- **Sync**: persisted global cursor, per-group `seq` gap backfill, 410 handling, idempotent event apply.
- **Outbox**: client_id, `pending → sent → delivered → read | failed`, retry with backoff, media upload
  (AES-256-GCM chunked encryption, then blob upload).
- **API to native (UniFFI)**: a `GimClient` object (async methods: register, login state, find user, create
  direct/group chat, add/remove member, send text/media/reply/edit/delete/reaction, mark read, typing, load
  older messages, fetch media to a file path) and **listener interfaces** delivering incremental diffs:
  chat list diffs, per-chat timeline diffs (insert/update/remove/reset, Element X style), connection state,
  typing. Native code never queries SQL.
- **Platform hooks** (native → Rust callbacks): secure key storage (Keychain / Keystore) for the device
  identity secret, app data directory, network reachability.
- **Workspace layout** (modelled on matrix-rust-sdk: `-common`, `-base`, `-crypto`, `-sqlite`, `-sdk`, `-ui`,
  `bindings/*-ffi`, `testing/*`). Each crate has one role; dependencies point downwards only.

  | Crate | Role | matrix-rust-sdk analogue |
  |---|---|---|
  | `crates/gim-common` | ids, errors, time, executor helpers; no I/O; wasm-compatible | `matrix-sdk-common` |
  | `crates/gim-proto` | wire types: gim-server REST/stream DTOs (from `openapi.json`), versioned CBOR envelope schema | `ruma` (external there) |
  | `crates/gim-crypto` | OpenMLS wrapper, envelope encrypt/decrypt, media AES-256-GCM; storage via a `CryptoStore` trait; no networking | `matrix-sdk-crypto` |
  | `crates/gim-base` | client state machine without networking: `StateStore` trait, event/sync processing, outbox state, receipts; in-memory store for tests | `matrix-sdk-base` |
  | `crates/gim-sqlite` | rusqlite implementation of `StateStore` + `CryptoStore` on one database, migrations, shared transaction so MLS state and message rows commit atomically | `matrix-sdk-sqlite` |
  | `crates/gim-sdk` | async `Client`: HTTP (reqwest/rustls), WebSocket + long-poll, sync loop, outbox sender, media upload/download | `matrix-sdk` |
  | `crates/gim-ui` | UI-facing services: chat list service and per-chat timeline producing `VectorDiff` streams (eyeball-im), typing aggregation | `matrix-sdk-ui` |
  | `bindings/gim-ffi` | the only UniFFI crate: `GimClient`, listener traits, platform-hook callbacks; thin mapping over `gim-ui`/`gim-sdk` | `matrix-sdk-ffi` |
  | `bindings/apple`, `bindings/android` | xcframework / cargo-ndk packaging scripts | `bindings/apple` |
  | `testing/gim-test` | fixtures, fake delivery service, test helpers | `matrix-sdk-test` |
  | `testing/gim-integration-testing` | tests against a real gim-server container | `matrix-sdk-integration-testing` |

  Dependency direction: `common ← proto ← crypto ← base ← sqlite`, `base + crypto + proto ← sdk ← ui ← ffi`.
  A future web client adds `gim-indexeddb` and a wasm build of `gim-sdk`/`gim-ui`; Windows consumes `gim-ffi`.
- **Bindings / packaging**: Kotlin (`.so` for `arm64-v8a`, `x86_64` via cargo-ndk in a Linux container) and
  Swift (`GIMCore.xcframework` + Swift sources, built on macOS CI).
- **Tests**: unit tests; multi-party test (3 devices, add/remove, out-of-order within an epoch); an
  integration test that runs two `GimClient`s against a real gim-server container.

### 4.3 Client architecture (native, UI only)

```
UI (screens) -> ViewModels -> gim-core GimClient (UniFFI)  [listeners push diffs up]
                    |
          platform hooks: Keychain/Keystore, files, reachability, notifications, pickers
```

ViewModels depend on a thin native protocol/interface over `GimClient` so UI tests and previews use a fake.

| Concern | iOS (`gim-ios`) | Android (`gim-android`) |
|---|---|---|
| Language / UI | Swift 6, SwiftUI shell + UIKit timeline (UICollectionView, precomputed layout) | Kotlin, Jetpack Compose, LazyColumn(reverseLayout) |
| Min OS | iOS 18 | Android 8.0 (API 26) |
| App id | `im.g.apps` | `im.g.apps` |
| Modules | `GIMUI` package + app target; vendored `GIMCore` bindings | `:core:bridge` (vendored bindings + jniLibs + fake), `:feature:*`, `:app` |
| Images | decode files gim-core has decrypted to disk | Coil over decrypted file paths |
| Tests | ViewModel tests with the fake client; UI build on macOS CI | ViewModel tests, Compose UI tests with the fake client |

### 4.4 How clients consume gim-core

gim-core scripts produce versioned artifacts; clients vendor them, pinned by a `GIM_CORE_VERSION` file
(no submodules, so CI needs no cross-repo secrets):
- Android: `core/bridge/src/main/jniLibs/<abi>/libgim_core.so` + generated Kotlin, refreshed by
  `scripts/sync-gim-core.sh` from a gim-core checkout.
- iOS: `Vendor/GIMCore.xcframework.zip` (gim-core macOS CI artifact) + generated Swift.
- Until real artifacts exist, clients build against the committed UniFFI interface description and a fake.

## 5. MVP scope (milestone M1)

1. Onboarding: server URL + handle + display name → device registration; token in Keychain / Android Keystore-backed storage.
2. Contacts: find users by handle; start a direct chat; create a group with members.
3. E2EE: every chat is an MLS group; KeyPackage upload and replenishment; Welcome handling; add/remove member.
4. Chat list: avatars, last message, unread badge, sorting, offline.
5. Chat screen: paginated timeline, date separators, bubbles, sender names in groups, text + image + file,
   reply preview, reactions, edited / deleted states, outbound status ticks (sent / delivered / read from encrypted receipts).
6. Composer: optimistic send through the outbox (client_id, retry), reply, image/file send (encrypted blobs).
7. Realtime: WebSocket stream with cursor persistence, reconnect with backoff, gap backfill by seq.
8. Typing indicators and read receipts (encrypted).

Out of M1: calls, push notifications, stickers, voice messages, search, multi-device history sync,
key verification UI (safety numbers), multi-window.

## 6. Workstreams (BKD three-tier, auto mode)

L1: issue `gzw7p2el` in BKD project `gimhq`. One L2 per repo; write scopes are disjoint.

| L2 | BKD project | Depends on | Acceptance |
|---|---|---|---|
| gim-server M1 | `gim-server` | — | §4.1 complete; `bun run lint && bun run typecheck && bun test` green; `openapi.json` committed; Docker image builds; seed script works |
| gim-core M1 | `gim-core` | gim-server contract (network/sync only) | §4.2 complete; `cargo fmt --check && cargo clippy -D warnings && cargo test` green in a Rust container; Android `.so` + Kotlin bindings build in a container; Swift bindings generated; xcframework built on macOS CI |
| gim-android M1 | `gim-android` (`pe8t79yb`) | gim-core API + Kotlin artifacts | §5 UI complete over `GimClient`; `./gradlew lint testDebugUnitTest assembleDebug` green in the Android SDK container |
| gim-ios M1 | `gim-ios` (`6xv6v959`) | gim-core API + xcframework, macOS CI | §5 UI complete over `GimClient`; app builds and tests on the macOS CI runner |

Client L2s start with dependency-free UI work (design system, app shell, screens on a fake client).
Wiring to the real `GimClient` waits until L1 confirms the gim-core API / artifacts are on gim-core `main`.
gim-core's network/sync subtasks wait for gim-server `openapi.json` on gim-server `main`
(read-only paths: `/srv/gimhq/im-client/server`, `/srv/gimhq/im-client/core`).

## 7. Risks

1. **macOS CI minutes**: the gimhq org is on the free plan; macOS minutes are scarce. Run macOS jobs only
   on `main` pushes and manual dispatch.
2. **GitHub repos**: created 2026-10-14 (private) and `main` pushed; L1 pushes `main` after each merge.
3. **MLS state durability**: losing local MLS state means losing the group; M1 accepts this (no backup).
4. **Binary artifacts in client repos** (.so, xcframework zip) grow history; acceptable for M1, revisit with a package registry later.
5. **Dependency versions**: the Android scaffold pins AGP 8.7.3 / Kotlin 2.1.0; L2 may upgrade.
