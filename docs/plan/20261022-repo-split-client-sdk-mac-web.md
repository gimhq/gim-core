# Plan: split gim-core, gim-client-sdk, gim-mac, gim-web

Status: implementing since 2026-10-22 (phase 0: task `20261022-2039-p0-core-cleanup-wasm`)

User decisions (2026-10-22):

- The gim-server mock repository is deleted. gim-hub is the only server.
- macOS gets a native client, benchmarked against Telegram for macOS.
- The client SDK lives in its own repository, `gim-client-sdk`.
- A web client is needed, built on the SDK compiled to WebAssembly.

## 1. Where we are

gim-core today holds everything that runs on a client, in one workspace
(about 75k lines of Rust):

| Crate | Lines | Role | I/O |
|---|---|---|---|
| `gim-common` | 0.2k | ids, errors, time | none |
| `gim-proto` | 3.1k | hub API v2 DTOs, vendored hub contract, CBOR envelope; still the gim-server v1 DTOs | none |
| `gim-identity` | 5.4k | root/device keys, DeviceCert, DeviceList | none |
| `gim-crypto` | 4.7k | OpenMLS engine, `CryptoStore` trait | none |
| `gim-base` | 5.1k | client state machine, `StateStore` trait | none |
| `gim-sqlite` | 5.0k | rusqlite + SQLCipher stores | file |
| `gim-sdk` | 28.1k | async client: HTTP, WebSocket, sync, outbox, media, hubs, link, push | network, tokio |
| `gim-ui` | 2.8k | chat list and timeline streams | tokio |
| `gim-ffi` | 5.0k | UniFFI: Swift and Kotlin | |
| `gim-cli` | 3.8k | Linux CLI client | |
| `gim-test`, `gim-integration-testing` | 6.3k | fixtures, `FakeDeliveryService` (gim-server v1), real-hub tests | |

The layering is already clean: the five lower crates do no I/O, and storage
sits behind the `StateStore` and `CryptoStore` traits. That is the seam along
which the split runs.

Consumers today:

- gim-ios vendors `GIMCore.xcframework.zip` and `GIMCore.swift`, pinned in
  `GIM_CORE_VERSION`.
- gim-android vendors the `.so` files and the Kotlin bindings, through
  `scripts/sync-gim-core.sh`.
- gim-hub re-implements identity verification in `gim-hub-identity`, with
  versions aligned to `gim-identity` by hand. It does not depend on gim-core.

## 2. Target layout

```
gim-core           protocol core: pure Rust, no I/O, builds for native and wasm32
  gim-common  gim-proto  gim-identity  gim-crypto  gim-base

gim-client-sdk     client runtime and every language binding (depends on gim-core by tag)
  crates/   gim-sdk  gim-ui  gim-store-sqlite  gim-store-web  gim-platform
  bindings/ uniffi (Swift, Kotlin)  node (napi-rs)  wasm (wasm-bindgen)  c (later)
  apps/     gim-cli
  testing/  gim-test  gim-integration-testing

gim-hub            server; may depend on gim-core's gim-identity and gim-proto (phase 6)
gim-ios            app; consumes the Swift package from gim-client-sdk releases
gim-android        app; consumes the Kotlin AAR or .so files from gim-client-sdk releases
gim-mac            new, native macOS app; consumes the same Swift package as iOS
gim-web            new, web app (React + Vite); consumes @gimhq/sdk-web (wasm)
```

Why the line is drawn here:

- **gim-core becomes small and stable.** It holds the wire formats,
  cryptography and the state machine. These are what the hub and every client
  must agree on, and they change slowly.
- **Everything that touches a platform moves to gim-client-sdk.** That means
  network, storage, async runtime and bindings, the parts each new target
  (Node, browser, macOS) needs to vary. One repository then owns every binding,
  so all of them ship from the same SDK version.
- **The no-I/O crates must keep compiling for `wasm32-unknown-unknown`.**
  gim-core's CI enforces this, and it is the precondition for the web client.

### Versioning and release

- gim-core is tagged `vX.Y.Z`. gim-client-sdk pins it as a git dependency by
  tag. Local cross-repo development uses a Cargo `[patch]` override.
- gim-client-sdk is tagged `vX.Y.Z` and its CI publishes these artifacts:
  - a Swift package with `GIMCore.xcframework`, sliced for iOS, the iOS
    simulator and macOS (arm64 + x86_64);
  - an Android AAR (or the current `.so` files plus Kotlin);
  - `@gimhq/sdk-node` (napi-rs prebuilt binaries);
  - `@gimhq/sdk-web` (wasm-bindgen + TypeScript types);
  - `gim-cli` binaries.
- The apps pin an SDK release instead of a core commit:
  `GIM_CORE_VERSION` becomes `GIM_SDK_VERSION`, and the sync scripts download
  release artifacts instead of building from a checkout.
- Module names stay `GIMCore` (Swift) and `im.g.gimcore` (Kotlin) for now, so
  the split causes no app code churn. A rename can follow on its own.

## 3. Phases

Every phase ends with all existing gates green:

- core: fmt, clippy, test, and the integration suites single, fed and mh;
- the iOS and Android gates;
- the apps keep working against hub v0.4.x.

### Phase 0: clean up inside gim-core (no repository change)

1. Remove the gim-server v1 remnants: the v1 DTOs in `gim-proto` and
   `FakeDeliveryService` in `gim-test`. Port the `gim-base` and `gim-sqlite`
   tests that use them to a v2 fake.
2. Add a CI job that builds `gim-common`, `gim-proto`, `gim-identity`,
   `gim-crypto` and `gim-base` for `wasm32-unknown-unknown`. For example:
   - `getrandom` with the `js` feature;
   - `web-time` instead of `std::time::Instant`;
   - OpenMLS with the RustCrypto provider, already pure Rust.

   Fix whatever does not build.
3. Make the store traits async-safe for a single-threaded runtime (no `Send`
   requirement leaking into the trait objects where the web store cannot meet
   it). This is a design check now, code later.

Phase 0 findings (2026-10-22):

- Item 1 was already done in code: `gim-proto` has no v1 DTOs left and
  `FakeDeliveryService` models API v2. Only README text still named
  gim-server.
- Item 2 needed only dependency features on `wasm32-unknown-unknown`:
  `getrandom` 0.2 with `js`, OpenMLS with its `js` feature (getrandom 0.4
  `wasm_js` and `web-time`), and `web-time` for `gim_common::now_ms`. No
  source change besides that import.
- Item 3: `CryptoStore`, `StateReader`, `StoreTxn` and `StateStore` are
  synchronous, and the SDK already runs every transaction through
  `spawn_blocking`. Two consequences for the web:
  - A web store must be synchronous inside the worker. sqlite-wasm on an OPFS
    synchronous access handle (dedicated workers only) meets that and keeps
    the one-transaction guarantee for MLS state and rows. IndexedDB is
    async-only and would need an in-memory working set with an async flush,
    which weakens that guarantee. This tilts the P4 open point towards
    sqlite-wasm on OPFS.
  - `StateStore: Send + Sync` is a supertrait. A store holding JS handles is
    not `Send` on wasm32. Move the bound from the trait to the native SDK
    call sites (`spawn_blocking`) in P2; removing it now would only break
    the SDK. `CryptoStore::Error: Send + Sync` and the `DeviceListLookup`
    bound are fine (pure Rust types).

### Phase 1: create gim-client-sdk

1. Create `gimhq/gim-client-sdk` with history. Use `git filter-repo` to move
   these paths:
   - `crates/gim-sdk`, `crates/gim-ui`;
   - `crates/gim-sqlite`, renamed to `gim-store-sqlite`;
   - `bindings/*`, `uniffi-bindgen`, `apps/gim-cli`, `testing/*`;
   - the build scripts: `build-android.sh`, the apple scripts,
     `integration-test.sh`, `gim-hub-dev.sh`.
2. gim-core keeps the five protocol crates, `docs/identity.md`, the vendored
   hub contract, and this plan history. `docs/API.md`, the FFI API, moves to
   the SDK.
3. Move CI accordingly:
   - core keeps rust plus the wasm build;
   - the SDK gets rust, integration, xcframework, android and release jobs.
4. Tag gim-core `v0.2.0`, the first release of the split layout. The SDK
   depends on it.
5. Switch gim-ios and gim-android to SDK release artifacts:
   - `sync-gim-core.sh` becomes `sync-gim-sdk.sh`;
   - the pin file is renamed.

   Their gates must pass unchanged, on the same API.

### Phase 2: platform seam in gim-sdk (prerequisite for Node and web)

Introduce a `gim-platform` crate with three traits, and move today's
implementations behind them:

| Trait | Native (today) | Web |
|---|---|---|
| `Runtime` (spawn, sleep, timers, blocking work) | tokio, `spawn_blocking` | `wasm-bindgen-futures`; blocking work inline or in a Web Worker |
| `HttpTransport` | reqwest + rustls | reqwest's wasm backend (fetch) |
| `StreamTransport` (WebSocket) | tokio-tungstenite, `Authorization` header | `web-sys` WebSocket; the token cannot go in a header from a browser |

Also behind a trait: the store lock (`store_lock.rs`, file lock today; Web
Locks API on the web) and media files (filesystem today; OPFS or in-memory on
the web).

### Phase 3: Node.js binding

- `bindings/node` with napi-rs, published as `@gimhq/sdk-node` with prebuilt
  binaries for linux-x64, linux-arm64 and darwin-arm64.
- It uses the native platform: tokio and `gim-store-sqlite`.
- Same API surface as the UniFFI binding: Promises, and callbacks as event
  emitters.
- Use cases: bots, server-side integrations, tests.
- A C ABI (`bindings/c`, cbindgen) for other Linux languages comes later, only
  when a consumer asks.

### Phase 4: WebAssembly SDK

1. **`gim-store-web`**: `StateStore` and `CryptoStore` on IndexedDB.
   - SQLCipher is not available in the browser. Data at rest is encrypted
     with a non-extractable WebCrypto AES-GCM key stored in IndexedDB. This
     protects against disk copies, not against script running in the page.
     The threat model in section 5 has to accept that.
   - Alternative to evaluate: SQLite compiled to wasm on OPFS (sqlite-wasm).
     It reuses the SQL schema but adds about 1 MB and a JS dependency. Decide
     after a spike.
2. **`bindings/wasm`** with wasm-bindgen, published as `@gimhq/sdk-web` with
   TypeScript types.
   - The SDK runs in a dedicated Web Worker, so the MLS work and storage stay
     off the UI thread.
   - Multiple tabs: one SharedWorker, or a Web Locks leader election, owns the
     store. The other tabs talk to it through a message channel.
3. **Hub changes needed** (gim-hub work items, not SDK):
   - CORS for configured web origins: a stored setting with an allowlist.
   - WebSocket authentication without a header. `?token=` already works, but
     URLs end up in logs, so add the token as a `Sec-WebSocket-Protocol`
     value, or as a short-lived stream ticket from `POST /v2/stream/ticket`.
   - Blob upload and download through CORS.
4. **Push:** Web Push (VAPID), handled by the future push server. A service
   worker wakes the SDK.

### Phase 5: gim-web (new repository)

- React + Vite single-page app on the pma-web baseline, consuming
  `@gimhq/sdk-web`.
- Scope v1, at parity with the mobile clients:
  - onboarding with two choices, the default hub and another hub;
  - linking as a new device by scanning a QR code with the phone. Desktop and
    web are linked devices first.
  - chats, groups, media, devices, hubs.
- Served as static files, for example from the hub's domain or a CDN, with a
  strict CSP.

### Phase 6: gim-mac (new repository), can start right after phase 1

Native macOS, benchmarked against Telegram for macOS: SwiftUI with AppKit
where SwiftUI falls short (text input, lists of 10k+ rows, window
management).

- **SDK:** the macOS slices of `GIMCore.xcframework` from the gim-client-sdk
  Swift package.
- **Shared Swift code:** the platform-neutral parts of gim-ios's `GIMKit` are
  `GIMClientKit` and the view models in `GIMFeatures`.
  - First, share them by a Swift package dependency on gim-ios at a tag.
  - Once both apps use them, extract them into their own package
    (`gim-apple-kit`).
- **Telegram-class baseline:**
  - Window and navigation:
    - sidebar chat list plus a chat pane;
    - multiple windows, and opening a chat in a new window;
    - menu bar commands and full keyboard navigation and shortcuts.
  - Media and files:
    - drag and drop of files and images, and paste of images;
    - Quick Look for media.
  - Messages:
    - fast message list with infinite scroll;
    - search;
    - link previews, done client-side, never through the hub.
  - System:
    - notifications through APNs for macOS, with the dock badge;
    - launch at login and a menu bar mode.
  - Onboarding:
    - "Link to existing device" by showing a QR code that the phone scans;
    - create, restore, and the default or other hub choice, as on iOS.
- **Distribution:** signed and notarized builds, Sparkle for updates outside
  the App Store; the App Store as an option later.

### Phase 7 (optional): gim-hub uses gim-core

gim-hub depends on `gim-identity` and `gim-proto` at a gim-core tag, instead
of keeping `gim-hub-identity` aligned by hand. One source of truth for
DeviceCert, DeviceList, the hosting record and the hub DTOs.

## 4. Order and dependencies

```
P0 core cleanup + wasm CI
  -> P1 gim-client-sdk repo, apps switch to SDK releases
       -> P2 platform seam
            -> P3 Node binding
            -> P4 wasm SDK (+ hub CORS / stream auth)
                 -> P5 gim-web
       -> P6 gim-mac            (parallel with P2-P5)
P7 hub on gim-core              (any time after P1)
```

P0 and P1 are pure moves and must not change behaviour. P2 is the only
refactor of SDK internals. Everything after it is additive.

## 5. Risks and open points

- **Web key storage.** A browser cannot protect keys against script running in
  the page; XSS equals account compromise. Mitigations:
  - a strict CSP, no third-party scripts, and Subresource Integrity;
  - the SDK isolated in a worker;
  - recommending the native apps for high-risk users.

  This needs a written threat-model section before P4.
- **MLS performance in wasm.** Commits in large groups may be slow on the
  main thread. That is why the SDK runs in a Worker. Benchmark in the P4
  spike.
- **Multi-tab consistency.** Only one tab may own the store; this is the
  same rule as the native store lock.
- **Release pipeline across repos.** A change that touches the protocol and
  the SDK now needs two pull requests and a core tag. That is acceptable
  because the protocol crates change rarely; the `[patch]` override covers
  development.
- **Private apps vs public SDK.** gim-ios and gim-android are private, while
  gim-core and gim-hub are public. gim-client-sdk should be public, so that
  its release artifacts can be downloaded without credentials, as for
  gim-hub.
- **Open:** for `gim-store-web`, IndexedDB or sqlite-wasm on OPFS. Decided
  by the P4 spike.
