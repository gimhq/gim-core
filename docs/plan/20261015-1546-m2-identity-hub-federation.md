# M2: Self-certifying identity, Rust hub, closed federation, multi-homing

Status: approved 2026-10-15 (user: "确认开始处理"); implemented 2026-10-16 (core main 9c6022c, hub main
bd8c9ca, ios main 22efac7, android main dc27681), awaiting user review
Predecessor: [20261014-2230-native-clients-mvp.md](20261014-2230-native-clients-mvp.md) (M1, complete)
Design basis: `/srv/docs/e2ee-im/cluster-architecture.md` and `mobile-client.md` (draft v0.1).
Section numbers below like "arch §7" refer to cluster-architecture.md.

## 1. Decisions

| # | Decision | Source |
|---|---|---|
| D1 | New devices are authorized by an existing device (QR link) plus a recovery code for loss of all devices | user 2026-10-15 |
| D2 | Federation is closed first (PeerID allowlist, optional libp2p pnet PSK); policy is behind an interface so open federation can be added without protocol changes | user 2026-10-15 |
| D3 | The server is rewritten in Rust as `gim-hub`; the Bun `gim-server` is frozen at 12e316e and used only for M2.0 device validation | user 2026-10-15 |
| D4 | Every linked device holds the user root key (wrapped by the platform keystore), so any device can link the next one. Recovery restores the root key from an encrypted backup | L1, from D1 |
| D5 | No production data exists: M1 databases and identities are not migrated; clients reset local state on the M2 schema bump | L1 |
| D6 | Client API stays REST + WebSocket with an OpenAPI contract (as in M1); hub-to-hub is libp2p request-response with protobuf | L1, arch §6 |
| D7 | Multi-homing is user-level (arch §9.6); device-level hub lists are deferred | arch §9.6 |
| D8 | Application messages are globally ordered by the owning hub (arch §7.2); owning-hub migration is out of scope | arch §10, §15 |
| D9 | The hub does not integrate APNs or FCM. Every push leaves the hub as one signed webhook to an external push server, which owns platform delivery. M2 uses a mock push server for tests | user 2026-10-16 |

Study, never copy, still applies (Wire, XMTP, Matrix, Signal, Telegram are references only).

## 2. Phases

```
M2.0 device validation  ──►  M2a identity  ──►  M2b federation  ──►  M2c multi-homing
                              P  push + iOS NSE (parallel with M2a/M2b)
```

### M2.0 Device validation (against gim-server 12e316e)

- iOS: XCUITest smoke on the iOS simulator in macOS CI against a gim-server started on the runner:
  onboarding, create group, send/receive text and image, reply, reaction, read ticks (two app
  instances or one app plus a scripted peer using the gim-core integration harness).
- Android: instrumented Compose test on an emulator in GitHub Actions (KVM runner) with the same
  flow; instrumented test of `KeystoreSecretCipher` on a real AndroidKeyStore; `assembleRelease`
  with a debug signing config.
- CLI client `gim` (gim-core `apps/gim-cli`, on the public gim-sdk API of the M1 core): profiles,
  all chat operations, `--json` output and a `wait-for` command for scripting (user request
  2026-10-15).
- Interop run: two CLI users and the Android app on a local KVM emulator walk through DM and group
  flows (text, image both ways, reply, reaction, edit, delete, read ticks, typing, rename, remove),
  asserted on both sides (`android/scripts/e2e-interop.sh`).
- Both: sign-out (wipe local store + keystore entries), configurable default hub URL.
  Android: chat-list relative times refresh on a timer.

### M2a Identity (arch §4, §5.5; D1, D4)

Core (`gim-crypto` / new `gim-identity` crate):
- User root key Ed25519; `user_id = "u" + base32(multihash(sha2-256, root_pubkey))`.
- `DeviceCert { user_id, device_sig_pubkey, device_id, created_at, seq }` signed by the root key.
- Signed `DeviceList { user_id, seq, certs[], revoked[] }`; higher `seq` wins.
- MLS credential = custom credential type carrying root pubkey + DeviceCert. Every Welcome, Commit,
  and Add is validated: chain verifies, leaf signature key equals cert key, device not revoked.
  BasicCredential is removed.
- Device linking: new device shows a QR (ephemeral X25519 pubkey, device sig pubkey, hub list,
  short auth string); old device scans, signs a DeviceCert, seals `{root key, cert, device list,
  self-group Welcome}` to the ephemeral key and posts it through the hub; both screens show the
  short auth string for confirmation.
- Recovery code: 24 random bytes shown once at identity creation (Crockford base32, grouped).
  `Argon2id(code)` derives a key that AEAD-encrypts the root key backup stored on the hub(s).
  Restore = fetch backup by user_id, decrypt, become a new device, revoke the lost ones.
- Self group (arch §9.4): MLS group of the user's own devices carrying contacts, read markers,
  settings, and device-list updates.
- Local storage: SQLCipher (rusqlite `bundled-sqlcipher-vendored-openssl`); DB key wrapped by the
  existing platform secret-cipher hook; schema reset per D5.
- Hardening carried from M1 (core L2 report): own Left recorded on the leaver's device;
  `create_client` with a lost store identity but a live keystore session; dangling MLS pending
  commit reconciliation; KeyPackagesLow recovery after a pruned window; groups joined via pruned
  Welcomes discovered on 410 recovery.

Hub (`gim-hub`, Rust):
- Parity with the gim-server contract semantics: WebSocket stream, long-poll, 410 on expired
  cursor, per-group seq, client_id idempotency, 409 on stale epoch, encrypted blobs.
- Changes: device auth by signature challenge against the DeviceList (no handle-only
  registration); epoch read from the MLS message framing, not a client field; same-Commit-hash
  resubmission returns success; `member_added`/`member_removed` events carry `user_id`;
  `gid = <owner_peer_id>/<random_128>`; endpoints for DeviceList, link-bundle relay, and recovery
  backup blobs; optional handle directory (handle → user_id, never a DHT key).
- Stack: axum + tokio, SQLite (WAL), utoipa-generated `openapi.json` committed as the contract.

Clients: identity onboarding (create, show and confirm recovery code), link-device flows (show QR /
scan QR with short auth string), restore from recovery code, device management (list, revoke).
QR: AVFoundation on iOS; CameraX + ZXing core (Apache-2.0) on Android, no Google ML Kit.

### M2b Closed federation (arch §5–§8, §10; D2, D6, D8)

Hub:
- rust-libp2p host: Noise, QUIC + TCP, private Kademlia `/gim/kad/1.0.0`, request-response
  `/gim/s2s/1.0.0` (prost). Hub root key signs runtime keys (arch §4.1).
- `UserHostingRecord` (arch §5.1) published per user; custom record validator (user_sig, every
  hub_sig, expiry, highest seq).
- `FederationPolicy` trait: `AllowlistPolicy` (PeerID allowlist + optional pnet PSK) implemented;
  open-federation policy (rate limits, reputation, blocklist) left as a documented extension point.
- S2S operations of arch §6.2 (SubmitCommit, SubmitMessage, Deliver, DeliverWelcome,
  ClaimKeyPackage, FetchLog), each authorized against the authenticated PeerID and the current
  hosting record. Owning-hub sequencer; one copy per member hub; durable per-peer outbound queue
  with at-least-once delivery, backoff, backlog cap and TTL; receiver dedup and gap fill.
- docker compose with 3 hubs on an isolated network; integration tests for cross-hub group
  create, send, add/remove, concurrent Commit conflict, peer outage and recovery.

Core: address users by user_id with hub resolution delegated to the user's own hub; group ids
carry the owner hub; cross-hub KeyPackage claim through the own hub.

### M2c Multi-homing (arch §9; D7)

- Hosting record hub list with priorities; each hub co-signs its entry.
- Core: one connection and cursor per hub; dedup by message id; order by `(gid, epoch, seq)`;
  disjoint KeyPackage sets per hub, each with its own last-resort KeyPackage; Commits and Welcomes
  fanned out to all hubs, application messages primary/fallback (arch §9.2).
- Hub: add/remove hub to a user's record, zero-downtime migration (arch §5.5); push sent by the
  primary hub only or with a collapse id.
- Clients: settings screen listing the user's hubs with state; add/remove hub.

### P Push and iOS NSE (mobile-client §3)

- Core: shared-container store path, cross-process file lock around MLS state mutation,
  `process_push(payload) -> NotificationContent` within the NSE memory budget (~24 MB).
- Hub (D9): push gateway with a webhook provider only (plus log-only for dev). Each push is an
  HMAC-signed HTTP POST of the push payload and the device's opaque registration to a configured
  external push server URL. The APNs, FCM and UnifiedPush providers from H4-P1/P2 are removed.
- Mock push server (in the hub repo): receives and verifies the webhook, records deliveries for
  tests, and forwards them to test devices (iOS simulator via `xcrun simctl push`, Android via a
  debug-only delivery path).
- iOS: Notification Service Extension target `im.g.apps.nse`, App Group `group.im.g.apps`.
- Android: push provider abstraction with a webhook/mock provider; no FCM or UnifiedPush client.
- Real APNs / FCM delivery is the external push server's job and outside this plan.

## 3. Workstreams (BKD three-tier, auto mode, decision system)

| L2 | Repo / BKD project | Phases |
|---|---|---|
| gim-hub | `hub/` gimhq/gim-hub (new, private) / gimhub | M2a hub, M2b, M2c hub, P hub |
| gim-core | `core/` / gimcore | M2a core, M2b core, M2c core, P core |
| gim-ios | `ios/` / gimios | M2.0 iOS, M2a/M2c UI, P iOS |
| gim-android | `android/` / gimandroid | M2.0 Android (incl. CLI interop run), M2a/M2c UI, P Android |
| gim-cli | `core/apps/gim-cli` / gimcore | CLI client and interop driver (M2.0); gim-core L2 keeps it building afterwards |

Contract order (L1 merges intermediate milestones to main so dependents can sync):
1. hub: identity types + client API v2 `openapi.json` + `s2s.proto` (contract milestone).
2. core: consumes the contract; ships identity + client v2; new artifacts (Android .so, xcframework
   with the link gate).
3. clients: re-vendor gim-core per milestone (`scripts/sync-gim-core.sh`).
M2.0 does not depend on any of the above and runs first on both clients.

## 4. Acceptance

- M2.0: both client CIs run a device-level E2E flow against gim-server and pass; sign-out works.
- M2a: a user can create an identity, link a second device by QR, revoke it, and restore from the
  recovery code; a forged or revoked credential is rejected in core tests; all chats run on gim-hub.
- M2b: 3-hub compose test passes cross-hub DMs and groups, conflict and outage cases; a hub not on
  the allowlist is refused.
- M2c: a user on two hubs keeps messaging when one hub is stopped; no duplicate messages; no
  KeyPackage claimed twice.
- P: hub → webhook → mock push server delivers a push for a new message; on the iOS simulator
  (Mac gate) the delivery reaches `simctl push`, and the NSE's handler code with an Extension-mode
  client on the App Group store decrypts the real hub payload (run in-app, test-only path:
  `simctl push` does not launch service extensions); the NSE process launch and its memory budget
  need a device or APNs and are deferred (user 2026-10-16, decision vngg8e56); Android shows the
  notification for a mock-delivered push on the emulator and the test phone.
- Every repo: its own checks green in CI on main; clients built against the vendored core of the
  final core main.

## 5. Out of scope

Multi-account (several identities in one app), calls, search, stickers, voice messages,
owning-hub migration, open-federation policy implementation, mac/win/web clients, real
APNs/FCM credentials, store publishing.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Private cross-repo CI access (hub needs gim-core crates; client E2E needs a server) | decision event; until resolved, contracts are vendored like M1 |
| SQLCipher + vendored OpenSSL cross-compiling for iOS/Android | dedicated core subtask; keep the xcframework link gate and 50 MB zip gate |
| rust-libp2p API churn | pin versions; isolate libp2p behind a hub-internal transport module |
| macOS CI minutes (free plan) | batch macOS runs; dispatch only on milestone branches |
| Android emulator in CI flakiness | single API level (35, x86_64), retries limited to infra failures |
