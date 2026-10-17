# Closed federation (M2b) design

Status: design, normative for the M2b implementation subtasks. Nothing in this document is
implemented yet.

This document specifies how gim hubs federate: peer authentication and the allowlist, hosting
records, remote users and groups, the cross-hub message flows, the durable outbound queue, the
contract changes they require, configuration, the test topology and an implementation breakdown.
It extends the single-hub implementation (`crates/gim-hub-api`, `crates/gim-hub-db`) and the
contracts in [`s2s.md`](s2s.md), [`api-v2.md`](api-v2.md) and the vendored identity spec
([`testdata/identity/identity.md`](../testdata/identity/identity.md)). "arch §N" refers to the
cluster architecture (`cluster-architecture.md`).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Scope and fixed decisions

In scope (M2b): closed federation between a small set of operator-approved hubs, every user hosted
on exactly one hub, groups owned and sequenced by their creator's hub.

Fixed decisions (not re-opened here):

| # | Decision |
|---|---|
| F1 | Closed federation first: a `FederationPolicy` trait with `AllowlistPolicy` (allowlist + optional libp2p pnet PSK). Open federation is an extension point only (§3.6). |
| F2 | rust-libp2p: Noise, QUIC + TCP, private Kademlia `/gim/kad/1.0.0`, request-response `/gim/s2s/1.0.0` (prost). libp2p is isolated behind a hub-internal transport module. |
| F3 | Hub ROOT key = persisted `hub_key` (determines `hub_id`); the runtime key is the libp2p identity (PeerId), certified by a `SignedHubRuntimeCert`. A PeerId is the 38-byte form on the wire. |
| F4 | `gid = "<owner hub_id>/<rand128 b32lower>"`, MLS `group_id` = UTF-8 gid bytes. The owning hub sequences every message of its groups (arch §7.2). Owning-hub migration is out of scope. |
| F5 | Handshake messages are `PublicMessage`; the owning hub validates `0xF001` credentials against DeviceLists. |
| F6 | `UserHostingRecord` per the identity spec (each hub entry signed by the hub ROOT key, canonical hub order); DHT key `/gim/user/<user_id>`. |
| F7 | Multi-homing (M2c) comes later. Nothing here may preclude a user hosted on several hubs: one copy per member hub, receivers dedup by `message_id`. |

Out of scope: open-federation policy implementation, NAT traversal (AutoNAT, Circuit Relay,
DCUtR; hubs are directly reachable), owning-hub migration, multi-homing behaviour (only kept
possible), push.

### 1.1 Terms

| Term | Meaning |
|---|---|
| local user | A user with a row in `users` on this hub (uploaded a DeviceList here). |
| hosted user | A local user whose current, unexpired hosting record lists this hub's `hub_id`. Only hosted users are federated. |
| remote user | Any user that is not a local user. |
| owning hub / owner | The hub whose `hub_id` prefixes a gid. |
| member hub | A hub hosting at least one current member of a group it does not own. |
| replica | A member hub's local copy of a remote-owned group (`groups` row, roster, log suffix). |
| bound peer | A libp2p PeerId for which a valid `Hello` has bound it to a `hub_id` (§3.2). |
| listed | The caller's bound `hub_id` appears in an entry of the acting user's current hosting record (entries carry `hub_root_pubkey`; `hub_id` is derived from it). |

Note: [`s2s.md`](s2s.md) currently says "the calling PeerID appears in the acting user's
hosting record". Hosting entries carry hub root keys, not PeerIds; this document refines
"listed" to the bound `hub_id`, and `s2s.md` is updated accordingly in H3-T1.

## 2. Architecture overview

```
                  client API (REST + WS, unchanged)
                               │
┌──────────────────────────────┴───────────────────────────────────────┐
│ gim-hub-api   handlers (groups, messages, keypackages, identity, ...) │
│               └── calls `Federation` (trait) for anything remote      │
├───────────────────────────────────────────────────────────────────────┤
│ gim-hub-s2s   federation service                                      │
│   ops/        inbound S2S handlers + outbound request helpers         │
│   hosting/    hosting record store, resolver, DHT publisher           │
│   outbox/     durable per-peer outbound queue worker                  │
│   policy.rs   FederationPolicy, AllowlistPolicy                       │
│   transport/  ONLY module that imports libp2p: swarm, Hello binding,  │
│               kad, request-response codec, pnet                       │
├───────────────────────────────────────────────────────────────────────┤
│ gim-hub-db    SQLite (new tables: §4.3, §5.1, §7.1, §8.1)             │
└───────────────────────────────────────────────────────────────────────┘
```

- `transport/` exposes a libp2p-free API to the rest of the crate:
  `request(hub_id, S2sRequest) -> Result<S2sResponse, TransportError>`, an inbound stream of
  `(hub_id, S2sRequest, Responder)`, `dht_put(key, bytes)`, `dht_get(key) -> Vec<bytes>`, and
  peer up/down notifications keyed by `hub_id`. Callers never see a PeerId or a multiaddr type,
  so a libp2p upgrade touches one module (plan risk "rust-libp2p API churn").
- `gim-hub-api` depends on a `Federation` trait (defined in `gim-hub-s2s`, object-safe, with a
  `Disabled` implementation). With federation disabled (`GIM_HUB_FEDERATION=false`, the default)
  the hub behaves exactly as today: remote targets are `missing`, remote gids are `not_found`.
- No network I/O happens inside a database write transaction. Handlers resolve everything remote
  first (hosting records, DeviceLists), then run the transaction, and the transaction only
  enqueues outbound work into the durable outbox (§7).

## 3. Peer authentication and policy

### 3.1 Runtime key and certificate

- The data directory gains `runtime_key` (32-byte Ed25519 seed, mode 0600) and `runtime_cert`
  (`SignedHubRuntimeCert` CBOR). Both are generated at first start when federation is enabled.
- The runtime key is the libp2p host key; `PeerId = 0x00 0x24 0x08 0x01 0x12 0x20 ||
  runtime_pubkey` (identity spec "libp2p PeerId").
- Certificate lifetime: `GIM_HUB_RUNTIME_CERT_DAYS` (default 30). At startup and then daily,
  when less than one third of the lifetime remains, the hub issues a new certificate for the
  **same** runtime key (PeerId unchanged), writes it atomically (temp file + rename), republishes
  its locator (§3.5) and sends a fresh `Hello` on each open connection.
- Rotating the runtime key (new PeerId) is an operator action: stop the hub, delete
  `runtime_key` and `runtime_cert`, start. gids, hosting records and allowlists are unaffected
  because they name `hub_id`, never a PeerId.
- Resolved in H3-T1: a new certificate's `not_before` is set 5 minutes before issuance, so peers
  whose clocks are slightly behind accept it immediately (step 2 of §3.2 checks
  `not_before <= now`). `not_after` is issuance + `GIM_HUB_RUNTIME_CERT_DAYS`.

### 3.2 Binding a PeerId to a hub_id: `Hello`

Noise authenticates the connection's PeerId. The binding PeerId → `hub_id` is established by the
first S2S operation on a connection, `Hello`, which carries the runtime certificate.

```
dialer D                                       listener L
  │── Noise handshake (PeerId_D, PeerId_L) ──────│
  │── S2sRequest{hello: HelloRequest{cert_D}} ──►│ verify cert_D, bind PeerId_D → hub_id_D,
  │                                              │ policy.allow_hub(hub_id_D)
  │◄── S2sResponse{hello: HelloResponse{cert_L}} │
  │ verify cert_L, bind PeerId_L → hub_id_L,     │
  │ check hub_id_L is the hub D meant to dial    │
```

Verification of a received certificate (both directions), in order; the first failure refuses
the peer:

1. Read `hub_root_pubkey` from the body (element 1) without trusting other fields, derive
   `hub_id` from it (identity spec "Verification order", step 2).
2. `HubRuntimeCert::verify(cert, hub_root_pubkey, now)` (signature, version, element count,
   `runtime_pubkey` valid, `not_before <= now < not_after`).
3. `peer_id(runtime_pubkey)` equals the connection's PeerId.
4. `policy.allow_hub(hub_id)` (§3.3).
5. Dialer only: when dialing for a specific `hub_id` (always, except bootstrap addresses without
   a known hub), the responder's `hub_id` equals it.

Rules:

- The binding is kept in memory per PeerId until `not_after` of the certificate, or until the
  policy is reloaded and no longer allows the hub. New connections from a bound PeerId reuse it.
  A newer certificate in a later `Hello` replaces the binding.
- Any operation other than `Hello` from an unbound PeerId fails with `HELLO_REQUIRED` (new
  code, §9.1). A caller receiving `HELLO_REQUIRED` sends `Hello` and retries the request once.
- An inbound connection that has not completed `Hello` within 5 seconds is closed.
- Requests may be sent concurrently on one connection after the binding exists (request-response
  opens one stream per request).
- `HelloRequest`/`HelloResponse` also carry the sender's advertised listen multiaddrs (binary
  multiaddr bytes). The receiver stores them in `s2s_peers.addrs` only if the binding succeeds.

### 3.3 Allowlist and PSK

`AllowlistPolicy` is configured by the file `GIM_HUB_FEDERATION_ALLOWLIST` (§10). The allowlist
holds **hub_ids** (which commit to the hub root public key), never PeerIds, so runtime-key
rotation needs no allowlist change:

```
# hub_id                                                  [multiaddr ...]
hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq  /dns4/hub-b/tcp/4001 /dns4/hub-b/udp/4001/quic-v1
hbbbbbb...                                                # address learned from the DHT
```

- One hub per line; `#` starts a comment; optional static multiaddrs (without `/p2p/`) after the
  hub_id. An invalid hub_id or multiaddr stops startup (and is logged and ignored on reload,
  keeping the previous policy).
- The hub's own `hub_id` may be present and is ignored.
- Reloaded on SIGHUP. Bindings of hubs no longer listed are dropped, their connections closed and
  their outbox entries kept (they expire by TTL, §7.5).
- An empty or missing allowlist with federation enabled stops startup.

PSK (optional, `GIM_HUB_P2P_PSK_FILE`, libp2p `swarm.key` format
`/key/swarm/psk/1.0.0/\n/base16/\n<64 hex chars>`):

- libp2p pnet only wraps stream transports, so with a PSK **the hub runs TCP only**: QUIC is
  neither listened on nor dialed. A QUIC multiaddr in `GIM_HUB_P2P_LISTEN`, `GIM_HUB_P2P_BOOTSTRAP`
  or the allowlist while a PSK is set is a configuration error that stops startup (silently
  ignoring it would hide a reachability problem).
- A peer without the PSK fails before Noise; no `Hello` is possible. The PSK is an additional
  network-level gate, never a replacement for the allowlist: both apply.

### 3.4 Refusal behaviour

| Situation | Behaviour |
|---|---|
| `Hello` with an invalid certificate (steps 1-3) | `S2sResponse.error = UNAUTHORIZED` (message names the failed step), then close the connection after the response is flushed (at most 1 s). |
| `Hello` from a hub not on the allowlist (step 4) | `UNAUTHORIZED` "hub not allowlisted", close, and deny new connections from that PeerId for 10 minutes (connection denied at establishment). Logged once per PeerId per 10 minutes at `warn` with `hub_id`. |
| Responder's `hub_id` not the one dialed (step 5) | Dialer closes the connection; the address is marked bad for 10 minutes. |
| Non-`Hello` op from an unbound PeerId | `HELLO_REQUIRED`. |
| Wrong or missing PSK | Connection fails in the pnet handshake; nothing reaches the hub logic. |
| Outbound to a hub not on the allowlist | Never dialed; the operation fails locally (`peer_refused`, §9.3). |

Kademlia: peers enter the routing table only after binding (kad `BucketInserts::Manual`; the
transport adds bound peers' addresses). Inbound `PUT_VALUE` is filtered (`StoreInserts::FilterBoth`)
and accepted only from bound peers that pass the record validator (§4.4). Inbound read queries
(`GET_VALUE`, `FIND_NODE`) on a not-yet-bound connection cannot be gated per request with the kad
behaviour; this residual exposure lasts at most the 5-second `Hello` window and only reveals
signed public records and hub addresses. Deployments that need this closed set a PSK (open
question Q1).

### 3.5 Hub address resolution

Every gid and hosting record names a `hub_id`; the transport resolves `hub_id` → (PeerId,
multiaddrs) in this order:

1. A bound connection to that hub.
2. `s2s_peers` (last certificate and addresses seen, §7.1).
3. Static addresses from the allowlist (dial without a PeerId; the `Hello` binding decides).
4. DHT locator record `/gim/hub/<hub_id>`.

Locator record (hub-internal, defined in `s2s.proto` as `HubLocator`, §9.1):
`HubLocator { runtime_cert, multiaddrs }`. Validator: the key's hub_id equals the hub_id derived
from the certificate's `hub_root_pubkey`, and the certificate verifies at `now` (steps 1-2 of
§3.2). Among valid records the one with the greatest `not_before` wins. Addresses are unsigned:
a poisoned address only fails the Noise PeerId check. Each hub republishes its locator every hour
and after a certificate renewal.

Bootstrap: `GIM_HUB_P2P_BOOTSTRAP` multiaddrs (with or without `/p2p/<PeerId>`) plus the
allowlist's static addresses are dialed at startup and every 5 minutes while the routing table is
empty.

Resolved in H3-T1:

- Step 2 uses an in-memory table of the last PeerId and addresses per bound hub (from `Hello` and
  the dialed address) until H3-T4 adds `s2s_peers`; nothing is persisted yet.
- The locator is published at startup, hourly, after a certificate renewal, and as soon as the
  first peer is bound when an earlier put found no peer.
- "Routing table empty" is read as "no hub currently bound" (peers enter the routing table only
  after binding, §3.4).

### 3.6 `FederationPolicy`

```rust
pub enum Decision { Allow, Deny(&'static str), RateLimited { retry_after_ms: u64 } }

pub trait FederationPolicy: Send + Sync + 'static {
    /// PSK for libp2p pnet; `Some` forces TCP-only transport.
    fn psk(&self) -> Option<[u8; 32]>;
    /// Hub-level admission after the runtime certificate verified (Hello, step 4).
    fn allow_hub(&self, hub_id: &HubId) -> Decision;
    /// Per-request admission for a bound hub, before the op handler runs.
    fn admit(&self, hub_id: &HubId, op: OpKind) -> Decision;
    /// Whether this hub may dial / send to `hub_id` at all.
    fn may_contact(&self, hub_id: &HubId) -> bool;
    /// Static addresses known for a hub (allowlist).
    fn static_addrs(&self, hub_id: &HubId) -> Vec<Multiaddr>;
}
```

- `AllowlistPolicy`: `allow_hub`/`may_contact` = membership in the allowlist; `admit` = `Allow`
  except the per-op rate limits of §6.8.
- Resolved in H3-T1: the trait has one more method with a default,
  `fn known_hubs(&self) -> Vec<HubId>` (empty by default; the allowlist's hubs for
  `AllowlistPolicy`), so bootstrap (§3.5) can dial the static addresses of every allowed hub.
  `Multiaddr` is the transport module's re-export, so callers still do not import libp2p.
- Open federation (extension point, not implemented): an `OpenPolicy` would allow any hub with a
  valid certificate, consult a blocklist and reputation in `allow_hub`, and apply per-hub token
  buckets in `admit`. No protocol change is needed: the decision points above are the only places
  the policy is consulted, and `RATE_LIMITED` already exists on the wire.

### 3.7 Authorization of S2S requests

Every request passes, in order: binding (§3.2) → `policy.admit` → the per-op check below. The
acting user's hosting record is resolved with §4.5; when the caller is not listed in a cached
record, the record is refreshed once (`GetHostingRecord` from the caller, then DHT) before
rejecting, so a freshly published record is not refused.

| Op | Check (beyond binding and policy) | Failure |
|---|---|---|
| `Hello` | §3.2 | `UNAUTHORIZED` |
| `SubmitCommit`, `SubmitMessage` | this hub owns `gid`; caller listed for `sender_user_id`; `(sender_user_id, sender_device_id)` is in the roster | `INVALID` (not owner), `UNAUTHORIZED` (not listed), `UNAUTHORIZED` + `client_code = not_member` |
| `Deliver` | for every message, caller's `hub_id` is the gid prefix | `UNAUTHORIZED` (whole batch) |
| `DeliverWelcome` | caller owns `gid`; this hub hosts `recipient_user_id` | `UNAUTHORIZED`, `NOT_FOUND` |
| `ClaimKeyPackage` | caller listed for `requester_user_id`; this hub hosts `target_user_id` | `UNAUTHORIZED`, `NOT_FOUND` |
| `FetchLog` | this hub owns `gid`; caller listed for at least one current member, or for a member removed by a Commit with `seq >= from_seq` (so a removed member's hub can fetch the removing Commit) | `UNAUTHORIZED` |
| `GetDeviceList`, `GetHostingRecord` | none (public signed objects) | - |
| `NotifyDeviceList` (new) | caller listed for `user_id` | `UNAUTHORIZED` |
| `FetchBlob` (H5-B1) | `blob_id` names this hub as origin and was uploaded here; caller is a reader hub of the uploader (§5.6) | `UNAUTHORIZED`, `INVALID` (legacy or malformed id), `NOT_FOUND` |

"This hub hosts U" means U is a hosted user (§1.1). A hub never acts on behalf of a user it does
not host: outbound requests with an acting user are only sent for hosted users, otherwise the
client call fails with 403 `hosting_record_required` (§9.3).

### 3.8 Dead connections, reconnect and retry (H11)

A hub that dies (crash, `docker stop`, host loss) does not close its connections: it exits
without sending a QUIC `CONNECTION_CLOSE`. Its peers keep the dead connection open until something
detects it, and the libp2p request-response behaviour spreads requests round-robin over all open
connections to a PeerId. When the hub comes back on the same runtime key and address, its peers
hold the dead connection next to the new one the restarted hub dials, and every other request
lands on the dead one. A restarted QUIC endpoint does not reset the old connection either: quinn
signs its connection ids with a key that is random per process, so the new endpoint drops the
peer's packets for old connection ids as invalid instead of answering with a stateless reset.
The dead connection therefore lives until the QUIC idle timeout (10 s); a dead TCP connection
whose host vanished without a FIN lives until the swarm's 300 s idle timeout.

Rules:

1. An outbound request that times out (`GIM_HUB_S2S_TIMEOUT_SECONDS`) or loses its connection
   (closed, reset, or an I/O error on the stream; not a malformed frame) closes every connection
   to the peer that was open when the request was sent; connections opened since are kept.
2. Idempotent ops are then retried once: the hub is resolved again (§3.5), which redials it, and
   the request is sent on the new connection. Every op is retried except `ClaimKeyPackage`, which
   consumes one-time KeyPackages and is not idempotent (s2s.md "Idempotency"); `Hello` has its
   own retry (§3.2). A claim that failed this way moves on to the user's next hub as before.
3. The redial and the retry together get one more S2S timeout. A request to a hub that is down
   therefore fails after at most one more timeout than before: with a dead connection open, 503
   `peer_unavailable` (with `Retry-After`) comes after at most 2 × `GIM_HUB_S2S_TIMEOUT_SECONDS`
   (plus the time `HELLO_REQUIRED` handling takes, unchanged). A hub that just restarted answers
   the first request after at most one timeout plus a redial.
4. A retried `SubmitCommit` or `SubmitMessage` the owning hub had already sequenced returns its
   original `seq` with `duplicate = true`, so the client may see 200 instead of 201; receivers
   dedup retried `Deliver`s by `message_id` and `(gid, seq)`.
5. libp2p ping runs on every connection (multihoming.md §8); a ping unanswered within the S2S
   timeout closes its connection, which bounds the life of a dead connection without traffic to
   about one ping interval plus one timeout.

The fed suite exercises this after every `docker compose stop|start` of a hub; the in-process
test `transport::tests::first_requests_after_a_peer_restart_succeed` reproduces it
deterministically (the peer is killed behind a cut UDP relay, then restarted on the same key and
address).

## 4. Hosting records

### 4.1 Lifecycle

```
client                                own hub H
  │ POST /v2/users/{u}/hosting-entry {priority}   (bearer, own user)
  │──────────────────────────────────────────────►│ HostingEntry::sign(hub_root, u, priority)
  │◄──────────── {hub_id, entry} ─────────────────│
  │ build HostingRecordBody{u, root_pub, seq, expires_at, [entry]}, sign with user root key
  │ PUT /v2/users/{u}/hosting-record {hosting_record}
  │──────────────────────────────────────────────►│ verify, seq rules, store, DHT put
  │◄──────────── 200/201 {hosting_record, ...} ───│
```

- The client (gim-core) builds and signs the record; the hub never holds the user root key.
- Records SHOULD have a lifetime of 7 days; the client renews (new `seq`, same entries) when less
  than 3 days remain, at app start and daily. The hub accepts lifetimes between 1 hour and
  30 days (`expires_at - now`), and emits `hosting_record.expiring` (§9.2) to the user's active
  devices when less than 48 hours remain (at most once per 24 hours per user).
- In M2c the client collects one entry per hub; nothing in these endpoints assumes a single entry.

### 4.2 Client API additions

All are additions to `/v2` (need L1 / gim-core sign-off, §9.2). Records and entries are opaque
gim-core CBOR, base64, as for DeviceLists.

**`POST /v2/users/{user_id}/hosting-entry`** (bearer; `user_id` must be the caller's user)

- Request: `{"priority": 0}` (0..=255, default 0).
- Response 200: `{"hub_id": "h...", "hub_root_pubkey": "<base64 32 bytes>", "priority": 0,
  "entry": "<base64 CBOR HostingEntry [hub_root_pubkey, priority, hub_sig]>"}`.
- Errors: 400 `validation_failed` (priority out of range), 401 `unauthorized`, 403 `forbidden`
  (`user_id` is not the caller's user).
- Signing is deterministic (Ed25519), so repeated calls return identical bytes. The hub signs for
  any local user that can authenticate; admission control for who may be hosted is the existing
  sign-up policy.

**`PUT /v2/users/{user_id}/hosting-record`** (no token: the record is self-certifying, like the
DeviceList)

- Request: `{"hosting_record": "<base64 CBOR SignedHostingRecord>"}`, at most 8192 bytes decoded.
- Checks, in order:
  1. `HostingRecord::verify(bytes, user_id, now)` (identity spec "Hosting record", steps 1-6,
     plus the looked-up `user_id` check) → 400 `invalid_hosting_record` with the identity error
     code in the message;
  2. `user_id` is a local user → else 404 `not_found`;
  3. `1 h <= expires_at - now <= 30 days` → else 400 `invalid_hosting_record`
     (`lifetime_out_of_range`);
  4. `R.supersedes(stored)` (identity spec "Update and seq rules"): `StaleSeq`/`SeqConflict` →
     409 `stale_hosting_record`; `Ok(false)` → 200 unchanged.
- Response: 201 (first record) or 200, body `{"user_id", "hosting_record", "seq", "expires_at",
  "hosted": bool}` where `hosted` says whether the record lists this hub.
- Effects: stored in `hosting_records` with `hosted`; if hosted, published to the DHT
  immediately (asynchronously, outside the request) and marked for republish. A record that does
  not list this hub (user moved away) is accepted and stored; the hub stops republishing it and
  stops acting for the user in federation (client API access is unchanged in M2b; draining is
  M2c).

**`GET /v2/users/{user_id}/hosting-record`** (no token, rate limited like recovery-backup GET)

- Local user: the stored record. Remote user: the resolved record (§4.5).
- 200 same body as PUT (`hosted` is about this hub); 404 `not_found` (no record, or expired);
  503 `peer_unavailable` (resolution needed a peer that did not answer and the DHT had nothing).

Resolved in H3-T2:

- A record larger than 8192 decoded bytes is 413 `payload_too_large` (as for recovery backups);
  a `hosting_record` that is not base64, or a record whose `seq` exceeds 2^63-1, is 400
  `invalid_hosting_record`. The message names the identity error code:
  `invalid hosting record (<code>)`, e.g. `(user_id_mismatch)` or `(lifetime_out_of_range)`.
- `POST .../hosting-entry` needs a JSON body; `{}` means priority 0.
- `GET .../hosting-record` is "rate limited like recovery-backup GET": both document 429 and
  neither enforces a limit yet. `hosted` is false for users that are not local. A local user's
  record is served even when it no longer lists this hub.

### 4.3 Storage

```sql
-- Hosting records: local users' records and the cache of remote users' records.
CREATE TABLE hosting_records (
    user_id      TEXT PRIMARY KEY,
    record       BLOB NOT NULL,      -- SignedHostingRecord CBOR, verbatim
    seq          INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    hosted       INTEGER NOT NULL CHECK (hosted IN (0, 1)),  -- local user AND lists this hub
    hub_ids      TEXT NOT NULL,      -- JSON array of listed hub_ids, canonical record order
    fetched_at   INTEGER NOT NULL,   -- last verification from a remote source (= updated_at for local)
    published_at INTEGER,            -- last successful DHT put (hosted only)
    updated_at   INTEGER NOT NULL
);
CREATE INDEX hosting_records_hosted ON hosting_records(hosted, published_at);
CREATE INDEX hosting_records_expires_at ON hosting_records(expires_at);
```

- The stored record bytes are re-verified when loaded for an authorization decision only if
  `expires_at <= now` would flip the outcome; otherwise the verification at insert time stands
  (same principle as stored DeviceLists).
- Expired remote cache rows are deleted by the hourly retention task; expired local rows are kept
  (they still order future uploads) with `hosted = 0`.

Resolved in H3-T2: two columns are added to `hosting_records`, `expiring_notified_seq` and
`expiring_notified_at`, so that `hosting_record.expiring` (§4.1) is emitted once per record `seq`
and at most once per 24 hours per user, across restarts. The check runs in the hourly retention
task (also when federation is disabled), only for hosted rows (`hosted = 1`, so a user that moved
away is not warned), right after the retention step that deletes expired cache rows and sets
`hosted = 0` on expired local rows.

### 4.4 DHT publication and validator

- Key `/gim/user/<user_id>`, value = `SignedHostingRecord` bytes; kad record `expires` = the
  record's `expires_at`; `publisher` = own PeerId.
- Publish on every accepted hosted upload; republish every `GIM_HUB_DHT_REPUBLISH_HOURS`
  (default 12) for every hosted, unexpired record; put quorum `One` (small closed network).
  Failures are retried on the next republish tick and counted in a metric.
- Record store: in-memory (`MemoryStore`), max 65536 records, max value 8192 bytes. Records are
  not persisted: their publishers republish.
- Validator (inbound `PUT_VALUE` and every `GET_VALUE` result), in order:
  1. key has the prefix `/gim/user/` and a syntactically valid `user_id`;
  2. `HostingRecord::verify(value, user_id_from_key, now)`;
  3. against a record already stored for the key: `R.supersedes(S)`; `Ok(true)` replaces,
     `Ok(false)` keeps, any `Err` rejects;
  4. inbound puts only: the sender is a bound peer.
- Key `/gim/hub/<hub_id>`: §3.5 validator. Any other key prefix is rejected.

Resolved in H3-T2: besides the republish tick (immediately at startup, then every
`GIM_HUB_DHT_REPUBLISH_HOURS`), hosted records whose current version was never published
(`published_at IS NULL`, e.g. the put failed for lack of peers) are published again whenever a
peer hub comes up. The failure metric is a counter on the hosting service
(`Hosting::publish_failures`).

### 4.5 Lookup and cache

`resolve(user_id, purpose)` returns the newest valid record known:

1. Local user: the stored record (no network).
2. Cache row younger than `GIM_HUB_HOSTING_CACHE_SECONDS` (default 600) and unexpired: use it.
   `purpose = authorize` with the caller not listed bypasses this step once (§3.7).
3. Cached but stale: `GetHostingRecord(user_id)` to the cached record's primary hub (lowest
   priority, ties by smallest hub_id), then the other listed hubs. Not cached and
   `purpose = authorize`: `GetHostingRecord(user_id)` to the calling hub first (it claims to host
   the user, so it holds the record).
4. Otherwise, or if 3 failed: DHT `get_record`, collecting results for up to 5 s or 3 distinct
   valid records, and `HostingRecord::latest` over them and the cached row.
5. The winner is stored (seq rules against the cached row; a lower seq from the network never
   replaces a cached higher one) with `fetched_at = now`.

Concurrent resolutions of the same `user_id` are coalesced (single flight).

Resolved in H3-T2:

- Step 3 asks the hubs in order (caller first for `purpose = authorize`, then the cached record's
  hubs by `(priority, hub_id)`, this hub skipped) and stops at the first valid record. A hub
  answers `GetHostingRecord` only for its local users (never from its cache, so a stale cache is
  not passed on); otherwise `NOT_FOUND`.
- Step 4: the transport's `dht_get` returns the collected values at once, so the 5 s limit is a
  timeout on the whole lookup (nothing is used on timeout); it stops early at 3 valid records.
- Step 5: a network record replaces the cached row only if it `supersedes` it (`Ok(true)`); an
  equal-seq conflict keeps the cached row. When the network returns the cached record itself,
  only `fetched_at` is refreshed. When nothing newer is found, an unexpired cached row is
  returned even if stale. The client API answers 503 `peer_unavailable` (with `Retry-After: 5`)
  only when no valid record is known and at least one asked hub did not answer; otherwise 404.
- Stored records were verified on insert, so loading one only decodes it and compares
  `expires_at` with the current time.
- Helpers for the other subtasks (`gim_hub_s2s::Hosting`): `require_hosting_record(user_id)`
  (local, unexpired, lists this hub; else `HostingError::Required`, mapped to 403
  `hosting_record_required`), `resolve(user_id)` and `resolve_for(user_id,
  Purpose::Authorize(caller))`.

## 5. Remote users, devices and groups

### 5.1 Remote DeviceLists

```sql
-- Cache of DeviceLists of remote users (users without a row in `users`).
CREATE TABLE remote_device_lists (
    user_id         TEXT PRIMARY KEY,
    root_pubkey     BLOB NOT NULL,
    device_list     BLOB NOT NULL,   -- SignedDeviceList CBOR, verbatim
    device_list_seq INTEGER NOT NULL,
    fetched_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
```

- The hub uses one accessor, `device_list(user_id)`: the `users` row if the user is local,
  otherwise `remote_device_lists`. `mls::check_leaf_credential` is unchanged; it receives the
  bytes from that accessor.
- Remote users never get `devices` rows, sessions or KeyPackages here: they cannot sign in on a
  hub that does not store them as local users.
- Fetch: `GetDeviceList(user_id)` to the user's primary hub (via §4.5), verified with
  `DeviceList::verify(bytes, user_id)`, stored with the seq rules (`supersedes`; a lower seq from
  the network is ignored, a conflict is logged and the cached copy kept).
- Refresh triggers:
  - cache miss, or `fetched_at` older than `GIM_HUB_DEVICE_LIST_CACHE_HOURS` (default 24) at the
    time of use;
  - a credential check for that user failing with `no_device_list`, `unknown_device` or
    `revoked_device` while the cached copy is older than 60 s: refetch once, then decide;
  - `NotifyDeviceList` push (below).
- Propagation (`device_list.updated`): when a local hosted user's DeviceList is replaced
  (`PUT /v2/users/{user_id}/device-list`, 200 with a higher seq), the hub enqueues one
  `NotifyDeviceList{user_id, device_list_cbor}` outbox entry (coalesced per peer and user, §7.1)
  for every peer hub that has a replica or ownership relation with that user: the owning hubs of
  all groups the user is in, and the member hubs of the groups this hub owns that contain the user.
  The receiver verifies, applies the seq rules to `remote_device_lists` (or to `users` if it has
  a local row for that user, as if uploaded) and answers `{}`. Event emission is unchanged from
  single-hub: `device_list.updated` goes only to the user's own devices, which all live on the
  user's hub.
- `GET /v2/users/{user_id}` and `GET /v2/users/{user_id}/device-list` for a remote user return
  the cached/fetched list (contract behaviour change, §9.2); 404 if the user cannot be resolved,
  503 `peer_unavailable` if their hub is unreachable and no cached copy exists.

Resolved in H3-T3:

- **Receiver events.** Since H2-T9 a single-hub DeviceList replacement also notifies the user's
  group peers. To keep parity, a hub that replaces a cached remote list with a higher seq (from
  `NotifyDeviceList` or a refresh) emits `device_list.updated` (payload as for a local upload) to
  its local active devices sharing a group with the user. Caching a list for the first time emits
  nothing (as the single-hub "created" case).
- **Peer hubs.** The `NotifyDeviceList` targets are computed from this hub's tables: the owner
  (gid prefix) of every group with the user as a member (owned groups and replicas), plus every
  hub listed in the stored hosting records of the other members of the groups this hub owns that
  contain the user; this hub excluded. Entries are queued only while the user's row in
  `hosting_records` is `hosted`.
- **Local receivers.** A `NotifyDeviceList` for a user with a `users` row here is applied with the
  upload path (seq rules, device (de)activation, events); a stale or equal list is a no-op. The
  receiver does not propagate it further (the sending hub does).
- **Fetch.** `GetDeviceList` goes to the hubs of the user's resolved record in
  `(priority, hub_id)` order, this hub skipped, stopping at the first valid list. A hub answers
  `GetDeviceList` only for its local users (never from its cache); otherwise `NOT_FOUND`. A list
  whose `seq` exceeds 2^63-1 is invalid. When no hub answers, a stale cached copy is used; 503
  only without any copy.
- **API.** `gim_hub_s2s::DeviceLists` (`AppState::device_lists`): `device_list_for(user_id)`
  (local row or cached/fetched remote copy) and `refetch_after_failure(user_id)` (refetch a remote
  copy older than 60 s) for the commit path; `ops::device_list::local_device_list` is the
  `OutboxSource::device_list` of `device_list` entries.

### 5.2 Remote KeyPackage claims

A client always claims through its own hub (`POST /v2/keypackages/claim`, unchanged request).
The own hub routes each target by its hosting record: hosted here (or local user without a record,
the single-hub case) → local claim as today; otherwise one `ClaimKeyPackage{requester_user_id,
target_user_id, device_id?}` per target to the target's primary hub, in parallel, each with the
S2S timeout.

The own hub records every brokered remote claim so it can later recognise the Add:

```sql
-- KeyPackages this hub claimed from other hubs on behalf of its users.
CREATE TABLE remote_kp_claims (
    kp_ref               BLOB PRIMARY KEY,   -- mls::key_package_hash of the KeyPackage
    user_id              TEXT NOT NULL,      -- target user
    device_id            TEXT NOT NULL,      -- target device (as returned by the target hub)
    target_hub_id        TEXT NOT NULL,
    claimed_by_user_id   TEXT NOT NULL,
    claimed_by_device_id TEXT NOT NULL,
    claimed_at           INTEGER NOT NULL
);
CREATE INDEX remote_kp_claims_claimed_at ON remote_kp_claims(claimed_at);
```

Rows older than 7 days are pruned by the retention task. A KeyPackage that does not parse
(`mls::parse_key_package`) is dropped and its target reported in `missing`.

Response: same shape plus a new `unavailable: [ClaimTarget]` list for targets whose hub could not
be reached, refused the request, or timed out (§9.2). `missing` keeps its meaning (unknown user,
no active device, no KeyPackage).

Resolved in H3-T3:

- **Routing.** With federation disabled every target is claimed locally (single-hub behaviour). A
  local user (row in `users`) is always claimed locally. Otherwise the target's record is resolved
  (§4.5): none known → `missing`; resolution failed for lack of a peer → `unavailable`; the record
  lists this hub → local (so `missing`); else the primary hub (lowest priority, ties by smallest
  `hub_id`) is asked. Only the primary hub is asked. *Superseded by docs/multihoming.md §5.2:
  the primary hub is asked first, then the fallback hubs, with a per-device follow-up
  (implemented in H4-M4).*
- **Requester check first.** If any target is remote and the caller has no valid hosting record
  listing this hub, the whole request fails with 403 `hosting_record_required` before anything
  is claimed.
- **Responses.** A `ClaimKeyPackage` answer without packages counts as `NOT_FOUND` (`missing`);
  every error other than `NOT_FOUND` (including `INVALID`) counts as `unavailable`. A package that
  does not parse is reported in `missing` with its `device_id`.
- **Ledger.** A reused last-resort package keeps one `remote_kp_claims` row (its `kp_ref` is the
  key), updated to the latest claim. Rows older than 7 days are deleted by the hourly retention
  loop of `main.rs`.
- **Handler.** `ClaimKeyPackage` checks, in order: the caller is listed for `requester_user_id`
  (`resolve_for(.., Authorize(caller))`; a resolution that needed an unreachable peer answers
  `INTERNAL`, retryable), the target is hosted here (`require_hosting_record`, else `NOT_FOUND`),
  then the 10/min limit per `(caller, requester, target)` as a fixed one-minute window
  (`RATE_LIMITED`); it then claims exactly as a local client would (including `keypackages.low`)
  and answers `NOT_FOUND` if nothing was claimed.

### 5.3 Groups on the owning hub

The owning hub keeps the authoritative group exactly as today (`groups`, `group_members`,
`messages`). `group_members` has no foreign key to `devices`, so remote members are stored the same
way as local ones. New:

```sql
-- Membership changes of each Commit, needed to rebuild SequencedMessage for Deliver and FetchLog.
CREATE TABLE commit_membership (
    gid       TEXT NOT NULL REFERENCES groups(gid) ON DELETE CASCADE,
    seq       INTEGER NOT NULL,
    change    TEXT NOT NULL CHECK (change IN ('added', 'removed')),
    user_id   TEXT NOT NULL,
    device_id TEXT NOT NULL,
    PRIMARY KEY (gid, seq, change, user_id, device_id)
) WITHOUT ROWID;
```

Credential validation of remote members (Commits submitted locally or via `SubmitCommit`):

- Committer's own leaves (Update proposals, UpdatePath): checked against `device_list(sender)`,
  expected identity = the sender, as today.
- Added members: the expected `(user_id, device_id)` comes from, in order:
  1. this hub's claim ledger (`key_packages` claimed rows, then `remote_kp_claims`) by `kp_ref`;
  2. only for Commits received via `SubmitCommit`: the `(user_id, device_id)` certified by the
     KeyPackage's `0xF001` credential itself. The submitting hub has already required the
     KeyPackage in *its* claim ledger (§6.3, step 2); the owner cannot see that ledger and instead
     relies on the cryptographic check below.

  Then `check_leaf_credential(leaf, device_list(user_id), user_id, device_id)`, fail closed.
  For a Commit submitted directly by a client of the owning hub, a KeyPackage missing from the
  owner's ledger is rejected as today.
- DeviceLists of all users involved are made fresh (§5.1) **before** the write transaction; the
  transaction re-reads them from the database.

Resolved in H3-T5:

- **Identity from the credential.** For a `SubmitCommit` Add whose `kp_ref` is in neither ledger,
  the expected identity is `(user_id of the credential's root key, device_id of the leaf's MLS
  signature key)`; `check_leaf_credential` then verifies it against that user's DeviceList.
- **Freshness and refetch.** Before the transaction the hub calls `device_list_for` for the
  committer (if it sets own leaves) and every added user, then runs the credential checks against
  the stored lists (`users`, else `remote_device_lists`) and calls `refetch_after_failure` for
  every user whose check failed. The transaction repeats the checks authoritatively. A remote list
  that cannot be fetched and is not cached answers 503 `peer_unavailable` (`INTERNAL` to a member
  hub); any other missing list fails closed (`device_list_unknown`).
- **Local events.** Events (`message`, membership, `welcome`) go only to devices of local users
  (a row in `users`); remote members get theirs from their own hub. Welcome recipients that are
  local get the pending Welcome and event as on a single hub; for the others one
  `DeliverWelcome` per (recipient hub, recipient user) is queued, with the Commit's `message_id`.
- **Fan-out records.** The hosting records of the roster and of the added users are resolved
  (cached) before the transaction; the transaction reads the stored rows. A user without a stored
  record contributes no hub.

Resolved in H3-FX3 (Proposals and Commits by reference):

- **Proposals.** A PublicMessage Proposal (Add, Remove, SelfRemove, Update) on
  `POST /v2/groups/{gid}/commits` or in `SubmitCommit` is sequenced like a Commit (member sender at
  its leaf, current epoch, dedup by hash, `client_id` unique) but leaves epoch and roster alone. It
  is stored as `messages.kind = 'proposal'` (`commit_hash` = its hash) and indexed in
  `pending_proposals (gid, proposal_ref, epoch, seq)` under its `ProposalRef` for SHA-256, SHA-384
  and SHA-512 (the hub does not know the group's ciphersuite; a reference's length selects the
  hash). Rows of earlier epochs are deleted whenever the epoch advances. An Update's leaf is checked
  against the sender's DeviceList; an Add only when a Commit references it.
- **Commits by reference.** Each `ProposalOrRef::Reference` is resolved against
  `pending_proposals` for the Commit's epoch before the transaction (an unknown reference is
  `INVALID` / 400); the resolved Adds, Removes and Updates then go through the same claim ledger,
  burn and credential checks as proposals by value. An Update by reference sets the proposer's
  leaf, which was checked when the Proposal was submitted.
- **Replicas** store a delivered Proposal with `kind = 'proposal'` and index it the same way when
  it belongs to the replica's current epoch, so a member hub resolves the references of a Commit
  it forwards (claim ledger rule for Adds by reference, §6.3 step 2). A reference unknown to the
  replica first triggers a bounded `FetchLog` catch-up; a replica still behind the Commit's epoch
  answers 503 `peer_unavailable`.

### 5.4 Replicas on member hubs

A member hub keeps a replica of every remote-owned group with a local member, so the client API
(`GET /v2/groups`, `GET /v2/groups/{gid}`, `GET /v2/groups/{gid}/messages`, events) works
locally and survives an owner outage for reads.

- Rows go into the existing `groups`, `group_members`, `messages` tables. Ownership is derived
  from the gid prefix (no new column). New columns on `groups`:

  ```sql
  ALTER TABLE groups ADD COLUMN replica_from_seq INTEGER;  -- NULL: owned; else first seq held locally
  ALTER TABLE groups ADD COLUMN detached INTEGER NOT NULL DEFAULT 0 CHECK (detached IN (0, 1));
  ```

- Creation: from `DeliverWelcome`, which carries a `GroupSnapshot` as of the Commit that added
  the recipient (§9.1): kind, creator, `created_at`, epoch after the Commit, `seq` of the Commit,
  full roster after the Commit. The replica starts with `last_seq = snapshot.seq`,
  `epoch = snapshot.epoch`, `replica_from_seq = snapshot.seq + 1`, roster = snapshot.
- If a replica exists but has no local members (`detached = 1`), a `DeliverWelcome` replaces it
  from the snapshot (its log suffix is stale). A replica with local members ignores the snapshot.
- Update: only by applying `SequencedMessage`s in `seq` order (§6.6). A Commit applies
  `added_members`/`removed_members` to the roster and sets `epoch = commit.epoch + 1`.
- When the last local member is removed, the replica is marked `detached = 1`; it no longer
  receives messages. Detached replicas older than the event retention are deleted by the retention
  task.
- History: a replica serves `GET /v2/groups/{gid}/messages` only from `replica_from_seq` on; a
  `from_seq` below it returns messages starting at `replica_from_seq` (the client could not
  decrypt earlier messages anyway). This is the only client-visible difference in reads (§6.7).

Resolved in H3-T5:

- **Join point.** A replica created (or replaced) from a `DeliverWelcome` starts just before the
  Commit that produced it: `last_seq = snapshot.seq - 1`, `epoch = snapshot.epoch - 1`,
  `replica_from_seq = snapshot.seq`, roster = snapshot. The Commit itself then arrives through
  `Deliver` (queued right behind the Welcome, §7.2) and emits `group.member_added` to the new
  local members as on a single hub. The Commit's `message` event goes to the previous local
  members only: devices the Commit adds are excluded even when the snapshot already lists them.
- "Local members" are roster devices of users with a `users` row. Replica roster rows have no
  leaf index (the owner validates Commits).
- With federation enabled, a gid whose prefix is another hub is always handled as a replica; with
  federation disabled every gid is handled locally (single-hub behaviour).
- **Detached replica retention (H4-CL3).** `groups.detached_at` (unix ms, migration
  `0008_replica_detached_at.sql`) is set when a replica is detached: by a Commit that removes its
  last local member (the Commit's time), or by the removal of its last local user (the user's
  `removed_at`, multihoming.md §7.3). Re-detaching keeps the first time; a replica replaced from a
  `DeliverWelcome` starts attached with `detached_at = NULL`. Replicas detached before the
  migration count from the migration time. The hourly retention task deletes replicas with
  `detached_at` older than `GIM_HUB_EVENT_RETENTION_DAYS`, cascading to their roster, messages and
  `commit_membership`; groups owned here (`replica_from_seq = NULL`) are never deleted.

### 5.6 Blobs (H5-B1)

Clients only talk to their own hub; the hub federates blob reads.

- **Ids.** `POST /v2/blobs` returns `blob_id = <origin hub_id>/b_<base64url(16 random bytes)>`,
  the uploading hub being the origin (same convention as gids; `/` is `%2F` in paths). Ids
  without `/` (`b_<...>`, uploaded before this change) are legacy single-hub ids: they always mean
  "this hub" and are never fetched over S2S. Existing rows keep their ids; no data migration.
- **Files.** Contents live in `$GIM_HUB_DATA_DIR/blobs/`. A legacy id is its own file name; for an
  origin-qualified id the `/` becomes `_` (hub ids are lowercase base32, so names stay distinct).
  Only ids that parse (valid `hub_id`, `b_` + 22 base64url characters) are mapped to a file, and
  only after a database lookup (`blobs` or `remote_blobs`), never from the path segment alone.
- **Tables.** `blobs` holds blobs uploaded here; `remote_blobs (blob_id, size, fetched_at)`
  (`0010_remote_blobs.sql`) holds cached copies of other hubs' blobs.
- **Download** (`GET /v2/blobs/{blob_id}`, authenticated as before):
  1. legacy id or own origin: `blobs` row → serve (Range as before), else 404;
  2. foreign origin with a `remote_blobs` row: serve the cached copy (Range as before);
  3. foreign origin, not cached, federation disabled: 404;
  4. foreign origin, not cached: fetch from the origin with `FetchBlob`, store, record, serve.
     Fetches are serialized per blob id (an in-process lock): concurrent downloads of one blob
     fetch it once, later ones find the cached copy. The fetch runs in its own task, so a client
     that disconnects does not abort it.
- **Fetch.** `FetchBlob{blob_id, offset, max_len = 4 MiB}` until `size` bytes arrived; every
  chunk must report the same `size` and echo its `offset`, and `size` must not exceed the
  requester's `GIM_HUB_MAX_BLOB_BYTES`, otherwise 502 `peer_refused`. Chunks go to
  `.<file name>.<random>.tmp`, synced and renamed into place before the `remote_blobs` row is
  written, so a partial fetch never becomes visible; a failed or interrupted fetch (restart) is
  simply repeated on the next download. Blobs are immutable, so a refetch is idempotent.
- **Error mapping** (as §6.3):

  | Origin result | Client response |
  |---|---|
  | chunk(s) | 200 / 206 from the cached copy |
  | `NOT_FOUND` | 404 `not_found` |
  | `UNAUTHORIZED`, `INVALID`, any other refusal, local policy refusal, inconsistent chunks, blob over the size limit | 502 `peer_refused` |
  | timeout, transport error, `INTERNAL`, `RATE_LIMITED`, `HELLO_REQUIRED` after retry | 503 `peer_unavailable` with `Retry-After` |

- **Authorization on the origin** (beyond binding and `policy.admit`, which rate-limits
  `FetchBlob` per caller with `GIM_HUB_FETCH_BLOB_PER_MINUTE`, default 600 requests of up to
  4 MiB):
  1. the id is origin-qualified and names this hub, else `UNAUTHORIZED` (another origin) or
     `INVALID` (legacy or malformed). A hub never serves a cached copy of another hub's blob: no
     transitive serving;
  2. a `blobs` row exists (uploaded here), else `NOT_FOUND`;
  3. the caller is a reader hub of the uploader, else `UNAUTHORIZED`. Reader hubs are
     `device_list_peer_hubs(uploader)` (the uploader's co-hosts, the owning hubs of the uploader's
     groups, the hubs of the members of groups owned here that contain the uploader) plus the
     hubs listed for every member of any group the uploader is in, whoever owns it (replicas
     included). The extension covers a group owned by a third hub, where the reader's hub is
     neither the owner nor listed in a group owned by the origin. Cached hosting records are used
     as they are (no refresh).
- **Threat model.** Blob ids carry 128 random bits and are unguessable; contents are encrypted
  end to end (the key travels inside MLS messages). The origin cannot know which message
  referenced a blob, so the check is relationship-based rather than per message: it ties access
  to an existing relationship with the uploader and keeps unrelated allowlisted hubs out. A
  malicious allowlisted hub that learns an id and hosts a user sharing a group with the uploader
  can fetch the ciphertext only. A malicious origin can only serve wrong bytes for its own ids,
  which the client's decryption rejects; it cannot overwrite another hub's blobs (file names are
  derived from the full id, including the origin).
- **Multi-homing.** Co-hosts of the uploader are reader hubs, so a user's other hubs fetch the
  same way. While the origin is down, a hub that already cached a copy keeps serving it; a hub
  that never fetched it answers 503 (multihoming.md Q6).
- **Retention.** Neither uploaded blobs nor cached copies are pruned today; a cache eviction
  policy is future work (operations.md).

## 6. Flows

Notation: `C@H` = client C on its own hub H. Owner of the group = A. All S2S calls go through the
binding/policy/authorization checks of §3. "Sync" = the client request waits for the S2S response
(timeout `GIM_HUB_S2S_TIMEOUT_SECONDS`, default 10); "queued" = durable outbox (§7).

### 6.1 Cross-hub KeyPackage claim (via own hub)

```
bob@B                    hub B                                  hub A (hosts alice)
 │ POST /v2/keypackages/claim {targets:[{user_id: alice}]}
 │──────────────────────►│ resolve(alice) → record lists A (§4.5)
 │                       │── ClaimKeyPackage{bob, alice} (sync) ────►│ caller B listed for bob? (resolve(bob))
 │                       │                                           │ alice hosted on A? claim one KP per
 │                       │                                           │ active device (keypackages.low locally)
 │                       │◄── {key_packages:[{device_id, kp, last_resort}]}
 │                       │ insert remote_kp_claims(kp_ref → alice/device, A, bob/device)
 │◄── 200 {key_packages:[...user_id: alice], missing:[], unavailable:[]}
```

Failure mapping: transport error, timeout, `INTERNAL`, `RATE_LIMITED`, `UNAUTHORIZED` →
`unavailable`; `NOT_FOUND` → `missing`. Nothing is retried automatically (claims are not
idempotent).

### 6.2 Group create with remote members

```
bob@B: POST /v2/groups {kind}            → B assigns gid = <B hub_id>/<rand>, epoch 0, bob only (local, as today)
bob@B: claim alice (A) and carol (C)     → 6.1
bob@B: POST /v2/groups/{gid}/commits {client_id, mls_message (Add alice, Add carol), welcome,
                                        welcome_recipients:[alice/d1, carol/d1], ratchet_tree?}
hub B (owner):
  1. parse, group_id check, epoch check, sender leaf check (as today)
  2. Adds: kp_ref found in remote_kp_claims → expected identities; ensure DeviceLists of alice,
     carol fresh (GetDeviceList to A and C, before the transaction); check_leaf_credential
  3. transaction: append Commit (seq s), commit_membership rows, epoch+1, roster update, local
     events (as today), and outbox entries:
       DeliverWelcome(alice …, snapshot@s) → A      DeliverWelcome(carol …, snapshot@s) → C
       Deliver(seq s)                      → A, C   (fan-out set, §6.4)
     Welcome entries are enqueued before the Deliver entry of the same Commit for the same peer.
  4. 201 {seq: s, epoch: 1, duplicate: false}
hub A on DeliverWelcome: create replica from snapshot (§5.4), pending_welcomes + `welcome` event
  to alice/d1 (dedup by message_id); on Deliver(seq s): seq <= last_seq → duplicate, ack s.
```

A direct message (`kind = direct`) is the same flow with one added member.

### 6.3 Commit from a member on a non-owning hub

```
alice@A: POST /v2/groups/{gid}/commits {...}        (gid owned by B)
hub A (member hub), before forwarding:
  1. replica exists and (alice, device) is in its roster → else 403 not_member / 404 not_found
  2. parse (PublicMessage Commit or Proposal, group_id = gid); for a Commit, proposal references
     resolve against the replica (§5.3) and every Add's kp_ref is in A's claim ledger
     (key_packages claimed rows or remote_kp_claims) → else 400 validation_failed
  3. alice hosted on A → else 403 hosting_record_required
hub A → hub B: SubmitCommit{gid, alice, device, client_id, mls_message, welcome?,
               welcome_recipient_device_ids, ratchet_tree?}  (sync)
hub B (owner): authorization (§3.7), then the same processing as a local Commit (§6.2 steps 1-3,
  identities of Adds per §5.3), dedup by Commit hash, first valid Commit per epoch wins.
  → SubmitCommitResponse{seq, epoch (new epoch; for a Proposal its unchanged epoch), duplicate,
    message: SequencedMessage (kind COMMIT or PROPOSAL)}
hub A: apply `message` to its replica immediately (§6.6), so alice's other devices get events
  and read-your-writes holds; then 201/200 to alice. B's later Deliver of the same seq is a
  duplicate and is only acknowledged.
```

Welcome recipients named only by `device_id` are resolved by the owner against the members added
by this Commit (which carry `user_id`); an unmatched device is `INVALID`.

Owner answers and the member hub's client response:

| Owner result | Client response |
|---|---|
| success, `duplicate = false` | 201 `{seq, epoch, duplicate: false}` |
| success, `duplicate = true` | 200 `{seq, epoch, duplicate: true}` |
| `CONFLICT` / `STALE_EPOCH` | member hub first catches up its replica with `FetchLog` (bounded to 2 s), then 409 `stale_epoch` with `current_epoch` from `Error.current_epoch` |
| `INVALID` | 400 `validation_failed`, message from `Error.message` (credential codes preserved) |
| `UNAUTHORIZED` with `client_code` `not_member` / `forbidden` | 403 with that code |
| `UNAUTHORIZED` otherwise (federation/hosting) | 502 `peer_refused` |
| `NOT_FOUND` | 404 `not_found` |
| timeout, transport error, `INTERNAL`, `RATE_LIMITED`, `HELLO_REQUIRED` after retry | 503 `peer_unavailable` (client retries the same Commit; idempotent by hash) |

### 6.4 Fan-out set

For each sequenced message the owner computes the peer set at sequencing time, inside the
transaction, from cached hosting records (resolved before the transaction):

- application message: hubs of the current roster's users;
- Commit: hubs of (roster before the Commit ∪ added users ∪ removed users), so removed members'
  hubs learn of their removal and new members' hubs get the Commit after the Welcome;
- minus this hub; one outbox entry per (peer hub, message), regardless of how many local members
  that hub has (arch §8.3).

"Hubs of a user" = every `hub_id` listed in the user's current hosting record. In M2b each user
lists exactly one hub; in M2c this rule is where the delivery strategy (all hubs for Commits and
Welcomes, primary/fallback for application messages, arch §9.2) plugs in. Receivers dedup by
`message_id`/`(gid, seq)`, so delivering to several hubs of one user is already safe.

The submitting member hub is included like any other member hub (its replica dedups), so a lost
`SubmitCommitResponse` heals through `Deliver`.

### 6.5 Application message forward

```
alice@A: POST /v2/groups/{gid}/messages {client_id, mls_message}     (gid owned by B)
hub A: membership check on the replica; fast path: (device, client_id) already in the replica
       → 200 with the stored message (as single-hub replay); alice hosted → else 403
hub A → hub B: SubmitMessage{gid, alice, device, client_id, mls_message} (sync)
hub B: authorization, epoch check against the group, dedup by (sender_device_id, client_id),
       append, local events, outbox Deliver → member hubs
       → SubmitMessageResponse{seq, epoch, duplicate, message}
hub A: apply message to the replica (events to alice's other devices), respond 201 (or 200 for
       duplicate) with the message DTO built from `message`.
```

Error mapping is the table of §6.3 (`STALE_EPOCH` → 409 `stale_epoch` with `current_epoch`).

### 6.6 Receiver handling (`Deliver`, `FetchLog` results, submit responses)

For each gid in a batch, messages in ascending `seq`; per message, in one write transaction per
batch:

1. `gid`'s owner prefix must be the caller (`Deliver`); otherwise the whole batch is rejected.
2. No replica for the gid (or a detached one): skip the gid's messages and ack
   `highest_contiguous_seq = 0` (or the detached replica's `last_seq`). A replica is only created
   by `DeliverWelcome`, which the owner queues ahead of the Commit's `Deliver` (§7.2); later
   messages then apply normally or are fetched with `FetchLog`.
3. `seq <= last_seq` → duplicate (also checked by `message_id`); skip.
4. `seq == last_seq + 1` → apply: insert into `messages` (owner's `message_id`, `created_at`,
   framing epoch), for a Commit update roster and epoch and insert `commit_membership`; emit
   the same local events a single hub emits (`message` to local previous members except the
   sender device; `group.member_added`/`group.member_removed` to local old and new members, with
   `epoch = commit.epoch + 1` and the Commit's `seq`); notify after commit.
5. `seq > last_seq + 1` → gap: stop processing this gid's remaining messages in the batch (they
   are not stored) and schedule `FetchLog(gid, last_seq + 1)` against the owner.

The `Deliver` response acks `GroupAck{gid, highest_contiguous_seq = last_seq}` for every gid in
the request. `FetchLog` pages (`limit` ≤ 256, owner caps at 256) are applied with the same steps
until `complete`; one gap fill per gid runs at a time.

`DeliverWelcome`: dedup by `(message_id, user_id, device_id)` (new `pending_welcomes.message_id`
column with a unique index); for each recipient device that is an active device of the hosted
recipient: create/replace the replica (§5.4), insert the pending Welcome and emit `welcome` with
the snapshot's `epoch`/`seq` and the request's `sender_device_id`. Unknown or inactive devices are
skipped; the response is `{}` either way.

Resolved in H3-T5:

- **Member hub forwarding (§6.3, §6.5).** Checks in order: replica exists (404) and the device is
  in its roster (403 `not_member`); for Commits every Add `kp_ref` is in this hub's ledger (400);
  the sender has a hosting record listing this hub (403 `hosting_record_required`). Transport
  failures map as: `PeerRefused` (local policy or the owner refused `Hello`) → 502 `peer_refused`;
  every other transport failure → 503 `peer_unavailable`. The owner's `Error.message` becomes the
  400 message. The stale-epoch catch-up is a gap fill bounded to 2 s; without
  `Error.current_epoch` the replica's epoch is reported.
- **Owner answers.** `SubmitCommit`/`SubmitMessage` for a gid this hub does not own → `INVALID`;
  caller not listed for the sender → `UNAUTHORIZED`; sender not in the roster → `UNAUTHORIZED` +
  `not_member`. Sequencing errors keep their client code in `client_code` (`validation_failed`,
  `not_member`, `forbidden`, `not_found`, `stale_epoch`); a stale epoch is `CONFLICT` for Commits
  and `STALE_EPOCH` for application messages, with `current_epoch`.
- **Gap fill.** One fill per (hub, gid) at a time, started by a gap in `Deliver` or in a submit
  response; it pages `FetchLog` (limit 256) from `last_seq + 1` until `complete` or no progress.
  A failed fill is retried when the next `Deliver` for the gid arrives (the outbox resends
  unacknowledged entries).
- **`FetchLog` (owner).** A gid this hub does not own → `UNAUTHORIZED`; unknown group →
  `NOT_FOUND`. "Listed" is first checked against the stored hosting records of the current and
  removed members; only if none lists the caller are they refreshed one by one (§3.7). `limit = 0`
  means 256; `next_seq` = last returned seq + 1 (or `from_seq`); `complete = next_seq > last_seq`.
- **`DeliverWelcome`.** Nothing is created when no recipient device is an active device here.
- **Outbox source (§7.7).** `ops::deliver::GroupSource` builds `deliver` entries from `messages` +
  `commit_membership`, `device_list` entries with `ops::device_list::local_device_list`, and the
  resync nudge from the newest message of every owned group with a member whose stored hosting
  record lists the peer. `refresh_peer` (H4-CL3) refreshes the records of the users of the
  peer's first 256 queued entries (the entry's `user_id`, or the recipient of a
  `deliver_welcome`) through `Hosting` with `Purpose::Refresh`: a remote user's record is
  re-resolved bypassing the fresh cache (listed hubs, then always the DHT) and stored if newer; a
  local user's record is republished to the DHT, where the peer's own refresh finds it.

### 6.7 Client-visible behaviour

Identical to single-hub for every endpoint: per-group `seq` (gap-free, assigned by the owner),
epochs read from the framing, 409 `stale_epoch` with `current_epoch`, Commit dedup by hash
(`duplicate: true`), `client_id` replay of application messages (200 with the stored message),
event types and payloads, Welcomes and pending Welcomes, 410 recovery.

Differences (all additive, §9.2):

- Requests that need a peer synchronously can fail with 503 `peer_unavailable` or 502
  `peer_refused`; KeyPackage claims report `unavailable` targets.
- Federated actions of a user without a valid hosting record listing their hub fail with 403
  `hosting_record_required`.
- A replica serves history only from the point its hub joined (§5.4).
- Events for messages of a remote-owned group arrive after the owner has sequenced them and the
  outbox has delivered them (seconds under normal operation, longer during a peer outage).

### 6.8 Rate limits

Per caller hub, token buckets in `AllowlistPolicy::admit` (constants in M2b, configurable later):
`ClaimKeyPackage` 10/min per `(caller, requester_user_id, target_user_id)` and 600/min per
caller; `GetDeviceList`/`GetHostingRecord` 600/min per caller; everything else unlimited in
closed federation. Exceeding → `RATE_LIMITED`.

Resolved in H3-T1: `admit(hub_id, op)` sees no request fields, so `AllowlistPolicy::admit`
enforces only the per-caller buckets (`ClaimKeyPackage` 600/min; `GetDeviceList` and
`GetHostingRecord` 600/min together). The 10/min limit per `(caller, requester_user_id,
target_user_id)` is enforced by the `ClaimKeyPackage` handler (H3-T3), answering `RATE_LIMITED`.

H5-B1: `FetchBlob` has its own bucket, `GIM_HUB_FETCH_BLOB_PER_MINUTE` requests (default 600,
each at most 4 MiB) per caller.

## 7. Durable outbound queue

Used for owner → member traffic only (`Deliver`, `DeliverWelcome`) and `NotifyDeviceList`.
Client-initiated member → owner requests are synchronous (the client needs the result) and are
never queued; their durability is the client's retry with the same `client_id`/Commit.

### 7.1 Schema

```sql
CREATE TABLE s2s_outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- FIFO order per peer
    peer_hub_id TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('deliver', 'deliver_welcome', 'device_list')),
    gid         TEXT,               -- deliver, deliver_welcome
    seq         INTEGER,            -- deliver: payload is rebuilt from messages + commit_membership
    user_id     TEXT,               -- device_list: latest list is read at send time
    payload     BLOB,               -- deliver_welcome: encoded DeliverWelcomeRequest
    size        INTEGER NOT NULL,   -- bytes counted against the backlog cap
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX s2s_outbox_peer ON s2s_outbox(peer_hub_id, id);
CREATE INDEX s2s_outbox_expires_at ON s2s_outbox(expires_at);
CREATE UNIQUE INDEX s2s_outbox_deliver ON s2s_outbox(peer_hub_id, gid, seq) WHERE kind = 'deliver';
CREATE UNIQUE INDEX s2s_outbox_device_list ON s2s_outbox(peer_hub_id, user_id) WHERE kind = 'device_list';

CREATE TABLE s2s_peers (
    hub_id            TEXT PRIMARY KEY,
    peer_id           BLOB,             -- 38 bytes, from the last valid certificate
    runtime_cert      BLOB,
    cert_not_after    INTEGER,
    addrs             BLOB,             -- encoded list of binary multiaddrs
    last_connected_at INTEGER,
    failures          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   INTEGER NOT NULL DEFAULT 0,
    needs_resync      INTEGER NOT NULL DEFAULT 0 CHECK (needs_resync IN (0, 1)),
    updated_at        INTEGER NOT NULL
);
```

Entries are inserted in the same transaction that sequences the message (or replaces the
DeviceList), so a crash never loses or invents fan-out. `device_list` entries are coalesced by
the unique index (`INSERT ... ON CONFLICT DO NOTHING`; the latest list is read when sending).

### 7.2 Sender worker

- One logical worker per peer with pending entries, **at most one request in flight per peer**,
  entries taken in `id` order. This gives FIFO per peer and therefore order per `(peer, gid)`,
  and keeps a Welcome ahead of the Deliver of its Commit.
- Batching: the head run of consecutive `deliver` entries is sent as one `Deliver` (≤ 256
  messages and ≤ 4 MiB encoded; may mix gids). A `deliver_welcome` or `device_list` entry is sent
  alone.
- Woken by enqueue (in-process notify), by peer-up, and by `next_attempt_at`.

### 7.3 Acknowledgement

| Entry | Removed when |
|---|---|
| `deliver` | the `Deliver` response acks `highest_contiguous_seq >= seq` for its gid. Entries in the batch above the ack stay and are resent (the receiver dropped them at a gap and is fetching the log). |
| `deliver_welcome` | the response is success (`{}`), including the receiver's dedup case. |
| `device_list` | success. |
| any | permanent failure (below) or expiry. |

Entries above the ack are resent with the normal per-peer backoff until the receiver's gap fill
has caught up and acks them, or until they expire (§7.5).

### 7.4 Retry and failure classes

- Retryable: transport error, timeout, `INTERNAL`, `RATE_LIMITED`, `HELLO_REQUIRED` (after one
  immediate re-`Hello`). Backoff is per peer: `min(1 s · 2^failures, GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS)`
  (default max 300 s) with ±20 % jitter; success resets `failures`.
- Permanent for the entry: `INVALID`, `NOT_FOUND`, and `UNAUTHORIZED` after refreshing the
  relevant hosting record once. The entry is dropped, logged at `warn` and counted.
- Peer refused by local policy (`may_contact` false): entries stay until TTL (the allowlist may be
  fixed by a reload).

### 7.5 Backlog cap and TTL

- TTL: `expires_at = created_at + GIM_HUB_OUTBOX_TTL_HOURS` (default 168). Expired entries are
  deleted by the worker and the retention task; if any `deliver` entry of a peer expires, the peer
  is marked `needs_resync`.
- Cap per peer: `GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER` (default 100000) and
  `GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER` (default 1 GiB, `deliver` size = payload length). On
  enqueue beyond the cap, the oldest `deliver` entries of that peer are deleted to make room and
  the peer is marked `needs_resync`. `deliver_welcome` and `device_list` entries are never evicted
  by the cap (only by TTL). Sequencing never fails because a peer is down.
- Operators are alerted by log (`error` once per peer per hour while over 80 % of either cap) and
  metrics (`s2s_outbox_entries{peer}`, `s2s_outbox_bytes{peer}`, `s2s_outbox_dropped_total{peer,reason}`).

### 7.6 Peer outage and recovery

- During an outage the worker backs off; new entries accumulate within the cap. Client requests
  that need the down hub synchronously get 503 `peer_unavailable`; everything else continues.
- On recovery (successful dial, inbound connection or `Hello` from that hub) `failures` and
  `next_attempt_at` reset and the queue drains in order.
- If `needs_resync` is set, after draining the worker sends, for every gid this hub owns with a
  member on that peer, a `Deliver` containing only the newest message of the gid (a "resync
  nudge"). The receiver sees a gap (or a duplicate) and fills it with `FetchLog`. The flag is then
  cleared. The owner's message log is never pruned in M2b, so `FetchLog` does not return `GONE`;
  if log pruning is added later, a pruned range returns `GONE` and the member hub resyncs its
  replica from `replica_from_seq = next available seq`.
- A member hub whose owner is down cannot submit (503) but keeps serving reads from replicas.
  Owner HA is out of scope (arch §10).

### 7.7 Implementation notes (Resolved in H3-T4)

Gaps in §7.1-§7.6 closed by the smallest consistent choice:

- **Enqueue API.** `gim_hub_s2s::OutboxSender::enqueue_in_tx(tx, peer_hub_id, NewEntry)` with
  `NewEntry::{Deliver{gid, seq, size}, DeliverWelcome{gid, payload}, DeviceList{user_id}}`
  (`gim_hub_db::outbox::NewEntry`). It inserts, enforces the cap in the same transaction and
  wakes the worker. `gim_hub_s2s::Disabled` implements it as a no-op.
- **Building requests.** The tables a request is rebuilt from belong to other subtasks, so the
  worker calls an `OutboxSource` (`deliver_messages`, `device_list`, `resync_nudge`, and
  `refresh_peer` for the `UNAUTHORIZED` refresh). An entry whose message or DeviceList no longer
  exists, or whose stored `DeliverWelcomeRequest` does not decode, is dropped (reason
  `unbuildable`). A source error is retried with the peer's backoff.
- **Backoff.** `failures` counts consecutive failures before the current one, so the first
  retry is after 1 s. A `Deliver` response that leaves batch entries unacknowledged counts as a
  failure for the peer.
- **Permanent errors on a batch.** A permanent error on a multi-entry `Deliver` does not drop
  the batch: its entries are resent one at a time, so only the offending entry is dropped.
  The single `UNAUTHORIZED` refresh is per drain run of a peer.
- **Cap.** A `deliver` entry that does not fit even after evicting every older `deliver` entry
  is evicted itself (the peer is marked `needs_resync`). `deliver_welcome` and `device_list`
  entries are queued beyond the cap. A `device_list` entry counts `len(user_id)` bytes.
- **Resync nudge.** Sent in batches of the §7.2 limits. A permanent rejection of the nudge
  still clears `needs_resync`; a retryable failure keeps it and backs off.
- **`s2s_peers`.** The outbox maintains `failures`, `next_attempt_at`, `needs_resync`,
  `last_connected_at` (on `PeerEvent::Up`) and `updated_at`. `peer_id`, `runtime_cert`,
  `cert_not_after` and `addrs` stay `NULL`: `PeerEvent` carries only the `hub_id` and the
  transport keeps its own address book.
- **Retention and metrics.** The worker deletes expired entries every 60 s (there is no
  separate retention task). The hub has no metrics exporter yet, so the §7.5 metrics are log
  fields: `s2s_outbox_entries`/`s2s_outbox_bytes` on every deferral and on the 80 % alert, and
  a `warn` line `s2s_outbox_dropped_total` with `peer`, `reason`
  (`evicted`/`expired`/`rejected`/`unbuildable`) and `count`; `Outbox::dropped_total` exposes
  the counters in process.

## 8. Database migrations

New migrations, appended to `MIGRATIONS` in `crates/gim-hub-db/src/migrate.rs` in this order (the
numbering lets subtasks work in parallel; each adds one line to the list):

| File | Contents | Subtask |
|---|---|---|
| `0002_hosting.sql` | `hosting_records` | H3-T2 |
| `0003_remote_identity.sql` | `remote_device_lists`, `remote_kp_claims` | H3-T3 |
| `0004_outbox.sql` | `s2s_outbox`, `s2s_peers` | H3-T4 |
| `0005_group_federation.sql` | `commit_membership`, `groups.replica_from_seq`, `groups.detached`, `pending_welcomes.message_id` + unique index `(message_id, user_id, device_id) WHERE message_id IS NOT NULL` | H3-T5 |
| `0008_replica_detached_at.sql` | `groups.detached_at` (§5.4) | H4-CL3 |
| `0009_message_proposal.sql` | `messages` rebuilt with `kind` `'proposal'`; `pending_proposals` (§5.3) | H3-FX3 |
| `0010_remote_blobs.sql` | `remote_blobs` (§5.6) | H5-B1 |

Single-hub databases migrate in place; owned groups have `replica_from_seq = NULL`. Existing
Commits get no `commit_membership` rows; a `FetchLog` over them returns Commits without membership
lists (acceptable: no federation existed when they were sequenced).

## 9. Contract changes

### 9.1 Proposed `proto/s2s.proto` diff

Additive within `gim.s2s.v1` (no field renumbering, no type changes), except the semantic change
to membership notices described after the diff. Applied in H3-T1 (together with the header comment
of `s2s.proto`, which now names the gid owner by `hub_id`), and `s2s.md` updated accordingly.

```diff
@@ message S2sRequest
     GetHostingRecordRequest get_hosting_record = 17;
     // 18-29: reserved for multi-homing (M2c) operations, e.g. hub
     //        add/remove and migration hand-off.
     // 30-39: reserved for push (P) operations, e.g. collapse-id coordination.
+    // 40-49: federation (M2b).
+    HelloRequest hello = 40;
+    NotifyDeviceListRequest notify_device_list = 41;
   }
@@ message S2sResponse
     GetHostingRecordResponse get_hosting_record = 17;
     // 18-39: reserved, mirroring S2sRequest.op.
+    HelloResponse hello = 40;
+    NotifyDeviceListResponse notify_device_list = 41;
   }
@@ enum ErrorCode
   ERROR_CODE_INTERNAL = 8;
+  // The calling PeerID is not bound to a hub_id yet (no valid Hello on this
+  // PeerID, or its runtime certificate expired). Send Hello, then retry once.
+  ERROR_CODE_HELLO_REQUIRED = 9;
 }
@@ message Error
   ErrorCode code = 1;
   string message = 2;
+  // STALE_EPOCH / CONFLICT: the group's current epoch at the owning hub.
+  optional uint64 current_epoch = 3;
+  // Client API error code the member hub should surface, when the owning hub
+  // rejected on behalf of group policy or validation, e.g. "not_member",
+  // "forbidden", "validation_failed". Empty otherwise.
+  string client_code = 4;
 }
+
+// ---------------------------------------------------------------------------
+// Peer binding
+// ---------------------------------------------------------------------------
+
+// First op on a connection: binds the caller's PeerID to its hub_id.
+message HelloRequest {
+  // gim-core SignedHubRuntimeCert (CBOR [tbs, sig]) for the caller's PeerID.
+  bytes runtime_cert = 1;
+  // Advertised listen addresses, binary multiaddrs.
+  repeated bytes listen_addrs = 2;
+}
+
+message HelloResponse {
+  bytes runtime_cert = 1;
+  repeated bytes listen_addrs = 2;
+}
+
+// DHT value under /gim/hub/<hub_id>.
+message HubLocator {
+  bytes runtime_cert = 1;
+  repeated bytes multiaddrs = 2;
+}
@@ message SubmitCommitResponse
   uint64 seq = 1;
+  // Epoch after the Commit (the group's new epoch), as in the client API.
   uint64 epoch = 2;
   bool duplicate = 3;
+  // The sequenced Commit as it will appear in Deliver / FetchLog.
+  SequencedMessage message = 4;
 }
@@ message SubmitMessageResponse
   uint64 seq = 1;
   uint64 epoch = 2;
   bool duplicate = 3;
+  SequencedMessage message = 4;
 }
@@ enum MessageKind
   MESSAGE_KIND_PROPOSAL = 3;
-  // Hub-generated membership notices; payload may be empty.
+  // Deprecated, never sent: membership changes are carried by the COMMIT
+  // entry (SequencedMessage.added_members / removed_members).
   MESSAGE_KIND_MEMBER_ADDED = 4;
   MESSAGE_KIND_MEMBER_REMOVED = 5;
 }
@@ message SequencedMessage
-  // Users added or removed (MEMBER_ADDED / MEMBER_REMOVED, Commits).
+  // Users added or removed by a COMMIT (union of the member lists below).
   repeated string affected_user_ids = 11;
 
   // 12-19 reserved for multi-homing (M2c) / push (P) metadata.
   reserved 12 to 19;
+
+  // COMMIT only: devices added / removed by this Commit, as derived by the
+  // owning hub from the parsed proposals.
+  repeated Member added_members = 20;
+  repeated Member removed_members = 21;
+}
+
+message Member {
+  string user_id = 1;
+  string device_id = 2;
 }
@@ message DeliverWelcomeRequest
   // 8-15 reserved for multi-homing (M2c) / push (P).
   reserved 8 to 15;
+
+  // Group state right after the Commit that produced this Welcome; lets the
+  // invitee's hub create its replica.
+  GroupSnapshot group = 16;
+  string sender_device_id = 17;
+}
+
+message GroupSnapshot {
+  string kind = 1;                 // "direct" | "group"
+  string created_by_user_id = 2;
+  string created_by_device_id = 3;
+  uint64 created_at = 4;           // unix ms
+  uint64 epoch = 5;                // epoch after the Commit
+  uint64 seq = 6;                  // seq of the Commit
+  repeated Member members = 7;     // roster after the Commit
 }
+
+// ---------------------------------------------------------------------------
+// Identity propagation (user's hub -> hubs sharing groups with the user)
+// ---------------------------------------------------------------------------
+
+message NotifyDeviceListRequest {
+  string user_id = 1;
+  bytes device_list_cbor = 2;      // gim-core DeviceList, CBOR [tbs, sig]
+}
+
+message NotifyDeviceListResponse {}
```

Semantic changes to `s2s.md` (same sign-off):

1. **Membership notices do not consume a seq.** `s2s.md` currently has the owner sequence
   separate `MEMBER_ADDED`/`MEMBER_REMOVED` entries after a Commit. The single-hub log and the
   client API have no such entries (membership events carry the Commit's `seq`), so separate
   entries would put gaps into client-visible `seq`. The membership change rides on the `COMMIT`
   entry instead; `affected_user_ids` stays filled for compatibility.
2. "Listed" = the caller's bound `hub_id` (§1.1), not its PeerID.
3. `SubmitCommitResponse.epoch` is the epoch after the Commit (matches client API
   `CommitResult.epoch`).
4. `CONFLICT` is used for a Commit whose epoch already has a sequenced Commit; `STALE_EPOCH` for an
   application message or Proposal for a non-current epoch. Both map to client 409 `stale_epoch`.
5. Authorization table gains `Hello` and `NotifyDeviceList` (§3.7); `FetchLog` also admits the hub
   of a member removed at or after `from_seq`.
6. Limits: `Deliver` ≤ 256 messages / 4 MiB, `FetchLog` limit capped at 256, request and response
   frames ≤ 8 MiB.

### 9.2 `/v2` contract additions (client API)

All additive; they need L1 / gim-core sign-off before implementation of the affected subtasks.

| Change | Detail |
|---|---|
| `POST /v2/users/{user_id}/hosting-entry` | §4.2 |
| `PUT /v2/users/{user_id}/hosting-record` | §4.2; new codes 400 `invalid_hosting_record`, 409 `stale_hosting_record` |
| `GET /v2/users/{user_id}/hosting-record` | §4.2 |
| `GET /v2/users/{user_id}`, `GET /v2/users/{user_id}/device-list` | also answer for remote users (cached/fetched DeviceList); may return 503 `peer_unavailable` |
| `POST /v2/keypackages/claim` response | new `unavailable: [ClaimTarget]` |
| `POST /v2/groups/{gid}/commits`, `POST /v2/groups/{gid}/messages` | for remote-owned gids: 502 `peer_refused`, 503 `peer_unavailable`; 403 `hosting_record_required` |
| `GET /v2/groups/{gid}/messages` | on a replica, history starts at the join point (§5.4) |
| `Message.kind` | new value `proposal` for Proposals sequenced through `POST /v2/groups/{gid}/commits` (§5.3, H3-FX3) |
| New event `hosting_record.expiring` | `{user_id, expires_at, seq}` to the user's active devices when < 48 h remain |
| Error codes | `invalid_hosting_record` (400), `stale_hosting_record` (409), `hosting_record_required` (403), `peer_refused` (502), `peer_unavailable` (503, with `Retry-After` seconds) |
| `POST /v2/blobs`, `GET /v2/blobs/{blob_id}` (H5-B1) | `blob_id` is `<origin hub_id>/b_<random>` (legacy `b_<random>` stays valid); `GET` of a foreign blob fetches it from the origin and may return 502 `peer_refused`, 503 `peer_unavailable` (§5.6) |

gim-core consequences (for the core L2): publish a hosting record at onboarding and renew it
(§4.1); treat `unavailable` claims as retryable; treat 502/503 as retryable with the same
`client_id`/Commit.

## 10. Configuration

New environment variables (same conventions as [`operations.md`](operations.md): empty = unset,
invalid value stops the hub naming the variable). All are ignored unless `GIM_HUB_FEDERATION=true`.

| Variable | Default | Meaning |
|---|---|---|
| `GIM_HUB_FEDERATION` | `false` | Enable the libp2p host and federation |
| `GIM_HUB_P2P_LISTEN` | `/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4001` | Comma-separated listen multiaddrs (TCP only when a PSK is set) |
| `GIM_HUB_P2P_EXTERNAL_ADDRS` | unset | Comma-separated multiaddrs advertised in `Hello` and the locator (default: the listen addresses that are not unspecified) |
| `GIM_HUB_P2P_BOOTSTRAP` | unset | Comma-separated bootstrap multiaddrs, `/p2p/<PeerId>` optional |
| `GIM_HUB_FEDERATION_ALLOWLIST` | `$GIM_HUB_DATA_DIR/allowlist` | Allowlist file (§3.3), reloaded on SIGHUP |
| `GIM_HUB_P2P_PSK_FILE` | unset | libp2p `swarm.key` file; set = pnet on, TCP only |
| `GIM_HUB_RUNTIME_CERT_DAYS` | `30` | Runtime certificate lifetime (minimum 2) |
| `GIM_HUB_S2S_TIMEOUT_SECONDS` | `10` | Timeout of one S2S request |
| `GIM_HUB_DHT_REPUBLISH_HOURS` | `12` | Republish cadence of hosted users' records |
| `GIM_HUB_HOSTING_CACHE_SECONDS` | `600` | Freshness of cached remote hosting records |
| `GIM_HUB_DEVICE_LIST_CACHE_HOURS` | `24` | Freshness of cached remote DeviceLists |
| `GIM_HUB_OUTBOX_TTL_HOURS` | `168` | Outbox entry lifetime |
| `GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER` | `100000` | Backlog cap, entries |
| `GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER` | `1073741824` | Backlog cap, bytes |
| `GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS` | `300` | Maximum retry backoff per peer |
| `GIM_HUB_FETCH_BLOB_PER_MINUTE` | `600` | `FetchBlob` requests served per caller hub and minute (§5.6, minimum 1) |

Data directory additions: `runtime_key`, `runtime_cert`, `allowlist` (default location). The
Docker image exposes 4001/tcp and 4001/udp. The `hub_id` and the PeerId are logged at startup;
`gim-hub hub-id` prints the `hub_id` (needed to build allowlists before first start:
`gim-hub hub-id` creates `hub_key` if missing).

## 11. Test topology and matrix

### 11.1 In-process (part of `scripts/check.sh`)

`crates/gim-hub/tests/federation.rs` starts three hubs in one process on loopback (TCP and QUIC on
ephemeral ports, temp data dirs, fixed test `hub_key` seeds, generated allowlists) and drives them
through the client API with scripted MLS clients (openmls + `gim-hub-identity` test utilities).
It covers the matrix below except the cases that need container control, which use a dropped and
restarted hub instead.

### 11.2 docker compose (M2b acceptance)

`deploy/federation/compose.yaml`, run by `scripts/fed-test.sh` (CI job, not part of `check.sh`):

```yaml
name: gim-fed
x-hub: &hub
  image: gim-hub:fedtest           # built from the repository Dockerfile by fed-test.sh
  labels: [ai-agent=true]          # added by fed-test.sh when run by an agent
  environment: &env
    GIM_HUB_FEDERATION: "true"
    GIM_HUB_P2P_LISTEN: /ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4001
    GIM_HUB_FEDERATION_ALLOWLIST: /config/allowlist
    GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS: "5"
services:
  hub-a: { <<: *hub, volumes: [a-data:/data, ./fixtures/a:/seed:ro, ./allowlist:/config/allowlist:ro], ports: ["127.0.0.1:18081:8080"] }
  hub-b: { <<: *hub, volumes: [b-data:/data, ./fixtures/b:/seed:ro, ./allowlist:/config/allowlist:ro], ports: ["127.0.0.1:18082:8080"] }
  hub-c: { <<: *hub, volumes: [c-data:/data, ./fixtures/c:/seed:ro, ./allowlist:/config/allowlist:ro], ports: ["127.0.0.1:18083:8080"] }
  hub-x:                            # not on the allowlist of a/b/c; its own allowlist lists hub-a
    <<: *hub
    profiles: [refusal]
    volumes: [x-data:/data, ./fixtures/x:/seed:ro, ./allowlist-x:/config/allowlist:ro]
    ports: ["127.0.0.1:18084:8080"]
volumes: { a-data: {}, b-data: {}, c-data: {}, x-data: {} }
```

- One project network (compose default), nothing else attached. Fixed test `hub_key` seeds
  (copied into `/data` by an entrypoint flag, test-only) give known `hub_id`s, so `allowlist`
  is a committed fixture listing a, b, c with `/dns4/hub-<n>/tcp/4001` and QUIC addresses.
- A `psk` variant (compose override `compose.psk.yaml`) sets `GIM_HUB_P2P_PSK_FILE` and TCP-only
  listen addresses on a, b, c; hub-x has no PSK.
- The test runner is a Rust test binary run on the host (`cargo test -p gim-hub --test fed_compose
  -- --ignored`, env `GIM_FED_HUBS=http://127.0.0.1:18081,...`); it stops and starts containers
  with `docker compose stop|start` for outage cases.

Resolved in H3-T6:

- The compose network has a fixed /24 (`GIM_FED_SUBNET`, default `10.231.64`) and every hub a
  static IP; allowlists and `GIM_HUB_P2P_EXTERNAL_ADDRS` use `/ip4/` addresses. A static IP also
  keeps a restarted hub reachable at its advertised address. (At H3-T6 the libp2p host had no
  DNS transport; since H4-CL1 the TCP and QUIC transports are wrapped in the system DNS resolver,
  so `/dns4/` and `/dns6/` multiaddrs such as the §3.3 example and the sketch above are dialable.)
- No test-only entrypoint flag and no committed key seeds: `scripts/fed-test.sh` runs
  `gim-hub hub-id` once per hub (creating `hub_key` in its volume) and generates the allowlists
  from the printed `hub_id`s into `.tmp/fed-<pid>/`. `hub-x` runs in every run (no `refusal`
  profile); its allowlist lists `hub-a` so it keeps dialing and is refused.
- No ports are published: the driver (`crates/gim-hub/tests/fed_compose.rs`, `#[ignore]`) runs
  in a `rust:1.99-bookworm` container attached to the compose network and reaches the hubs by
  service name. It stops and starts hubs through the Docker Engine API on the mounted Docker
  socket (`curl --unix-socket`), so it needs no Docker CLI.
- Covered by the compose driver: T1 (resolution only), T2, T3, T4, T5, T7 (dave@C instead of
  carol, who is removed by T4; a stopped hub has no client API, so "carol-side submits get 503"
  is checked by T9 instead), T9 and T10 (eve's claim of alice lists her in `unavailable` or
  `missing`: hub-x cannot resolve alice's record at all; hub-a logs `Hello refused` with hub-x's
  `hub_id`; hub-a knows nothing about eve). Not covered by the compose driver: T6 (only the
  `NotifyDeviceList` propagation is tested, in process, in
  `crates/gim-hub-api/tests/federation_identity.rs`), T8 (in process, `federation_groups.rs`),
  T11 (no `compose.psk.yaml` yet; PSK mismatch and QUIC-with-PSK are covered by the transport
  tests in `crates/gim-hub-s2s`) and T12.
- §11.1: the in-process three-hub tests live in `crates/gim-hub-api/tests/federation_groups.rs`
  and `federation_identity.rs` (they need the API crate's test helpers); no separate
  `crates/gim-hub/tests/federation.rs` was added.

Resolved in H4-CL2:

- T6 is covered by the compose driver: alice@A publishes DeviceList seq 2 certifying a second
  device and seq 3 revoking it; once `GET .../device-list` on hub-b returns each new list
  (propagated by `NotifyDeviceList`, hub-b's cache is not stale), bob@B's Commit adding a
  KeyPackage of the revoked device gets 400 `validation_failed`
  `invalid MLS credential (revoked_device)` from the owner hub-b and nothing is logged.
- T11: `deploy/federation/compose.psk.yaml` (applied by `GIM_FED_PSK=1 scripts/fed-test.sh`; CI
  runs the default variant only) gives hub-a, hub-b and hub-c a `swarm.key` generated per run
  under `.tmp/fed-<pid>/` and TCP-only listen, external and allowlist addresses; hub-x has no key.
  The script first checks that hub-a with the key and a QUIC listen address exits with the
  `QUIC is not available with GIM_HUB_P2P_PSK_FILE` error, then runs every scenario; in T10 hub-a
  must log no refused `Hello` of hub-x (its dials fail in the pnet handshake).
- T12 is not covered. Certificate renewal keeps the PeerId and runs only when less than a third
  of the certificate lifetime remains (checked at startup and daily, §3.1), so a running hub
  cannot be made to renew within a test run; rotating the runtime key (new PeerId) needs a hub
  restart with `runtime_key` and `runtime_cert` deleted. There is no runtime rotation to test;
  the restart variant would need the driver to delete files in a stopped hub's volume.

### 11.3 Matrix

| # | Case | Steps | Assertions |
|---|---|---|---|
| T1 | Hosting record | alice@A gets entry, publishes record; B and C resolve it | `GET /v2/users/alice/hosting-record` on B and C returns seq 1; DHT and `GetHostingRecord` paths both exercised; stale seq upload → 409 |
| T2 | Cross-hub DM | bob@B claims alice@A, creates direct group, adds alice; both send 3 messages | alice gets Welcome + messages in order; seqs identical on A and B; no duplicates; `client_id` replay → 200 same message |
| T3 | Group across 3 hubs | bob@B creates group with alice@A, carol@C; each sends | every member sees every message once, same `(epoch, seq)` everywhere; replicas on A and C list the full roster |
| T4 | Add/remove from a non-owning hub | alice@A adds dave@C, then removes carol@C | Commits go through `SubmitCommit`; `group.member_added`/`removed` with `user_id` on all hubs; carol gets the removing Commit, then nothing; C's replica keeps dave |
| T5 | Concurrent Commit conflict | alice@A and carol@C commit at the same epoch simultaneously | exactly one 201; the other 409 `stale_epoch` with `current_epoch = e+1`; loser's retry after catching up succeeds; resubmitting the winner → 200 `duplicate: true` |
| T6 | Credential rejection | a Commit adding a KeyPackage with a revoked device of a remote user | 400 `validation_failed (revoked_device)` after the owner refreshes the DeviceList; `NotifyDeviceList` propagated the revocation |
| T7 | Peer outage + recovery | stop hub-c; bob and alice send 50 messages; start hub-c | carol receives all 50 in order with no duplicates; while down, carol-side submits get 503 and B's outbox for C grows then drains |
| T8 | Backlog cap + resync | hub-b with cap 10 entries; stop hub-c; send 30; start hub-c | B marks C `needs_resync`, sends a nudge; C fills the gap via `FetchLog`; carol gets all 30 |
| T9 | Owner outage | stop hub-b (owner); alice sends | 503 `peer_unavailable`; reads from A's replica still work; after restart sends succeed |
| T10 | Non-allowlisted hub refused | profile `refusal`: eve@X claims alice@A and submits to a group owned by A | A answers `Hello` with `UNAUTHORIZED` and closes; eve's claim lists alice in `unavailable`; A logs the refusal; nothing stored on A |
| T11 | PSK | `compose.psk.yaml`: T2 between A and B over TCP; hub-x without PSK | T2 passes; X cannot connect (pnet handshake fails); startup with a QUIC listen address and a PSK fails |
| T12 | Runtime cert renewal / rotation | restart hub-a with a new runtime key | B re-binds via `Hello`; gid and hosting records unchanged; messaging continues |
| T13 | Leave by Proposal | frank@B sends a self-Remove Proposal for a group owned by A; grace@C commits it by reference | Proposal forwarded and sequenced by A (epoch unchanged, `kind = proposal` on every hub); C resolves the reference on its replica; frank removed on every hub with `group.member_removed` |
| T14 | Cross-hub blobs (H5-B1) | alice@A uploads two attachments of the DM with bob@B (one larger than a 4 MiB chunk); bob downloads the first on B; stop hub-a; bob downloads both; start hub-a | B fetches from A and serves the bytes (Range too); while A is down the cached blob is served and the other one is 503 `peer_unavailable` with `Retry-After`; after the restart it is served |

## 12. Implementation breakdown

Six subtasks with disjoint file ownership. Shared files with append-only edits (`migrate.rs`
list, `dto.rs`, `lib.rs` route table, `Cargo.toml`, `openapi.json` regenerated) are expected to
merge trivially; `openapi.json` is regenerated after each merge.

| Subtask | Scope | Owns | Depends on |
|---|---|---|---|
| H3-T1 transport, policy, contract | proto diff (§9.1) + `s2s.md` updates; libp2p host (Noise, QUIC/TCP, pnet, kad, request-response codec); runtime key/cert; `Hello` binding; `FederationPolicy`/`AllowlistPolicy`; locator records; config keys; `Federation` trait with `Disabled` impl and op dispatch skeleton (all ops `INTERNAL` "not implemented") | `proto/s2s.proto`, `docs/s2s.md`, `crates/gim-hub-proto/**`, `crates/gim-hub-s2s/src/{lib.rs,config.rs,policy.rs,federation.rs,transport/**}`, `crates/gim-hub/src/main.rs`, workspace `Cargo.toml`/`Cargo.lock` (libp2p pinned) | L1/gim-core sign-off of §9.1 |
| H3-T2 hosting records | §4: endpoints, storage, DHT publish/republish, validator, resolver/cache, `GetHostingRecord`, `hosting_record.expiring` | `migrations/0002_hosting.sql`, `gim-hub-db/src/hosting.rs`, `gim-hub-api/src/handlers/hosting.rs`, `gim-hub-s2s/src/hosting/**` | T1 |
| H3-T3 remote identity and claims | §5.1, §5.2: remote DeviceList cache, `GetDeviceList`, `NotifyDeviceList` (send via outbox API, receive), claim routing + ledger + `unavailable`, remote `GET /v2/users/*` | `migrations/0003_remote_identity.sql`, `gim-hub-db/src/remote_identity.rs`, `gim-hub-api/src/handlers/{keypackages.rs,identity.rs}`, `gim-hub-s2s/src/ops/{claim.rs,device_list.rs}` | T1, T2 (resolver API; can stub) |
| H3-T4 outbox | §7: schema, enqueue API (`enqueue_in_tx`), per-peer worker, batching, acks, backoff, cap, TTL, resync nudge hook, metrics | `migrations/0004_outbox.sql`, `gim-hub-db/src/outbox.rs`, `gim-hub-s2s/src/outbox/**` | T1 |
| H3-T5 group federation | §5.3, §5.4, §6.2-§6.6: owner path for remote members (credential identity, `commit_membership`, fan-out set), replicas, `SubmitCommit`/`SubmitMessage` forward + error mapping, `Deliver`/`DeliverWelcome`/`FetchLog` send and receive, gap fill | `migrations/0005_group_federation.sql`, `gim-hub-api/src/{mls.rs,handlers/groups.rs,handlers/messages.rs,handlers/welcomes.rs}`, `gim-hub-db/src/{groups.rs,messages.rs,welcomes.rs}`, `gim-hub-s2s/src/ops/{submit.rs,deliver.rs,welcome.rs,fetch_log.rs}` | T1, T3, T4 |
| H3-T6 topology and acceptance | §11: in-process 3-hub test, compose files and fixtures, `scripts/fed-test.sh`, CI job, `docs/operations.md` federation section, Dockerfile ports | `crates/gim-hub/tests/**`, `deploy/federation/**`, `scripts/fed-test.sh`, `.github/workflows/*` (fed job), `docs/operations.md`, `Dockerfile` | T5 (harness can start after T1) |

Order: T1 → {T2, T3, T4} in parallel → T5 → T6 (T6's harness and compose skeleton may start
right after T1).

## 13. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Kademlia read queries from a connection that has not completed `Hello` cannot be gated per request (§3.4); unbound peers can read signed public records and hub addresses for up to 5 s. | Accept for M2b: records are signed and the architecture already treats `user_id → hubs` as visible to anyone knowing the `user_id` (arch §11). Recommend a PSK in deployments where the hub directory itself is confidential. Revisit with a gated kad handler if open federation lands. |
| Q2 | Membership notices: separate seq-consuming `MEMBER_*` entries (current `s2s.md`) vs. riding on the `COMMIT` entry (this design). | Ride on the `COMMIT` entry (§9.1 change 1), keeping client-visible `seq` identical to single-hub. Needs L1 sign-off because it changes the H1 contract text. |
| Q3 | Hosting record lifetime and who renews it: the hub cannot re-sign (no user root key). | Client renews: 7-day records renewed below 3 days, hub warns with `hosting_record.expiring` at 48 h. gim-core sign-off needed. |
| Q4 | Replica history before the join point is not served (§5.4). | Accept: the joiner cannot decrypt it. If a client ever needs it, proxy the range to the owner with `FetchLog`. |
| Q5 | Backlog cap behaviour: evict oldest `deliver` entries + resync nudge, vs. refusing to sequence while a peer is over cap. | Evict + nudge: one dead peer must not stop a group; the owner's unpruned log makes recovery lossless. |
| Q6 | Group policy for remote members: currently any member may add/remove. | Keep parity with single-hub in M2b; policy is enforced only by the owner, so tightening it later needs no protocol change. |
| Q7 | New client error codes `peer_unavailable` (503) / `peer_refused` (502) / `hosting_record_required` (403) and claim `unavailable`. | Adopt as listed in §9.2; gim-core maps 502/503 to retryable. |
| Q8 | Users who never publish a hosting record (M2a clients) cannot federate. | Require it: gim-core publishes a record at onboarding and on first start after the upgrade; the hub returns 403 `hosting_record_required` for federated actions without one. |
| Q9 | Rate-limit values (§6.8) are constants. | Keep constants for M2b; move to config when open federation is designed. |
| Q10 | DHT record store is in memory: after a restart of every hub at once, records reappear only on republish. | Accept: each hub republishes its hosted users at startup (immediately, then every 12 h), and `GetHostingRecord` from cached hubs covers lookups in between. |
| Q11 | NAT traversal (AutoNAT, relay, DCUtR) is not configured. | Defer: hubs are server deployments with reachable addresses; add when a deployment needs it (transport module only). |
