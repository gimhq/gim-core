# Server-to-server protocol

Contract between gim hubs. The wire schema is [`proto/s2s.proto`](../proto/s2s.proto)
(proto3, package `gim.s2s.v1`); Rust types are generated into the `gim-hub-proto` crate
(`gim_hub_proto::s2s`).

## libp2p protocols

| Protocol id | Purpose |
|---|---|
| `/gim/s2s/1.0.0` | Request-response. One `S2sRequest` and one `S2sResponse` per stream, protobuf-encoded. |
| `/gim/kad/1.0.0` | Private Kademlia DHT shared by gim hubs only (never the public IPFS DHT). |

Transport is libp2p (QUIC or TCP) with a Noise handshake, so every request arrives with an
authenticated PeerID. The first operation on a connection is `Hello`, which binds the PeerID to the
caller's `hub_id` through its runtime certificate (see [Peer binding](#peer-binding)). Federation
policy (`hub_id` allowlist, optional pnet PSK) is applied to the bound `hub_id` before any other
operation is processed. With a PSK the hub runs TCP only (pnet wraps stream transports only).
Design: [`federation.md`](federation.md) §3.

### DHT records

- Key: `/gim/user/<user_id>`.
- Value: the user's `UserHostingRecord`, gim-core CBOR encoding `[tbs, sig]` (defined in
  gim-core `docs/identity.md`). The hub does not re-model it.
- The record validator checks the user signature, every hub signature and expiry, and selects the
  record with the highest `seq`.
- `GetHostingRecord` fetches the same bytes directly from a hub; a hub uses it first and falls
  back to a DHT lookup when the peer is unreachable or returns `NOT_FOUND`.
- Key `/gim/hub/<hub_id>`: the hub's `HubLocator { runtime_cert, multiaddrs }` (current runtime
  certificate and advertised addresses). Valid when the certificate verifies and names that
  `hub_id`; the greatest `not_before` wins. Addresses are unsigned (a wrong address only fails the
  Noise PeerID check). Each hub republishes its locator hourly and after a certificate renewal.
- Records under any other key prefix are rejected. Inbound `PUT_VALUE` is accepted only from bound
  peers; peers enter the routing table only after `Hello`.

## Identifiers

- `user_id`, `device_id`: opaque strings; format owned by gim-core.
- `gid`: `<owner hub_id>/<random_128 base32lower>` (gim-core `HubId` of the owning hub's root key;
  128 random bits, lowercase unpadded base32). The owning hub is the hub whose `hub_id` prefixes
  the gid; it runs the group's sequencer. The gid is stable across runtime-key rotation (arch
  §4.1); the owning hub's current PeerID is resolved from its runtime certificate (bound
  connection, last `Hello`, allowlist addresses, or its DHT locator). The MLS `group_id` is the
  UTF-8 bytes of the gid.
- `client_id`: client-chosen idempotency key, unique per sender device.
- `message_id`: globally unique id assigned by the owning hub to every sequenced message and
  Welcome.
- Identity objects (`DeviceList`, `UserHostingRecord`, ...) appear only as opaque CBOR `bytes`.

## Envelope

```
S2sRequest  { string request_id; oneof op { ... } }
S2sResponse { string request_id; oneof result { ... }; Error error }
Error       { ErrorCode code; string message; optional uint64 current_epoch; string client_code }
```

- `request_id` is echoed back for correlation and logging; it is not an idempotency key.
- A response sets exactly one of `result` (same field number as the request op) or `error`.
- Field numbers 18-29 of both oneofs hold multi-homing (M2c) operations (`NotifyHostingRecord` =
  18, `SeedReplica` = 19, `CopyPendingWelcomes` = 20; 21-29 reserved); 30-39 are reserved for push
  (P) operations; 40-49 hold federation (M2b) operations (`Hello` = 40, `NotifyDeviceList` = 41).
- `Error.current_epoch` is set with `STALE_EPOCH` / `CONFLICT`: the group's current epoch at the
  owning hub. `Error.client_code` is the client API error code a member hub should surface when the
  owning hub rejected on behalf of group policy or validation (e.g. `not_member`, `forbidden`,
  `validation_failed`); empty otherwise.

## Peer binding

```
HelloRequest  { bytes runtime_cert; repeated bytes listen_addrs }
HelloResponse { bytes runtime_cert; repeated bytes listen_addrs }
```

`runtime_cert` is the sender's gim-core `SignedHubRuntimeCert` (CBOR `[tbs, sig]`) and
`listen_addrs` its advertised binary multiaddrs. The dialer sends `Hello`; the listener answers with
its own certificate, so one exchange binds both directions. Each side verifies the received
certificate in order, and the first failure refuses the peer:

1. read `hub_root_pubkey` from the body and derive `hub_id`;
2. the certificate verifies for that key at the current time;
3. the certified runtime key's PeerID equals the connection's PeerID;
4. the policy admits `hub_id` (allowlist);
5. dialer only: when dialing a specific hub, the responder's `hub_id` is that hub.

- A refused `Hello` is answered with `UNAUTHORIZED` and the connection is closed after the response;
  a hub not on the allowlist is also denied new connections for 10 minutes. A dialer whose
  responder fails step 5 closes the connection and avoids that address for 10 minutes.
- The binding lasts until the certificate's `not_after` or until the policy no longer admits the
  hub; new connections from a bound PeerID reuse it, and a later `Hello` replaces it.
- Every other operation from an unbound PeerID fails with `HELLO_REQUIRED`; the caller sends
  `Hello` and retries once. An inbound connection without `Hello` within 5 seconds is closed.

## Operations

"Acting user" is the user on whose behalf the request is made (the `sender_user_id` or
`requester_user_id`). "Listed" means the caller's bound `hub_id` appears in an entry of the acting
user's current `UserHostingRecord` (entries carry hub root keys, from which `hub_id` is derived).
Every operation except `Hello` first requires a binding and the policy's admission (rate limits).

| Op | Direction | Request -> Response | Authorization |
|---|---|---|---|
| `Hello` | dialer -> listener | `runtime_cert, listen_addrs` -> `runtime_cert, listen_addrs` | Certificate checks of [Peer binding](#peer-binding); not subject to an existing binding. |
| `SubmitCommit` | member hub -> owning hub | `gid, sender_user_id, sender_device_id, client_id, mls_message, welcome?, welcome_recipient_device_ids, ratchet_tree?` -> `seq, epoch, duplicate, message` | Caller listed for `sender_user_id`; responder must be the owning hub of `gid`; group policy (who may add/remove) enforced by the owning hub. |
| `SubmitMessage` | member hub -> owning hub | `gid, sender_user_id, sender_device_id, client_id, mls_message` -> `seq, epoch, duplicate, message` | Caller listed for `sender_user_id`; sender is a group member. |
| `Deliver` | owning hub -> member hub | `messages: [SequencedMessage]` -> `acks: [GroupAck{gid, highest_contiguous_seq}]` | Caller is the owning hub of every `gid` in the batch (`hub_id` prefix of the gid). |
| `DeliverWelcome` | owning hub -> invitee's hub | `gid, sender_user_id, recipient_user_id, recipient_device_ids, welcome, ratchet_tree?, message_id, group, sender_device_id` -> `{}` | Caller is the owning hub of `gid`; responder hosts `recipient_user_id`. |
| `ClaimKeyPackage` | requester's hub -> target's hub | `requester_user_id, target_user_id, device_id?` -> `key_packages: [ClaimedKeyPackage{device_id, key_package, last_resort}]` | Caller listed for `requester_user_id`; responder hosts `target_user_id`. |
| `FetchLog` | member hub -> owning hub | `gid, from_seq, limit` -> `messages, next_seq, complete` | Responder owns `gid`; caller listed for at least one current member of `gid`, or for a member removed by a Commit with `seq >= from_seq` (so a removed member's hub can fetch the removing Commit). |
| `GetDeviceList` | any hub -> user's hub | `user_id` -> `device_list_cbor` (gim-core `DeviceList`) | Federation policy only (public, signed object). |
| `GetHostingRecord` | any hub -> user's hub | `user_id` -> `hosting_record_cbor` (gim-core `UserHostingRecord`) | Federation policy only (public, signed object); fallback is the DHT. |
| `NotifyDeviceList` | user's hub -> hubs sharing groups with the user | `user_id, device_list_cbor` -> `{}` | Caller listed for `user_id`. The receiver verifies the DeviceList and applies the seq rules to its cached copy. |
| `NotifyHostingRecord` | a user's hub (under the new or the superseded record) -> co-hosts, removed hubs, owners and member hubs sharing groups with the user | `user_id, hosting_record_cbor` -> `{}` | Caller listed in the sent record or in the stored record it supersedes. Fails with `UNAUTHORIZED`, or `INVALID` when the record does not verify. The answer is `{}` for an applied, stale or identical record. |
| `SeedReplica` | owning hub -> a hub newly listed for a member | `gid, user_id, group` -> `{}` | Caller owns `gid`; responder hosts `user_id`; `user_id` is in `group.members`. Fails with `UNAUTHORIZED`, `NOT_FOUND`, `INVALID`. |
| `CopyPendingWelcomes` | co-host -> newly listed hub | `user_id, welcomes: [PendingWelcome{device_id, gid, message_id, payload_json, created_at}]` -> `{}` | Caller listed for `user_id`; responder hosts `user_id`. Fails with `UNAUTHORIZED`, `NOT_FOUND`. |

Notes:

- `SubmitCommit` carries a Commit or a Proposal as an MLS `PublicMessage` (`SubmitMessage`
  carries only `PrivateMessage` application messages). The owning hub parses the `PublicMessage`
  and reads the epoch from its framing rather than trusting a request field. It extracts the
  Add/Remove (and Update) proposals, validates the gim-core MLS credential (custom credential
  type `0xF001`, format owned by gim-core `docs/identity.md`) of every added member against that
  member's DeviceList (fetched with `GetDeviceList` when the user is hosted elsewhere), enforces
  group policy, and derives the roster and fan-out set from the result. Member hubs never send
  roster deltas: the owning hub cannot verify them.
- Membership changes do not consume a `seq`: they ride on the Commit's own `COMMIT` entry, whose
  `added_members` / `removed_members` list the devices the owning hub derived from the parsed
  proposals, and whose `affected_user_ids` is the union of their users (kept for compatibility).
  Member hubs turn them into `group.member_added` / `group.member_removed` client events carrying
  the Commit's `seq`, exactly as a single hub does. `MEMBER_ADDED` / `MEMBER_REMOVED` are
  deprecated and never sent.
- `SubmitCommitResponse.epoch` is the epoch after the Commit (the group's new epoch, as the client
  API's `CommitResult.epoch`); `SubmitMessageResponse.epoch` is the message's epoch. Both responses
  carry `message`, the `SequencedMessage` as it appears in `Deliver` / `FetchLog`, so the member hub
  can apply it to its replica immediately.
- `SubmitCommitRequest.welcome` and `DeliverWelcomeRequest.welcome` hold a TLS-encoded MLSMessage
  (wire_format = mls_welcome) carrying a Welcome, as raw bytes. The receiver checks this framing
  (not the encrypted contents) and refuses anything else with `INVALID`, storing nothing; a member
  hub checks a client's `welcome` before forwarding it. `CopyPendingWelcomes` skips a
  `PendingWelcome` whose `payload_json` has no `welcome` field holding the base64 of such a message.
- `DeliverWelcomeRequest.group` is a `GroupSnapshot` (kind, creator, `created_at`, epoch after the
  Commit, `seq` of the Commit, roster after the Commit) from which the invitee's hub creates its
  replica; `sender_device_id` is the committing device.
- A `SubmitCommit` whose `mls_message` is not a `PublicMessage` Commit/Proposal, or that adds a
  member with an invalid credential, fails with `INVALID`. A Commit rejected by group policy
  (sender not allowed to add/remove) fails with `UNAUTHORIZED`.
- `SequencedMessage` = `gid, seq, epoch, kind, sender_user_id, sender_device_id, client_id,
  payload, message_id, created_at (unix ms), affected_user_ids, added_members, removed_members`.
  `kind` is one of `COMMIT`, `APPLICATION`, `PROPOSAL` (`MEMBER_ADDED`, `MEMBER_REMOVED` are
  deprecated).
- `Deliver` sends one copy per member hub, not per device; the member hub fans out to its local
  devices. A batch may mix gids; within a gid messages are in ascending `seq`.
- `ClaimKeyPackage` without `device_id` returns one KeyPackage per device of the target user.
  One-time KeyPackages are consumed on claim; `last_resort = true` marks the device's reusable
  last-resort KeyPackage, returned only when no one-time KeyPackage is left.
- `FetchLog` returns messages with `seq >= from_seq`, at most `limit` (the owning hub may cap
  lower). Continue with `from_seq = next_seq` until `complete = true`.
- The multi-homing operations (`NotifyHostingRecord`, `SeedReplica`, `CopyPendingWelcomes`) are
  specified in [`multihoming.md`](multihoming.md) §4.2-§4.4. All three are served with
  federation.

## Error codes

| Code | Meaning | Caller action |
|---|---|---|
| `UNSPECIFIED` | Default value; never sent intentionally. | Treat as `INTERNAL`. |
| `UNAUTHORIZED` | `Hello` refused (invalid certificate or hub not allowed by federation policy); caller's `hub_id` not listed in the acting user's current hosting record, or not the owning hub for `Deliver` / `DeliverWelcome`; or a Commit rejected by group policy (then `client_code` says why, e.g. `not_member`). | Do not retry; refresh the hosting record if it may be stale. |
| `NOT_FOUND` | Unknown user, device, group, record, or no KeyPackage available. | Do not retry the same request. |
| `STALE_EPOCH` | An application message or Proposal for an epoch other than the group's current epoch; `current_epoch` is set. | Client fetches the latest state (via `FetchLog`) and resubmits. |
| `CONFLICT` | A Commit whose epoch already has a sequenced Commit; `current_epoch` is set. | Client fetches the latest state and retries on top of it. |
| `GONE` | The requested log range was pruned. | Re-join or resync from a newer `seq`. |
| `RATE_LIMITED` | Caller exceeded a rate limit. | Retry with exponential backoff. |
| `INVALID` | Malformed request: bad gid, unparsable MLS framing, handshake not a `PublicMessage`, `welcome` not an MLSMessage carrying a Welcome, invalid member credential, missing required field. | Do not retry unchanged. |
| `INTERNAL` | Unexpected failure on the responder. | Retry with exponential backoff. |
| `HELLO_REQUIRED` | The calling PeerID is not bound to a `hub_id` (no valid `Hello` on this PeerID, or its runtime certificate expired). | Send `Hello`, then retry once. |

`STALE_EPOCH` and `CONFLICT` both map to the client API's 409 `stale_epoch`.

## Limits

- Frames: one length-prefixed protobuf message per direction (unsigned varint length, prost
  length-delimited encoding); request and response frames are at most 8 MiB.
- `Deliver`: at most 256 messages and 4 MiB encoded per request.
- `FetchLog`: the owning hub caps `limit` at 256.
- DHT values: at most 8192 bytes.

## Idempotency

All operations may be retried (the outbound queue is at-least-once), including through a different
hub of a multi-homed user.

- `SubmitCommit`: the owning hub dedups by Commit hash. Resubmitting the same Commit returns the
  originally assigned `seq` / `epoch` with `duplicate = true`. A *different* Commit for an epoch
  that already has one returns `CONFLICT`.
- `SubmitMessage`: dedup by `(sender_device_id, client_id)`; a repeat returns the original
  `seq` / `epoch` with `duplicate = true`.
- `Deliver`, `DeliverWelcome`: receivers dedup by `message_id` (and by `(gid, seq)` for
  `Deliver`); a repeat is acknowledged without being stored twice.
- `SeedReplica` and `CopyPendingWelcomes` are idempotent (receiver ignores a seed for a live
  replica and dedups Welcomes by `message_id`); `NotifyHostingRecord` follows the record seq rules.
- `ClaimKeyPackage` is not idempotent: each successful call consumes one-time KeyPackages.
- `FetchLog`, `GetDeviceList`, `GetHostingRecord` are read-only.

## Ordering

- The owning hub assigns a per-gid `seq` (strictly increasing, gap-free) and the MLS `epoch` to
  every message; for a given epoch the first valid Commit wins.
- Application messages also pass through the owning hub so every hub observes the same order.
- Clients order by `(gid, epoch, seq)`; ordering never depends on which member hub delivered a
  message.
- `GroupAck.highest_contiguous_seq` is the highest seq up to which the receiver holds every
  message for that gid. The owning hub resends anything above it.
- A receiver that sees a gap (`seq` greater than its contiguous high-water mark + 1) calls
  `FetchLog(gid, highest_contiguous_seq + 1, limit)` against the owning hub.

## Extensibility

- Request/response oneof fields 18-29 are multi-homing (M2c) operations (`NotifyHostingRecord`,
  `SeedReplica`, `CopyPendingWelcomes` = 18-20; 21-29 reserved); 30-39 for push (P); 40-49 are
  federation (M2b) operations.
- Per-message reserved ranges (`SubmitCommitRequest` 9-15, `SubmitMessageRequest` 6-15,
  `DeliverWelcomeRequest` 8-15, `SequencedMessage` 12-19) hold future delivery-strategy hints,
  push collapse ids and priorities.
- Breaking changes require a new package (`gim.s2s.v2`) and protocol id (`/gim/s2s/2.0.0`).
