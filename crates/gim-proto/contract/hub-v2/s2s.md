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
authenticated PeerID. Federation policy (PeerID allowlist, optional pnet PSK) is applied to the
PeerID before any operation is processed.

### DHT records

- Key: `/gim/user/<user_id>`.
- Value: the user's `UserHostingRecord`, gim-core CBOR encoding `[tbs, sig]` (defined in
  gim-core `docs/identity.md`). The hub does not re-model it.
- The record validator checks the user signature, every hub signature and expiry, and selects the
  record with the highest `seq`.
- `GetHostingRecord` fetches the same bytes directly from a hub; a hub uses it first and falls
  back to a DHT lookup when the peer is unreachable or returns `NOT_FOUND`.

## Identifiers

- `user_id`, `device_id`: opaque strings; format owned by gim-core.
- `gid`: `<owner hub_id>/<random_128 base32lower>` (gim-core `HubId` of the owning hub's root key;
  128 random bits, lowercase unpadded base32). The owning hub is the hub whose `hub_id` prefixes
  the gid; it runs the group's sequencer. The gid is stable across runtime-key rotation (arch
  §4.1); the owning hub's current PeerID is resolved from its runtime certificate / hosting
  records. The MLS `group_id` is the UTF-8 bytes of the gid.
- `client_id`: client-chosen idempotency key, unique per sender device.
- `message_id`: globally unique id assigned by the owning hub to every sequenced message and
  Welcome.
- Identity objects (`DeviceList`, `UserHostingRecord`, ...) appear only as opaque CBOR `bytes`.

## Envelope

```
S2sRequest  { string request_id; oneof op { ... } }
S2sResponse { string request_id; oneof result { ... }; Error error }
Error       { ErrorCode code; string message }
```

- `request_id` is echoed back for correlation and logging; it is not an idempotency key.
- A response sets exactly one of `result` (same field number as the request op) or `error`.
- Field numbers 18-39 of both oneofs are reserved for multi-homing (M2c) and push (P) operations.

## Operations

"Acting user" is the user on whose behalf the request is made (the `sender_user_id` or
`requester_user_id`). "Listed" means the calling PeerID appears in the acting user's current
`UserHostingRecord`.

| Op | Direction | Request -> Response | Authorization |
|---|---|---|---|
| `SubmitCommit` | member hub -> owning hub | `gid, sender_user_id, sender_device_id, client_id, mls_message, welcome?, welcome_recipient_device_ids, ratchet_tree?` -> `seq, epoch, duplicate` | Caller listed for `sender_user_id`; responder must be the owning hub of `gid`; group policy (who may add/remove) enforced by the owning hub. |
| `SubmitMessage` | member hub -> owning hub | `gid, sender_user_id, sender_device_id, client_id, mls_message` -> `seq, epoch, duplicate` | Caller listed for `sender_user_id`; sender is a group member. |
| `Deliver` | owning hub -> member hub | `messages: [SequencedMessage]` -> `acks: [GroupAck{gid, highest_contiguous_seq}]` | Caller is the owning hub of every `gid` in the batch (`hub_id` prefix of the gid). |
| `DeliverWelcome` | owning hub -> invitee's hub | `gid, sender_user_id, recipient_user_id, recipient_device_ids, welcome, ratchet_tree?, message_id` -> `{}` | Caller is the owning hub of `gid`; responder hosts `recipient_user_id`. |
| `ClaimKeyPackage` | requester's hub -> target's hub | `requester_user_id, target_user_id, device_id?` -> `key_packages: [ClaimedKeyPackage{device_id, key_package, last_resort}]` | Caller listed for `requester_user_id`; responder hosts `target_user_id`. |
| `FetchLog` | member hub -> owning hub | `gid, from_seq, limit` -> `messages, next_seq, complete` | Caller listed for at least one current member of `gid`. |
| `GetDeviceList` | any hub -> user's hub | `user_id` -> `device_list_cbor` (gim-core `DeviceList`) | Federation policy only (public, signed object). |
| `GetHostingRecord` | any hub -> user's hub | `user_id` -> `hosting_record_cbor` (gim-core `UserHostingRecord`) | Federation policy only (public, signed object); fallback is the DHT. |

Notes:

- `SubmitCommit` carries a Commit or a Proposal as an MLS `PublicMessage` (`SubmitMessage`
  carries only `PrivateMessage` application messages). The owning hub parses the `PublicMessage`
  and reads the epoch from its framing rather than trusting a request field. It extracts the
  Add/Remove (and Update) proposals, validates the gim-core MLS credential (custom credential
  type `0xF001`, format owned by gim-core `docs/identity.md`) of every added member against that
  member's DeviceList (fetched with `GetDeviceList` when the user is hosted elsewhere), enforces
  group policy, and derives the roster and fan-out set from the result. Member hubs never send
  roster deltas: the owning hub cannot verify them.
- For each accepted Commit the owning hub sequences, after the `COMMIT` entry, hub-generated
  `MEMBER_ADDED` / `MEMBER_REMOVED` `SequencedMessage`s whose `affected_user_ids` list the users
  added or removed. Member hubs turn them into `group.member_added` / `group.member_removed`
  client events.
- A `SubmitCommit` whose `mls_message` is not a `PublicMessage` Commit/Proposal, or that adds a
  member with an invalid credential, fails with `INVALID`. A Commit rejected by group policy
  (sender not allowed to add/remove) fails with `UNAUTHORIZED`.
- `SequencedMessage` = `gid, seq, epoch, kind, sender_user_id, sender_device_id, client_id,
  payload, message_id, created_at (unix ms), affected_user_ids`. `kind` is one of `COMMIT`,
  `APPLICATION`, `PROPOSAL`, `MEMBER_ADDED`, `MEMBER_REMOVED`.
- `Deliver` sends one copy per member hub, not per device; the member hub fans out to its local
  devices. A batch may mix gids; within a gid messages are in ascending `seq`.
- `ClaimKeyPackage` without `device_id` returns one KeyPackage per device of the target user.
  One-time KeyPackages are consumed on claim; `last_resort = true` marks the device's reusable
  last-resort KeyPackage, returned only when no one-time KeyPackage is left.
- `FetchLog` returns messages with `seq >= from_seq`, at most `limit` (the owning hub may cap
  lower). Continue with `from_seq = next_seq` until `complete = true`.

## Error codes

| Code | Meaning | Caller action |
|---|---|---|
| `UNSPECIFIED` | Default value; never sent intentionally. | Treat as `INTERNAL`. |
| `UNAUTHORIZED` | PeerID not allowed by federation policy, not listed in the acting user's current hosting record, or not the owning hub for `Deliver` / `DeliverWelcome`; or a Commit rejected by group policy. | Do not retry; refresh the hosting record if it may be stale. |
| `NOT_FOUND` | Unknown user, device, group, record, or no KeyPackage available. | Do not retry the same request. |
| `STALE_EPOCH` | The Commit or message targets an epoch older than the group's current epoch. | Client fetches the latest state (via `FetchLog`) and resubmits. |
| `CONFLICT` | A different Commit was already sequenced for this epoch. | Client fetches the latest state and retries on top of it. |
| `GONE` | The requested log range was pruned. | Re-join or resync from a newer `seq`. |
| `RATE_LIMITED` | Caller exceeded a rate limit. | Retry with exponential backoff. |
| `INVALID` | Malformed request: bad gid, unparsable MLS framing, handshake not a `PublicMessage`, invalid member credential, missing required field. | Do not retry unchanged. |
| `INTERNAL` | Unexpected failure on the responder. | Retry with exponential backoff. |

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

- Request/response oneof fields 18-29 are reserved for multi-homing (M2c), e.g. hub add/remove
  and migration hand-off; 30-39 for push (P).
- Per-message reserved ranges (`SubmitCommitRequest` 9-15, `SubmitMessageRequest` 6-15,
  `DeliverWelcomeRequest` 8-15, `SequencedMessage` 12-19) hold future delivery-strategy hints,
  push collapse ids and priorities.
- Breaking changes require a new package (`gim.s2s.v2`) and protocol id (`/gim/s2s/2.0.0`).
