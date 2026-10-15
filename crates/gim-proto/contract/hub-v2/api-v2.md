# Client API v2

The contract is [`openapi.json`](../openapi.json) at the repository root. It is generated from the
utoipa annotations in `crates/gim-hub-api` and must not be edited by hand:

```bash
bash scripts/gen-openapi.sh   # regenerate after changing DTOs or handlers
bash scripts/check.sh         # fails if openapi.json is out of date
```

Conventions are unchanged from v1: JSON with snake_case fields, timestamps in integer milliseconds
since the Unix epoch, binary values as standard base64 (`contentEncoding: base64`), errors as
`{"error":{"code","message"}}`, bearer token auth unless an endpoint says otherwise.

## Identity objects are opaque

gim-core owns every identity wire format (DeviceCert, DeviceList, AuthChallenge, recovery backup,
link bundle): CBOR `[tbs, sig]` objects defined in gim-core `docs/identity.md`. The API never
re-models them as JSON; it carries the CBOR bytes as base64 strings (`device_list`, `challenge`,
`backup`, `sealed_bundle`). `user_id` and `device_id` are opaque strings whose format is also owned
by gim-core.

## Auth flow

The hub authenticates a device by a signature over a challenge, checked against the device's
DeviceCert in the user's stored DeviceList. There is no handle-only registration.

1. Create the identity locally (gim-core), then upload the signed DeviceList:
   `PUT /v2/users/{user_id}/device-list {device_list}`. No token is needed: the list is
   self-certifying. The first upload creates the user on this hub. A later upload with a higher
   `seq` replaces the stored list (200); re-uploading the identical list (same `seq`, same bytes)
   is idempotent and also returns 200. A lower `seq`, or the same `seq` with different bytes, is
   409 `stale_device_list`. A replacement emits a `device_list.updated` event (payload: the new
   `{user_id, device_list}`) to the user's active devices and to every active device of users
   sharing at least one group with them, so peers re-verify the user's MLS credentials against
   the new list.
2. `POST /v2/auth/challenge {user_id, device_id}` returns `{challenge, expires_at, hub_id}`
   (404 `not_found` unless the device is active in the stored DeviceList). `challenge` is a
   gim-core AuthChallenge (CBOR, base64) with `audience` = this hub's `hub_id`, a 32-byte random
   nonce and a 5-minute lifetime.
3. The device signs the exact challenge bytes into a gim-core AuthResponse (gim-core
   docs/identity.md, *Device authentication*) and calls `POST /v2/auth/session {response}`
   (AuthResponse CBOR, base64). The hub verifies it against the stored DeviceList and its
   `hub_id`, and accepts each challenge once, for the device it was issued to, before
   `expires_at`. It returns `{token, expires_at}` (token lifetime `GIM_HUB_SESSION_TTL_DAYS`,
   default 30 days). Errors: 400 `validation_failed` (malformed body or AuthResponse); 401
   `invalid_challenge` (unknown, used, expired or foreign challenge), `invalid_signature`, or
   `device_not_active` (device revoked or not in the DeviceList).
4. Use `Authorization: Bearer <token>` (or `?token=` on `GET /v2/stream`). Sign in again after
   `expires_at` or on 401.

Long-lived event delivery re-checks the session (unexpired, device still active). `GET /v2/stream`
checks it with every batch of events (after reading it, before sending it), on every wake-up and at
least every 30 seconds; once the session is deleted, expires or its device is revoked by a
DeviceList update, the hub sends no further events and closes the connection with code 4401 (a
revoking upload wakes the revoked devices, so their streams close promptly). `GET /v2/events?wait=`
checks it again when the wait ends and then answers 401 `unauthorized` instead of returning events.

Linking a new device: the new device shows a QR code with a `link_id`; the old device (signed in)
posts `POST /v2/link-bundles {link_id, sealed_bundle, expires_in}` and uploads the DeviceList that
includes the new device; the new device long-polls `GET /v2/link-bundles/{link_id}?wait=30`
without a token (the bundle is deleted on first fetch) and then signs in as above.

Recovery: `PUT /v2/users/{user_id}/recovery-backup` stores the encrypted backup (own user only,
at most 65536 bytes); after losing every device, `GET /v2/users/{user_id}/recovery-backup` (no
token; rate limited per client IP and per `user_id`, `GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN`
(default 20) and `GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN` (default 10) requests per minute, 429
`rate_limited` with `Retry-After`) returns it for decryption with the recovery code.

### Public reads

`GET /v2/users/{user_id}/device-list` and `GET /v2/users/{user_id}` need no token; a bearer token,
if sent, is ignored (an invalid one is not rejected). A device restoring from a recovery code is
not yet in the DeviceList, so it cannot sign in, but it must read the current list to publish the
next `seq`. This exposes nothing new: DeviceLists are self-certifying and already uploaded without
a token, and `user_id` is an unguessable hash (the same exposure as hosting records in the DHT).

- They return only public data: `{user_id, device_list}` and, for `GET /v2/users/{user_id}`, the
  optional `handle` of this hub's directory. No presence, last-seen time, device activity, group
  or session information.
- Remote users resolve as described under *Remote users and cross-hub claims* (cached copy, fetch
  from the user's hub, or 503 `peer_unavailable` with `Retry-After`).
- Both endpoints share token-bucket limits, checked per client IP first (before any lookup or
  remote fetch) and then per target `user_id`: `GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN` (default 120)
  and `GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN` (default 60) requests per minute, with a burst of the
  same size. IPv6 clients are counted per /64. Over a limit the answer is 429 `rate_limited` with
  `Retry-After` seconds (at least 1).

## Membership and wire format

Handshake messages (Commit, Proposal) are sent as MLS `PublicMessage`; application messages stay
`PrivateMessage`. Membership is therefore visible to the owning hub, which enforces group policy
anyway (arch §7.3, MIMI hub model). Clients do not declare roster changes: a client-declared
roster delta cannot be verified by the hub and is not part of the API.

Group IDs: `POST /v2/groups` assigns `gid = <owner hub_id>/<random_128>`, where `hub_id` is the
gim-core `HubId` of the owning hub's root key (`"h" || base32(...)`, not a libp2p PeerID) and
`random_128` is 16 random bytes in lowercase unpadded base32 (26 characters). The gid is stable
across runtime-key rotation (arch §4.1); the hub's current PeerID is resolved from its runtime
certificate / hosting records. Clients use the UTF-8 bytes of the gid as the MLS `group_id`; the
hub rejects a Commit whose framing carries any other group ID. Percent-encode the gid in paths
(`/` as `%2F`).

On `POST /v2/groups/{gid}/commits` the owning hub:

1. parses the `PublicMessage` and reads the epoch from its framing;
2. extracts the Add, Remove and Update proposals: inline in the Commit, or referenced by
   `ProposalRef` (RFC 9420 §5.2) to Proposals the hub sequenced for the group in the Commit's epoch
   (the hash function follows from the reference length: SHA-256, SHA-384 or SHA-512);
3. validates gim-core MLS credentials (custom credential type `0xF001`, format owned by gim-core
   `docs/identity.md` "MLS credential") against DeviceLists stored on this hub, failing closed:
   - for every Add, the KeyPackage's leaf credential must certify the device that owns the claimed
     KeyPackage it resolves to, and verify against that user's stored DeviceList;
   - the leaf of every Update proposal and of the Commit's UpdatePath must certify the committing
     device itself (a member cannot change identity);
4. checks group policy (who may add or remove members);
5. derives the member events (`group.member_added` / `group.member_removed` with `user_id` and
   `device_ids`), the group roster and the fan-out set from the parsed proposals.

A Proposal on the same endpoint (types Add, Remove, Update and SelfRemove; others are rejected)
must come from a member at its own leaf, for the group's current epoch (else 409 `stale_epoch`),
without Welcome fields. `welcome` (and the `welcome` field of the `welcome` event and of pending
Welcomes) is the base64 of a TLS-encoded MLSMessage (wire_format = mls_welcome) carrying a Welcome
(the hub checks this framing, not the encrypted contents);
`ratchet_tree` is the TLS-encoded ratchet tree. An Update's leaf is checked like the committer's own leaves; a Remove must
target an occupied leaf; an Add is checked (claim ledger, credential) only when a Commit references
it. The hub sequences the Proposal, delivers it to the other members as a `message` of kind
`proposal` and answers `{seq, epoch, duplicate}` with the unchanged epoch. Neither the epoch nor
the roster changes: a member leaving with a self-Remove Proposal stays in the roster until another
member's Commit references it. Proposals of an epoch can no longer be referenced once the epoch
advances. Resubmitting the same Proposal answers 200 `duplicate: true`.

| Rejection | Status | Code |
|---|---|---|
| `mls_message` is not a `PublicMessage` Commit/Proposal for this group, a Commit references an unknown or no longer pending Proposal, or Welcome fields inconsistent | 400 | `validation_failed` |
| A checked leaf's credential is invalid or belongs to another device (see *MLS credential checks*) | 400 | `validation_failed` |
| `welcome` is not exactly one MLSMessage with wire_format = mls_welcome (e.g. a bare Welcome without the MLSMessage wrapper, another wire format, trailing bytes): `welcome is not an MLSMessage carrying a Welcome` | 400 | `validation_failed` |
| Sender is not a member, or group policy does not allow the change | 403 | `not_member` / `forbidden` |

### MLS credential checks

`POST /v2/keypackages` applies the same check to every uploaded KeyPackage: its leaf must carry
the calling device's credential; one failing package rejects the whole upload.

A leaf credential is accepted only if all of these hold, in order:

1. the credential type is `0xF001` and its content decodes (gim-core validation steps 1-2);
2. the DeviceCert verifies under the credential's root key and the leaf's MLS signature key equals
   the certified device key (gim-core steps 3-4);
3. the expected user has a valid stored DeviceList on this hub (`device_list_unknown`), it is the
   certified user's list (`identity_mismatch`), it does not revoke the device (`revoked_device`)
   and it certifies the device with the leaf's key (`device_not_in_list`) (gim-core step 5);
4. the certified `(user_id, device_id)` is the expected device (`identity_mismatch`).

The `validation_failed` message names the first failing check by its code: the gim-core
credential codes (`wrong_credential_type`, `non_canonical_cbor`, `malformed_content`,
`unsupported_version`, `bad_cert_signature`, `user_id_mismatch`, `device_id_mismatch`,
`invalid_cert`, `leaf_key_mismatch`, `device_list_unknown`, `revoked_device`,
`device_not_in_list`) or the hub code `identity_mismatch` (the leaf is not the expected device),
e.g. `invalid MLS credential (leaf_key_mismatch)`.

`POST /v2/groups/{gid}/messages` carries only `PrivateMessage` application messages; the hub reads
the epoch from the framing but cannot see their content.

A `Message` (submit responses, `GET /v2/groups/{gid}/messages`, `message` events) carries
`gid`, `seq`, `sender_user_id`, `sender_device_id`, `client_id`, `message_id`, `kind`, `epoch`,
`mls_message` and `created_at`. `message_id` (string, always present) is the opaque ID assigned by
the owning hub and is identical on every hub that stores the message; it equals the push
`message_id` / `collapse_id` and is the cross-hub dedup key (docs/multihoming.md §6.3).

## Pending Welcomes and 410 recovery

Every Welcome addressed to a device is also kept as a pending Welcome for that device:

- `GET /v2/welcomes/pending?limit=` (bearer) returns `{welcomes: [...]}`, the Welcomes addressed to
  the calling device that it has not acknowledged, oldest first. `limit` defaults to 50, at most
  200. Each item carries the `welcome` event payload (`gid`, `sender_user_id`, `sender_device_id`,
  `epoch`, `seq`, `welcome`, `ratchet_tree?`) plus `created_at`.
- `POST /v2/welcomes/{gid}/ack` (bearer, `gid` percent-encoded) marks the pending Welcome(s) for
  `gid` as processed for the calling device and returns 204. It is idempotent: acknowledging again,
  or a `gid` with nothing pending, also returns 204.

Pending Welcomes are retained independently of event retention, until acknowledged or until the
group is deleted. A retention cap may be added later.

A client acknowledges a Welcome once it has joined the group (or decided to ignore it), whether it
learned of it from a `welcome` event or from the pending list. Recovery after 410
`cursor_expired` (from `GET /v2/events` or close code 4410 on `GET /v2/stream`):

1. Keep the head `cursor` from the 410 response.
2. Page through `GET /v2/welcomes/pending` and join each group from its Welcome (and
   `ratchet_tree`), then `POST /v2/welcomes/{gid}/ack`.
3. Resync groups already joined: `GET /v2/groups`, message history from the last known `seq`
   (for a newly joined group, from the Welcome's `seq + 1`), DeviceLists.
4. Continue `GET /v2/events` / `GET /v2/stream` from the head cursor.

## Hosting records

A user's hosting record (gim-core `SignedHostingRecord`, signed with the user root key) lists the
hubs that host the user; federation acts only for users whose current record lists the hub
([`federation.md`](federation.md) §4). The client builds, signs and renews the record; the hub
never holds the user root key.

1. `POST /v2/users/{user_id}/hosting-entry {priority}` (bearer, own user; `priority` 0..=255,
   default 0) returns `{hub_id, hub_root_pubkey, priority, entry}`: this hub's `HostingEntry`
   (CBOR, base64) co-signed with its root key. Signing is deterministic.
2. The client puts the entries into a record (`seq`, `expires_at`, entries in canonical order),
   signs it and uploads it with `PUT /v2/users/{user_id}/hosting-record {hosting_record}` (no
   token; at most 8192 decoded bytes). Checks, in order: the record verifies for `user_id` (400
   `invalid_hosting_record`, the message names the gim-core error code); the user is local to this
   hub (404 `not_found`); `expires_at - now` is between 1 hour and 30 days (400
   `invalid_hosting_record`, `lifetime_out_of_range`); a lower `seq`, or the same `seq` with a
   different body, is 409 `stale_hosting_record`, the identical record is 200 unchanged. The first
   record is 201. The response is `{user_id, hosting_record, seq, expires_at, hosted}`; `hosted`
   says whether the record lists this hub. A hosted record is published to the federation DHT.
3. Records should live 7 days and be renewed (new `seq`) when less than 3 days remain. When less
   than 48 hours remain, the hub emits `hosting_record.expiring` (payload
   `{user_id, expires_at, seq}`) to the user's active devices, once per record `seq` and at most
   once per 24 hours.

`GET /v2/users/{user_id}/hosting-record` (no token) returns the stored record of a local user, or
the newest valid record of a remote user resolved through federation (cache, the user's hubs, the
DHT): 404 `not_found` if none is known or it expired, 503 `peer_unavailable` (with `Retry-After`
seconds) if a needed peer hub did not answer and nothing else is known.

Federated actions of a user without a valid record listing their hub fail with 403
`hosting_record_required`.

## Remote users and cross-hub claims

With federation ([`federation.md`](federation.md) §5.1, §5.2), clients keep talking only to their
own hub:

- `GET /v2/users/{user_id}` and `GET /v2/users/{user_id}/device-list` also answer for users of
  other hubs. The hub serves its cached copy of the user's DeviceList, fetching it from the user's
  hub when it is not cached or older than `GIM_HUB_DEVICE_LIST_CACHE_HOURS` (default 24). A stale
  copy is served while the user's hub is unreachable; without any copy the answer is 503
  `peer_unavailable` (with `Retry-After` seconds), and 404 `not_found` if no hosting record of the
  user is known. `handle` is absent for remote users (handles are per-hub).
- When a hosted user's DeviceList is replaced, the hub pushes it to the hubs sharing groups with
  the user; those hubs emit `device_list.updated` to their users in those groups, as for a local
  update.
- `POST /v2/keypackages/claim` routes each target by its hosting record: targets on this hub are
  claimed locally; targets on another hub are claimed from their hubs (primary first, see
  [Multi-homing](#multi-homing)) on the caller's behalf (in parallel). The response gains
  `unavailable: [ClaimTarget]` for targets whose hub could not be reached, refused the request or
  timed out; retry those later (claims are never retried by the hub). `missing` keeps its meaning (unknown user, no active device, no KeyPackage). If any
  target is on another hub, the caller needs a valid hosting record listing this hub (403
  `hosting_record_required`); no package is claimed then.

## Groups across hubs

With federation ([`federation.md`](federation.md) §5.3, §5.4, §6), a group may have members on
several hubs. The hub named by the gid prefix owns the group and assigns every `seq`; every other
hub with a member keeps a replica. Clients still talk only to their own hub, and the API behaves
as on a single hub:

- `POST /v2/groups/{gid}/commits` and `POST /v2/groups/{gid}/messages` for a group owned by
  another hub are forwarded to the owner; the response is the owner's result (same `seq`,
  `epoch`, `duplicate`, 409 `stale_epoch` with `current_epoch`, `client_id` replay), and the
  local replica already holds the message when the client gets it. Additional errors: 403
  `hosting_record_required` (no valid hosting record lists this hub), 502 `peer_refused` (the
  owning hub refused), 503 `peer_unavailable` with `Retry-After` (the owning hub is unreachable;
  retry with the same Commit or `client_id`, both are idempotent).
- Adding a member of another hub works like a local Add: claim the KeyPackage through your own
  hub (`POST /v2/keypackages/claim`), then commit. The owning hub checks the added member's
  credential against their DeviceList, fetched from their hub. The Welcome reaches the member's
  devices through their own hub (`welcome` event and `GET /v2/welcomes/pending`, with the
  Commit's `seq` and `epoch`).
- Events (`message`, `group.member_added`, `group.member_removed` with `user_id`, `welcome`) are
  emitted by each member's own hub, after the owner sequenced the message and delivered it to
  that hub (seconds normally; after a hub outage the missed messages arrive in `seq` order, without
  gaps or duplicates).
- `GET /v2/groups`, `GET /v2/groups/{gid}` and `GET /v2/groups/{gid}/messages` are served from
  the replica, also while the owning hub is down. A replica holds the log from the Commit that
  added its hub's first member on; a lower `from_seq` returns messages starting there.

## Multi-homing

A user's hosting record may list several hubs ([`multihoming.md`](multihoming.md) §9.2). The
client keeps one connection and cursor per listed hub and merges by `message_id`.

- `GET /v2/hub` (no token) returns `{hub_id, hub_root_pubkey, version}`: this hub's id, its
  32-byte Ed25519 root public key (standard base64, as in `hosting-entry`) and the hub version. A
  client checks that a URL belongs to the `hub_id` in its record before signing in. Live.
- `POST /v2/keypackages`: a KeyPackage is uploaded to at most one hub, ever. An upload containing
  a KeyPackage this hub already claimed from another hub on a client's behalf is rejected as a
  whole with 409 `duplicate_key_package` (§5.3). Live.
- `POST /v2/keypackages/claim`: each target is claimed from the listed hubs in
  `(priority, hub_id)` order, moving to the next hub when one is unavailable or has no package;
  devices the first answering hub did not return are requested from the following hubs. The
  response shape is unchanged (§5.2). A local user whose record does not list this hub is claimed
  from its listed hubs too. Claim and commit through the same hub. Live.
- `POST /v2/groups/{gid}/commits`: an Add whose KeyPackage was not claimed through this hub keeps
  failing with 400 `validation_failed`, with the message
  `key package not claimed through this hub (kp_not_claimed)`; re-claim through this hub and
  commit again (§5.4). Live.

- Event `hosting_record.updated`, payload
  `{user_id, seq, expires_at, hosted, hubs: [{hub_id, priority}]}` (`hosted` = the record lists
  this hub). Emitted to the user's active devices on this hub when a stored record changes the
  listed hubs or their priorities; renewals with the same entries emit nothing. Devices dedup by
  `seq` across hubs ([`multihoming.md`](multihoming.md) §4.5). Live with federation.
- Record propagation: a hub that stores a record changing the listed hubs or priorities (client
  `PUT` or from another hub) passes it on to the user's other hubs, the hubs it removed, and the
  hubs sharing groups with the user, so a `PUT` to one reachable hub is enough for the others to
  learn it (§4.2). DeviceList uploads also reach the user's other listed hubs (§3.2). Live with
  federation.
- Removed users: when a stored record stops listing this hub, the user is removed here. During
  `GIM_HUB_UNHOSTED_GRACE_HOURS` (default 168) sign-in, reads, `GET /v2/stream`,
  `GET /v2/events`, pending Welcomes and their acks, `POST .../hosting-entry`, and `PUT` of the
  DeviceList and hosting record keep working; every other write fails with 403
  `hosting_record_required`. The unclaimed KeyPackages are deleted at once; after the grace
  period the user's data is purged, keeping the hosting record. A later record that lists this
  hub again ends the removal (§7.3). Live with federation.
- Bootstrap of an added hub: once a hub is listed, the owners of the user's groups seed its
  replicas at their current seq (no events; history before the seed is not served there), and the
  user's other hubs copy the unacknowledged pending Welcomes, which appear in
  `GET /v2/welcomes/pending` and as `welcome` events and are acknowledged on each hub
  independently (§4.3, §4.4). Commits, messages and Welcomes reach every listed hub of a member
  (§2.2). Live with federation.

## Push

`PUT /v2/push/registration` stores the calling device's push registration (one per device,
replacing the previous one) and `DELETE` removes it; both return 204. Tokens are validated per
provider (400 `validation_failed`); `unifiedpush` also requires the RFC 8291 keys `p256dh` and
`auth`, which encrypt its bodies. The hub then pushes `message` and `welcome` events to the
device's provider (never to the sender's own device; never for `message` events of kind
`proposal`). Payload, provider mapping and the test-only
`GET /v2/debug/push-log` (off by default): [`push.md`](push.md).

## Differences from v1

| Area | v1 (gim-server) | v2 (gim-hub) |
|---|---|---|
| Prefix | `/v1` | `/v2` |
| Sign-in | `POST /v1/devices {handle, display_name}` returns a token | DeviceList upload + `POST /v2/auth/challenge` + `POST /v2/auth/session` |
| Users | handle and display name required | `user_id` derived from the root key; `GET /v2/users/{user_id}` returns the DeviceList and an optional handle; no display name on the hub |
| Devices | `GET /v1/users/{user_id}/devices` | `GET`/`PUT /v2/users/{user_id}/device-list` (signed gim-core DeviceList) |
| Handles | lookup `GET /v1/users?handle=` | optional directory: `PUT`/`DELETE`/`GET /v2/handles/{handle}`; never a federation key |
| New | - | recovery backups, link-bundle relay, push registration (`PUT`/`DELETE /v2/push/registration`) |
| KeyPackage upload | `last_resort` is a separate package field | `last_resort: true` flag; the request then holds exactly one package |
| KeyPackage claim | `{device_ids}` | `{targets: [{user_id, device_id?}]}`, one package per active device; results carry `user_id` |
| Group ID | `group_id`, opaque | `gid = <owner hub_id>/<random_128 base32lower>`, assigned by the hub (MLS group ID = gid bytes); percent-encode it in paths (`/` as `%2F`) |
| Group create | `{kind, member_device_ids}` | `{kind}`; members are added by Commits |
| Membership | `POST /members`, `DELETE /members/{device_id}` | removed; driven by `POST /v2/groups/{gid}/commits {client_id, mls_message, welcome?, welcome_recipients?, ratchet_tree?}` returning `{seq, epoch, duplicate}` |
| Epoch | client `epoch` field | read by the hub from the MLS framing |
| Commit retry | `client_id` replay | same Commit or Proposal (same hash) returns success with `duplicate: true`; any other Commit or Proposal for a past epoch is 409 `stale_epoch` |
| Messages | `{client_id, epoch, kind, payload, recipients?}` | `{client_id, mls_message}` for application messages; Commits and Proposals go to `/commits`; `kind` is `commit`, `proposal` or `application` |
| History | `?after_seq` (exclusive) | `?from_seq` (inclusive) |
| Welcome | message of kind `welcome` with `recipients` | `welcome` event to each recipient device |
| Members | `device_id` | `user_id` + `device_id` |
| Events | `message`, `group.member_added`, `group.member_removed`, `keypackages.low` | same, membership events carry `user_id` and `device_ids`; plus `welcome` and `device_list.updated`; unacknowledged Welcomes via `GET /v2/welcomes/pending` |
| Health | `{status}` | `{status, version}`; plus `GET /v2/hub` `{hub_id, hub_root_pubkey, version}` |

Unchanged semantics: per-device event cursor, long-poll `GET /v2/events?cursor&wait`, 410
`cursor_expired` with the head cursor, WebSocket `GET /v2/stream` with the same frames and close
codes (4401, 4410), per-group `seq`, `client_id` idempotency, encrypted blobs with single byte
ranges.

## Status

Implemented: `/healthz`, `/v2/hub`, sign-in (`/v2/auth/*`), DeviceLists and users (`/v2/users/*`, `/v2/me`),
recovery backups, device linking (`/v2/link-bundles*`), handles, KeyPackages, groups and commits,
messages, pending Welcomes, events (long-poll and `/v2/stream`), blobs, hosting records,
federation (remote users and KeyPackage claims, groups across hubs), multi-homing (H4,
[`multihoming.md`](multihoming.md): fan-out to every listed hub, record propagation and
`hosting_record.updated`, replica seeding and Welcome copies for an added hub, claim routing
across a user's hubs, removal with a grace period, primary-only push with failover) and push
(registration and delivery for local and federated events; log provider, APNs, FCM and
UnifiedPush when configured; payload v1 without `sender_user_id`, optional minimal wake-up mode
`GIM_HUB_PUSH_MINIMAL`, UnifiedPush bodies encrypted per RFC 8291 `aes128gcm`).

Pending:

- Multi-homing known limits ([`multihoming.md`](multihoming.md) §13): a group whose owning hub is
  down cannot sequence (503 `peer_unavailable`); blobs are not replicated; an added hub serves no
  history before its replica seed; pushes in the failover window after the primary stops are
  not sent late; pending Welcome acknowledgements are per hub; `message` events carry no
  `message_id`, so clients merge the streams of several hubs by `(gid, seq)`.
- Push: no real APNs/FCM credentials have been exercised yet.
- Validation of an added member's MLS credential (type `0xF001`) against their DeviceList is not
  enforced yet: the hub accepts every added member until gim-core identity part 3 defines the
  credential format. The 400 `validation_failed` rejection for credentials in the commit table
  above applies once it lands.
