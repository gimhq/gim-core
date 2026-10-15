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
token, rate limited) returns it for decryption with the recovery code.

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
2. extracts the Add, Remove and Update proposals (inline in the Commit or referenced);
3. validates gim-core MLS credentials (custom credential type `0xF001`, format owned by gim-core
   `docs/identity.md` "MLS credential") against DeviceLists stored on this hub, failing closed:
   - for every Add, the KeyPackage's leaf credential must certify the device that owns the claimed
     KeyPackage it resolves to, and verify against that user's stored DeviceList;
   - the leaf of every Update proposal and of the Commit's UpdatePath must certify the committing
     device itself (a member cannot change identity);
4. checks group policy (who may add or remove members);
5. derives the member events (`group.member_added` / `group.member_removed` with `user_id` and
   `device_ids`), the group roster and the fan-out set from the parsed proposals.

| Rejection | Status | Code |
|---|---|---|
| `mls_message` is not a `PublicMessage` Commit/Proposal for this group, or Welcome fields inconsistent | 400 | `validation_failed` |
| A checked leaf's credential is invalid or belongs to another device (see *MLS credential checks*) | 400 | `validation_failed` |
| Sender is not a member, or group policy does not allow the change | 403 | `not_member` / `forbidden` |

### MLS credential checks

`POST /v2/keypackages` applies the same check to every uploaded KeyPackage: its leaf must carry
the calling device's credential; one failing package rejects the whole upload.

A leaf credential is accepted only if all of these hold, in order:

1. the credential type is `0xF001` and its content decodes (gim-core validation steps 1-2);
2. the expected user has a valid stored DeviceList on this hub;
3. the DeviceCert verifies under the credential's root key, the leaf's MLS signature key equals the
   certified device key, and the stored DeviceList does not revoke the device (gim-core steps 3-5);
4. the certified `(user_id, device_id)` is the expected device;
5. the stored DeviceList certifies that device.

The `validation_failed` message names the first failing check by its code: the gim-core
credential codes (`wrong_credential_type`, `non_canonical_cbor`, `malformed_content`,
`unsupported_version`, `bad_cert_signature`, `user_id_mismatch`, `device_id_mismatch`,
`invalid_cert`, `leaf_key_mismatch`, `revoked_device`) or the hub
codes `no_device_list`, `identity_mismatch` and `unknown_device`, e.g.
`invalid MLS credential (leaf_key_mismatch)`.

`POST /v2/groups/{gid}/messages` carries only `PrivateMessage` application messages; the hub reads
the epoch from the framing but cannot see their content.

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

## Changes from v1

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
| Commit retry | `client_id` replay | same Commit (same hash) returns success with `duplicate: true`; any other Commit for a past epoch is 409 `stale_epoch` |
| Messages | `{client_id, epoch, kind, payload, recipients?}` | `{client_id, mls_message}` for application messages; Commits go to `/commits`; `kind` is `commit` or `application` |
| History | `?after_seq` (exclusive) | `?from_seq` (inclusive) |
| Welcome | message of kind `welcome` with `recipients` | `welcome` event to each recipient device |
| Members | `device_id` | `user_id` + `device_id` |
| Events | `message`, `group.member_added`, `group.member_removed`, `keypackages.low` | same, membership events carry `user_id` and `device_ids`; plus `welcome` and `device_list.updated`; unacknowledged Welcomes via `GET /v2/welcomes/pending` |
| Health | `{status}` | `{status, version}` |

Unchanged semantics: per-device event cursor, long-poll `GET /v2/events?cursor&wait`, 410
`cursor_expired` with the head cursor, WebSocket `GET /v2/stream` with the same frames and close
codes (4401, 4410), per-group `seq`, `client_id` idempotency, encrypted blobs with single byte
ranges.

## Status

Implemented: `/healthz`, sign-in (`/v2/auth/*`), DeviceLists and users (`/v2/users/*`, `/v2/me`),
recovery backups, device linking (`/v2/link-bundles*`), handles, KeyPackages, groups and commits,
messages, pending Welcomes, events (long-poll and `/v2/stream`) and blobs.

Pending:

- `PUT`/`DELETE /v2/push/registration` return 501 `not_implemented`.
- Validation of an added member's MLS credential (type `0xF001`) against their DeviceList is not
  enforced yet: the hub accepts every added member until gim-core identity part 3 defines the
  credential format. The 400 `validation_failed` rejection for credentials in the commit table
  above applies once it lands.
