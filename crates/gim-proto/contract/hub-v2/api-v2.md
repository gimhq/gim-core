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
   409 `stale_device_list`.
2. `POST /v2/auth/challenge {user_id, device_id}` returns
   `{challenge_id, challenge, expires_at, hub_peer_id}`. `challenge` is a gim-core AuthChallenge
   (CBOR, base64) binding this hub's PeerID.
3. The device signs the challenge bytes with its device key and calls
   `POST /v2/auth/session {challenge_id, signature}`, which returns `{token, expires_at}` if the
   device is still active in the stored DeviceList.
4. Use `Authorization: Bearer <token>` (or `?token=` on `GET /v2/stream`). Sign in again after
   `expires_at` or on 401.

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

On `POST /v2/groups/{gid}/commits` the owning hub:

1. parses the `PublicMessage` and reads the epoch from its framing;
2. extracts the Add, Remove and Update proposals (inline in the Commit or referenced);
3. for every added member, validates the gim-core MLS credential (custom credential type
   `0xF001`, format owned by gim-core `docs/identity.md`) against the member's DeviceList: the
   device must be active in the user's current DeviceList and the credential's key must match its
   DeviceCert;
4. checks group policy (who may add or remove members);
5. derives the member events (`group.member_added` / `group.member_removed` with `user_id` and
   `device_ids`), the group roster and the fan-out set from the parsed proposals.

| Rejection | Status | Code |
|---|---|---|
| `mls_message` is not a `PublicMessage` Commit/Proposal for this group, or Welcome fields inconsistent | 400 | `validation_failed` |
| Added member's credential is malformed, not type `0xF001`, or does not match an active device in the member's DeviceList | 400 | `validation_failed` |
| Sender is not a member, or group policy does not allow the change | 403 | `not_member` / `forbidden` |

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
| Group ID | `group_id`, opaque | `gid = <owner_peer_id>/<random_128 base32>`, assigned by the hub; percent-encode it in paths (`/` as `%2F`) |
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

Until the hub logic lands every `/v2` route returns 501 `not_implemented`; `/healthz` is live.
