# Push gateway

The hub wakes devices through a push provider when events are addressed to them. A push is only a
wake-up hint: the client always syncs its event stream (`GET /v2/events` from its cursor)
afterwards. Pushes may be coalesced, dropped or duplicated; correctness never depends on them.

This document is normative for the payload (section 2) and the provider mapping (section 3); gim-core
`process_push(payload)` parses it.

## 1. Registration

`PUT /v2/push/registration` (bearer auth) stores the calling device's registration, replacing any
previous one (one per device); `DELETE` removes it. Both return 204. The body is
`{provider, token, app_id?, sandbox?}` (see `openapi.json`):

| `provider` | `token` | `app_id` | `sandbox` |
|---|---|---|---|
| `apns` | APNs device token: 64-200 hex digits (even), stored lowercase | APNs topic (bundle ID); defaults to `GIM_HUB_PUSH_APNS_TOPIC` | use the APNs sandbox |
| `fcm` | FCM registration token: at least 32 chars of `A-Z a-z 0-9 - _ : .` | ignored | ignored |
| `unifiedpush` | endpoint URL: `https`, no credentials, not `localhost` or a non-public IP (loopback, private, link-local, CGNAT, NAT64, 6to4, ...) | ignored | ignored |
| `log` | any string without control characters | ignored | ignored |

Every token is 1-4096 bytes; `app_id` is 1-255 chars of `A-Z a-z 0-9 . - _ :`. Invalid input is
400 `validation_failed`. Registrations are accepted for every provider even when the hub has no
credentials for it; sends to an unconfigured provider are logged as skipped.

A registration is removed when the provider reports the token as invalid (APNs 410 or
`BadDeviceToken`/`DeviceTokenNotForTopic`, FCM 404 or `UNREGISTERED`/`SENDER_ID_MISMATCH`,
UnifiedPush 404/410), unless the device registered a different token meanwhile. It is also
removed with the device.

## 2. Payload

```json
{
  "v": 1,
  "type": "message",
  "gid": "<gid>",
  "seq": 42,
  "message_id": "<message_id>",
  "sender_user_id": "<user_id>",
  "collapse_id": "<message_id>",
  "mls_message": "<base64>"
}
```

- `v`: payload version, `1`. Clients ignore unknown fields.
- `type`: the event type. `message` and `welcome` always; `group.member_added` and
  `group.member_removed` only when the hub sets `GIM_HUB_PUSH_MEMBER_EVENTS=true`.
- `gid`, `seq`: the group and per-group sequence number of the message (for `welcome` and
  membership events: of the Commit that produced them).
- `message_id`: the hub's ID of the stored message at `(gid, seq)`. If the hub does not store that
  message, a stand-in: the first 16 bytes of `SHA-256(gid || 0x00 || seq as u64 big-endian)`,
  lowercase hex.
- `sender_user_id`: the sender of the message or Welcome; for membership events the user who
  committed the change.
- `collapse_id`: always equal to `message_id`, so a device collapses duplicate pushes for the same
  message (e.g. from several hubs of a multi-homed user, arch §9.5).
- `mls_message` (optional): standard base64 of the MLS message (`message`) or the MLS Welcome
  (`welcome`, only when the Welcome has no separate ratchet tree). Present only if the encoded
  provider payload stays within the provider limit (section 3); otherwise omitted and the client
  fetches `GET /v2/groups/{gid}/messages?from_seq={seq}` (or `GET /v2/welcomes/pending`). Never
  present for membership events.

The hub never sees plaintext; `mls_message` is the same ciphertext the event stream carries. The
metadata fields (`gid`, `seq`, `sender_user_id`) are visible to the push provider.

## 3. Provider mapping

### APNs

`POST https://api.push.apple.com/3/device/<token>` (`api.sandbox.push.apple.com` if the
registration has `sandbox: true` or `GIM_HUB_PUSH_APNS_SANDBOX=true`), HTTP/2, token-based auth.

| Header | Value |
|---|---|
| `authorization` | `bearer <ES256 JWT {alg: ES256, kid: KEY_ID} {iss: TEAM_ID, iat}>`, reused for 50 minutes |
| `apns-topic` | registration `app_id`, else `GIM_HUB_PUSH_APNS_TOPIC` |
| `apns-push-type` | `alert` (`message`, `welcome`); `background` (membership) |
| `apns-priority` | `10` (alert); `5` (background) |
| `apns-collapse-id` | `collapse_id` |
| `content-type` | `application/json` |

Body (`message`; `welcome` uses the body `New conversation`):

```json
{
  "aps": {"alert": {"title": "gim", "body": "New message"}, "mutable-content": 1},
  "gim": { ...payload... }
}
```

Membership events use `"aps": {"content-available": 1}`. The Notification Service Extension
passes `gim` (re-serialized as JSON) to `process_push` and replaces the generic alert. The whole
body is at most 4096 bytes: `mls_message` is inlined only if the body fits.

### FCM

`POST https://fcm.googleapis.com/v1/projects/<project_id>/messages:send` with
`authorization: Bearer <OAuth access token>`. The token comes from the service account's
`token_uri` with a JWT bearer grant (RS256 JWT `{iss: client_email, scope:
https://www.googleapis.com/auth/firebase.messaging, aud: token_uri, iat, exp: iat + 3600}`) and is
reused until a minute before it expires. Data-only message:

```json
{
  "message": {
    "token": "<token>",
    "data": {"gim": "<payload as a JSON string>"},
    "android": {"priority": "HIGH", "collapse_key": "<collapse_id>"}
  }
}
```

`priority` is `NORMAL` for membership events. `data` (key `gim` plus the JSON string) is at most
4000 bytes: `mls_message` is inlined only if it fits.

### UnifiedPush

`POST <token>` (the endpoint URL) with the payload JSON as body, at most 4096 bytes (`mls_message`
inlined only if it fits), and headers `content-type: application/json`, `ttl: 86400`,
`urgency: high` (`normal` for membership events) and `topic: <collapse_id>` when it is a valid
Web Push topic (at most 32 base64url characters). The body is not Web Push encrypted (RFC 8291).
The hub refuses to connect if the endpoint's host resolves to any non-public address (checked on
every send, so DNS rebinding cannot reach internal hosts) and does not follow redirects (a 3xx is a
permanent failure).

### log

Writes a structured log line (target `gim_hub_push::log`) and records the payload (as for
UnifiedPush: plain JSON, 4096-byte limit) in an in-memory ring of the last 256 pushes.

## 4. Dispatch

- The dispatcher tails the `events` table every 500 ms, starting at the head when the hub starts
  (events from before the start are not pushed). For each `message`/`welcome` event (and
  membership events if enabled) addressed to a device that is active and has a registration, it
  queues a push. The sender's own device never gets a `message` event, so it gets no push.
- Queue: at most one pending push per device; a newer one replaces it. At most
  `GIM_HUB_PUSH_QUEUE_CAPACITY` devices are queued; further pushes are dropped (counted and
  logged). Four workers send concurrently.
- Errors: `InvalidToken` deletes the registration; `Retryable` (transport errors, throttling, 5xx,
  expired provider credentials) retries after 1, 2, 4, 8 s (5 attempts in total) unless a newer
  push for the device is queued; `Permanent` drops the push.
- The API request that produced the event is never affected by push failures.
- Multi-homing hook: `Dispatcher::set_gate` installs a filter deciding whether this hub pushes to a
  device (e.g. only if it is the user's primary hub). Without a gate every hub pushes and devices
  collapse duplicates on `collapse_id`.
- Counters (`enqueued`, `coalesced`, `dropped`, `sent`, `skipped`, `invalid_token`, `retried`,
  `failed`) are available from `Dispatcher::metrics`.

## 5. Test-only push log endpoint

`GET /v2/debug/push-log?device_id=<device_id>` returns
`{"notifications": [{user_id, device_id, token, payload, sent_at}]}`, oldest first, from the `log`
provider's ring (all devices if `device_id` is omitted). It is unauthenticated, not part of the
API contract (`openapi.json`), and answers 404 `not_found` unless `GIM_HUB_PUSH_LOG_ENDPOINT=true`.
Enable it only in test deployments (CI flows register devices with provider `log`).
