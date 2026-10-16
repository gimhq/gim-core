# Push gateway

The hub wakes devices when events are addressed to them. It does not talk to any push platform
itself: every push leaves the hub as one signed HTTP webhook to an external **push server**, which
owns platform delivery (APNs, FCM, Web Push or anything else) and its credentials. A push is only a
wake-up hint: the client always syncs its event stream (`GET /v2/events` from its cursor)
afterwards. Pushes may be coalesced, dropped or duplicated; correctness never depends on them.

This document is normative for the webhook a push server implements (section 2) and for the
payload (section 3), which gim-core `process_push(payload)` parses.

## 1. Registration

`PUT /v2/push/registration` (bearer auth) stores the calling device's registration, replacing any
previous one (one per device); `DELETE` removes it. Both return 204. The body is
`{provider, token, app_id?, sandbox?, p256dh?, auth?}` (see `openapi.json`). Every field is opaque
to the hub: it checks the shape only and passes the values to the push server.

| Field | Rule |
|---|---|
| `provider` | 1-64 chars of `a-z 0-9 . _ -`, e.g. `apns`, `fcm`, `unifiedpush`. `log` is the hub's test provider (section 5); every other value goes to the webhook. |
| `token` | 1-4096 bytes, no control characters. |
| `app_id` | optional, 1-255 chars of `A-Z a-z 0-9 . - _ :` (e.g. a bundle ID). |
| `sandbox` | optional bool; absent unless set. |
| `p256dh`, `auth` | optional, each 1-256 chars of base64url (padding optional), e.g. Web Push keys. Not required by any provider. |

Invalid input is 400 `validation_failed`. Registrations are accepted for every provider even when
no push server is configured; their pushes are then skipped (logged and counted).

A registration is removed when the push server answers 404 or 410 for it (section 2.4), unless the
device registered a different provider or token meanwhile. It is also removed with the device.

## 2. Webhook

Configured with `GIM_HUB_PUSH_WEBHOOK_URL`, `GIM_HUB_PUSH_WEBHOOK_SECRET` and
`GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS` ([`operations.md`](operations.md)).

### 2.1 Request

```
POST <GIM_HUB_PUSH_WEBHOOK_URL>
content-type: application/json
X-Gim-Signature: t=<unix seconds>,v1=<lowercase hex HMAC-SHA256>
X-Gim-Delivery: <delivery_id>
```

`X-Gim-Delivery` equals the body's `delivery_id`. The hub does not follow redirects.

### 2.2 Signature

`v1 = hex(HMAC-SHA256(GIM_HUB_PUSH_WEBHOOK_SECRET, "<t>." || raw body bytes))`, where `<t>` is the
decimal timestamp of the `t=` field. The timestamp is bound into the MAC, so a receiver can reject
replays outside a window. To verify:

1. Split the header on `,` into `key=value` pairs; take `t` and `v1`.
2. Reject if `|now - t| > 300` seconds (recommended window).
3. Compute the HMAC over the ASCII bytes of `t`, a `.` and the **raw** request body (before any
   JSON parsing or re-serialization), hex-encode it in lowercase and compare it with `v1` in
   constant time.

Example: secret `example-secret-0123456789abcdef0123`, `t = 1760600000` and the raw body

```
{"v":1,"hub_id":"hubexample","delivery_id":"3f1c0d9a8b7e6f5a4b3c2d1e0f9a8b7c"}
```

give

```
X-Gim-Signature: t=1760600000,v1=41f7f7c39db767f966e6c1cd60c6a460266194f33b271d1244ac9bb7b38e544e
```

In Python: `hmac.new(secret, f"{t}.".encode() + body, hashlib.sha256).hexdigest()` and
`hmac.compare_digest`.

### 2.3 Body

```json
{
  "v": 1,
  "hub_id": "<hub_id>",
  "delivery_id": "<32 lowercase hex chars>",
  "sent_at": 1760600000123,
  "registration": {
    "provider": "apns",
    "token": "<token>",
    "app_id": "im.g.apps",
    "sandbox": false,
    "p256dh": "<base64url>",
    "auth": "<base64url>"
  },
  "priority": "high",
  "collapse_id": "<collapse_id>",
  "ttl": 86400,
  "payload": { ...payload v1 or the wake object, section 3... }
}
```

- `v`: webhook version, `1`. Receivers ignore unknown fields.
- `hub_id`: the sending hub.
- `delivery_id`: unique per push and identical across retries of that push: the idempotency key
  (section 2.5).
- `sent_at`: unix milliseconds of the first attempt (unchanged on retries).
- `registration`: the stored registration (section 1). `app_id`, `sandbox`, `p256dh` and `auth`
  are absent when not set; `p256dh` and `auth` are re-encoded as unpadded base64url.
- `priority`: `high` for `message` and `welcome`, and for any push that coalesced one of them
  (section 4), e.g. a `group.member_added` payload that replaced a queued `message` push;
  `normal` otherwise (membership events, silent).
- `collapse_id`: equal to the payload's `collapse_id` (section 4).
- `ttl`: seconds the push server may keep trying to deliver, always `86400`.
- `payload`: what the device receives (section 3).

The body carries no `user_id` or `device_id`: the push server only needs the registration.

### 2.4 Responses and retries

| Response | Hub action |
|---|---|
| 2xx | Delivered. |
| 404, 410 | The registration is invalid: deleted, unless the device registered a different provider or token meanwhile. |
| 429, 5xx, timeout, transport error | Retried after 1, 2, 4, 8 s (5 attempts in total), but not before `Retry-After` (delay seconds, honoured up to 60 s); dropped once a newer push for the device is queued (section 4). |
| Any other status, including 3xx and other 4xx | Permanent failure: the push is dropped and logged, the registration kept. |

### 2.5 Idempotency

A retry may reach the push server although an earlier attempt was delivered (e.g. the response
was lost). Push servers deduplicate on `delivery_id` (keep the ids seen within `ttl`). Pushes for
the same message from several hubs of a multi-homed user carry different `delivery_id`s but the
same `collapse_id` (section 4).

## 3. Payload

```json
{
  "v": 1,
  "type": "message",
  "gid": "<gid>",
  "seq": 42,
  "message_id": "<message_id>",
  "collapse_id": "<message_id>",
  "mls_message": "<base64>"
}
```

- `v`: payload version, `1`. Clients ignore unknown fields.
- `type`: the event type. `message` (except kind `proposal`, section 4) and `welcome` always;
  `group.member_added` and `group.member_removed` only when the hub sets
  `GIM_HUB_PUSH_MEMBER_EVENTS=true`.
- `gid`, `seq`: the group and per-group sequence number of the message (for `welcome` and
  membership events: of the Commit that produced them).
- `message_id`: the hub's ID of the stored message at `(gid, seq)`. If the hub does not store that
  message, a stand-in: the first 16 bytes of `SHA-256(gid || 0x00 || seq as u64 big-endian)`,
  lowercase hex.
- `collapse_id`: always equal to `message_id` (section 4).
- `mls_message` (optional): standard base64 of the MLS message (`message`) or of the TLS-encoded
  MLSMessage (wire_format = mls_welcome) carrying the Welcome (`welcome`, the same bytes as the
  event's `welcome` field; only when the Welcome has no separate ratchet tree). Present only if
  the payload JSON stays within 3072 bytes, leaving room for the push server's platform envelope;
  otherwise omitted and the client fetches `GET /v2/groups/{gid}/messages?from_seq={seq}` (or
  `GET /v2/welcomes/pending`). Never present for membership events. A push server whose platform
  limit is still exceeded drops `mls_message` and keeps the rest.

The payload never names the sender: it is inside the MLS ciphertext. The hub never sees
plaintext; `mls_message` is the same ciphertext the event stream carries. The metadata fields
(`gid`, `seq`, `message_id`) are visible to the push server and to the platform it uses; minimal
mode hides them.

### Minimal mode

With `GIM_HUB_PUSH_MINIMAL=true` (default `false`) every payload is exactly

```json
{"v": 1, "type": "wake", "collapse_id": "<message_id>"}
```

with no `gid`, `seq`, `message_id` or `mls_message`; the client syncs `GET /v2/events`. The
webhook body is unchanged otherwise: `priority` follows the same rule as without minimal mode
(section 2.3) and `collapse_id` is the same.

## 4. Dispatch

- The dispatcher tails the `events` table every 500 ms, starting at the head when the hub starts
  (events from before the start are not pushed). For each `message`/`welcome` event (and
  membership events if enabled) addressed to a device that is active and has a registration, it
  queues a push. The sender's own device never gets a `message` event, so it gets no push.
- MLS Proposals are not pushed: a `message` event of kind `proposal` changes nothing until a Commit
  covers it, and that Commit (and its membership events) is pushed as usual.
- Queue: at most one pending push per device. At most `GIM_HUB_PUSH_QUEUE_CAPACITY` devices are
  queued; further pushes are dropped (counted and logged). Four workers send concurrently.
- Priority: a push is an alert (`priority` `high`) for `message` and `welcome`, silent (`normal`)
  for membership events. There are exactly these two levels.
- Coalescing: a new push for a device with a pending push replaces it. The pending push becomes
  the **newest** notification (type, `gid`, `seq`, `message_id`/`collapse_id`, `mls_message`,
  `delivery_id`) with priority = max(pending, new), so a pending alert is never downgraded: an
  alert followed by a membership push of the same Commit is sent once, as the membership payload
  with priority `high`. The payload rules of section 3 apply to the merged push as to any other:
  `mls_message` is inlined only if the newest notification has one that fits (never for
  membership events; the client then syncs by `seq` / its events), and minimal mode sends the
  wake object. `ttl` is the constant `86400` for every push, so the merged push keeps it.
- The events of one read of the `events` table (up to 500) are queued at once, so the pushes of
  one write (e.g. the `message` and membership events of a Commit, or a federation `Deliver`
  batch) coalesce per device before any of them is sent.
- Retries: a retry (section 2.4) never replaces a newer pending push for the device; it is
  dropped. If the retry is an alert and the pending push is silent, the pending push is raised to
  alert (its payload kept).
- Registrations with provider `log` go to the log provider (section 5); every other registration
  goes to the webhook, or is skipped when `GIM_HUB_PUSH_WEBHOOK_URL` is unset.
- Collapse and dedup: `collapse_id` is always the message ID, so a device (or the push server)
  collapses duplicate pushes for the same message, e.g. from several hubs of a multi-homed user
  (arch §9.5). Push servers map it to the platform's collapse key.
- The API request that produced the event is never affected by push failures.
- Multi-homing: `Dispatcher::set_gate` installs a filter deciding whether this hub pushes to a
  device. With multi-homing only the user's primary hub pushes, a fallback hub only while every
  hub before it is down ([`multihoming.md`](multihoming.md) §8). Without a gate every hub pushes
  and duplicates collapse on `collapse_id`.
- Counters (`enqueued`, `coalesced`, `upgraded`, `dropped`, `sent`, `skipped`, `invalid_token`,
  `retried`, `failed`) are available from `Dispatcher::metrics`. `upgraded` counts silent pushes
  raised to alert by coalescing with an alert (new or retried).

## 5. Log provider and test-only push log endpoint

Registrations with provider `log` never reach the webhook. The hub writes a structured log line
(target `gim_hub_push::log`) and records the payload (plain JSON, `mls_message` inlined within
4096 bytes) in an in-memory ring of the last 256 pushes.

`GET /v2/debug/push-log?device_id=<device_id>` returns
`{"notifications": [{user_id, device_id, token, payload, sent_at}]}`, oldest first, from that ring
(all devices if `device_id` is omitted). It is unauthenticated, not part of the API contract
(`openapi.json`), and answers 404 `not_found` unless `GIM_HUB_PUSH_LOG_ENDPOINT=true`. Enable it
only in test deployments (CI flows register devices with provider `log`).
