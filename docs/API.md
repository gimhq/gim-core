# gim-core native API

The contract between gim-core (Rust) and the Android / iOS apps. It is defined
by `bindings/gim-ffi/src/` (UniFFI proc-macros) and exposed as:

| | Kotlin | Swift |
|---|---|---|
| Library | `libgim_core.so` | `libgim_core.a` / `GIMCore.xcframework` |
| Namespace | package `im.g.gimcore` | module `GIMCore` (C module `GIMCoreFFI`) |
| Generated source | `bindings/gim-ffi/generated/kotlin/im/g/gimcore/gim_core.kt` | `bindings/gim-ffi/generated/swift/GIMCore.swift`, `GIMCoreFFI.h`, `GIMCoreFFI.modulemap` |

The generated files are committed. After changing anything in `bindings/gim-ffi/src/`, run
`scripts/generate-bindings.sh --docker` (or without `--docker` with a local Rust toolchain) and
commit the result; re-running it on an unchanged tree must produce no diff.

Native code never touches SQL, MLS state, media keys or the server API directly: everything goes
through `GimClient`, and everything shown on screen comes from the listeners.

## Naming

Rust `snake_case` becomes `camelCase` in both languages (`send_text` → `sendText`,
`chat_id` → `chatId`). Every `async fn` is a Kotlin `suspend fun` and a Swift `async` function;
every `Result<_, GimError>` throws (`GimException` in Kotlin, `GimError` in Swift).

All ids (user, device, chat, message) are opaque strings. All timestamps are Unix epoch
milliseconds (`u64`). Counts and indices are `u32`.

## Lifecycle

1. **Create the client** once per process:
   `createClient(ClientConfig(serverUrl), hooks)`. `serverUrl` must be an `http://` or `https://`
   URL with a host, otherwise `InvalidInput`. `hooks` implements `PlatformHooks` (below). If
   `localStateReset()` is `true`, an existing local database could not be opened (its key was
   lost, or it is incompatible) and was discarded with the session and history: show onboarding
   and tell the user that local history is gone. A keystore that cannot be read fails
   `createClient` with the hook's error instead; retry once it is available (e.g. after the first
   unlock).
2. **Session**: `session()` returns the persisted `Session`, or `null`/`nil` on first launch. In
   that case show onboarding (see *Identity and devices*): create a new identity, link this device
   to an existing one, or restore from the recovery code. Most other calls fail with
   `NotRegistered` until a session exists. `Session.handle` is empty until `claimHandle`.
3. **Sync**: call `startSync()` when the app comes to the foreground and `stopSync()` when it goes
   to the background. Sync reconnects on its own: after a failure it reports `Offline` and retries
   with exponential backoff (up to 60 s). Report reachability changes with
   `setNetworkReachable(reachable)`: `true` after `false` wakes the loop for an immediate reconnect
   and retries pending sends; `false` neither pauses sync nor forces `Offline`.
4. **Listeners**: subscribe with `chatList(listener)`, `timeline(chatId).addListener(listener)`,
   `connectionState(listener)` and `typing(chatId, listener)`. Each returns a `TaskHandle`.
5. **Sign out**: `signOut()` stops sync and the listeners and deletes the session, the local
   database and the keystore secrets (session, root key, device key, database key). Create a new
   client afterwards. See *Teardown* for the callback guarantees.

## Identity and devices

A user is identified by its root key; each device has its own signing key certified in the
user's signed DeviceList. Handles are optional directory entries pointing at a user id.

- **New identity**: `createIdentity(displayName)` returns the recovery code. It is stored
  nowhere: show it once and ask the user to write it down. Then optionally `claimHandle(handle)`.
- **Link a new device** (the user has another signed-in device):
  1. New device: `link = startLink(hubs)`, show `link.qrString()` as a QR code, call
     `sas = waitLink(link)` (waits up to 10 minutes).
  2. Old device: scan the QR code, `approval = approveLink(qrString)`, show `approval.sas()`.
  3. The user compares the two six-digit codes (`"123 456"`) and confirms on **both** devices:
     old device `confirmApproval(approval, accepted)`, new device `confirmLink(accepted)`.
     On a mismatch, `confirmApproval(approval, false)` revokes the new device and
     `confirmLink(false)` wipes it like `signOut()` (create a new client afterwards).

  Call order, strictly: new `startLink` → old `approveLink` → new `waitLink` → (SAS compared) →
  old `confirmApproval` and new `confirmLink`. The link bundle carries the root key, the new
  device's certificate and the DeviceList but no self-group Welcome, so the new device is in no
  chat until the old device calls `confirmApproval(approval, true)`, which adds it to the self
  group and every joined chat; the new device then joins them on its next sync. The new device
  must have finished `waitLink` before `confirmApproval(…, true)` (it needs its KeyPackages).
  Rejecting must happen on both devices. `waitLink` fails after 10 minutes without a bundle, or
  on a bundle that does not verify; a `LinkSession` accepts one bundle, so start a new one. If
  the old device approved but the link was abandoned, revoke the new device with
  `revokeDevice(approval.deviceId())`. See `docs/identity.md`, "Device link flow".
- **Retrying onboarding**: a failed `createIdentity`, `restoreFromRecovery` or `waitLink` never
  blocks a retry; no `signOut()` or new client is needed. Each of them first records in the
  keystore that an enrollment is in progress (`gim.enrollment.v1`), and only removes that record
  once every step succeeded (`createIdentity`: DeviceList upload, sign-in, recovery backup,
  KeyPackages, self group; `restoreFromRecovery`: the same without the backup; `waitLink`: the
  same without backup and self group). On failure, the call deletes what the attempt stored (root
  and device key, session, local database contents) before returning the error; if the process
  dies first, the next `createClient` (its session restore) or onboarding call does it. A
  completed identity is never discarded this way: onboarding calls fail with `InvalidInput`
  (already logged in) once one exists, until `signOut()`.
  - `createIdentity`: call it again; it creates a new user (new user id and recovery code, show
    only the code of the call that succeeded). What the failed attempt uploaded belongs to a user
    nobody holds the root key of.
  - `restoreFromRecovery`: call it again with the same arguments. It uses a new device key; if
    the failed attempt's device made it into the hub's DeviceList, the new list revokes it.
  - `waitLink`: if no bundle arrived (network error, timeout), call it again with the same
    `LinkSession`. If it failed after the bundle arrived, the session is used up: start a new link
    (new QR code) and approve it on the old device again; the old device should reject the first
    approval with `confirmApproval(firstApproval, false)`, which revokes the device of the failed
    attempt (it stays listed otherwise; `revokeDevice` works too). The new device shows the QR
    code again; the old device shows a second SAS for the new offer.
- **Restore** after losing every device: `restoreFromRecovery(userId, recoveryCode,
  revokeOthers)` on a fresh client. It reads the user's current DeviceList from the hub (a public
  read, no session needed), verifies it against the recovered root key and publishes the next one
  (seq + 1) with this device added: `revokeOthers = true` revokes every previously listed device
  (they can no longer sign in and peers remove them), `false` keeps them all active. A list that
  lands concurrently is read and rebuilt once. Chats are not rejoined automatically; other members
  (or another own device) must add this device again.
- **Hosting record** (federation): gim-core keeps the user's hosting record, signed with the root
  key, on the hub without any app call. `createIdentity` and `restoreFromRecovery` publish one,
  `waitLink` only if the hub has no valid one; while sync runs it is renewed (7-day lifetime,
  renewed with less than 3 days left: at `startSync`, daily, and when the hub announces the expiry).
  Publication failures never fail these calls and are retried by sync. A federated request the
  hub rejects with 403 `hosting_record_required` publishes the record and is retried once; only if
  that fails does the call fail with `Server(403, …)`.
- **Multiple hubs** (multi-homing): gim-core keeps a registry of the hubs the hosting
  record lists, with each hub's URL and this device's session there; it is persisted and restored
  with the session. The hub the client was created with (the home hub) is checked with
  `GET /v2/hub` and recorded. A URL set on this device for another listed hub is used only after
  `GET /v2/hub` there proves the listed hub id, then the device signs in there too; URLs set on a
  device are shared with the user's other devices through the hidden self group. The registry
  follows the record on every publication and on the hub's `hosting_record.updated` event. The
  app manages it with `hubs`, `addHub`, `removeHub`, `setPrimaryHub` and `hubList` (see *Hub
  management*). With a single hub nothing changes: `hubs()` returns the home hub.
  - Hub URLs received from the user's other devices are recorded but not contacted: such a hub
    stays unverified (no `GET /v2/hub`, no sign-in, no KeyPackages, no sending or receiving)
    until URL-bound hub verification lands, because a relay at a wrong URL could pass the
    current checks and obtain this device's session. Only a URL set on this device (and the URL
    the client was created with) is used.
  - Receiving: while sync runs, the device follows every listed hub with a verified URL, each with
    its own event stream (long-poll fallback) and persisted cursor; hubs joining or leaving the
    registry are started or stopped. Every hub delivers the same messages; each is applied once
    (by chat id and seq, which the owning hub assigns together with the message id), so the
    timeline is the same whichever hub delivered first, and messages keep arriving through the
    other hubs while one is down. A missing message is read from the hub that showed the gap,
    else from another listed hub. A chat invitation is joined once and acknowledged on every hub
    that holds it. An expired cursor on one hub is recovered from that hub alone. `connectionState`
    reports the best state over the followed hubs: `Connected` while at least one of them is
    reachable; failures are retried in the background per hub.
  - Sending: messages, member changes and leave Proposals go to the primary hub (lowest priority).
    If that hub itself cannot be reached (network error, timeout, 5xx), gim-core sends the same
    request (same `client_id` and bytes) to the next listed hub; the chat's owning hub keeps it
    once. A 503 `peer_unavailable` (the owning hub is down) is retried on the same hub after its
    `Retry-After`, never sent elsewhere; a definite rejection (4xx) is never resent. Member
    additions claim KeyPackages and commit through the same hub; if that hub becomes unreachable
    or answers `kp_not_claimed`, gim-core claims again through the hub in use and rebuilds the
    change.
  - KeyPackages: each listed hub the device is signed in to gets its own one-time KeyPackages and
    last-resort KeyPackage; a KeyPackage is uploaded to one hub only, ever (also after that hub
    is removed). A hub's `keypackages.low` (or an expired cursor there) tops up that hub only.
  - Reads of DeviceLists, of the user directory and of the hosting record go to the home hub and,
    while it cannot be reached (network error, 5xx), to the other listed hubs in priority order; a
    definite answer (also a rejection) is never retried elsewhere.
  - Uploads, chat creation, handles, linking and all other requests still go through the home hub.
  - After a restore from the recovery code the hub list is read again from the hosting record and
    the hub map is sent to the new self group, so devices linked from the restored one learn the
    hub URLs; a newly linked device gets the map from the device approving it.
- **Federation**: users are addressed by user id everywhere; a remote user may have no handle and is
  shown by display name, else a short user id. A chat is created on the own hub, which owns it (the
  `<hub_id>/` prefix of its id); in chats owned by another hub, messages and member changes of
  others arrive once the owner has sequenced and delivered them (seconds normally, longer during
  an outage), and the history starts where the own hub joined.
  - Invitees whose hub is unreachable when a chat is created or members are added (`unavailable`
    KeyPackage claims) do not fail the call: the reachable ones are added at once, the others stay
    pending and are claimed again by sync with backoff (30 s doubling to 15 min) and added when
    their hub answers. A chat or direct chat with only unreachable invitees is created with the
    invites pending. After 24 h a pending invite is dropped and reported as a
    `MembershipChanged(Removed)` change for that user (not stored). Pending invites live in memory:
    they are lost when the app restarts.
  - 502 `peer_refused` and 503 `peer_unavailable` on sending to a chat owned by another hub are
    retried with the same message (same `client_id`): queued messages wait for the hub's
    `Retry-After` (at most 5 min) instead of the usual backoff. A member change is resubmitted
    as the very same Commit, within the call when `Retry-After` is at most 10 s; otherwise the call
    fails (`RetryLater(503, …)` or `Server(502|503, …)`), the Commit stays pending and is
    resubmitted unchanged before the next sync, send or member change of that chat. Until it is
    settled, incoming messages of that chat are held back; other chats sync normally.
- **Devices**: `devices()` lists the user's devices, `userDevices(userId)` another user's, and
  `revokeDevice(deviceId)` revokes another own device (it is removed from every chat and can no
  longer sign in).

## Platform hooks

`PlatformHooks` is implemented by the app and called on gim-core's callback thread (see
*Threading of platform callbacks*); keep the implementations fast and thread-safe.

| Method | Contract |
|---|---|
| `secureStoreGet(key)` | Read a secret from Keychain / Android Keystore; `null`/`nil` if absent. Throw `GimError` if the keystore cannot be read (e.g. locked): gim-core then fails the call rather than treating the secret as missing, so it never replaces the database key. |
| `secureStoreSet(key, value)` | Write or replace a secret; throw `GimError` on failure. |
| `secureStoreDelete(key)` | Delete a secret; a missing key is not an error. |
| `dataDir()` | Absolute path of an app-private directory. The SQLite database and media cache live under it. Must be stable across launches. |
| `isNetworkReachable()` | Current reachability; changes are pushed with `GimClient.setNetworkReachable`. |

## GimClient

| Method | Returns | Notes |
|---|---|---|
| `session()` | `Session?` | |
| `userId()` | `String?` | Synchronous. `null`/`nil` without a session. |
| `localStateReset()` | `Boolean` | Synchronous. Whether opening this client discarded an existing local database. |
| `createIdentity(displayName)` | recovery code | Creates the user with this device as its first one and signs in. |
| `restoreFromRecovery(userId, recoveryCode, revokeOthers)` | | See *Identity and devices*. `InvalidInput` for a malformed code, `Crypto` for a wrong one, `NotFound` if the hub has no DeviceList of the user, `RetryLater` while the hub throttles the read. |
| `startLink(hubs)` | `LinkSession` | Synchronous. New device; `LinkSession.qrString()`. |
| `waitLink(link)` | SAS | New device; signs in once the bundle arrives. |
| `confirmLink(accepted)` | | New device; `false` wipes it like `signOut()`. |
| `approveLink(qrString)` | `PendingApproval` | Old device; `PendingApproval.sas()`, `.deviceId()`. |
| `confirmApproval(approval, accepted)` | | Old device; `true` adds the new device to all chats, `false` revokes it. |
| `devices()` | `[DeviceInfo]` | Own devices, including revoked ones. |
| `userDevices(userId)` | `[DeviceInfo]` | Another user's devices; empty for an unknown user. |
| `revokeDevice(deviceId)` | | `InvalidInput` for the current device. |
| `setDisplayName(name)` | | Synced to the user's other devices and announced to every joined chat. `InvalidInput` if empty. |
| `claimHandle(handle)` | | `Server(409)` if taken. |
| `releaseHandle()` | | `InvalidInput` if no handle is claimed. |
| `signOut()` | | |
| `startSync()` / `stopSync()` | | |
| `setNetworkReachable(reachable)` | | Synchronous, never throws. Becoming reachable reconnects and retries the outbox at once; becoming unreachable changes nothing by itself. |
| `findUser(handle)` | `UserProfile?` | `null`/`nil` if no such user. |
| `createDirectChat(userId)` | chat id | Returns the existing direct chat if there is one. `NotFound` (and no chat is created) if the user does not exist or has no device; a user whose hub is unavailable is invited later (see *Federation*). |
| `createGroupChat(name, memberUserIds)` | chat id | The name is shared with the members (and with members added later) in an encrypted group info message. Invitees that do not exist or have no device are skipped, each reported as a `MembershipChanged(Removed)` change for that user (not stored); `NotFound` (and no chat is created) if that is every invitee. |
| `chatMembers(chatId)` | `[UserProfile]` | Current members, one entry per user (not per device), including the signed-in user. Names come from the local user directory, filled by `findUser`, registration, and directory lookups the client makes for members of created or joined chats, added members and unknown senders; until a lookup succeeds a user shows as its user id. Resolved names arrive as `ChatListDiff`s and timeline `Set`s. No members listener in M1: re-query when a `ChatListDiff` touches that chat or a `TimelineItem.MembershipChange` arrives. |
| `addMembers(chatId, userIds)`, `removeMember(chatId, userId)` | | `addMembers` skips users that do not exist or have no device like `createGroupChat`, and fails with `NotFound` (nothing committed) if that is every user. |
| `leaveChat(chatId)` | | Submits a leave Proposal and returns once the hub accepted it, with the chat `ChatState.Leaving`; another member commits it, then the chat is `Left` and shows the own `Left` change. gim-core keeps and re-sends the leave across restarts (native code does not persist it); calling `leaveChat` again while leaving re-sends it. A leave the hub refuses for good (4xx) returns the chat to `Active` and throws the rejection. `ChatNotActive(Left)` once left. See *Chat state*. |
| `chatState(chatId)` | `ChatState` | From local state, no network call: correct right after a restart, before any other call. `NotFound` for an unknown chat. |
| `setGroupInfo(chatId, name?, avatarFilePath?)` | | `null`/`nil` leaves a field unchanged; at least one must be set. The avatar is encrypted and uploaded before the call returns (MIME type from the file extension), then the change is applied locally and sent to the members. `InvalidInput` for direct chats. |
| `sendText(chatId, body, replyTo?)` | message id | The message appears in the timeline immediately with `SendState.Pending`. |
| `sendMedia(chatId, filePath, mime, caption?, replyTo?)` | message id | The file is copied before the call returns. |
| `editMessage(chatId, messageId, newBody)`, `deleteMessage(chatId, messageId)` | | |
| `react(chatId, messageId, emoji)`, `unreact(chatId, messageId, emoji)` | | |
| `retrySend(chatId, messageId)`, `cancelSend(chatId, messageId)` | | For messages in `SendState.Failed`. |
| `markRead(chatId, upToMessageId)` | | Also sends a read receipt. M1 marks the whole chat read; `upToMessageId` is only validated. |
| `setTyping(chatId, active)` | | Call with `true` on each keystroke (sent at most every 3 s) and `false` when typing stops. |
| `stopTyping(chatId)` | | Same as `setTyping(chatId, false)`: call when the input is cleared, the message sent or the chat is left. Does nothing unless typing was reported. |
| `fetchMedia(chatId, messageId, destPath)` | file path | Downloads and decrypts the attachment. A blob uploaded on another hub is fetched by the own hub from that hub on first access. `NotFound` if the blob is unknown (or federation is disabled on the own hub); `RetryLater(503, …)` while the uploader's hub stays unreachable and `Server(502, …)` while it keeps refusing, after up to 3 attempts within the call. |
| `fetchThumbnail(chatId, messageId, destPath)` | file path? | `null`/`nil` if the media has no thumbnail. |
| `chatList(listener)` | `TaskHandle` | Rows are `ChatSummary` (`chatId`, `kind`, `name`, `avatar?`, `lastMessage?`, `unreadCount`, `updatedAtMs`, `memberCount`, `state`). |
| `timeline(chatId)` | `Timeline` | |
| `setLocalTimeZone(zone?)` | | Synchronous, never throws. Date separators follow `zone`; `null`/`nil` is UTC (the default). See *Local time zone*. |
| `connectionState(listener)` | `TaskHandle` | `Offline` until `startSync` and after a failure while waiting to retry; `Connecting` → `Syncing` (catching up) → `Connected`. |
| `typing(chatId, listener)` | `TaskHandle` | Reports user ids other than the signed-in user. |
| `hubs()` | `[HubInfo]` | See *Hub management*. |
| `addHub(url)` | `HubInfo` | See *Hub management*. `InvalidInput` for a URL that is not `http(s)://host…` or does not serve a gim hub, `Network` if it cannot be reached. |
| `removeHub(hubId, confirmOwnedGroups)` | | See *Hub management*. `HomeHub`, `LastHub`, `HubOwnsGroups`, `HubNotDrained`; `InvalidInput` for a hub that is not listed. |
| `setPrimaryHub(hubId)` | | See *Hub management*. `InvalidInput` for a hub that is not listed or, when its priority has to change, not reachable from this device. |
| `hubList(listener)` | `TaskHandle` | `HubListListener.onUpdate(hubs)`: the current `hubs()` first, then again whenever the registry may have changed. |

A message id is the client id chosen when the message is queued; it stays the same from local echo
to delivery, so native code can key views by it.

`DeviceInfo` is `deviceId`, `createdAtMs` (when the device was certified; 0 for revoked devices),
`isCurrent` (this client's device) and `revoked`.

### Hub management

For the hub settings screen. A user's hosting record lists 1 to 16 hubs; every own device uses all
of them (see *Multiple hubs*). `HubInfo` is `hubId`, `url?` (client API base URL, once known),
`state` (`HubState`), `priority` (lower is preferred), `isPrimary` (the first listed hub:
messages are submitted there first), `isHome` (the hub of `ClientConfig.serverUrl`) and `signedIn`
(this device holds a session there). `hubs()` lists them primary first (priority, then hub id),
including removed ones.

| `HubState` | Meaning |
|---|---|
| `Unverified` | Listed, but this device has no URL for it that proved the hub's identity (none yet, or only one shared by another own device, which is never contacted): call `addHub(url)` with its URL on this device. |
| `Verified` | Listed and in use. |
| `Removed` | No longer listed by the hosting record. |

- `addHub(url)`: the user enters the URL on this device, so gim-core may contact it. It checks the
  URL with `GET /v2/hub`, uploads the DeviceList there, signs in, has the hub co-sign its entry
  (listed last, i.e. least preferred), publishes the new hosting record (to the home hub, the new
  hub and the other listed hubs), uploads this device's KeyPackages and the recovery backup there,
  follows its events while sync runs and shares its URL with the user's other devices. Each
  other device stays `Unverified` for that hub until the URL is entered there too. Calling it for a
  listed hub only records the URL for it on this device.
- `removeHub(hubId, confirmOwnedGroups)`: the home hub is never removed (`HomeHub`): to move away
  from it, make another hub primary and keep it as a secondary hub. The only listed hub is never
  removed (`LastHub`). If the hub owns chats of this user (the `<hubId>/` prefix of the chat id),
  the call fails with `HubOwnsGroups(hubId, groupCount)` unless `confirmOwnedGroups`: chats are not
  moved to another hub; the removed hub keeps running them and this user reaches them through the
  remaining hubs. Before the record changes, gim-core reads the hub's pending events and chat
  invitations (skipped if it cannot be reached; the other hubs hold the same messages) and flushes
  the outbox; `HubNotDrained` while messages or member changes are still unsent (try again later).
  Then the record without the hub is published (also to the removed hub), its event stream stops
  and its session is dropped; its KeyPackages are never reused.
- `setPrimaryHub(hubId)`: gives the hub priority 0, the others follow in their current order;
  each hub whose priority changes co-signs a new entry, so this device must be signed in there.
  Messages and member changes are then submitted to the new primary first. Nothing happens for
  the current primary.
- Every change re-sends the hub map to the user's other devices; their registries follow the
  record when their hubs announce it (`hosting_record.updated`). `hubList` reports changes from any
  of these sources.

### Chat state

`ChatSummary.state`, `chatState(chatId)` and `Timeline.chatState()` give where this device stands
in a chat, read from local state (so they are right from the first callback after a restart):

| `ChatState` | Meaning |
|---|---|
| `Active` | A member; messages can be sent. |
| `Leaving` | `leaveChat` was accepted by the hub; still an MLS member until another member commits the removal, but nothing can be sent. |
| `Left` | Removed: after leaving, by another member, or hub-side. History is kept; nothing can be sent. |

Transitions reach the chat list as a `Set` of the row: `Active → Leaving` (`leaveChat`),
`Leaving → Left` (removal applied), `Leaving → Active` (the hub refused the leave for good),
`Active → Left` (removed by another member).

Calls that send to or change a `Leaving` or `Left` chat (`sendText`, `sendMedia`, `editMessage`,
`deleteMessage`, `react`, `unreact`, `retrySend`, `setGroupInfo`, `addMembers`, `removeMember`;
`leaveChat` once `Left`) throw `ChatNotActive(chatId, state)` instead of `InvalidInput`. Do not
parse `InvalidInput` reasons to detect leaving.

`MediaRef` identifies an attachment (`chatId`, `messageId`, `mime`, `size`, `hasThumbnail`).
Encryption keys and blob ids never leave Rust; pass the ids to `fetchMedia` / `fetchThumbnail`.

### Timeline

`timeline(chatId)` is cheap. On the returned `Timeline`:

- `addListener(listener)` → `TaskHandle`; the first callback is a `Reset` with the items loaded so
  far, oldest first.
- `paginateBackwards(count)` loads up to `count` older items (they arrive through the listener as
  diffs) and returns whether more history exists.
- `chatId()`.
- `chatState()` → `ChatState?`: the chat's current state (see *Chat state*); `null`/`nil` while the
  chat is not known locally.

`TimelineItem` is a `Message` (`MessageItem`), a `DateSeparator` (`dayStartMs`: start of a local
calendar day, see *Local time zone*) or a `MembershipChange` (`Added`, `Removed`, `Left`; group chats
only, in seq order among the messages, at the time the change was applied on this device).
A `MembershipChange` carries `userName`, `change`, `atMs`, `userId` (the user who joined or left)
and `actorUserId?` (who caused it: the adder or remover; the user themselves for `Left`, whoever
committed the removal; `null`/`nil` if unknown). An invitee that could not be added (unknown user,
or a pending invite that expired) shows as `Removed` with the inviter as actor. The signed-in
user's own `Left` has `userId` equal to the own user id.
`paginateBackwards` pages through locally stored history first, then through the server history:
messages this device cannot decrypt (sent before it joined, or already read once and removed
locally) are skipped, and it returns `false` once nothing older is readable. `MessageItem.sendState` is set only for own
messages: `Pending → Sent → Delivered → Read`, or `Failed(reason)`. `Delivered` and `Read` are
group ticks: they need a receipt from **every** device of **every** other member, so one
recipient device that has not reported keeps the message at `Sent` (or `Delivered`).

### Local time zone

Date separators split calendar days in the time zone set with
`setLocalTimeZone(zone)`; `null` / `nil` (the default) is UTC. `LocalTimeZone` is implemented by
the app and answers `utcOffsetSecs(atMs)`: the offset from UTC in seconds in effect at that
instant, DST included, so each item is bucketed with the offset valid at its own time:

- Kotlin: `TimeZone.getDefault().getOffset(atMs) / 1000`
- Swift: `Int32(TimeZone.current.secondsFromGMT(for: Date(timeIntervalSince1970: Double(atMs) / 1000)))`

Set it once after `createClient`, before opening timelines. Call it again when the system time
zone changes (Android `ACTION_TIMEZONE_CHANGED`, iOS `NSSystemTimeZoneDidChange`): every open
timeline moves its date separators to the new days through its listener, as ordinary diffs
(separators removed and inserted; message items stay). Offsets are asked once per UTC hour of the
item timestamps (at the start of that hour) and cached until the zone is replaced, so it is
called on gim-core's callback thread and must not call back into `GimClient`. The chat list does
not bucket by day; format its timestamps natively.

### Push

| Method | Returns | Notes |
|---|---|---|
| `registerPush(registration)` | | Validates the registration, stores it on the device and sends it to every verified hub this device is signed in to (`PUT /v2/push/registration`). `InvalidInput` for a malformed field, `Server(400, …)` if a hub rejects it; an unreachable hub gets it on the next connect. |
| `unregisterPush()` | | Removes the registration from every hub (`DELETE /v2/push/registration`), then the local copy. Throws the first hub failure; the local copy is removed anyway. |
| `processPush(payload)` | `NotificationContent` | For the notification extension / service. `InvalidInput` only if `payload` is not a JSON object. |

`PushRegistration` is `provider` (`apns`, `fcm`, `unifiedpush`, …: 1-64 characters of
`a-z 0-9 . _ -`), `token` (1-4096 bytes, no control characters), `appId?` (1-255 characters of
`A-Z a-z 0-9 . - _ :`), `sandbox?`, `p256dh?` and `auth?` (Web Push keys: 1-256 characters of
base64url). Call `registerPush` whenever the platform hands out a new token; gim-core keeps the
registration across restarts and sends it again by itself when a hub is added or becomes
verified, after a renewed sign-in, after restore or link, and on each connect to a hub that has
not received it yet. `signOut()` removes it from the hubs (best effort, a few seconds at most)
before wiping the device.

`processPush(payload)` takes the data payload exactly as delivered (the JSON object the hub sent
through the push server) and returns within about 15 s; it does not open event streams, top up
KeyPackages or download media. What it does depends on the payload type:

- a message: decrypts the inline MLS message, or fetches it from the hub by its seq, and applies
  it like sync does. A message the stream (or another hub's push) already applied is not applied
  again; the stored message is described instead.
- a chat invitation: joins the chat through the pending invitations, as sync does.
- a member change: catches the chat up; silent.
- a wake-up (minimal mode) or an unknown type: reads the pending events once, without moving the
  sync position (the app's stream reads them again), and shows the newest unread message.

`NotificationContent` is `chatId?`, `chatTitle?` (the group name, or the other user's name in a
direct chat), `senderUserId?`, `senderDisplayName?`, `body` (text, caption, `Photo`,
`File: <name>`, or `reacted <emoji>`), `messageId?`, `collapseId?`, `kind`
(`NotificationKind`), `shouldDisplay` and `timestamp` (Unix ms).

| `NotificationKind` | Meaning |
|---|---|
| `Message` | A new text or media message (also the silent edit or delete of one). |
| `Reaction` | A new reaction; `messageId` is the reacted-to message. |
| `Invite` | This device joined a chat; `senderUserId` added it. |
| `Membership` | Members were added or removed; never displayed. |
| `Generic` | The content is unknown, or there is nothing to show. |

Show the notification only if `shouldDisplay`. It is `false` for own messages, edits, deletes,
receipts, member changes and messages already read. If the push cannot be decrypted or processed
in time, the call still succeeds with `Generic` content: body `New message`, `shouldDisplay =
true`, and `chatId` / `chatTitle` when the chat is known locally. An iOS Notification Service
Extension can therefore always display the result. Use `collapseId` as the platform collapse key
(`apns-collapse-id`, FCM `tag`): every hub of the user may push the same message.

## Listeners and threading

`ChatListListener`, `TimelineListener`, `ConnectionStateListener`, `TypingListener` and
`HubListListener` are implemented by the app.

- **Callbacks arrive on gim-core's callback thread** (see *Threading of platform callbacks*). Hop to the main thread (Kotlin:
  `withContext(Dispatchers.Main)` / `Handler(Looper.getMainLooper())`; Swift:
  `Task { @MainActor in ... }` / `DispatchQueue.main.async`) before touching UI state, and keep
  the order of callbacks.
- Do not block in a callback; copy the data and return.
- **Keep the `TaskHandle`.** Dropping it (Kotlin: `close()` / garbage collection; Swift: releasing
  the last reference) or calling `cancel()` ends the subscription. `isFinished()` reports whether it
  has ended.
- `ConnectionStateListener.onChange`, `TypingListener.onUpdate` and `HubListListener.onUpdate`
  first deliver the current value.

### Threading of platform callbacks

Applies to every interface the app implements: `PlatformHooks`, `LocalTimeZone`,
`ChatListListener`, `TimelineListener`, `ConnectionStateListener` and `TypingListener`.

- **One thread.** gim-core calls all of them, for every client, on a single long-lived native
  thread named `gim-callbacks`, one call at a time, in order. The Rust code that needs the
  result waits for it. A callback is therefore never called on a tokio worker or blocking
  thread, never inside a UniFFI future poll or continuation, and never on a thread that is about
  to exit. Releasing the objects passed in (UniFFI's `free` when gim-core drops its last
  reference) also happens on that thread.
- **Keep callbacks short and non-blocking.** All callbacks share the thread: a slow keystore read
  delays listener updates, and the Rust side waiting for the result (possibly a sync call such as
  `setLocalTimeZone`) waits too. Copy the data and return; hop to the main thread or your own
  executor for anything else.
- **Never call into gim-core from inside a callback.** That means no `GimClient` call, no
  `close()` / `destroy()` of a gim-core object, no `runBlocking` / semaphore around a suspend
  call, and no waiting on a thread that is itself waiting for gim-core. Such a call runs nested on
  the callback thread. A nested callback deadlocks or, on Android, makes JNA detach the thread
  while the outer callback is still running (ART aborts with `attempting to detach while still
  running code`). Post the work to another thread instead.
- **Call suspend functions from a real dispatcher (Android).** UniFFI resumes a suspended call
  from a continuation callback on the Rust thread that completed the work. With a
  `CoroutineDispatcher` (`Dispatchers.Main`, `Dispatchers.IO`, `Dispatchers.Default`,
  `viewModelScope`) the coroutine continues on that dispatcher. A context without one resumes
  inline on the Rust thread: `Dispatchers.Unconfined`, `UnconfinedTestDispatcher`, and Compose
  test frame-clock interceptors (`ApplyingContinuationInterceptor`, e.g. a `LaunchedEffect`
  under `createComposeRule`). UniFFI then reports completion with a callback nested in that
  frame, with the same ART abort. Wrap such call sites in `withContext(Dispatchers.IO)` (or
  `Default`). iOS has no JVM attach step; Swift `async` calls are unaffected.

### Teardown

- **`signOut()` returns only after every callback in flight returned** (listeners,
  `LocalTimeZone`, and `PlatformHooks` calls made by background work), waiting at most 5 s for a
  callback that does not return. Once it returned, no listener, `LocalTimeZone` or
  `PlatformHooks` method is called for that client any more, and its `TaskHandle`s are finished.
- **Releasing the client** (Kotlin: `close()` / garbage collection; Swift: releasing the last
  reference) does the same without deleting anything. Released on a gim-core thread (a runtime
  thread or the callback thread) it does not wait, so it cannot deadlock on a callback.
- The objects passed in (listeners, hooks, time zone) may still be released later, on the
  callback thread; that only drops gim-core's reference.

### Diff semantics

`ChatListDiff` and `TimelineDiff` mirror eyeball-im `VectorDiff` (the Element X model). Native code
keeps its own list and applies each `onUpdate(diffs)` batch **in order**; indices refer to the list
as it is after the previous diff of the batch.

| Diff | Effect |
|---|---|
| `Append(values)` | Add `values` at the end. |
| `Clear` | Remove all items. |
| `PushFront(value)` / `PushBack(value)` | Insert at the start / end. |
| `PopFront` / `PopBack` | Remove the first / last item. |
| `Insert(index, value)` | Insert before `index` (`index == size` appends). |
| `Set(index, value)` | Replace the item at `index` (edits, reactions, send state). |
| `Remove(index)` | Remove the item at `index`. |
| `Truncate(length)` | Keep only the first `length` items. |
| `Reset(values)` | Replace the whole list with `values`. |

The chat list is ordered most recently updated first; a timeline oldest first.

## Errors

| `GimError` | Meaning | Typical handling |
|---|---|---|
| `Network(reason)` | Server unreachable or connection lost. | Show offline state; retry later. |
| `NotRegistered` | No session, signed out, or this device was revoked. | Go to onboarding. |
| `InvalidInput(reason)` | Argument rejected locally, the call does not fit the state (e.g. `createIdentity` with a session), the payload is too large for the hub, or the hub rejected the request as invalid (400 `validation_failed`, 422). gim-core does not resend a rejected request. | Bug or validation message. |
| `NotFound(reason)` | Unknown chat, message, user or media. | Refresh the screen. |
| `Crypto(reason)` | MLS or media decryption failure. | Report; show placeholder. |
| `Storage(reason)` | Local database or file system failure. | Report; may need disk space. |
| `Server(status, reason)` | Non-success HTTP status from the hub; 502 `peer_refused` or 503 `peer_unavailable` (no `Retry-After`) when a remote hub failed. A 4xx (e.g. 403 `forbidden` / `not_member`) is a definite rejection that gim-core does not resend; a 5xx, 408 or 429 has an unknown outcome and gim-core resends the request unchanged. | Show generic error; peer failures are retried by gim-core. |
| `RetryLater(status, retryAfterSecs, reason)` | The hub throttles a public read (429 `rate_limited`) or a remote hub is unavailable (503 `peer_unavailable`), and gim-core's bounded retries (2 retries, at most 60 s of waiting for reads; see *Federation* for sends and member changes) are used up. | Retry after `retryAfterSecs`. |
| `Cancelled` | Cancelled by `stopSync`, `signOut` or `cancelSend`. | Ignore. |
| `NotImplemented` | In the contract but not implemented in this build. | Development builds only. |
| `Internal(reason)` | Bug, or an unexpected exception thrown by a platform hook. | Report. |
| `ChatNotActive(chatId, state)` | The call sends to or changes a chat this device is leaving (`state = Leaving`) or has left (`Left`); see *Chat state*. | Show the chat read-only. |
| `HubOwnsGroups(hubId, groupCount)` | `removeHub` without `confirmOwnedGroups`: the hub owns `groupCount` chats of this user; see *Hub management*. | Ask the user, then call again with `confirmOwnedGroups = true`. |
| `LastHub(hubId)` | `removeHub` of the only listed hub. | Explain; add another hub first. |
| `HomeHub(hubId)` | `removeHub` of the hub the client was created for. | Explain; offer `setPrimaryHub` for another hub. |
| `HubNotDrained(hubId, reason)` | `removeHub` while messages or member changes are not settled yet. | Retry later. |

Kotlin throws `GimException.<Variant>`; Swift throws `GimError.<Variant>`. `ChatNotActive` was added
after M2b, and `HubOwnsGroups`, `LastHub`, `HomeHub` and `HubNotDrained` in M2c: an exhaustive
Swift `switch` / Kotlin `when` over the error needs the new cases.

## Other functions

- `coreVersion()` — version of the gim-core library.
- `ciphersuiteName()` — the MLS ciphersuite used by every chat.
