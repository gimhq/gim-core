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
5. **Sign out**: `signOut()` stops sync and deletes the session, the local database and the
   keystore secrets (session, root key, device key, database key). Create a new client
   afterwards.

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

`PlatformHooks` is implemented by the app and may be called from any Rust thread; keep the
implementations fast and thread-safe.

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
| `createDirectChat(userId)` | chat id | Returns the existing direct chat if there is one. |
| `createGroupChat(name, memberUserIds)` | chat id | The name is shared with the members (and with members added later) in an encrypted group info message. |
| `chatMembers(chatId)` | `[UserProfile]` | Current members, one entry per user (not per device), including the signed-in user. Names come from the local user directory, filled by `findUser`, registration, and directory lookups the client makes for members of created or joined chats, added members and unknown senders; until a lookup succeeds a user shows as its user id. Resolved names arrive as `ChatListDiff`s and timeline `Set`s. No members listener in M1: re-query when a `ChatListDiff` touches that chat or a `TimelineItem.MembershipChange` arrives. |
| `addMembers(chatId, userIds)`, `removeMember(chatId, userId)`, `leaveChat(chatId)` | | |
| `setGroupInfo(chatId, name?, avatarFilePath?)` | | `null`/`nil` leaves a field unchanged; at least one must be set. The avatar is encrypted and uploaded before the call returns (MIME type from the file extension), then the change is applied locally and sent to the members. `InvalidInput` for direct chats. |
| `sendText(chatId, body, replyTo?)` | message id | The message appears in the timeline immediately with `SendState.Pending`. |
| `sendMedia(chatId, filePath, mime, caption?, replyTo?)` | message id | The file is copied before the call returns. |
| `editMessage(chatId, messageId, newBody)`, `deleteMessage(chatId, messageId)` | | |
| `react(chatId, messageId, emoji)`, `unreact(chatId, messageId, emoji)` | | |
| `retrySend(chatId, messageId)`, `cancelSend(chatId, messageId)` | | For messages in `SendState.Failed`. |
| `markRead(chatId, upToMessageId)` | | Also sends a read receipt. M1 marks the whole chat read; `upToMessageId` is only validated. |
| `setTyping(chatId, active)` | | Call with `true` on each keystroke (sent at most every 3 s) and `false` when typing stops. |
| `stopTyping(chatId)` | | Same as `setTyping(chatId, false)`: call when the input is cleared, the message sent or the chat is left. Does nothing unless typing was reported. |
| `fetchMedia(chatId, messageId, destPath)` | file path | Downloads and decrypts the attachment. |
| `fetchThumbnail(chatId, messageId, destPath)` | file path? | `null`/`nil` if the media has no thumbnail. |
| `chatList(listener)` | `TaskHandle` | |
| `timeline(chatId)` | `Timeline` | |
| `connectionState(listener)` | `TaskHandle` | `Offline` until `startSync` and after a failure while waiting to retry; `Connecting` → `Syncing` (catching up) → `Connected`. |
| `typing(chatId, listener)` | `TaskHandle` | Reports user ids other than the signed-in user. |

A message id is the client id chosen when the message is queued; it stays the same from local echo
to delivery, so native code can key views by it.

`DeviceInfo` is `deviceId`, `createdAtMs` (when the device was certified; 0 for revoked devices),
`isCurrent` (this client's device) and `revoked`.

`MediaRef` identifies an attachment (`chatId`, `messageId`, `mime`, `size`, `hasThumbnail`).
Encryption keys and blob ids never leave Rust; pass the ids to `fetchMedia` / `fetchThumbnail`.

### Timeline

`timeline(chatId)` is cheap. On the returned `Timeline`:

- `addListener(listener)` → `TaskHandle`; the first callback is a `Reset` with the items loaded so
  far, oldest first.
- `paginateBackwards(count)` loads up to `count` older items (they arrive through the listener as
  diffs) and returns whether more history exists.
- `chatId()`.

`TimelineItem` is a `Message` (`MessageItem`), a `DateSeparator` (start of a calendar day; in M1
days are UTC days, not local ones) or a `MembershipChange` (`Added`, `Removed`, `Left`; group chats
only, in seq order among the messages, at the time the change was applied on this device).
`paginateBackwards` pages through locally stored history first, then through the server history:
messages this device cannot decrypt (sent before it joined, or already read once and removed
locally) are skipped, and it returns `false` once nothing older is readable. `MessageItem.sendState` is set only for own
messages: `Pending → Sent → Delivered → Read`, or `Failed(reason)`. `Delivered` and `Read` are
group ticks: they need a receipt from **every** device of **every** other member, so one
recipient device that has not reported keeps the message at `Sent` (or `Delivered`).

## Listeners and threading

`ChatListListener`, `TimelineListener`, `ConnectionStateListener` and `TypingListener` are
implemented by the app.

- **Callbacks arrive on a Rust background thread.** Hop to the main thread (Kotlin:
  `withContext(Dispatchers.Main)` / `Handler(Looper.getMainLooper())`; Swift:
  `Task { @MainActor in ... }` / `DispatchQueue.main.async`) before touching UI state, and keep
  the order of callbacks.
- Do not block in a callback; copy the data and return.
- **Keep the `TaskHandle`.** Dropping it (Kotlin: `close()` / garbage collection; Swift: releasing
  the last reference) or calling `cancel()` ends the subscription. `isFinished()` reports whether it
  has ended.
- `ConnectionStateListener.onChange` and `TypingListener.onUpdate` first deliver the current value.

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
| `InvalidInput(reason)` | Argument rejected locally, the call does not fit the state (e.g. `createIdentity` with a session), or the payload is too large for the hub. | Bug or validation message. |
| `NotFound(reason)` | Unknown chat, message, user or media. | Refresh the screen. |
| `Crypto(reason)` | MLS or media decryption failure. | Report; show placeholder. |
| `Storage(reason)` | Local database or file system failure. | Report; may need disk space. |
| `Server(status, reason)` | Non-success HTTP status from the hub; 502 `peer_refused` or 503 `peer_unavailable` (no `Retry-After`) when a remote hub failed. | Show generic error; peer failures are retried by gim-core. |
| `RetryLater(status, retryAfterSecs, reason)` | The hub throttles a public read (429 `rate_limited`) or a remote hub is unavailable (503 `peer_unavailable`), and gim-core's bounded retries (2 retries, at most 60 s of waiting for reads; see *Federation* for sends and member changes) are used up. | Retry after `retryAfterSecs`. |
| `Cancelled` | Cancelled by `stopSync`, `signOut` or `cancelSend`. | Ignore. |
| `NotImplemented` | In the contract but not implemented in this build. | Development builds only. |
| `Internal(reason)` | Bug, or an unexpected exception thrown by a platform hook. | Report. |

Kotlin throws `GimException.<Variant>`; Swift throws `GimError.<Variant>`.

## Other functions

- `coreVersion()` — version of the gim-core library.
- `ciphersuiteName()` — the MLS ciphersuite used by every chat.
