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
   URL with a host, otherwise `InvalidInput`. `hooks` implements `PlatformHooks` (below).
2. **Session**: `session()` returns the persisted `Session`, or `null`/`nil` on first launch. In
   that case show onboarding and call `register(handle, displayName)`, which returns the new
   `Session`. Most other calls fail with `NotRegistered` until a session exists.
3. **Sync**: call `startSync()` when the app comes to the foreground and `stopSync()` when it goes
   to the background. Sync reconnects on its own; report reachability changes with
   `setNetworkReachable(reachable)` so it can back off or reconnect immediately.
4. **Listeners**: subscribe with `chatList(listener)`, `timeline(chatId).addListener(listener)`,
   `connectionState(listener)` and `typing(chatId, listener)`. Each returns a `TaskHandle`.
5. **Sign out**: `signOut()` stops sync and deletes the session, the local database and the
   keystore secrets. Create a new client afterwards.

## Platform hooks

`PlatformHooks` is implemented by the app and may be called from any Rust thread; keep the
implementations fast and thread-safe.

| Method | Contract |
|---|---|
| `secureStoreGet(key)` | Read a secret from Keychain / Android Keystore; `null`/`nil` if absent. |
| `secureStoreSet(key, value)` | Write or replace a secret; throw `GimError` on failure. |
| `secureStoreDelete(key)` | Delete a secret; a missing key is not an error. |
| `dataDir()` | Absolute path of an app-private directory. The SQLite database and media cache live under it. Must be stable across launches. |
| `isNetworkReachable()` | Current reachability; changes are pushed with `GimClient.setNetworkReachable`. |

## GimClient

| Method | Returns | Notes |
|---|---|---|
| `session()` | `Session?` | |
| `register(handle, displayName)` | `Session` | |
| `signOut()` | | |
| `startSync()` / `stopSync()` | | |
| `setNetworkReachable(reachable)` | | Synchronous, never throws. |
| `findUser(handle)` | `UserProfile?` | `null`/`nil` if no such user. |
| `createDirectChat(userId)` | chat id | Returns the existing direct chat if there is one. |
| `createGroupChat(name, memberUserIds)` | chat id | |
| `addMembers(chatId, userIds)`, `removeMember(chatId, userId)`, `leaveChat(chatId)` | | |
| `setGroupInfo(chatId, name?, avatarFilePath?)` | | `null`/`nil` leaves a field unchanged. |
| `sendText(chatId, body, replyTo?)` | message id | The message appears in the timeline immediately with `SendState.Pending`. |
| `sendMedia(chatId, filePath, mime, caption?, replyTo?)` | message id | The file is copied before the call returns. |
| `editMessage(chatId, messageId, newBody)`, `deleteMessage(chatId, messageId)` | | |
| `react(chatId, messageId, emoji)`, `unreact(chatId, messageId, emoji)` | | |
| `retrySend(chatId, messageId)`, `cancelSend(chatId, messageId)` | | For messages in `SendState.Failed`. |
| `markRead(chatId, upToMessageId)` | | Also sends a read receipt. |
| `setTyping(chatId, active)` | | |
| `fetchMedia(chatId, messageId, destPath)` | file path | Downloads and decrypts the attachment. |
| `fetchThumbnail(chatId, messageId, destPath)` | file path? | `null`/`nil` if the media has no thumbnail. |
| `chatList(listener)` | `TaskHandle` | |
| `timeline(chatId)` | `Timeline` | |
| `connectionState(listener)` | `TaskHandle` | |
| `typing(chatId, listener)` | `TaskHandle` | Reports user ids other than the signed-in user. |

A message id is the client id chosen when the message is queued; it stays the same from local echo
to delivery, so native code can key views by it.

`MediaRef` identifies an attachment (`chatId`, `messageId`, `mime`, `size`, `hasThumbnail`).
Encryption keys and blob ids never leave Rust; pass the ids to `fetchMedia` / `fetchThumbnail`.

### Timeline

`timeline(chatId)` is cheap. On the returned `Timeline`:

- `addListener(listener)` → `TaskHandle`; the first callback is a `Reset` with the items loaded so
  far, oldest first.
- `paginateBackwards(count)` loads up to `count` older items (they arrive through the listener as
  diffs) and returns whether more history exists.
- `chatId()`.

`TimelineItem` is a `Message` (`MessageItem`), a `DateSeparator` (start of a local calendar day) or
a `MembershipChange` (`Added`, `Removed`, `Left`). `MessageItem.sendState` is set only for own
messages: `Pending → Sent → Delivered → Read`, or `Failed(reason)`.

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
| `NotRegistered` | No session. | Go to onboarding. |
| `InvalidInput(reason)` | Argument rejected locally. | Bug or validation message. |
| `NotFound(reason)` | Unknown chat, message, user or media. | Refresh the screen. |
| `Crypto(reason)` | MLS or media decryption failure. | Report; show placeholder. |
| `Storage(reason)` | Local database or file system failure. | Report; may need disk space. |
| `Server(status, reason)` | Non-success HTTP status from gim-server. | Show generic error. |
| `Cancelled` | Cancelled by `stopSync`, `signOut` or `cancelSend`. | Ignore. |
| `NotImplemented` | In the contract but not implemented in this build. | Development builds only. |
| `Internal(reason)` | Bug, or an unexpected exception thrown by a platform hook. | Report. |

Kotlin throws `GimException.<Variant>`; Swift throws `GimError.<Variant>`.

## Other functions

- `coreVersion()` — version of the gim-core library.
- `ciphersuiteName()` — the MLS ciphersuite used by every chat.
