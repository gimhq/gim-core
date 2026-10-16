# Multi-homing (M2c) hub-side design

Sign-off: L1 accepted §9 entirely and the recommendations for Q1-Q9 (§13). Q1 (application
messages fan out to every listed hub) is a deliberate deviation from arch §9.2, chosen for
simplicity and failure tolerance at our scale, at a bandwidth cost. Q6 (blobs are not replicated)
is a known limit, narrowed by federated blob reads (H5-B1, fed §5.6). The migration is
`0007_multihoming.sql` (`0006` is taken).

Status: design, normative for the M2c hub subtasks (§12). Every contract change (§9) is a proposal that needs L1 / gim-core sign-off before the
subtask that implements it starts. Implemented: §2.2, §3.2, §4.2-§4.5, §5, §7.3 and §8 (H4-M1 to
H4-M5); the §11 compose suite runs in CI (`GIM_FED_SUITE=mh scripts/fed-test.sh`) with the
adaptations listed in §11.

This document specifies how a hub behaves when a user's hosting record lists several hubs:
fan-out, per-hub state and bootstrap of a new hub, KeyPackages, idempotent submission through
several hubs, adding and removing a hub (zero-downtime migration), push deduplication, the
contract changes, the test matrix and an implementation breakdown. It extends
[`federation.md`](federation.md) (M2b, "fed §N" below), whose rules apply unchanged unless a
section here says otherwise, and the contracts in [`s2s.md`](s2s.md), [`api-v2.md`](api-v2.md) and
the vendored identity spec ([`testdata/identity/identity.md`](../testdata/identity/identity.md)).
"arch §N" refers to the cluster architecture (`cluster-architecture.md`), "plan" to the M2 plan
(`20261015-1546-m2-identity-hub-federation.md`).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Scope and fixed decisions

In scope (M2c): a user whose current `UserHostingRecord` lists 1 to 16 hubs; all of the user's
devices use all listed hubs (user-level hub list, plan D7, arch §9.6); adding and removing a hub
while both run (arch §5.5); push deduplication between the user's hubs.

Fixed decisions (not re-opened here):

| # | Decision |
|---|---|
| M1 | The owning hub of a gid (gid prefix) sequences every message of the group, as in M2b. Multi-homing never changes who sequences; owning-hub migration stays out of scope (plan D8). |
| M2 | Owner → member hub delivery fans out to **every** hub listed for a member, for every message kind (Commits, application messages, Welcomes). Receivers and clients dedup by `message_id`. See §2.2 for why application messages are not primary/fallback on this leg. |
| M3 | Client → hub submission is primary/fallback: the client submits to its primary hub and, if that hub is unreachable, to the next one. The owner dedups (§6). |
| M4 | Each hub holds a disjoint set of one-time KeyPackages per device plus its own last-resort KeyPackage (arch §9.1). |
| M5 | Only the user's primary hub sends push, with a failover rule (§8); every push carries `collapse_id = message_id`. |
| M6 | A hub never holds the user root key: only the client changes the hub list (fed §4.1). |

Out of scope: device-level hub lists (arch §9.6), owning-hub migration and owner HA (a group
whose owning hub is down cannot sequence, whichever hubs its members use), replication of blobs
(blobs stay on the hub they were uploaded to; other hubs fetch them on demand, Q6), open
federation.

### 1.1 Terms

| Term | Meaning |
|---|---|
| listed hubs of U | The `hub_id`s of the entries of U's current (stored, unexpired) hosting record. |
| primary hub of U | The listed hub with the lowest `priority`, ties broken by the smallest `hub_id` (identity spec "Ordering and primary hub"). |
| co-host | Another hub listed for the same user. A and B are co-hosts of U when both are listed hubs of U. |
| multi-homed user | A user with more than one listed hub. |
| hosted user | Unchanged from fed §1.1: a local user whose current record lists this hub. |
| removed user | A local user whose stored record **was** hosted here and was superseded by a record that does not list this hub (§7.3). Expiry alone never makes a user removed. |
| added hub | A hub listed by a new record and not by the record it supersedes. |

## 2. Hub roles for a multi-homed user

### 2.1 Sequencing is unchanged

- The gid prefix names the owner; the owner assigns `(epoch, seq)` to every message (M1).
- A multi-homed user's devices may talk to any of the user's hubs. For a gid owned by one of
  them, that hub takes the local path; every other hub of the user is a member hub with a
  replica (fed §5.4) and forwards submissions with `SubmitCommit` / `SubmitMessage` (fed §6.3,
  §6.5).
- `POST /v2/groups` assigns the gid of the hub it is called on. gim-core SHOULD create groups on
  the user's primary hub, so that the groups a user creates share the fate of the hub the user
  prefers.
- A group whose owner is down cannot sequence: submissions through any hub get 503
  `peer_unavailable` (fed §6.7). The acceptance case "keeps messaging when one hub is stopped"
  (plan §4) therefore holds for every group whose owner is not the stopped hub (§11, MH7).

### 2.2 Fan-out set (change to fed §6.4)

fed §6.4 already defines "hubs of a user" as every hub listed in the user's current record, and
`hubs_of` (`crates/gim-hub-api/src/handlers/groups.rs`) already implements it. M2c keeps that rule
for all message kinds and makes the following normative changes:

| fed §6.4 text | M2c rule |
|---|---|
| "in M2c this rule is where the delivery strategy (all hubs for Commits and Welcomes, primary/fallback for application messages, arch §9.2) plugs in" | **All listed hubs for every kind.** No primary/fallback on the owner → member hub leg. |
| `DeliverWelcome` per (recipient hub, recipient user) (fed §5.3 "Local events") | One `DeliverWelcome` per (listed hub of the recipient, recipient user), this hub excluded. Each hub stores the pending Welcome; devices dedup by `message_id` (§4.4). |
| Fan-out computed from cached records | Unchanged, plus: a record update that adds hubs triggers replica seeding *before* the new hub enters any fan-out set (§4.3). |

Why application messages are not primary/fallback here (deviation from arch §9.2):

1. A replica must hold a gap-free log (fed §6.6). A member hub that receives only some
   application messages of a group sees a gap at every message it skipped and would `FetchLog`
   it anyway; primary/fallback would save no traffic and add a gap fill per message.
2. Every device keeps a cursor on every hub of its user (§3) and may be reading any of them
   when another hub fails; a hub that did not receive a message cannot serve it later without a
   fetch from the owner, which may itself be down.
3. The outbox already batches per peer (fed §7.2); the extra cost is one copy per additional
   listed hub, bounded by 16 hubs per record and in practice 2 or 3.

Primary/fallback stays the client's submission strategy (M3, §6) and the push rule (§8).

The owner's own local events are unchanged (fed §5.3 "Local events"): when the owner is itself a
listed hub of a member, it emits that member's events locally and excludes itself from the fan-out
set (`hubs_of` already drops `own`).

### 2.3 What each hub of a user does

Every listed hub of U is equal for everything except push and claim routing:

| Function | Which hub(s) of U |
|---|---|
| Client sessions, events, pending Welcomes, replicas | every listed hub, independently (§3) |
| Receive `Deliver` / `DeliverWelcome` / `SeedReplica` for U's groups | every listed hub (§2.2, §4.3) |
| Forward U's submissions to the owner | whichever hub the device submitted to (§6) |
| Act for U in S2S (`SubmitCommit`, `SubmitMessage`, `ClaimKeyPackage` as requester, `FetchLog`) | any listed hub (fed §3.7 "listed" already admits any of them) |
| Serve claims of U's KeyPackages to other hubs | the hub the requester routes to (§5.2) |
| Answer `GetDeviceList` / `GetHostingRecord` for U | every listed hub that has U as a local user |
| Publish and republish U's record to the DHT | every listed hub (identical bytes; the DHT keeps one per key) |
| Propagate U's DeviceList and record changes | the hub that accepted the change (§3.2, §4.2) |
| Push to U's devices | the primary, or the first reachable hub by priority when the primary is down (§8) |

## 3. Per-hub state of a co-hosted user

### 3.1 What a hub stores

A co-host stores a co-hosted user exactly like a single-hub user; no table changes for the
per-user state. Nothing is shared between co-hosts except through the client, the owner, or the
propagation ops of §3.2, §4.2-§4.4.

| State | Per hub | Source on each hub |
|---|---|---|
| `users` row + DeviceList, `devices` | yes, identical content | client `PUT .../device-list` on each hub; `NotifyDeviceList` between co-hosts (§3.2) |
| `sessions` | yes, independent | each device signs in on each hub (challenge audience = that hub's `hub_id`) |
| `events` and the device cursor | yes, independent; event ids differ between hubs | local emission from local, replica and propagated changes |
| `pending_welcomes` | yes, deduplicated by `(message_id, user_id, device_id)` | `DeliverWelcome` to every listed hub (§2.2); local owner path; copy at bootstrap (§4.4) |
| replicas (`groups`, `group_members`, `messages`) | yes, same `(gid, seq, message_id)` everywhere | `DeliverWelcome`, `Deliver`, `FetchLog`; `SeedReplica` at bootstrap (§4.3) |
| `key_packages` | yes, **disjoint** (§5) | client uploads a distinct set to each hub |
| `remote_kp_claims` | yes, independent | claims brokered by that hub |
| `hosting_records` row | yes, identical record | client `PUT` to every listed hub; `NotifyHostingRecord` (§4.2) |
| `push_registrations` | yes | client registers on each hub (§8) |
| `recovery_backups` | yes | client `PUT` on each hub (it is the same encrypted blob) |
| `handles` | per hub, optional | handles are a per-hub directory (api-v2); not propagated |

### 3.2 DeviceList propagation to co-hosts (change to fed §5.1)

The client uploads every new DeviceList to all its listed hubs. In addition, the hub that accepts
a replacement (client upload or `NotifyDeviceList`) for a hosted user propagates it, so a hub
that the client cannot reach at the moment still learns about revocations:

- `remote_identity::device_list_peer_hubs` gains the user's own other listed hubs (co-hosts).
  Today it covers the owners of the user's groups and the hubs of the other members of owned
  groups, and explicitly excludes the user's own hubs.
- A co-host receiving `NotifyDeviceList` for a user with a `users` row applies it with the upload
  path (fed §5.1 "Local receivers"), including device (de)activation, `device_list.updated`
  events and waking revoked devices' streams. It does not propagate further.
- A device linked on hub A appears on co-host B through this propagation and can then sign in on
  B without the client re-uploading the list there.

## 4. Hosting record changes and bootstrap of a new hub

### 4.1 Client procedure to add a hub (normative for gim-core, informative here)

Adding hub B for a user U hosted on A (all steps through B's client API unless noted):

1. `PUT /v2/users/{U}/device-list` with U's current DeviceList (creates U on B).
2. Sign in each device on B (`/v2/auth/challenge`, `/v2/auth/session`).
3. `POST /v2/users/{U}/hosting-entry {priority}` (B co-signs its entry).
4. Build a record with `seq + 1`, the existing entries plus B's, sign it, and
   `PUT /v2/users/{U}/hosting-record` on **every** hub of the new record and on every hub of the
   previous record (here A and B). Hubs that cannot be reached learn it via §4.2.
5. Upload a fresh, distinct set of one-time KeyPackages and one last-resort KeyPackage per device
   to B (§5.1); register push on B; `PUT .../recovery-backup` on B.
6. Open `GET /v2/stream` on B for every device (cursor starts at B's head; nothing before is
   needed, §4.3).

A DeviceList on B is required before step 3 (`hosting-entry` needs a session), so a record never
lists a hub that has no `users` row for U: B is a hosted hub for U from the moment it stores the
record, and `DeliverWelcome` / `SeedReplica` addressed to B for U never fail with `NOT_FOUND`.

### 4.2 Record propagation: `NotifyHostingRecord` (new op)

When a hub stores a record R for a local user that supersedes the stored one (client `PUT`, or
`NotifyHostingRecord` below), and the set of `(hub_id, priority)` entries changed, it queues one
`NotifyHostingRecord{user_id, hosting_record_cbor}` outbox entry (kind `hosting_record`,
coalesced per peer and user like `device_list`, latest record read at send time) to:

- every hub listed in R or in the superseded record, this hub excluded (co-hosts, added hubs and
  removed hubs);
- every peer of `device_list_peer_hubs` (owners of the user's groups and member hubs of the
  owned groups that contain the user), so owners update their fan-out set promptly instead of
  after the 600 s cache (fed §4.5).

Only hubs that host the user under R or under the superseded record send it (a removed hub
announces its own removal once, which is how co-hosts learn it when the client could not reach
them).

Receiver: verify (`HostingRecord::verify`, user id check), then:

| Receiver state | Action |
|---|---|
| U is a local user here | apply as a client `PUT` (seq rules, `hosted`, DHT publish, §4.3 hook, §4.5 event, §7.3 removal). |
| otherwise | store in the remote cache with the seq rules of fed §4.5 step 5 (§4.3 hook applies). |

Authorization: the caller is listed in R or in the stored record R supersedes (fed §3.7 table,
new row). The answer is `{}` for an applied, stale or identical record; `INVALID` for a record
that does not verify.

A record renewal (new `seq`, same entries) is not propagated: hubs refresh it through the normal
lookup (fed §4.5) and the client's `PUT` to every listed hub.

### 4.3 Replica seeding: `SeedReplica` (new op)

A newly added hub has no replicas of the user's existing groups. A member hub only creates a
replica from `DeliverWelcome` (fed §5.4), and `Deliver` for an unknown gid is skipped (fed §6.6
step 2). The owner therefore seeds the added hub.

Hook (owner side): every code path that stores a record superseding the stored one (client
`PUT`, `NotifyHostingRecord`, a resolution in `Hosting::resolve`) computes the added hubs and, in
the **same write transaction** as the record update, for every group this hub owns that has U in
its roster:

1. builds a `GroupSnapshot` of the current state (kind, creator, `created_at`, `epoch` = current
   epoch, `seq` = `last_seq`, roster);
2. enqueues `SeedReplica{gid, user_id: U, group: snapshot}` (kind `seed_replica`, payload stored)
   to every added hub that is not this hub.

A hub that hosts U under either record also queues `NotifyHostingRecord` to each added hub ahead
of the seeds and the `CopyPendingWelcomes` entry (the later queueing of §4.2 coalesces with it),
so the added hub stores the record before it authorizes them, even when the client's `PUT` to it
comes later. An owner that only caches U's record has no such ordering: a seed that reaches the
added hub before the record is refused with `NOT_FOUND` and dropped.

Because the fan-out of every later message is computed in a later transaction from the stored
record, and the outbox is FIFO per peer (fed §7.2), the seed reaches the added hub ahead of every
`Deliver` that includes it, and its snapshot `seq` is exactly the `seq` before that first
`Deliver`. If the owner learns the record late (down, or cache), the added hub only misses
messages that were never fanned out to it; the seed snapshot starts after them.

Receiver (added hub), authorization: the caller owns `gid` (gid prefix); this hub hosts
`user_id`; `user_id` is in `group.members`. Else `UNAUTHORIZED` / `NOT_FOUND` / `INVALID`.

| Local replica state | Action |
|---|---|
| none, or detached | create or replace: `last_seq = seq`, `epoch = epoch`, `replica_from_seq = seq + 1`, roster = snapshot. No events (the user's devices already joined the group through another hub). |
| exists with local members | ignore (another member of this hub kept it current). |
| this hub owns `gid` | ignore. |

The answer is `{}`. Unlike the `DeliverWelcome` join point (fed §5.4 "Join point"), the replica
starts **after** `snapshot.seq`: no Commit follows the seed. History before `replica_from_seq` is
not served by this hub (fed §5.4 "History"); the device already holds it from its other hubs.

A record that removes hubs triggers nothing on the owner: removed hubs simply leave the fan-out set
of later messages.

### 4.4 Pending Welcomes: `CopyPendingWelcomes` (new op)

Welcomes delivered before B was added exist only on U's earlier hubs (the owner does not keep
Welcome bytes after delivery). When a hub that hosts U under the new record stores a record that
adds hubs, it enqueues one `CopyPendingWelcomes{user_id}` entry (kind `pending_welcomes`, built at
send time) to each added hub. The request carries every unacknowledged pending Welcome of U's
devices on the sender: `device_id`, `gid`, `message_id`, the stored event payload. `message_id` is
the stored column, else the `message_id` of the Commit `(gid, seq)` in the sender's log; a row
without either is skipped.

Receiver: caller listed for `user_id` (under the receiver's stored record); this hub hosts
`user_id`. For each item whose device is an active device of U: insert the pending Welcome
(dedup by `(message_id, user_id, device_id)`) and emit `welcome`. A Welcome whose replica does not
exist yet is stored anyway; the replica arrives with `SeedReplica` from the owner. Answer `{}`.

Every co-host sends its copy; the receiver's dedup makes that harmless. Acknowledgements are not
propagated: a device acknowledges a Welcome on every hub on which it sees it (§9.2, gim-core
rule). Pending Welcomes retained on a hub the device no longer reads are deleted with the user's
data when that hub is removed (§7.3).

### 4.5 `hosting_record.updated` event (new)

When a hub stores, for a local user, a record whose `(hub_id, priority)` entries differ from the
superseded one, it emits `hosting_record.updated` to the user's active devices on this hub, with
payload `{user_id, seq, expires_at, hosted, hubs: [{hub_id, priority}]}` (`hosted` = the record
lists this hub). Renewals with the same entries emit nothing. Devices dedup by `seq` across hubs
and use it to open sessions to added hubs (once they know the hub's URL, Q2) and to stop using
removed ones.

## 5. KeyPackages

### 5.1 Client obligations

- For each device and each listed hub, the client uploads its own one-time KeyPackages and one
  last-resort KeyPackage. A KeyPackage (by `kp_ref`) is uploaded to **at most one hub, ever**,
  including after that hub is removed. Unused private keys of a removed hub's packages are kept
  until the packages' MLS lifetime ends (a claim may have happened just before removal).
- `keypackages.low` is per hub; the client replenishes that hub with new packages.
- The client claims and commits through the same hub (§5.4).

### 5.2 Claim routing (change to fed §5.2 "Routing")

`POST /v2/keypackages/claim` on hub H, per target user T:

1. T is a local user of H and T's record lists H, or T has no record at all (single-hub case) →
   claim locally (as today). Unlike M2b, a local user that is **not** hosted here (removed,
   §7.3) is routed by its record, not claimed locally.
2. Otherwise, the listed hubs of T in `(priority, hub_id)` order (the primary first). Send
   `ClaimKeyPackage{requester, T}` to the first; move to the next hub when the answer is in the
   `unavailable` class (fed §6.1: transport error, timeout, `INTERNAL`, `RATE_LIMITED`,
   `UNAUTHORIZED`) or `NOT_FOUND`.
3. Per device: once a hub has answered with packages, the active devices of T (from T's
   DeviceList, `device_list_for`) it did not return are requested from the following hubs with
   `device_id` set, one request per (device, hub), stopping at the first hub that returns a
   package for the device. This covers a device that has not uploaded to the primary yet.
4. No hub answered and at least one was `unavailable` → T is in `unavailable`; otherwise, no
   package for any device → `missing`.

Each device yields at most one package per claim request, from exactly one hub.

### 5.3 Guarantee and its limits

Guarantee: **a one-time KeyPackage is handed out at most once across the federation, provided the
client uploaded it to only one hub** (§5.1). It rests on:

- disjoint sets: a package exists on one hub only (client obligation; see enforcement below);
- per-hub atomic claims: a hub marks a package claimed in the same transaction that returns it
  (`key_packages.claimed_at`), so two claims on that hub never get the same one-time package;
- routing changes only *where* a claim is served, never re-serves a package: a claim that timed
  out on the primary but succeeded there consumed that package (wasted, never reused), and the
  fallback serves a different package from its own disjoint set.

The last-resort package of each hub may be handed out repeatedly, as in M2b (MLS last-resort
semantics, RFC 9420); each hub has its own, so they are distinct packages.

Hub enforcement (best effort; a hub cannot see other hubs' stores):

| Check | Where | Result |
|---|---|---|
| `kp_ref` already stored on this hub | upload (`key_packages_kp_ref` unique index; today silently ignored) | ignored as today (idempotent re-upload of the same bytes) |
| `kp_ref` is in this hub's `remote_kp_claims` (this hub brokered a claim of it from another hub) | `POST /v2/keypackages` | the whole upload is rejected with 409 `duplicate_key_package` (new code) |
| a brokered remote claim returns a `kp_ref` that is stored here unclaimed | claim (§5.2) | the local copy is marked claimed ("burned") and a `warn` is logged with `user_id`, `device_id` |
| an Add's `kp_ref` is stored here unclaimed | Commit validation on the owner or forwarding hub | the local copy is burned and logged (the Commit continues with the M2b ledger rule) |

Limits: a client that uploads one package to two hubs that never see each other's claims can
still get it claimed twice; detection is possible only where a hub's own ledger meets the
package. This is a client bug, made observable by the burns above; gim-core tests MUST cover the
disjointness rule.

### 5.4 Ledger rule for Adds (unchanged)

fed §5.3 / §6.3 step 2 require the `kp_ref` of an Add to be in the ledger of the hub that
receives the Commit from the client. M2c keeps this rule: the client claims and commits through the
same hub. A client that fails over between claim and commit re-claims through the new hub (the
first claim's packages are consumed, never reused). The 400 message for this case becomes
`key package not claimed through this hub (kp_not_claimed)` so gim-core can re-claim instead of
reporting a credential error. Relaxing the rule is Q3.

## 6. Submission and idempotency across hubs

### 6.1 Client strategy

- The client submits Commits and application messages to its primary hub. On a transport
  failure or timeout to that hub (the hub itself is unreachable), it resubmits **the same Commit
  bytes / the same `client_id` and `mls_message`** to the next hub by priority. On 503
  `peer_unavailable` from a reachable hub (the owner is down) switching hubs does not help; the
  client retries later and MAY try the next hub.
- Reads and events: the client keeps a stream (or long-poll) and a cursor on every listed hub and
  merges by `message_id` (arch §9.3).

### 6.2 Owner-side dedup (existing, normative for forwarded submits)

| Kind | Dedup key on the owner | Behaviour |
|---|---|---|
| application message | `(gid, sender_device_id, client_id)` (`messages` unique index) | a repeat returns the original `seq` / `epoch` with `duplicate = true` and the stored message |
| Commit / Proposal | `(gid, commit_hash)` (`messages` unique index) | a repeat returns the original `seq` / `epoch` with `duplicate = true` |

The key does not include the submitting hub. Therefore:

- client → A (forwarded `SubmitMessage`) then client → B (forwarded `SubmitMessage`) with the
  same `client_id`: the owner sequences once; B gets `duplicate = true` and the original
  `SequencedMessage`, applies it to its replica (or fills the gap up to it) and answers the client
  200 with the stored message;
- the owner is one of the user's hubs (A) and the second attempt arrives directly at A: the local
  path hits the same index;
- the member hub's fast path (fed §6.5: `(device, client_id)` already in the replica → 200) is
  still taken first; it is only an optimisation.

The owner's log is never pruned (fed §7.6), so the dedup window is unbounded. A client MUST NOT
reuse a `client_id` for different content within a group; a reused `client_id` returns the first
message (as on a single hub).

### 6.3 Delivery dedup

Each listed hub receives each sequenced message once per owner fan-out (§2.2) and dedups
`Deliver` by `(gid, seq)` / `message_id` (fed §6.6), so a hub's replica holds every message
once. A device receives each message once per hub it reads; event ids differ between hubs but the
payload carries the owner's `message_id`, `gid`, `seq`, `epoch`. The client dedups by
`message_id` and orders by `(gid, epoch, seq)`.

## 7. Adding and removing a hub; zero-downtime migration

### 7.1 Procedure (arch §5.5)

Migration of U from A to C:

1. **Add**: §4.1 with C (record `seq n+1` lists A and C; C usually with a higher `priority`
   value, i.e. less preferred, until the switch).
2. **Run both**: C is seeded (§4.3), receives every new message (§2.2) and copied Welcomes
   (§4.4); devices read A and C.
3. **Switch** (optional): record `seq n+2` makes C primary (priority change). Push moves to C
   (§8); claims route to C first (§5.2).
4. **Remove**: when the client's drain check passes, record `seq n+3` lists C only, `PUT` to A
   and C.

Client drain check before step 4 (gim-core; the hub provides the data): every device has an open
session on C; `GET /v2/groups` on C lists every group the device is in; `GET /v2/welcomes/pending`
on A is empty or every item is also pending (or acknowledged) on C; the device has read A's events
up to the head; KeyPackages and last resort uploaded to C.

### 7.2 Owners and other hubs

- Removing a hub changes only the fan-out set of later messages (the removed hub is no longer in
  "hubs of U"); outbox entries already queued to it are delivered or expire as usual.
- A removed hub that **owns** groups keeps owning and sequencing them for all members, U
  included (M1): U's submissions now arrive through C as `SubmitMessage` / `SubmitCommit`, and A
  authorizes C as listed for U. Decommissioning a hub that owns groups loses those groups
  (owning-hub migration is out of scope, Q5).
- Every S2S request made by the removed hub on U's behalf is refused by the other hubs with
  `UNAUTHORIZED` once they hold the new record (fed §3.7 "listed"; the one-time refresh on a
  cache miss finds the new record).

### 7.3 Behaviour of the removed hub

When a hub stores, for a local user U, a record that supersedes one listing this hub and does not
list it (client `PUT` or `NotifyHostingRecord`), U becomes **removed** here. In the same
transaction the hub:

1. sets `hosting_records.removed_at = now` (new column, §9.3) and `hosted = 0`;
2. deletes U's unclaimed key packages (one-time and last resort), so no route can claim them;
3. deletes U's queued `device_list` outbox entries (they would be refused; co-hosts propagate) and
   queues `NotifyHostingRecord` (§4.2);
4. marks every replica whose only local members belong to removed users `detached = 1`;
5. emits `hosting_record.updated` with `hosted: false` (§4.5).

Then, during the grace period `GIM_HUB_UNHOSTED_GRACE_HOURS` (default 168, the outbox TTL):

| Client API | Behaviour for U's devices |
|---|---|
| sign-in, `GET` endpoints, `GET /v2/stream`, `GET /v2/events`, `GET /v2/welcomes/pending`, `POST /v2/welcomes/{gid}/ack` | served (devices drain their cursor) |
| `PUT .../device-list`, `PUT .../hosting-record` | accepted (revocations still land; a record that lists this hub again clears `removed_at` and ends the removal) |
| every other write (`POST /v2/groups`, commits, messages, KeyPackage upload and claim, blob upload, link bundles, handles, recovery backup, push registration) | 403 `hosting_record_required`, message `user is not hosted on this hub` |

No push is sent for a removed user (§8). Federation: the hub sends no request on U's behalf
(fed §3.7: only hosted users) and answers `ClaimKeyPackage` for U with `NOT_FOUND`;
`GetDeviceList` / `GetHostingRecord` for U are still answered until the purge.

Purge, by the hourly retention task when `removed_at + grace <= now`: delete the `users` row
(cascading `devices`, `sessions`, `key_packages`, `handles`, `recovery_backups`,
`push_registrations`), U's `events` and `pending_welcomes`, and U's `remote_kp_claims` rows as
requester. Kept: the `hosting_records` row as a tombstone (it keeps ordering future uploads, so an
old record that still lists this hub cannot be replayed to make it host U again), and owned groups
with U in the roster (U is a remote user of this hub from then on). Blobs follow their own
retention.

Expiry is not removal: a record that merely expires sets `hosted = 0` (fed §4.3) without
`removed_at`, writes keep working as for any user without a valid record (federated actions 403,
local ones as today), and nothing is purged.

## 8. Push

Push gateway, provider and payload are H4-P1's. This section specifies **which hub pushes** and
the dedup rule; H4-P1's "primary-only" hook is `PushGate::should_push(user_id) -> bool`,
implemented in the multihoming module of `gim-hub-s2s`.

Rule, evaluated per user when a pushable event is emitted for a local device:

1. U is not hosted here (no valid record listing this hub, or removed) → `false`. Without
   federation, or with a single listed hub that is this hub → `true`.
2. This hub is U's primary → `true`.
3. Otherwise `true` only if every listed hub that precedes this hub in `(priority, hub_id)` order
   is **down** in this hub's view; else `false`.

"Down" comes from the transport's peer state, not from a per-message probe: a hub keeps a
connection to each co-host of its hosted users and pings it (libp2p ping inside `transport/`,
every 10 s); a co-host is down after `GIM_HUB_PUSH_FAILOVER_SECONDS` (default 30) without a
successful ping or S2S exchange, and up again on the next success. A fallback hub therefore starts
pushing at most ~30 s after the primary stops, and stops when it sees the primary again. Pushes
for messages that arrived while the primary was down but before the failover delay elapsed are not
sent late; the devices still receive the messages from their streams.

Every push carries `collapse_id = message_id` (the push server maps it to the platform's collapse
key), and the client (NSE / Android service) dedups by `message_id`. That bounds the effect of a split view
(the primary is up but a fallback cannot reach it, so both push): the device shows one
notification.

Implementation (H4-M5a): `gim_hub_s2s::multihoming::PushGate`, installed on the push dispatcher
only when federation is enabled. The dispatcher calls the gate synchronously, so the gate reads an
in-memory view of the hosted users' hub lists, reloaded from the database every 10 s (a record
change reaches the gate up to 10 s late), and `transport::Liveness`, fed by libp2p ping
(every 10 s, shorter only when the failover delay is under 30 s) and by every S2S exchange. The
same 10 s loop keeps a connection open to every co-host. A co-host first seen by the view gets the
full failover delay before it counts as down.

## 9. Contract changes (proposals, need L1 / gim-core sign-off)

### 9.1 `proto/s2s.proto`

Additive within `gim.s2s.v1`, in the oneof range 18-29 reserved for M2c:

```diff
@@ message S2sRequest
     GetHostingRecordRequest get_hosting_record = 17;
-    // 18-29: reserved for multi-homing (M2c) operations, e.g. hub
-    //        add/remove and migration hand-off.
+    // 18-29: multi-homing (M2c).
+    NotifyHostingRecordRequest notify_hosting_record = 18;
+    SeedReplicaRequest seed_replica = 19;
+    CopyPendingWelcomesRequest copy_pending_welcomes = 20;
     // 30-39: reserved for push (P) operations, e.g. collapse-id coordination.
@@ message S2sResponse
-    // 18-39: reserved, mirroring S2sRequest.op.
+    NotifyHostingRecordResponse notify_hosting_record = 18;
+    SeedReplicaResponse seed_replica = 19;
+    CopyPendingWelcomesResponse copy_pending_welcomes = 20;
+    // 21-39: reserved, mirroring S2sRequest.op.
+
+// ---------------------------------------------------------------------------
+// Multi-homing (M2c)
+// ---------------------------------------------------------------------------
+
+// A user's hub (under the new or the superseded record) -> co-hosts, removed
+// hubs, owners and member hubs sharing groups with the user.
+message NotifyHostingRecordRequest {
+  string user_id = 1;
+  bytes hosting_record_cbor = 2;   // gim-core SignedHostingRecord
+}
+message NotifyHostingRecordResponse {}
+
+// Owning hub -> a hub newly listed for a member: creates the replica.
+message SeedReplicaRequest {
+  string gid = 1;
+  string user_id = 2;              // the member whose record added the hub
+  GroupSnapshot group = 3;         // current state: epoch, seq = last_seq, roster
+}
+message SeedReplicaResponse {}
+
+// Co-host -> newly listed hub: the user's unacknowledged pending Welcomes.
+message CopyPendingWelcomesRequest {
+  string user_id = 1;
+  repeated PendingWelcome welcomes = 2;
+}
+message PendingWelcome {
+  string device_id = 1;
+  string gid = 2;
+  string message_id = 3;
+  string payload_json = 4;         // the stored `welcome` event payload
+  uint64 created_at = 5;           // unix ms on the sending hub
+}
+message CopyPendingWelcomesResponse {}
```

`SequencedMessage` 12-19 and `DeliverWelcomeRequest` 8-15 stay reserved: push needs no extra
field (`collapse_id = message_id`), and every hub receives every copy, so no delivery-strategy
hint is needed.

`s2s.md` changes (same sign-off): the three ops in the operations table with the authorization
below; the idempotency section adds "`SeedReplica` and `CopyPendingWelcomes` are idempotent
(receiver ignores a seed for a live replica and dedups Welcomes by `message_id`);
`NotifyHostingRecord` follows the record seq rules"; the extensibility note for 18-29 now names
these ops.

| Op | Authorization (beyond binding and policy) | Failure |
|---|---|---|
| `NotifyHostingRecord` | caller listed in the sent record or in the stored record it supersedes | `UNAUTHORIZED`; `INVALID` (record does not verify) |
| `SeedReplica` | caller owns `gid`; this hub hosts `user_id`; `user_id` in `group.members` | `UNAUTHORIZED`, `NOT_FOUND`, `INVALID` |
| `CopyPendingWelcomes` | caller listed for `user_id`; this hub hosts `user_id` | `UNAUTHORIZED`, `NOT_FOUND` |

The `NotifyDeviceList` sender set changes (§3.2); its authorization is unchanged.

### 9.2 Client API (`/v2`)

| Change | Detail |
|---|---|
| New event `hosting_record.updated` | §4.5: `{user_id, seq, expires_at, hosted, hubs: [{hub_id, priority}]}` to the user's active devices when the hub list or priorities change |
| `POST /v2/keypackages` | new 409 `duplicate_key_package` (§5.3) |
| `POST /v2/keypackages/claim` | routing per §5.2 (fallback hubs, per-device follow-up); response shape unchanged |
| `POST /v2/groups/{gid}/commits` | the existing 400 `validation_failed` for an Add whose KeyPackage was not claimed through this hub uses the message `... (kp_not_claimed)` (§5.4) |
| Writes of a removed user | 403 `hosting_record_required` (existing code) during the grace period (§7.3) |
| New `GET /v2/hub` (no token) | `{hub_id, hub_root_pubkey, version}`, so a client can check that a URL belongs to the `hub_id` in its record before signing in (Q2) |

gim-core rules that the hub relies on (for the core L2): one connection and cursor per listed hub
and merge by `message_id` (§6.3); submission primary/fallback with identical retries (§6.1);
disjoint KeyPackages per hub and claim+commit through one hub (§5.1, §5.4); add-hub procedure
(§4.1) and drain check (§7.1); acknowledge a Welcome on every hub that lists it (§4.4); push
dedup by `message_id` (§8).

### 9.3 Database migration `0007_multihoming.sql`

- `hosting_records.removed_at INTEGER` (NULL unless removed, §7.3).
- `s2s_outbox.kind` CHECK gains `hosting_record`, `seed_replica`, `pending_welcomes`. SQLite
  cannot alter a CHECK constraint, so the migration rebuilds `s2s_outbox` (create new table, copy,
  drop, rename, recreate the indexes), plus
  `CREATE UNIQUE INDEX s2s_outbox_hosting_record ON s2s_outbox(peer_hub_id, user_id) WHERE kind
  = 'hosting_record'` and the same for `pending_welcomes`. `seed_replica` entries store their
  encoded request in `payload` (like `deliver_welcome`) and, like `deliver_welcome`, are never
  evicted by the cap (fed §7.5).
- `OutboxSource` gains `hosting_record(user_id)` and `pending_welcomes(user_id, peer)`; the
  worker sends `hosting_record`, `seed_replica` and `pending_welcomes` entries alone, acked on
  `{}` (fed §7.3).

## 10. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GIM_HUB_UNHOSTED_GRACE_HOURS` | `168` | Grace period after a user removes this hub before their data is purged (§7.3) |
| `GIM_HUB_PUSH_FAILOVER_SECONDS` | `30` | A co-host without a successful ping or exchange for this long is down for the push rule (§8) |

Both are ignored unless `GIM_HUB_FEDERATION=true`; with federation disabled there are no co-hosts
and no removal.

## 11. Test matrix (3-hub compose, extends H3-T6)

Same harness as fed §11.2 (`deploy/federation/compose.yaml`, runner
`cargo test -p gim-hub --test fed_compose -- --ignored`), new test file
`crates/gim-hub/tests/multihoming_compose.rs`, hubs a, b, c with `GIM_HUB_UNHOSTED_GRACE_HOURS=1`
and `GIM_HUB_PUSH_FAILOVER_SECONDS=5`, push provider `log` (H4-P1). Users: alice on A+B (A
primary), bob on B, carol on C. Group G owned by C with alice, bob, carol; group H owned by A
with alice and carol. "Alice's view" = the union of her device's events on A and B, merged by
`message_id`.

| # | Case | Steps | Assertions |
|---|---|---|---|
| MH1 | Add hub | alice starts on A only, in G and H, with one unacknowledged Welcome for a group W owned by C; she adds B (§4.1) | B has `users`/devices for alice; A and C store record seq 2; B has replicas of G (from C) and H (from A) with `replica_from_seq = last_seq + 1`; B lists W's Welcome in `GET /v2/welcomes/pending`; alice's devices got one `hosting_record.updated` per hub |
| MH2 | Fan-out | bob and carol send 20 messages each to G; a Commit adds a device of carol | A and B each receive every message once (identical `(seq, message_id)`); alice's view has 40 + 1 distinct messages in `(epoch, seq)` order; the Welcome for a new alice device reaches A and B |
| MH3 | Hub stopped | `docker compose stop hub-a`; alice sends 20 to G via B; bob and carol send 20 | every member receives alice's 20 once; alice's view (B only) has all 40; B pushes for alice after ≤ 5 s (log provider), A pushed nothing |
| MH4 | No duplicates after return | (continues MH3) start hub-a; alice submits `client_id` X via A, then the same X via B | owner C sequences X once (B answers 200 `duplicate: true`, same `seq`); A drains its backlog from C; alice's view has no duplicate `message_id`; A's and B's replicas of G are identical; push goes back to A only |
| MH5 | KeyPackages | alice's device uploads 5 one-time + last resort to A and a disjoint 5 + last resort to B; bob@B claims alice 3×; carol@C claims alice 4× (A up), then 4× with A stopped; alice re-uploads a `kp_ref` B obtained via a brokered claim | all returned `kp_ref`s distinct except last-resort repeats; local claims on B came from B's set, C's claims from A then B; the re-upload is 409 `duplicate_key_package` |
| MH6 | DeviceList propagation | alice links a new device on A (DeviceList uploaded to A only) | B receives `NotifyDeviceList`, the new device signs in on B; a revocation uploaded on B reaches A and closes the revoked device's stream on A |
| MH7 | Owner stopped | stop hub-a; alice sends to H via B | 503 `peer_unavailable` (documented limit, §2.1); reads of H on B work; after restart the send succeeds |
| MH8 | Migration A → C | alice in G and H on A only; bob sends to G at 2 msg/s throughout; alice adds C (seq 2), makes C primary (seq 3), passes the drain check, removes A (seq 4) | alice's view (A then C) contains every bob message, gap-free in `seq`; A emits `hosting_record.updated` `hosted: false`, refuses alice's writes with 403, answers `ClaimKeyPackage` for alice with `NOT_FOUND`; alice's messages to H still sequence on A via C; B refuses a `SubmitMessage` from A on alice's behalf (`UNAUTHORIZED`); after the 1 h grace (clock advanced via the test clock) A's `users` row for alice is gone and the tombstone record remains |
| MH9 | Removal notice | stop hub-b; alice (A+B) removes B with a `PUT` to A only; start hub-b | B gets `NotifyHostingRecord` from A's outbox and enters the removed state |

The compose suite (H4-M5b, `GIM_FED_SUITE=mh scripts/fed-test.sh`, override
`deploy/federation/compose.mh.yaml`) runs MH1-MH9 with these adaptations:

- MH8 uses a second user, mia (on A, in G and H), because alice is on A+B from MH1 on; MH9 uses
  alice.
- `message` events carry no `message_id` (api-v2 `Message`), so views are merged by `(gid, seq)`
  and the copies on each hub are compared byte for byte; pushes are matched by `gid` and `seq`.
- MH1: bob is on B, so B already holds a live replica of G and ignores C's seed (§4.3); B keeps
  G's full log. H is seeded by A. The §4.3 race case (an owner that only caches the record) is
  W: with the record `PUT` to B first (§4.1), C's seed reaches B and creates the replica at
  `last_seq`. B emits `hosting_record.updated` because it had cached alice's seq 1 as a remote
  user; a hub with no stored record would emit nothing (§4.5).
- MH3: A's push log is in memory, so "A pushed nothing" is checked as "B pushed nothing while A
  was up" (MH2, and no B push before the stop in MH3); MH4 checks that push returns to A only.
- MH5's 409 `duplicate_key_package` needs a hub that brokered a claim of the uploading user and
  hosts her later; it runs in MH8 (C brokers a claim of mia from A; after adding C, mia uploads
  that package to C).
- MH6 waits on the revoked device's long-poll (`GET /v2/events?wait`, same wake-up as
  `/v2/stream`), which ends with 401.
- MH8: the run cannot advance the clock, so the purge after the grace period is covered by
  `multihoming_records.rs` (`removed_hub_refuses_writes_then_purges_and_can_be_listed_again`);
  the compose suite asserts the removed state, the 403s, the `users` row and the tombstone
  record. "A answers `ClaimKeyPackage` with `NOT_FOUND`" and "B refuses A's `SubmitMessage`" are
  not observable over the client API (other hubs route by the new record, and A refuses the
  user's writes before forwarding); the suite asserts instead that a claim of mia through A is
  served by C, and the refusal of unlisted submitters is covered by `federation_groups.rs`
  (`submits_from_unlisted_or_unknown_hubs_are_refused`).

Blobs (Q6, H5-B1) are covered by the federation suite (fed §11.3 T14) and
`crates/gim-hub-api/tests/federation_blobs.rs`: a co-host is a reader hub like any other, so it
fetches and caches the blob the same way, and while the origin is down it serves only copies it
fetched before (others are 503 `peer_unavailable`).

MH1-MH6, MH8 cover the plan's M2c acceptance: messaging continues with one hub stopped (MH3),
no duplicate messages (MH2, MH4), no KeyPackage claimed twice (MH5), migration without loss
(MH8). The in-process suite (fed §11.1) gets MH1, MH4 and MH5 with a dropped and restarted hub.

## 12. Implementation breakdown

Shared append-only files as in fed §12 (`migrate.rs` list, `dto.rs`, route table, `openapi.json`
regenerated).

| Subtask | Scope | Owns | Depends on |
|---|---|---|---|
| H4-M1 contract | §9.1 proto diff and `s2s.md`; §9.2 DTOs, `hosting_record.updated` payload type, `GET /v2/hub`, error code `duplicate_key_package`, `api-v2.md`; op dispatch stubs (`INTERNAL` "not implemented") | `proto/s2s.proto`, `docs/s2s.md`, `docs/api-v2.md`, `crates/gim-hub-proto/**`, `crates/gim-hub-api/src/{dto.rs,handlers/health.rs}`, `crates/gim-hub-s2s/src/ops/mod.rs` | sign-off of §9 |
| H4-M2 record propagation and removal | §3.2, §4.2, §4.5, §7.3: `NotifyHostingRecord` send/receive, hub-set diff hook API (called in the record-store transaction), `device_list_peer_hubs` co-hosts, removed state, write refusal, purge in retention, `0007_multihoming.sql` | `crates/gim-hub-db/migrations/0007_multihoming.sql`, `crates/gim-hub-db/src/{hosting.rs,remote_identity.rs,outbox.rs}`, `crates/gim-hub-s2s/src/hosting/**`, `crates/gim-hub-s2s/src/ops/hosting_record.rs`, `crates/gim-hub-s2s/src/outbox/**`, `crates/gim-hub-api/src/handlers/{hosting.rs,identity.rs}`, `crates/gim-hub-api/src/auth.rs` (write gate) | M1 |
| H4-M3 bootstrap | §4.3, §4.4, §2.2: owner seeding via the M2 hook, `SeedReplica` receive, `CopyPendingWelcomes` send/receive, DeliverWelcome to all listed hubs (verify and test) | `crates/gim-hub-api/src/handlers/{groups.rs,welcomes.rs}`, `crates/gim-hub-db/src/{groups.rs,welcomes.rs}`, `crates/gim-hub-s2s/src/ops/{seed.rs,welcome.rs}` | M1, M2 |
| H4-M4 KeyPackages | §5.2, §5.3, §5.4: claim fallback and per-device follow-up, routing of removed users, `duplicate_key_package`, burns, `kp_not_claimed` message | `crates/gim-hub-api/src/handlers/keypackages.rs`, `crates/gim-hub-db/src/keypackages.rs`, `crates/gim-hub-s2s/src/ops/claim.rs`, `crates/gim-hub-api/src/mls.rs` (message only) | M1 |
| H4-M5 push gate and acceptance | §8: `PushGate` implementation, co-host ping and down state in `transport/`, config §10; §11 compose tests and fixtures, `docs/operations.md` multi-homing section | `crates/gim-hub-s2s/src/{multihoming.rs,transport/**,config.rs}`, `crates/gim-hub/tests/multihoming_compose.rs`, `deploy/federation/**` (multihoming fixtures), `docs/operations.md` | M2, M3, M4, H4-P1 (gate hook), H3-T6 (harness) |

Order: M1 → {M2, M4} in parallel → M3 → M5. M5's ping/down state can start after M1.

## 13. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Fan-out to every listed hub for application messages deviates from arch §9.2 (primary/fallback). | Adopt (§2.2): replicas need gap-free logs, and the traffic cost is bounded by the small number of hubs per user. Revisit only if users list many hubs. Needs L1 sign-off as an arch deviation. |
| Q2 | Hosting records carry `hub_id`s, not client API URLs; a device learning of an added hub from `hosting_record.updated` cannot connect without the URL. | gim-core syncs `hub_id → URL` through the self group (arch §9.4); the hub adds `GET /v2/hub` so the client can check a URL against the `hub_id` before signing in. Do not put URLs into the signed record (format owned by gim-core, and URLs change more often than hub keys). |
| Q3 | Should a forwarding hub or owner accept an Add whose `kp_ref` is not in its ledger when the committer is multi-homed (failover between claim and commit)? | No for M2c: the client re-claims through the hub it commits through (§5.4). Relaxing would let an Add use a package that is still claimable on its hub. Revisit with a cross-hub ledger query if re-claims waste too many packages. |
| Q4 | Replicas seeded on an added hub serve no history before the seed (§4.3). | Accept: devices already hold that history from their other hubs; a device restored from backup reads it from the owner's log via another hub or uses `FetchLog`-backed reads if fed Q4 is ever implemented. |
| Q5 | Migrating away from a hub that will be shut down loses the groups it owns (owning-hub migration out of scope, plan D8). | Document in the client: a hub that owns groups should stay up (as owner only) after removal; decommissioning needs owning-hub migration (a later milestone). gim-core SHOULD warn when the removed hub owns groups the user is in. |
| Q6 | Blobs live only on the hub they were uploaded to; while that hub is down, attachments are unavailable. | Closed by H5-B1 (fed §5.6): blob ids name their origin hub and every other hub, co-hosts included, fetches a blob from the origin with `FetchBlob` on first download and caches it. While the origin is down a co-host that already cached a copy keeps serving it; a hub that never fetched it answers 503 `peer_unavailable`. No replication to co-hosts at upload time. |
| Q7 | Push failover can miss notifications for messages in the first `GIM_HUB_PUSH_FAILOVER_SECONDS` after the primary stops (§8). | Accept for M2c: the delay prevents double pushes during short blips, and the messages are on the stream. An S2S "pushed" receipt between co-hosts (oneof range 30-39) can close the gap later if needed. |
| Q8 | Pending Welcome acknowledgements are not propagated between co-hosts (§4.4). | Accept: the device acknowledges on every hub where it sees the Welcome; unacknowledged copies on removed hubs are purged with the user's data. A propagation op adds traffic and a new trust question for little gain. |
| Q9 | `NotifyHostingRecord` admits a removed hub as sender (it is listed in the superseded record). A malicious removed hub could only resend the genuine signed record. | Accept: the record is self-certifying and the seq rules make resends no-ops. |
