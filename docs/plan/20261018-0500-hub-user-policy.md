# H12: gim-hub user allow/deny list

Status: approved 2026-10-18 (user: "黑名单方案同意"; request: "hub可以做黑白名单方式，有一个黑名单和白名单选项，可以配置只转发特定用户或者拒绝特定用户")
Repo: `hub/` (gimhq/gim-hub), workstream gim-hub (BKD cvl4rl1o); small follow-ups in core and the clients

## 1. Decisions

| # | Decision |
|---|---|
| U1 | One policy per hub: `GIM_HUB_USER_POLICY = open` (default, today's behaviour) \| `allow` (only listed users) \| `deny` (everyone except listed users) |
| U2 | Built on H14 (configuration in SQLite, approved 2026-10-18): the mode is a stored setting and the list a table of `user_id`s, edited in the admin UI and the `gim-hub config` CLI (validated, applied at once, audited). The environment variable `GIM_HUB_USER_POLICY` overrides the stored mode (H14 S3) |
| U3 | Entries are `user_id`s (the stable identity), not handles; the admin UI resolves a handle to its `user_id` when adding |
| U4 | A user the policy rejects is "not admitted". Local use: the first DeviceList upload (registration) is refused, sign-in answers 403 `user_not_admitted`, and existing sessions are deleted when the list changes. This subsumes the per-user suspension for policy use; suspension stays as the quick admin action |
| U5 | Relay (federation): the hub refuses traffic acting for a non-admitted remote user wherever the request names that user and refusing is safe: `ClaimKeyPackage` (cannot start a chat with local users), `DeliverWelcome` (cannot invite local users), `SubmitCommit` / `SubmitMessage` on groups this hub owns (cannot post in them). It does not drop single `Deliver` entries of groups owned elsewhere: that breaks the group's sequence and MLS state; local members remove such a user through MLS |
| U6 | Metadata only, as in H10: the hub decides on `user_id`s it already sees, no message content |

## 2. Scope

- Hub: policy and list loader, enforcement points of U4 and U5, admin UI page (mode shown, list view and edit, handle lookup), audit entries, docs (`operations.md`, `admin.md`, `api-v2.md`, `s2s.md`), new error code `user_not_admitted` (client API 403; S2S `UNAUTHORIZED`).
- Core: map 403 `user_not_admitted` like `UserSuspended` (typed error, no sign-in loop); a refused ClaimKeyPackage / Welcome surfaces as a distinct error to the sender.
- Clients: show "not admitted on this hub" and "this user does not accept contacts from you" where the core errors arrive.

Out of scope: per-group policy, handle patterns or wildcards, hub-level blocking (that is the federation allowlist).

## 3. Acceptance

- Unit tests of the loader and of every enforcement point in both modes; SIGHUP and admin edit apply at once and are audited.
- Federation test: in `allow` and `deny` mode a non-admitted remote user cannot claim a KeyPackage of, invite, or post in a group owned by the policy hub; admitted users are unaffected; existing groups owned elsewhere keep working.
- `scripts/check.sh`, fed-test (fed, mh), lode-smoke and admin-e2e stay green; core and client gates as usual.
