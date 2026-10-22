# H14: gim-hub configuration stored in SQLite

Status: approved 2026-10-18 (user: "批准"; request: "hub引入sqlite，用sqlite去做配置"; S3 environment-first precedence as proposed)
Repo: `hub/` (gimhq/gim-hub), workstream gim-hub (BKD cvl4rl1o)

The hub already keeps all its data in SQLite (`$GIM_HUB_DATA_DIR/hub.db`). Its configuration is
read only from `GIM_HUB_*` environment variables and two files (federation allowlist, PSK). This
plan moves the runtime configuration into `hub.db`, managed from the admin UI and a CLI.

## 1. Decisions

| # | Decision |
|---|---|
| S1 | Two tiers. Bootstrap settings stay environment-only, because they are needed before the database opens or to reach the admin UI: `GIM_HUB_DATA_DIR`, `GIM_HUB_DATABASE_PATH`, `GIM_HUB_LISTEN`, `GIM_HUB_ADMIN_LISTEN`, `GIM_HUB_ADMIN_TOKEN` / `_TOKEN_FILE`, `GIM_HUB_ADMIN_TRUSTED_HEADER` / `_TRUSTED_PROXIES`, `GIM_HUB_ADMIN_COOKIE_SECURE`. Every other setting is a stored setting |
| S2 | Stored settings live in a `settings` table (key, JSON value, updated_at, updated_by), created by a migration. Unset key = built-in default |
| S3 | Precedence: environment variable > stored value > default. A setting set by the environment is shown as "set by environment" and is read-only in the UI, so existing Docker/lode.toml deployments keep working unchanged |
| S4 | Lists move to tables: the federation allowlist (`federation_allowlist`) and the H12 user list. `GIM_HUB_FEDERATION_ALLOWLIST` (file) keeps working when set (S3) |
| S5 | Apply: settings that can change at runtime (rate limits, push options and webhook, retention, caches, outbox limits, allowlist) apply at once; the others (federation on/off, P2P listen/external/bootstrap, public URL, PSK) are saved and marked "restart required"; the UI offers a restart through lode when supervised |
| S6 | Validation is the same as today's environment parsing; an invalid value is refused on write, never stored. Secrets (push webhook secret, PSK) are write-only: the API and UI show only whether they are set |
| S7 | Every change is an `admin_audit` entry (key, old and new value; secrets redacted) |
| S8 | CLI for headless setup: `gim-hub config list | get <key> | set <key> <value> | unset <key>` on the same database (works while the hub runs; the hub picks the change up) |

## 2. Scope

- Hub: settings registry (key, type, default, validation, live or restart), loader with S3 precedence, migration, live-reload plumbing for the runtime settings, admin API (`GET/PUT/DELETE /admin/api/settings/{key}`) and UI settings page (grouped, edit, restart-required badge), the CLI, docs (`operations.md` tables gain a "stored / env-only / live" column, `admin.md`).
- H12 (user allow/deny list) is built on top of this: its mode is a stored setting and its list a table, not a file.
- H13 (admin token from env or file) is unaffected: the token is a bootstrap setting.

Out of scope: importing an existing environment into the database, multi-hub shared configuration, configuration history beyond the audit log.

## 3. Acceptance

- Unit tests: precedence (env > stored > default), validation refuses bad values, secrets never returned, each live setting takes effect without restart, restart-required settings apply after restart.
- Admin E2E: edit a live setting and see it applied, edit the allowlist in the UI, a setting set by the environment is read-only.
- CLI test against a running hub.
- `scripts/check.sh`, fed-test (fed, mh), lode-smoke and admin-e2e stay green; an existing env-only deployment upgrades with no change in behaviour.
