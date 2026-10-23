# 20261023-0638-p1-gim-client-sdk-repo P1: create the gim-client-sdk repository

- **status**: in_progress
- **priority**: P1
- **owner**: claude/gim-core-p1
- **createdAt**: 2026-10-23 06:38

## Description

Phase 1 of plan `20261022-repo-split-client-sdk-mac-web`: create
`gimhq/gim-client-sdk` (public) with history via `git filter-repo`, holding
the client runtime, bindings, CLI, integration tests and build scripts. It
depends on the gim-core protocol crates by git rev.

User decisions (2026-10-23): split the SDK into its own repository; gim-core
is the protocol core shared with the hub and is left as is for now.

Acceptance: fmt, clippy -D warnings and cargo test pass in gim-client-sdk
with `--locked`; generated bindings unchanged; CI workflow adapted.

## ActiveForm

Creating the gim-client-sdk repository

## Dependencies

- **blocked by**: 20261022-2039-p0-core-cleanup-wasm
- **blocks**: switching gim-ios and gim-android to SDK releases

## Notes

- `testing/gim-test` stays in gim-core: the gim-crypto and gim-base tests
  use it. The SDK uses it as a git dev-dependency.
- 2026-10-23: `/srv/gimhq/gim-client-sdk` extracted with history (374
  commits); gim-sqlite renamed to gim-store-sqlite; core crates and gim-test
  pinned by git rev `d2a58f8`; unused workspace deps dropped; CI paths and
  README adapted. fmt, clippy -D warnings, cargo test --locked (388 tests)
  pass; generated bindings unchanged. Pending: create the public GitHub
  repository and push (needs user permission).
- 2026-10-23: pushed to https://github.com/gimhq/gim-client-sdk (public,
  `main` at `a0301c5`). Open: SDK CI still gates the integration job on
  `GIM_HUB_DEPLOY_KEY` although gim-hub is public; remove the SDK crates from
  gim-core; switch gim-ios and gim-android to SDK releases.
