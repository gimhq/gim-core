# 20261022-2039-p0-core-cleanup-wasm P0: core cleanup and wasm32 build

- **status**: completed
- **priority**: P1
- **owner**: claude/gim-core-p0
- **createdAt**: 2026-10-22 20:39

## Description

Phase 0 of plan `20261022-repo-split-client-sdk-mac-web`:

1. Remove the gim-server v1 remnants.
2. Build `gim-common`, `gim-proto`, `gim-identity`, `gim-crypto` and `gim-base`
   for `wasm32-unknown-unknown`, enforced by a CI job.
3. Design check: store traits usable from a single-threaded (web) runtime.

Acceptance: fmt, clippy and test stay green; the wasm32 build of the five
crates passes locally and in CI; no behaviour change on native targets.

## ActiveForm

Cleaning up gim-core and building the protocol crates for wasm32

## Dependencies

- **blocked by**: (none)
- **blocks**: Phase 1 (gim-client-sdk repository)

## Notes

(none)

- complete: Native fmt, clippy -D warnings and cargo test (100 suites, 591 tests) pass; clippy -D warnings passes for wasm32-unknown-unknown on each of the five protocol crates. Integration suites not run locally (no SDK code changed). Findings recorded in the plan under Phase 0.
