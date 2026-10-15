#!/usr/bin/env bash
# Runs testing/gim-integration-testing against a real gim-hub container.
#
# Builds gim-hub (GIM_HUB_SRC at GIM_HUB_REV, default 9608f34, see
# scripts/gim-hub-dev.sh), starts it on the traefik network, waits for /healthz and runs the tests in
# a rust:1 container on the same network. The hub container is always
# stopped on exit. The hub commit is printed before the tests run.
#
# Env: SUBTASK_ID (default: short git sha) names the hub container;
#      GIM_HUB_SRC, GIM_HUB_REV, GIM_HUB_BUILD (see scripts/gim-hub-dev.sh);
#      extra arguments are passed to the test binaries (e.g. a test name).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SUBTASK_ID=${SUBTASK_ID:-$(git -C "$repo" rev-parse --short HEAD)}
hub=ai-agent-gim-hub-it-$SUBTASK_ID
cargo_cache=/srv/.tmp/cache/cargo

cleanup() {
    "$repo/scripts/gim-hub-dev.sh" stop "$hub"
}
trap cleanup EXIT

"$repo/scripts/gim-hub-dev.sh" start "$hub" >/dev/null
echo "gim-hub commit under test: $("$repo/scripts/gim-hub-dev.sh" commit "$hub")"

mkdir -p "$cargo_cache"
docker run --rm --label ai-agent=true --network traefik \
    -v "$repo:$repo" -w "$repo" \
    -v "$cargo_cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
    -e GIM_HUB_URL="http://$hub:8080" \
    rust:1 cargo test -p gim-integration-testing --no-fail-fast -- --include-ignored --nocapture "$@"
