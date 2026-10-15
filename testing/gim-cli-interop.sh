#!/usr/bin/env bash
# Runs the gim CLI-to-CLI interop test (apps/gim-cli/tests/interop.rs)
# against a disposable gim-hub container.
#
# Starts the hub with scripts/gim-hub-dev.sh (stopped on exit) and runs the
# test in a rust:1 container on the same network.
#
# Env: GIM_HUB_SRC, GIM_HUB_REV (default 9608f34), GIM_HUB_BUILD (see
# scripts/gim-hub-dev.sh).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hub=ai-agent-gim-hub-cli-$(git -C "$repo" rev-parse --short HEAD)
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
    rust:1 cargo test -p gim-cli --test interop -- --nocapture
