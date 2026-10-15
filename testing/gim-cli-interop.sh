#!/usr/bin/env bash
# Runs the gim CLI-to-CLI interop test (apps/gim-cli/tests/interop.rs)
# against a disposable gim-server container.
#
# Starts the server with scripts/gim-server-dev.sh (stopped on exit) and runs
# the test in a rust:1 container on the same network.
#
# Env: GIM_SERVER_SRC, GIM_SERVER_BUILD (see scripts/gim-server-dev.sh).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server=ai-agent-gim-server-cli-$(git -C "$repo" rev-parse --short HEAD)
cargo_cache=/srv/.tmp/cache/cargo

cleanup() {
    "$repo/scripts/gim-server-dev.sh" stop "$server"
}
trap cleanup EXIT

"$repo/scripts/gim-server-dev.sh" start "$server" >/dev/null

mkdir -p "$cargo_cache"
docker run --rm --label ai-agent=true --network traefik \
    -v "$repo:$repo" -w "$repo" \
    -v "$cargo_cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
    -e GIM_SERVER_URL="http://$server:8080" \
    rust:1 cargo test -p gim-cli --test interop -- --nocapture
