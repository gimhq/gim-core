#!/usr/bin/env bash
# Runs the gim CLI-to-CLI interop test (apps/gim-cli/tests/interop.rs)
# against a disposable gim-hub container.
#
# Starts the hub with scripts/gim-hub-dev.sh (stopped on exit) and runs the
# test in a rust:1 container on the same network.
#
# With GIM_FEDERATION=1 it starts a closed federation instead
# (`gim-hub-dev.sh fed-start`, removed on exit) and runs the cross-hub
# variant (cli_to_cli_interop_across_hubs): profiles on hub a and hub b.
#
# Env: GIM_HUB_SRC, GIM_HUB_REV (default
# 18afc7bdde8cd643e4f4e21a35758fdb3a0bc155), GIM_HUB_BUILD,
# GIM_HUB_IMAGE (see scripts/gim-hub-dev.sh); GIM_FEDERATION=1.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cargo_cache=/srv/.tmp/cache/cargo
mkdir -p "$cargo_cache"

if [ "${GIM_FEDERATION:-0}" = 1 ]; then
    run=cli-$(git -C "$repo" rev-parse --short HEAD)-$$
    cleanup() {
        "$repo/scripts/gim-hub-dev.sh" fed-stop "$run"
    }
    trap cleanup EXIT

    env_file=$(mktemp)
    "$repo/scripts/gim-hub-dev.sh" fed-start "$run" >"$env_file"
    network=$(sed -n 's/^GIM_FED_NETWORK=//p' "$env_file")
    hub_a=$(sed -n 's/^GIM_FED_HUB_A=//p' "$env_file")
    hub_b=$(sed -n 's/^GIM_FED_HUB_B=//p' "$env_file")
    rm -f "$env_file"

    docker run --rm --label ai-agent=true --label "ai-agent-run=gim-fed-$run" \
        --network "$network" \
        -v "$repo:$repo" -w "$repo" \
        -v "$cargo_cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
        -e GIM_HUB_URL="$hub_a" -e GIM_HUB_URL_B="$hub_b" \
        rust:1 cargo test -p gim-cli --test interop cli_to_cli_interop_across_hubs -- --nocapture
    exit 0
fi

hub=ai-agent-gim-hub-cli-$(git -C "$repo" rev-parse --short HEAD)

cleanup() {
    "$repo/scripts/gim-hub-dev.sh" stop "$hub"
}
trap cleanup EXIT

"$repo/scripts/gim-hub-dev.sh" start "$hub" >/dev/null
echo "gim-hub commit under test: $("$repo/scripts/gim-hub-dev.sh" commit "$hub")"

docker run --rm --label ai-agent=true --network traefik \
    -v "$repo:$repo" -w "$repo" \
    -v "$cargo_cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
    -e GIM_HUB_URL="http://$hub:8080" \
    rust:1 cargo test -p gim-cli --test interop -- --nocapture
