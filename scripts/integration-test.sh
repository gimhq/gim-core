#!/usr/bin/env bash
# Runs testing/gim-integration-testing against a real gim-hub container.
#
# Builds gim-hub (GIM_HUB_SRC at GIM_HUB_REV, default 9608f34, see
# scripts/gim-hub-dev.sh), starts it on the traefik network, waits for /healthz and runs the tests in
# a rust:1 container on the same network. The hub container is always
# stopped on exit. The hub commit is printed before the tests run.
#
# With GIM_FEDERATION=1 it runs the federation suite
# (tests/federation.rs) instead: `gim-hub-dev.sh fed-start` starts a closed
# federation of GIM_FED_HUBS (2 or 3) hubs plus a hub nobody allows on a
# network of its own, and the tests run one at a time on that network with
# the Docker socket mounted (they stop and start hub b). Hub logs are
# printed on failure; containers, network and volumes are always removed.
#
# Env: SUBTASK_ID (default: short git sha) names the hub container;
#      GIM_HUB_SRC, GIM_HUB_REV, GIM_HUB_BUILD, GIM_HUB_IMAGE, GIM_FED_HUBS
#      (see scripts/gim-hub-dev.sh); GIM_FEDERATION=1 for the federation
#      suite; extra arguments are passed to the test binaries (e.g. a test
#      name).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SUBTASK_ID=${SUBTASK_ID:-$(git -C "$repo" rev-parse --short HEAD)}
cargo_cache=/srv/.tmp/cache/cargo
mkdir -p "$cargo_cache"

if [ "${GIM_FEDERATION:-0}" = 1 ]; then
    run=$SUBTASK_ID-$$
    status=1
    cleanup() {
        if [ "$status" != 0 ]; then
            for c in $(docker ps -aq --filter "label=ai-agent-run=gim-fed-$run"); do
                echo "--- logs of $(docker inspect -f '{{.Name}}' "$c")" >&2
                docker logs --tail 200 "$c" >&2 || true
            done
        fi
        "$repo/scripts/gim-hub-dev.sh" fed-stop "$run"
    }
    trap cleanup EXIT

    env_file=$(mktemp)
    "$repo/scripts/gim-hub-dev.sh" fed-start "$run" >"$env_file"
    env_args=()
    while IFS= read -r line; do
        env_args+=(-e "$line")
    done <"$env_file"
    rm -f "$env_file"
    network=$(printf '%s\n' "${env_args[@]}" | sed -n 's/^GIM_FED_NETWORK=//p')
    echo "gim-hub commit under test: $(docker image inspect -f '{{index .Config.Labels "gim.hub.commit"}}' "${GIM_HUB_IMAGE:-ai-agent/gim-hub}")"

    docker run --rm --label ai-agent=true --label "ai-agent-run=gim-fed-$run" \
        --network "$network" \
        -v "$repo:$repo" -w "$repo" \
        -v "$cargo_cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
        -v /var/run/docker.sock:/var/run/docker.sock \
        "${env_args[@]}" \
        rust:1 cargo test -p gim-integration-testing --test federation --no-fail-fast \
        -- --include-ignored --nocapture --test-threads 1 "$@"
    status=0
    exit 0
fi

hub=ai-agent-gim-hub-it-$SUBTASK_ID

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
    rust:1 cargo test -p gim-integration-testing --no-fail-fast -- --include-ignored --nocapture "$@"
