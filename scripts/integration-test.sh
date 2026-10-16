#!/usr/bin/env bash
# Runs testing/gim-integration-testing against a real gim-hub container.
#
# Builds gim-hub (GIM_HUB_SRC at GIM_HUB_REV, pinned in
# scripts/gim-hub-dev.sh), starts it on GIM_HUB_NETWORK (default traefik)
# with GIM_HUB_PUBLIC_URL http://<container>:8080, the URL the tests use,
# waits for /healthz and runs the tests in a rust:1 container on the same
# network. The hub container is always stopped on exit; its logs are printed
# on failure. The hub commit is printed before the tests run. The hub
# pushes membership events (GIM_HUB_PUSH_MEMBER_EVENTS=true); a second hub
# from the same image sends minimal push payloads (GIM_HUB_PUSH_MINIMAL=true,
# GIM_HUB_MINIMAL_URL in the tests). Both serve the test push log.
#
# With GIM_FEDERATION=1 it runs the federation suite
# (tests/federation.rs) instead: `gim-hub-dev.sh fed-start` starts a closed
# federation of GIM_FED_HUBS (2 or 3) hubs plus a hub nobody allows on a
# network of its own, and the tests run one at a time on that network with
# the Docker socket mounted (they stop and start hub b). Hub logs are
# printed on failure; containers, network and volumes are always removed.
#
# With GIM_MULTIHOMING=1 it runs the multi-homing suite
# (tests/multihoming.rs) the same way on a federation of three hubs
# (GIM_FED_HUBS=3; the tests stop and start hub a).
#
# Env: SUBTASK_ID (default: short git sha) names the hub container;
#      GIM_HUB_SRC, GIM_HUB_REV, GIM_HUB_CHECKOUT, GIM_HUB_BUILD,
#      GIM_HUB_IMAGE, GIM_HUB_NETWORK, GIM_FED_HUBS (see
#      scripts/gim-hub-dev.sh); GIM_FEDERATION=1 for the federation suite,
#      GIM_MULTIHOMING=1 for the multi-homing suite;
#      GIM_CARGO_CACHE: CARGO_HOME mounted into the test container (default
#      /srv/.tmp/cache/cargo); CARGO_INCREMENTAL, CARGO_PROFILE_DEV_DEBUG,
#      CARGO_PROFILE_TEST_DEBUG and CARGO_TERM_COLOR are passed through when
#      set; extra arguments are passed to the test binaries (e.g. a test
#      name).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SUBTASK_ID=${SUBTASK_ID:-$(git -C "$repo" rev-parse --short HEAD)}
cargo_cache=${GIM_CARGO_CACHE:-/srv/.tmp/cache/cargo}
mkdir -p "$cargo_cache"
cargo_env=(-e CARGO_INCREMENTAL -e CARGO_PROFILE_DEV_DEBUG
    -e CARGO_PROFILE_TEST_DEBUG -e CARGO_TERM_COLOR)

if [ "${GIM_FEDERATION:-0}" = 1 ] || [ "${GIM_MULTIHOMING:-0}" = 1 ]; then
    suite=federation
    if [ "${GIM_MULTIHOMING:-0}" = 1 ]; then
        suite=multihoming
        export GIM_FED_HUBS=3
    fi
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
        "${cargo_env[@]}" "${env_args[@]}" \
        rust:1 cargo test -p gim-integration-testing --test "$suite" --no-fail-fast \
        -- --include-ignored --nocapture --test-threads 1 "$@"
    status=0
    exit 0
fi

hub=ai-agent-gim-hub-it-$SUBTASK_ID
minimal_hub=$hub-minimal
network=${GIM_HUB_NETWORK:-traefik}
status=1

cleanup() {
    for h in "$hub" "$minimal_hub"; do
        if [ "$status" != 0 ]; then
            echo "--- logs of $h" >&2
            "$repo/scripts/gim-hub-dev.sh" logs "$h" 2>&1 | tail -n 200 >&2 || true
        fi
        "$repo/scripts/gim-hub-dev.sh" stop "$h"
    done
}
trap cleanup EXIT

GIM_HUB_PUSH_MEMBER_EVENTS=true "$repo/scripts/gim-hub-dev.sh" start "$hub" >/dev/null
GIM_HUB_BUILD=0 GIM_HUB_PUSH_MINIMAL=true \
    "$repo/scripts/gim-hub-dev.sh" start "$minimal_hub" >/dev/null
echo "gim-hub commit under test: $("$repo/scripts/gim-hub-dev.sh" commit "$hub")"

docker run --rm --label ai-agent=true --network "$network" \
    -v "$repo:$repo" -w "$repo" \
    -v "$cargo_cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
    "${cargo_env[@]}" -e GIM_HUB_URL="http://$hub:8080" \
    -e GIM_HUB_PUSH_MEMBER_EVENTS=true -e GIM_HUB_MINIMAL_URL="http://$minimal_hub:8080" \
    rust:1 cargo test -p gim-integration-testing --no-fail-fast -- --include-ignored --nocapture "$@"
status=0
