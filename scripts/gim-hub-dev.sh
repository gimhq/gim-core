#!/usr/bin/env bash
# Runs a disposable gim-hub container for local interop and integration runs.
#
# Sibling repos (gim-android, gim-ios) call this from their own scripts:
#   url=$(scripts/gim-hub-dev.sh start)
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: gim-hub-dev.sh <start|stop|ip|url|status|commit|logs> [name]
       gim-hub-dev.sh <build|rev>
       gim-hub-dev.sh <fed-start|fed-stop> <run>

Commands:
  start   Build the image (unless GIM_HUB_BUILD=0), start the container
          (reusing it if already running) with GIM_HUB_PUBLIC_URL, wait for
          /healthz and print that URL on stdout. Status messages, including
          the hub commit, go to stderr.
  stop    Stop the container (it runs with --rm); no error if already gone.
  ip      Print the container IP on GIM_HUB_NETWORK; exit 1 if not running.
  url     Print the hub's public URL; exit 1 if not running.
  status  Print running/stopped; exit 0 if running, 1 otherwise.
  commit  Print the hub commit the image was built from.
  logs    Pass through to docker logs.
  build   Build the image (always, regardless of GIM_HUB_BUILD).
  rev     Print GIM_HUB_REV (the pinned hub commit CI checks out).

Closed federation (multi-hub mode):
  fed-start  Build the image (unless GIM_HUB_BUILD=0) and start GIM_FED_HUBS
             hubs (a, b and with 3 also c) allowing each other, plus hub x
             that no other hub allows (its own allowlist lists hub a), on a
             new network ai-agent-gim-fed-<run>. Each hub has its own root
             key in a named volume (kept across `docker stop`/`start`); all
             share a generated libp2p PSK (TCP only), so x is refused by the
             allowlist rather than by the network. Waits for every hub's
             /healthz and for a, b (and c) to have bound each other, then
             prints KEY=VALUE lines on stdout: GIM_FED_NETWORK,
             GIM_FED_HUB_<X>=http://hub-<x>:8080 (reachable on that network,
             and each hub's GIM_HUB_PUBLIC_URL),
             GIM_FED_CONTAINER_<X> and GIM_FED_HUB_ID_<X>.
  fed-stop   Remove the run's containers, network, volumes and config dir
             (everything labelled ai-agent-run=gim-fed-<run>).

Arguments:
  name    Container name; overrides GIM_HUB_NAME. Prefixed with "ai-agent-"
          if it does not already start with it.
  run     Id of a federation run, unique per concurrent run.

Env:
  GIM_HUB_SRC      gim-hub git checkout (default /srv/gimhq/im-client/hub)
  GIM_HUB_REV      commit to build (default
                   50b3401726c99781e30b7c0311f5c63a56bc5657); exported with
                   `git archive`, so local changes in the checkout are ignored
  GIM_HUB_CHECKOUT directory holding gim-hub at GIM_HUB_REV (e.g. a CI
                   checkout); when set, the image is built from it as is,
                   with no `git archive` of GIM_HUB_SRC. If it is a git
                   checkout, its HEAD must be GIM_HUB_REV.
  GIM_HUB_NAME     container name (default ai-agent-gim-hub-dev)
  GIM_HUB_IMAGE    image tag (default ai-agent/gim-hub)
  GIM_HUB_NETWORK  docker network (default traefik)
  GIM_HUB_BUILD    1 = build image on start (default), 0 = reuse image
  GIM_HUB_PUBLIC_URL  start: the hub's public URL (default
                   http://<name>:8080, reachable by name on GIM_HUB_NETWORK).
                   gim-core signs in only at the URL the hub proves, so
                   clients must use exactly this URL; set it when they reach
                   the hub another way (e.g. a published port).
  GIM_FED_HUBS     federation: 2 (default) or 3 allowlisted hubs
EOF
}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GIM_HUB_SRC=${GIM_HUB_SRC:-/srv/gimhq/im-client/hub}
GIM_HUB_REV=${GIM_HUB_REV:-50b3401726c99781e30b7c0311f5c63a56bc5657}
GIM_HUB_IMAGE=${GIM_HUB_IMAGE:-ai-agent/gim-hub}
GIM_HUB_NETWORK=${GIM_HUB_NETWORK:-traefik}
GIM_HUB_BUILD=${GIM_HUB_BUILD:-1}

cmd=${1:-}
case "$cmd" in
    -h | --help | help)
        usage
        exit 0
        ;;
    start | stop | ip | url | status | commit | logs | build | rev | fed-start | fed-stop) ;;
    *)
        usage >&2
        exit 2
        ;;
esac

case "$cmd" in
    fed-*)
        if [ -z "${2:-}" ]; then
            usage >&2
            exit 2
        fi
        ;;
esac
name=${2:-${GIM_HUB_NAME:-ai-agent-gim-hub-dev}}
case "$name" in
    ai-agent-*) ;;
    *) name=ai-agent-$name ;;
esac
image=$GIM_HUB_IMAGE
net=$GIM_HUB_NETWORK

is_running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ]
}

container_ip() {
    local ip
    ip=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"$net\"}}{{.IPAddress}}{{end}}" \
        "$name" 2>/dev/null) || true
    if ! is_running || [ -z "$ip" ]; then
        echo "$name is not running on network $net" >&2
        return 1
    fi
    echo "$ip"
}

# The public URL the running container was started with.
public_url() {
    container_ip >/dev/null || return 1
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$name" |
        sed -n 's/^GIM_HUB_PUBLIC_URL=//p'
}

image_commit() {
    docker image inspect -f '{{index .Config.Labels "gim.hub.commit"}}' "$image" 2>/dev/null
}

# Builds the image from a clean export of GIM_HUB_REV in a project-scoped
# temp dir, never from the (possibly dirty) checkout itself.
build() {
    local commit tmp
    if [ -n "${GIM_HUB_CHECKOUT:-}" ]; then
        build_checkout
        return
    fi
    commit=$(git -C "$GIM_HUB_SRC" rev-parse --verify "$GIM_HUB_REV^{commit}")
    tmp=$repo/.tmp/gim-hub-src-$$
    rm -rf "$tmp"
    mkdir -p "$tmp"
    git -C "$GIM_HUB_SRC" archive "$commit" | tar -x -C "$tmp"
    echo "building $image from $GIM_HUB_SRC @ $commit" >&2
    local status=0
    docker build --label ai-agent=true --label "gim.hub.commit=$commit" \
        -t "$image" "$tmp" >&2 || status=$?
    rm -rf "$tmp"
    return "$status"
}

# Builds the image from GIM_HUB_CHECKOUT, a directory that already holds
# GIM_HUB_REV (CI checks it out with actions/checkout).
build_checkout() {
    local src=$GIM_HUB_CHECKOUT commit=$GIM_HUB_REV head
    if [ -e "$src/.git" ]; then
        head=$(git -C "$src" rev-parse HEAD)
        commit=$(git -C "$src" rev-parse --verify "$GIM_HUB_REV^{commit}")
        if [ "$head" != "$commit" ]; then
            echo "$src is at $head, expected GIM_HUB_REV $GIM_HUB_REV" >&2
            return 1
        fi
    fi
    echo "building $image from $src @ $commit" >&2
    docker build --label ai-agent=true --label "gim.hub.commit=$commit" \
        -t "$image" "$src" >&2
}

wait_healthy() {
    local _
    for _ in $(seq 1 60); do
        if docker exec "$name" gim-hub healthcheck >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

start() {
    if is_running; then
        echo "reusing running container $name" >&2
    else
        if [ "$GIM_HUB_BUILD" != 0 ]; then
            build
        fi
        echo "starting $name on $net" >&2
        # Disposable: the hub's data lives in memory and goes with it.
        docker run -d --rm --label ai-agent=true --network "$net" --name "$name" \
            --tmpfs /data:rw,uid=10001,gid=10001,mode=0700 \
            -e "GIM_HUB_PUBLIC_URL=${GIM_HUB_PUBLIC_URL:-http://$name:8080}" \
            "$image" >/dev/null
    fi

    echo "waiting for $name /healthz" >&2
    if ! wait_healthy; then
        echo "gim-hub did not become healthy" >&2
        docker logs "$name" >&2 || true
        docker stop "$name" >/dev/null 2>&1 || true
        exit 1
    fi
    echo "gim-hub commit: $(image_commit)" >&2
    public_url
}


# Closed federation: hubs a, b (c) allow each other; x is allowed by nobody.
fed_prefix=ai-agent-gim-fed-${2:-}
fed_label=ai-agent-run=gim-fed-${2:-}
fed_dir=$repo/.tmp/gim-fed-${2:-}

fed_hubs() {
    case "${GIM_FED_HUBS:-2}" in
        2) echo a b ;;
        3) echo a b c ;;
        *)
            echo "GIM_FED_HUBS must be 2 or 3" >&2
            return 1
            ;;
    esac
}

fed_stop() {
    docker ps -aq --filter "label=$fed_label" | xargs -r docker rm -f >/dev/null
    docker network ls -q --filter "label=$fed_label" | xargs -r docker network rm >/dev/null
    docker volume ls -q --filter "label=$fed_label" | xargs -r docker volume rm >/dev/null
    rm -rf "$fed_dir"
}

# Waits until hub $1's log shows a binding of every hub id in $2...
fed_wait_bound() {
    local hub=$1 _ id missing
    shift
    for _ in $(seq 1 60); do
        missing=
        for id in "$@"; do
            docker logs "$fed_prefix-$hub" 2>&1 | grep "peer hub bound" | grep -q "$id" ||
                missing=$id
        done
        [ -z "$missing" ] && return 0
        sleep 1
    done
    echo "hub-$hub did not bind $missing" >&2
    return 1
}

fed_start() {
    local hubs hub id labels=(--label ai-agent=true --label "$fed_label")
    hubs=$(fed_hubs)
    declare -A hub_id
    if [ "$GIM_HUB_BUILD" != 0 ]; then
        build
    fi
    fed_stop
    mkdir -p "$fed_dir"
    {
        echo "/key/swarm/psk/1.0.0/"
        echo "/base16/"
        od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
        echo
    } >"$fed_dir/swarm.key"
    docker network create "${labels[@]}" "$fed_prefix" >/dev/null
    for hub in $hubs x; do
        docker volume create "${labels[@]}" "$fed_prefix-$hub" >/dev/null
        # Creates the hub root key in the volume and prints its hub_id.
        hub_id[$hub]=$(docker run --rm "${labels[@]}" -v "$fed_prefix-$hub:/data" \
            "$image" gim-hub hub-id | tr -d '\r\n')
        echo "hub-$hub hub_id ${hub_id[$hub]}" >&2
    done
    for hub in $hubs; do
        echo "${hub_id[$hub]} /dns4/hub-$hub/tcp/4001"
    done >"$fed_dir/allowlist"
    echo "${hub_id[a]} /dns4/hub-a/tcp/4001" >"$fed_dir/allowlist-x"
    chmod 0755 "$fed_dir"
    chmod 0644 "$fed_dir"/*

    local allowlist
    for hub in $hubs x; do
        allowlist=allowlist
        [ "$hub" = x ] && allowlist=allowlist-x
        docker run -d "${labels[@]}" --name "$fed_prefix-$hub" \
            --network "$fed_prefix" --network-alias "hub-$hub" \
            -v "$fed_prefix-$hub:/data" -v "$fed_dir:/config:ro" \
            -e RUST_LOG=info \
            -e GIM_HUB_FEDERATION=true \
            -e "GIM_HUB_PUBLIC_URL=http://hub-$hub:8080" \
            -e GIM_HUB_P2P_LISTEN=/ip4/0.0.0.0/tcp/4001 \
            -e "GIM_HUB_P2P_EXTERNAL_ADDRS=/dns4/hub-$hub/tcp/4001" \
            -e "GIM_HUB_FEDERATION_ALLOWLIST=/config/$allowlist" \
            -e GIM_HUB_P2P_PSK_FILE=/config/swarm.key \
            -e GIM_HUB_S2S_TIMEOUT_SECONDS=3 \
            -e GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS=2 \
            "$image" >/dev/null
    done
    for hub in $hubs x; do
        name=$fed_prefix-$hub
        echo "waiting for $name /healthz" >&2
        if ! wait_healthy; then
            echo "$name did not become healthy" >&2
            docker logs "$name" >&2 || true
            return 1
        fi
    done
    local others
    for hub in $hubs; do
        others=()
        for id in $hubs; do
            [ "$id" != "$hub" ] && others+=("${hub_id[$id]}")
        done
        fed_wait_bound "$hub" "${others[@]}" || return 1
    done
    echo "gim-hub commit: $(image_commit)" >&2

    echo "GIM_FED_NETWORK=$fed_prefix"
    for hub in $hubs x; do
        local upper=${hub^^}
        echo "GIM_FED_HUB_$upper=http://hub-$hub:8080"
        echo "GIM_FED_CONTAINER_$upper=$fed_prefix-$hub"
        echo "GIM_FED_HUB_ID_$upper=${hub_id[$hub]}"
    done
}

case "$cmd" in
    start) start ;;
    build) build ;;
    rev) echo "$GIM_HUB_REV" ;;
    fed-start) fed_start ;;
    fed-stop) fed_stop ;;
    stop) docker stop "$name" >/dev/null 2>&1 || true ;;
    ip) container_ip ;;
    url) public_url ;;
    status)
        if is_running; then
            echo running
        else
            echo stopped
            exit 1
        fi
        ;;
    commit) image_commit ;;
    logs) docker logs "$name" ;;
esac
