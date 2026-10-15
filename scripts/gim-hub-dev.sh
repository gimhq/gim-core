#!/usr/bin/env bash
# Runs a disposable gim-hub container for local interop and integration runs.
#
# Sibling repos (gim-android, gim-ios) call this from their own scripts:
#   url=$(scripts/gim-hub-dev.sh start)
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: gim-hub-dev.sh <start|stop|ip|url|status|commit|logs> [name]

Commands:
  start   Build the image (unless GIM_HUB_BUILD=0), start the container
          (reusing it if already running), wait for /healthz and print
          http://<ip>:8080 on stdout. Status messages, including the hub
          commit, go to stderr.
  stop    Stop the container (it runs with --rm); no error if already gone.
  ip      Print the container IP on GIM_HUB_NETWORK; exit 1 if not running.
  url     Print http://<ip>:8080; exit 1 if not running.
  status  Print running/stopped; exit 0 if running, 1 otherwise.
  commit  Print the hub commit the image was built from.
  logs    Pass through to docker logs.

Arguments:
  name    Container name; overrides GIM_HUB_NAME. Prefixed with "ai-agent-"
          if it does not already start with it.

Env:
  GIM_HUB_SRC      gim-hub git checkout (default /srv/gimhq/im-client/hub)
  GIM_HUB_REV      commit to build (default e11ad00); exported with
                   `git archive`, so local changes in the checkout are ignored
  GIM_HUB_NAME     container name (default ai-agent-gim-hub-dev)
  GIM_HUB_IMAGE    image tag (default ai-agent/gim-hub)
  GIM_HUB_NETWORK  docker network (default traefik)
  GIM_HUB_BUILD    1 = build image on start (default), 0 = reuse image

Containers on the same network can also reach the hub by name:
  http://<name>:8080
EOF
}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GIM_HUB_SRC=${GIM_HUB_SRC:-/srv/gimhq/im-client/hub}
GIM_HUB_REV=${GIM_HUB_REV:-e11ad00}
GIM_HUB_IMAGE=${GIM_HUB_IMAGE:-ai-agent/gim-hub}
GIM_HUB_NETWORK=${GIM_HUB_NETWORK:-traefik}
GIM_HUB_BUILD=${GIM_HUB_BUILD:-1}

cmd=${1:-}
case "$cmd" in
    -h | --help | help)
        usage
        exit 0
        ;;
    start | stop | ip | url | status | commit | logs) ;;
    *)
        usage >&2
        exit 2
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

image_commit() {
    docker image inspect -f '{{index .Config.Labels "gim.hub.commit"}}' "$image" 2>/dev/null
}

# Builds the image from a clean export of GIM_HUB_REV in a project-scoped
# temp dir, never from the (possibly dirty) checkout itself.
build() {
    local commit tmp
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

    local ip
    ip=$(container_ip)
    echo "http://$ip:8080"
}

case "$cmd" in
    start) start ;;
    stop) docker stop "$name" >/dev/null 2>&1 || true ;;
    ip) container_ip ;;
    url)
        ip=$(container_ip)
        echo "http://$ip:8080"
        ;;
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
