#!/usr/bin/env bash
# Runs a disposable gim-server container for local interop runs.
#
# Sibling repos (gim-android, gim-ios) call this from their own scripts:
#   url=$(scripts/gim-server-dev.sh start)
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: gim-server-dev.sh <start|stop|ip|url|status|logs> [name]

Commands:
  start   Build the image (unless GIM_SERVER_BUILD=0), start the container
          (reusing it if already running), wait for /healthz and print
          http://<ip>:8080 on stdout. Status messages go to stderr.
  stop    Stop the container (it runs with --rm); no error if already gone.
  ip      Print the container IP on GIM_SERVER_NETWORK; exit 1 if not running.
  url     Print http://<ip>:8080; exit 1 if not running.
  status  Print running/stopped; exit 0 if running, 1 otherwise.
  logs    Pass through to docker logs.

Arguments:
  name    Container name; overrides GIM_SERVER_NAME. Prefixed with
          "ai-agent-" if it does not already start with it.

Env:
  GIM_SERVER_SRC      server source dir (default /srv/gimhq/im-client/server)
  GIM_SERVER_NAME     container name (default ai-agent-gim-server-dev)
  GIM_SERVER_IMAGE    image tag (default ai-agent/gim-server)
  GIM_SERVER_NETWORK  docker network (default traefik)
  GIM_SERVER_BUILD    1 = build image on start (default), 0 = reuse image

Containers on the same network can also reach the server by name:
  http://<name>:8080
EOF
}

GIM_SERVER_SRC=${GIM_SERVER_SRC:-/srv/gimhq/im-client/server}
GIM_SERVER_IMAGE=${GIM_SERVER_IMAGE:-ai-agent/gim-server}
GIM_SERVER_NETWORK=${GIM_SERVER_NETWORK:-traefik}
GIM_SERVER_BUILD=${GIM_SERVER_BUILD:-1}

cmd=${1:-}
case "$cmd" in
    -h | --help | help)
        usage
        exit 0
        ;;
    start | stop | ip | url | status | logs) ;;
    *)
        usage >&2
        exit 2
        ;;
esac

name=${2:-${GIM_SERVER_NAME:-ai-agent-gim-server-dev}}
case "$name" in
    ai-agent-*) ;;
    *) name=ai-agent-$name ;;
esac
image=$GIM_SERVER_IMAGE
net=$GIM_SERVER_NETWORK

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

wait_healthy() {
    local _
    for _ in $(seq 1 60); do
        if docker exec "$name" bun -e \
            "fetch('http://127.0.0.1:8080/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))" \
            >/dev/null 2>&1; then
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
        if [ "$GIM_SERVER_BUILD" != 0 ]; then
            echo "building $image from $GIM_SERVER_SRC" >&2
            docker build --label ai-agent=true -t "$image" "$GIM_SERVER_SRC" >&2
        fi
        echo "starting $name on $net" >&2
        docker run -d --rm --label ai-agent=true --network "$net" --name "$name" \
            "$image" >/dev/null
    fi

    echo "waiting for $name /healthz" >&2
    if ! wait_healthy; then
        echo "gim-server did not become healthy" >&2
        docker logs "$name" >&2 || true
        docker stop "$name" >/dev/null 2>&1 || true
        exit 1
    fi

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
    logs) docker logs "$name" ;;
esac
