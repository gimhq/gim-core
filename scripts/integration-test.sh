#!/usr/bin/env bash
# Runs testing/gim-integration-testing against a real gim-server container.
#
# Builds gim-server from GIM_SERVER_SRC, starts it on the traefik network,
# waits for /healthz and runs the tests in a rust:1 container on the same
# network. The server container is always stopped on exit.
#
# Env: SUBTASK_ID (default: short git sha) names the server container;
#      GIM_SERVER_SRC (default: /srv/gimhq/im-client/server).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SUBTASK_ID=${SUBTASK_ID:-$(git -C "$repo" rev-parse --short HEAD)}
GIM_SERVER_SRC=${GIM_SERVER_SRC:-/srv/gimhq/im-client/server}
server=ai-agent-gim-server-$SUBTASK_ID
cargo_cache=/srv/.tmp/cache/cargo

docker build --label ai-agent=true -t ai-agent/gim-server "$GIM_SERVER_SRC"

cleanup() {
    docker stop "$server" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --rm --label ai-agent=true --network traefik --name "$server" \
    ai-agent/gim-server >/dev/null

echo "waiting for $server /healthz"
healthy=
for _ in $(seq 1 60); do
    if docker exec "$server" bun -e \
        "fetch('http://127.0.0.1:8080/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))" \
        >/dev/null 2>&1; then
        healthy=1
        break
    fi
    sleep 1
done
if [ -z "$healthy" ]; then
    echo "gim-server did not become healthy" >&2
    docker logs "$server" >&2 || true
    exit 1
fi

mkdir -p "$cargo_cache"
docker run --rm --label ai-agent=true --network traefik \
    -v "$repo:$repo" -w "$repo" \
    -v "$cargo_cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
    -e GIM_SERVER_URL="http://$server:8080" \
    rust:1 cargo test -p gim-integration-testing -- --nocapture
