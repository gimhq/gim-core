#!/usr/bin/env bash
# Regenerates the committed Kotlin and Swift bindings of gim-ffi.
#
#   scripts/generate-bindings.sh            # use the local Rust toolchain
#   scripts/generate-bindings.sh --docker   # run inside the rust:1 container
#
# Re-run after any change to the gim-ffi API and commit the result.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"

if [[ "${1:-}" == "--docker" ]]; then
    cache=/srv/.tmp/cache/cargo
    mkdir -p "$cache"
    docker run --rm --label ai-agent=true \
        -v "$repo:$repo" -w "$repo" \
        -v "$cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
        rust:1 sh -c "scripts/generate-bindings.sh && chown -R $(id -u):$(id -g) bindings/gim-ffi/generated target"
    exit 0
fi

out=bindings/gim-ffi/generated
cargo build -p gim-ffi
for language in kotlin swift; do
    rm -rf "${out:?}/$language"
    cargo run -p uniffi-bindgen -- generate \
        --library target/debug/libgim_core.so \
        --language "$language" \
        --no-format \
        --out-dir "$out/$language"
done
