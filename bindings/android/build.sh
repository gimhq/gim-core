#!/usr/bin/env bash
# Builds the Android artifacts of gim-core in the ai-agent/gim-core-android
# container:
#
#   out/android/jniLibs/{arm64-v8a,x86_64}/libgim_core.so
#   out/android/kotlin/im/g/gimcore/*.kt
#   out/android/GIM_CORE_VERSION
#
# Environment:
#   SKIP_IMAGE_BUILD=1   reuse the existing image instead of rebuilding it
#   CARGO_CACHE_DIR      host directory mounted as CARGO_HOME
#                        (default /srv/.tmp/cache/cargo)
set -euo pipefail

image=ai-agent/gim-core-android
abis=(arm64-v8a x86_64)
out=out/android

# Runs inside the container; the host part below re-invokes this script.
if [[ "${GIM_ANDROID_IN_CONTAINER:-}" == "1" ]]; then
    trap 'chown -R "$HOST_UID:$HOST_GID" out target' EXIT
    rm -rf "$out"
    targets=()
    for abi in "${abis[@]}"; do
        targets+=(-t "$abi")
    done
    cargo ndk "${targets[@]}" --platform 26 -o "$out/jniLibs" build -p gim-ffi --release
    cargo run -p uniffi-bindgen -- generate \
        --library "$out/jniLibs/arm64-v8a/libgim_core.so" \
        --language kotlin \
        --no-format \
        --out-dir "$out/kotlin"
    pkgid=$(cargo pkgid -p gim-ffi)
    echo "${pkgid##*[#@]}+$GIT_SHA" > "$out/GIM_CORE_VERSION"
    exit 0
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"

if [[ "${SKIP_IMAGE_BUILD:-}" != "1" ]]; then
    docker build --label ai-agent=true -t "$image" -f docker/android.Dockerfile docker/
fi

cache=${CARGO_CACHE_DIR:-/srv/.tmp/cache/cargo}
mkdir -p "$cache"
commit=$(git rev-parse --short HEAD)

start=$SECONDS
docker run --rm --label ai-agent=true \
    -v "$repo:$repo" -w "$repo" \
    -v "$cache:/cache/cargo" -e CARGO_HOME=/cache/cargo \
    -e GIM_ANDROID_IN_CONTAINER=1 \
    -e GIT_SHA="$commit" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    "$image" bindings/android/build.sh

artifacts=("$out/GIM_CORE_VERSION")
for abi in "${abis[@]}"; do
    artifacts+=("$out/jniLibs/$abi/libgim_core.so")
done
shopt -s nullglob
kotlin=("$out"/kotlin/im/g/gimcore/*.kt)
if [[ ${#kotlin[@]} -eq 0 ]]; then
    echo "error: no Kotlin bindings in $out/kotlin/im/g/gimcore" >&2
    exit 1
fi
artifacts+=("${kotlin[@]}")
for artifact in "${artifacts[@]}"; do
    if [[ ! -s "$artifact" ]]; then
        echo "error: missing artifact $artifact" >&2
        exit 1
    fi
done

echo "gim-core $(cat "$out/GIM_CORE_VERSION") built in $((SECONDS - start))s:"
for artifact in "${artifacts[@]}"; do
    printf '%12s  %s\n' "$(stat -c %s "$artifact")" "$artifact"
done
