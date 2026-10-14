#!/usr/bin/env bash
# Generates the Swift bindings of gim-ffi (Linux or macOS).
#
#   bindings/apple/generate-swift.sh
#   GIM_CORE_LIB=target/aarch64-apple-ios/release/libgim_core.a bindings/apple/generate-swift.sh
#
# Without GIM_CORE_LIB a release host library of gim-ffi is built first.
#
# Output (out/swift):
#   Sources/GIMCore/GIMCore.swift
#   include/GIMCoreFFI.h
#   include/module.modulemap   (module GIMCoreFFI)
#   GIM_CORE_VERSION
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"

out=out/swift

if [[ -n "${GIM_CORE_LIB:-}" ]]; then
    lib=$GIM_CORE_LIB
    if [[ ! -f "$lib" ]]; then
        echo "error: GIM_CORE_LIB=$lib does not exist" >&2
        exit 1
    fi
else
    case "$(uname -s)" in
        Darwin) lib=target/release/libgim_core.dylib ;;
        *) lib=target/release/libgim_core.so ;;
    esac
    cargo build -p gim-ffi --release
fi

version=$(awk -F'"' '/^\[workspace.package\]/ { s = 1 } s && /^version *=/ { print $2; exit }' Cargo.toml)
if sha=$(git -c safe.directory="$repo" rev-parse --short=12 HEAD 2>/dev/null); then
    version="$version+g$sha"
fi

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

cargo run -p uniffi-bindgen -- generate \
    --library "$lib" \
    --language swift \
    --no-format \
    --out-dir "$staging"

rm -rf "$out"
mkdir -p "$out/Sources/GIMCore" "$out/include"
mv "$staging/GIMCore.swift" "$out/Sources/GIMCore/GIMCore.swift"
mv "$staging/GIMCoreFFI.h" "$out/include/GIMCoreFFI.h"
mv "$staging/GIMCoreFFI.modulemap" "$out/include/module.modulemap"
grep -q '^module GIMCoreFFI ' "$out/include/module.modulemap" || {
    echo "error: $out/include/module.modulemap does not declare module GIMCoreFFI" >&2
    exit 1
}
echo "$version" > "$out/GIM_CORE_VERSION"

echo "Swift bindings $version written to $out"
