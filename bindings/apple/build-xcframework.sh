#!/usr/bin/env bash
# Builds GIMCore.xcframework (arm64 device + arm64 simulator static libraries)
# and the matching Swift sources. macOS only (needs Xcode).
#
#   bindings/apple/build-xcframework.sh
#
# Output (out/ios):
#   GIMCore.xcframework/
#   GIMCore.xcframework.zip
#   GIMCore.xcframework.zip.sha256
#   Sources/GIMCore/GIMCore.swift
#   GIM_CORE_VERSION
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    echo "error: build-xcframework.sh requires macOS with Xcode (found $(uname -s))" >&2
    exit 1
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"

export IPHONEOS_DEPLOYMENT_TARGET=18.0

device_target=aarch64-apple-ios
# Apple-silicon simulators only; Intel-Mac simulators (x86_64-apple-ios) are
# not supported.
sim_target=aarch64-apple-ios-sim
profile=release-apple
out=out/ios
lib_name=libgim_core.a

rustup target add "$device_target" "$sim_target"
rustup component add llvm-tools
# rustc's own LLVM tools: Xcode's nm/strip cannot read objects carrying bitcode
# from rustc's newer LLVM.
llvm_bin=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin

# `--crate-type staticlib` alone: with gim-ffi's "lib" crate type in the same
# build the archive also bundles every dependency's rlib objects (and their
# embedded bitcode) next to the LTO output, which multiplies its size.
for target in "$device_target" "$sim_target"; do
    cargo rustc -p gim-ffi --lib --crate-type staticlib --profile "$profile" --target "$target"
done

device_lib=target/$device_target/$profile/$lib_name
sim_lib=target/$sim_target/$profile/$lib_name

GIM_CORE_LIB=$device_lib bash bindings/apple/generate-swift.sh

# The sysroot's compiler_builtins objects are never LTO'd and are copied into
# the archive with an embedded __LLVM,__bitcode section that Xcode's tools
# cannot parse: drop it (machine code only), plus debug and local symbols
# (= strip -S -x). The exported UniFFI symbols must survive.
for lib in "$device_lib" "$sim_lib"; do
    "$llvm_bin/llvm-objcopy" \
        --remove-section=__LLVM,__bitcode \
        --remove-section=__LLVM,__cmdline \
        --strip-debug \
        --discard-all \
        "$lib"
    sections=$("$llvm_bin/llvm-objdump" --section-headers "$lib")
    bitcode_members=$(awk '/file format/ { m = $1 } $2 == "__bitcode" { print m }' <<< "$sections" | sort -u | wc -l | tr -d ' ')
    symbols=$("$llvm_bin/llvm-nm" --quiet --extern-only --defined-only "$lib")
    exports=$(grep -c ' _uniffi_gim_core_fn_' <<< "$symbols" || true)
    echo "$lib: $bitcode_members members with bitcode, $exports uniffi_gim_core_fn_* exports"
    if [[ "$bitcode_members" != 0 ]]; then
        echo "error: $lib still contains bitcode sections" >&2
        exit 1
    fi
    if [[ "$exports" == 0 ]]; then
        echo "error: $lib lost its uniffi_gim_core_fn_* exports after strip" >&2
        exit 1
    fi
done

rm -rf "$out"
mkdir -p "$out/Sources/GIMCore"

xcodebuild -create-xcframework \
    -library "$device_lib" -headers out/swift/include \
    -library "$sim_lib" -headers out/swift/include \
    -output "$out/GIMCore.xcframework"

(cd "$out" && ditto -c -k --sequesterRsrc --keepParent GIMCore.xcframework GIMCore.xcframework.zip)
swift package compute-checksum "$out/GIMCore.xcframework.zip" > "$out/GIMCore.xcframework.zip.sha256"

cp out/swift/Sources/GIMCore/GIMCore.swift "$out/Sources/GIMCore/GIMCore.swift"
cp out/swift/GIM_CORE_VERSION "$out/GIM_CORE_VERSION"

echo "GIMCore.xcframework $(cat "$out/GIM_CORE_VERSION") written to $out"
echo "checksum: $(cat "$out/GIMCore.xcframework.zip.sha256")"
for lib in "$device_lib" "$sim_lib"; do
    echo "$lib: $(wc -c < "$lib" | tr -d ' ') bytes"
done
echo "$out/GIMCore.xcframework.zip: $(wc -c < "$out/GIMCore.xcframework.zip" | tr -d ' ') bytes"
