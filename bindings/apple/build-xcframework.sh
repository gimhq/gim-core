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

# Members of an archive that carry an embedded __LLVM,__bitcode section.
bitcode_members() {
    "$llvm_bin/llvm-objdump" --section-headers "$1" \
        | awk '/file format/ { m = $1 } $2 == "__bitcode" { print m }' \
        | sed -e 's/^.*(//' -e 's/):$//' | sort -u
}

# The sysroot's compiler_builtins objects are never LTO'd and are copied into
# the archive with an embedded __LLVM,__bitcode section that Xcode's tools
# cannot parse (rustc's LLVM is newer). Only those members are rewritten, and
# only their bitcode sections are dropped; every other member stays exactly as
# rustc/cc produced it. Do not strip local symbols: __eh_frame relocates
# against ltmp*/GCC_except_table* labels, and ld asserts ("LSDA in __eh_frame
# section not supported") once they are gone.
for lib in "$device_lib" "$sim_lib"; do
    lib_path=$repo/$lib
    if [[ -n $("$llvm_bin/llvm-ar" t "$lib_path" | sort | uniq -d) ]]; then
        echo "error: $lib has duplicate member names" >&2
        exit 1
    fi
    members=()
    while IFS= read -r member; do
        members+=("$member")
    done < <(bitcode_members "$lib_path")
    if (( ${#members[@]} > 0 )); then
        work=$(mktemp -d)
        (
            cd "$work"
            "$llvm_bin/llvm-ar" x "$lib_path" "${members[@]}"
            for member in "${members[@]}"; do
                "$llvm_bin/llvm-objcopy" \
                    --remove-section=__LLVM,__bitcode \
                    --remove-section=__LLVM,__cmdline \
                    "$member"
            done
            # `r` replaces the members in place, keeping the member order.
            "$llvm_bin/llvm-ar" r "$lib_path" "${members[@]}"
        )
        rm -rf "$work"
    fi
    remaining=$(bitcode_members "$lib_path" | wc -l | tr -d ' ')
    symbols=$("$llvm_bin/llvm-nm" --quiet --extern-only --defined-only "$lib_path")
    exports=$(grep -c ' _uniffi_gim_core_fn_' <<< "$symbols" || true)
    echo "$lib: ${#members[@]} bitcode members rewritten, $remaining left, $exports uniffi_gim_core_fn_* exports"
    if [[ "$remaining" != 0 ]]; then
        echo "error: $lib still contains bitcode sections" >&2
        exit 1
    fi
    if [[ "$exports" == 0 ]]; then
        echo "error: $lib has no uniffi_gim_core_fn_* exports" >&2
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
