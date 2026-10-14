#!/usr/bin/env bash
# Builds GIMCore.xcframework (device + simulator static libraries) and the
# matching Swift sources. macOS only (needs Xcode).
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
sim_targets=(aarch64-apple-ios-sim x86_64-apple-ios)
out=out/ios
lib_name=libgim_core.a

rustup target add "$device_target" "${sim_targets[@]}"

for target in "$device_target" "${sim_targets[@]}"; do
    cargo build -p gim-ffi --release --target "$target"
done

device_lib=target/$device_target/release/$lib_name
sim_dir=target/ios-simulator-universal/release
sim_lib=$sim_dir/$lib_name
mkdir -p "$sim_dir"
sim_inputs=()
for target in "${sim_targets[@]}"; do
    sim_inputs+=("target/$target/release/$lib_name")
done
lipo -create "${sim_inputs[@]}" -output "$sim_lib"

GIM_CORE_LIB=$device_lib bash bindings/apple/generate-swift.sh

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
