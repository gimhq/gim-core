# Apple packaging

Scripts that turn `gim-ffi` into a Swift package input for the iOS client.

| Script | Host | Output |
|---|---|---|
| `generate-swift.sh` | Linux or macOS | `out/swift/` — Swift bindings, C header, module map |
| `build-xcframework.sh` | macOS + Xcode | `out/ios/` — `GIMCore.xcframework` (+ zip, checksum), Swift sources |

Wrappers with the same names live in `scripts/`.

## generate-swift.sh

Builds a release host library of `gim-ffi` (or uses `GIM_CORE_LIB` when it
points to an existing `libgim_core.{so,dylib,a}`) and runs `uniffi-bindgen` in
library mode:

```
out/swift/
  Sources/GIMCore/GIMCore.swift
  include/GIMCoreFFI.h
  include/module.modulemap     # module GIMCoreFFI
  GIM_CORE_VERSION
```

## build-xcframework.sh

Builds the `libgim_core.a` static library for `aarch64-apple-ios`,
`aarch64-apple-ios-sim` and `x86_64-apple-ios` (`IPHONEOS_DEPLOYMENT_TARGET=18.0`),
merges the two simulator slices with `lipo`, generates the Swift bindings from
the device library and packages:

```
out/ios/
  GIMCore.xcframework/
  GIMCore.xcframework.zip
  GIMCore.xcframework.zip.sha256   # swift package compute-checksum
  Sources/GIMCore/GIMCore.swift
  GIM_CORE_VERSION
```

The iOS client vendors `GIMCore.xcframework.zip` and `Sources/GIMCore`,
pinned by `GIM_CORE_VERSION`. The script is idempotent: `out/ios` is rebuilt
from scratch on every run.
