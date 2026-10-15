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

Builds the `libgim_core.a` static library for `aarch64-apple-ios` (device) and
`aarch64-apple-ios-sim` (simulator) with `IPHONEOS_DEPLOYMENT_TARGET=18.0`,
generates the Swift bindings from the device library, post-processes both
archives with rustc's `llvm-tools` (`llvm-objcopy`: drops `__LLVM,__bitcode` /
`__LLVM,__cmdline` sections and debug and local symbols, like `strip -S -x`),
fails if any member still has a `__bitcode` section (`llvm-objdump`) or the
`uniffi_gim_core_fn_*` exports are gone (`llvm-nm`), and packages:

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

### Size

GitHub rejects files over 100 MB, and the iOS client vendors the zip, so it
must stay below 50 MB (the CI `xcframework` job fails at 50,000,000 bytes and
prints the slice and zip sizes). What keeps it small:

- No `x86_64-apple-ios` slice: the simulator slice is Apple silicon only.
  **Intel-Mac simulators are not supported.**
- `cargo rustc --crate-type staticlib`: built together with gim-ffi's `lib`
  crate type, the archive also carries every dependency's rlib objects with
  embedded bitcode next to the LTO output (about 5x larger).
- `[profile.release-apple]` in the root `Cargo.toml`: `release` with
  `opt-level = "s"`, fat LTO, one codegen unit, no debug info, `panic =
  "unwind"` (UniFFI needs it). A profile `strip` does not apply to static
  libraries, hence the explicit strip.

### Bitcode

The sysroot's `compiler_builtins` objects are never part of LTO and are copied
into the staticlib as shipped, with an embedded `__LLVM,__bitcode` section.
Xcode's `nm`/`strip`/linker read that bitcode and fail on rustc's newer LLVM
("Unknown attribute kind"), so the script removes it. The archives hold
machine code only. Rust's own LTO output has no embedded bitcode, so
`-C embed-bitcode=no` is not needed. Xcode's `nm` is not used as a gate.

