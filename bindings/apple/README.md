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
generates the Swift bindings from the device library, removes embedded bitcode
from both archives (see *Bitcode*), fails if any member still has a
`__bitcode` section (`llvm-objdump`) or the `uniffi_gim_core_fn_*` exports are
missing (`llvm-nm`), and packages:

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
  "unwind"` (UniFFI needs it).

### SQLCipher and OpenSSL

The local database is SQLCipher (`rusqlite` feature
`bundled-sqlcipher-vendored-openssl`): `openssl-src` builds a static
`libcrypto` for each slice (`ios64-cross` / `iossimulator-arm64-xcrun`, needs
Xcode's clang, `perl` and `make`) and rustc bundles it into `libgim_core.a`.
That adds roughly 14 MB per slice to the archives and about 7-8 MB to the zip;
the app's linker dead-strips the unused parts.

libsqlite3-sys can use CommonCrypto instead (`-DSQLCIPHER_CRYPTO_CC`, linking
`Security`), but only with plain `bundled-sqlcipher` and an Apple host
building for an Apple target. With one workspace feature set that is not
possible: it would need a target-specific `rusqlite` dependency
(`bundled-sqlcipher` on Apple, `bundled-sqlcipher-vendored-openssl`
elsewhere), so every target keeps the vendored OpenSSL.

### Bitcode

The sysroot's `compiler_builtins` objects are never part of LTO and are copied
into the staticlib as shipped, with an embedded `__LLVM,__bitcode` section.
Xcode's `nm`/`strip`/linker read that bitcode and fail on rustc's newer LLVM
("Unknown attribute kind"). The script extracts only those members with
rustc's `llvm-ar`, drops their `__LLVM,__bitcode` / `__LLVM,__cmdline`
sections with `llvm-objcopy` and puts them back in place (`llvm-ar r`, same
member order). Every other member, including the LTO output, stays byte for
byte as rustc/cc produced it. Rust's own LTO output has no embedded bitcode, so
`-C embed-bitcode=no` is not needed. Xcode's `nm` is not used as a gate.

Nothing is stripped. `__eh_frame` relocates against local `ltmp*` /
`GCC_except_table*` labels; stripping local symbols (`--discard-all`) leaves
a malformed object and Xcode's linker asserts "LSDA in __eh_frame section not
supported".

### Link test

The CI `xcframework` job links `link-test/main.c` (calls
`uniffi_gim_core_fn_func_core_version`) against each slice with `xcrun clang`
(`arm64-apple-ios18.0` / `arm64-apple-ios18.0-simulator`), and does a
relocatable `-Xlinker -r -Xlinker -all_load` link of every member as SwiftPM
does. The job fails on any linker error or assertion.
