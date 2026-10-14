# Android packaging

`build.sh` (or `scripts/build-android.sh`) builds the Android artifacts of
gim-core in the `ai-agent/gim-core-android` container
(`docker/android.Dockerfile`: Rust, Android NDK r27d, cargo-ndk). It runs from
any directory on a Docker host and needs nothing else installed.

```sh
scripts/build-android.sh                      # rebuild the image, then build
SKIP_IMAGE_BUILD=1 scripts/build-android.sh   # reuse the existing image
```

Output (min SDK 26):

```
out/android/jniLibs/arm64-v8a/libgim_core.so
out/android/jniLibs/x86_64/libgim_core.so
out/android/kotlin/im/g/gimcore/*.kt
out/android/GIM_CORE_VERSION                  # <workspace version>+<short git sha>
```

`CARGO_CACHE_DIR` (default `/srv/.tmp/cache/cargo`) is mounted as `CARGO_HOME`.
