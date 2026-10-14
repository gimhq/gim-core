# gim-core

Rust core shared by the gim native clients (iOS, Android): MLS end-to-end
encryption (OpenMLS), and — as later work lands — storage, networking, sync,
outbox and UI-facing services, exposed to Swift and Kotlin through UniFFI.

The workspace is modelled on matrix-rust-sdk: one role per crate, dependencies
point downwards only
(`common ← proto ← crypto ← base ← sqlite`, `base + crypto + proto ← sdk ← ui ← ffi`).

| Crate | Role |
|---|---|
| `crates/gim-common` | ids (`UserId`, `DeviceId`, `GroupId`, `ClientId`, `MessageId`, `DeviceRef`), error helpers, time; no I/O |
| `crates/gim-proto` | gim-server REST/stream DTOs and the versioned CBOR envelope schema (skeleton) |
| `crates/gim-crypto` | OpenMLS wrapper (`MlsEngine`), `CryptoStore` trait + `MemoryCryptoStore`; no networking |
| `crates/gim-base` | client state machine without networking, `StateStore` trait (skeleton) |
| `crates/gim-sqlite` | rusqlite `StateStore` + `CryptoStore` on one database (skeleton) |
| `crates/gim-sdk` | async `Client`: HTTP, WebSocket/long-poll, sync, outbox, media (skeleton) |
| `crates/gim-ui` | chat list and timeline `VectorDiff` streams (skeleton) |
| `bindings/gim-ffi` | the only UniFFI crate; builds `libgim_core.{so,a,dylib}` |
| `bindings/android`, `bindings/apple` | packaging scripts |
| `uniffi-bindgen` | `uniffi-bindgen` binary used by the packaging scripts |
| `testing/gim-test` | fixtures and `FakeDeliveryService` (in-memory gim-server delivery) |
| `testing/gim-integration-testing` | tests against a real gim-server container (skeleton) |

MLS ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, pure-Rust
crypto (RustCrypto provider), no C toolchain needed.

## Checks

Builds run in a container:

```sh
mkdir -p /srv/.tmp/cache/cargo
docker run --rm --label ai-agent=true -v "$PWD:$PWD" -w "$PWD" \
  -v /srv/.tmp/cache/cargo:/cache/cargo -e CARGO_HOME=/cache/cargo rust:1 \
  sh -c 'rustup component add rustfmt clippy && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test'
```

## Bindings

```sh
cargo build -p gim-ffi
cargo run -p uniffi-bindgen -- generate --library target/debug/libgim_core.so --language kotlin --out-dir out/kotlin
cargo run -p uniffi-bindgen -- generate --library target/debug/libgim_core.so --language swift --out-dir out/swift
```

Kotlin package `im.g.gimcore`; Swift module `GIMCore` (FFI module `GIMCoreFFI`).

## Envelope and media formats

**Envelope** (`gim_proto::envelope`, carried inside MLS application messages):
one CBOR map with short keys — `v` version (`1`), `id` message id, `ts` sent
time in Unix ms, optional `re` reply-to id (text and media only), `c` content
tagged by `t`: `text`, `media`, `edit`, `delete`, `reaction`, `receipt`
(`delivered` | `read`), `typing`, `group_info`. Unknown keys are ignored;
version 0, newer versions and unknown content tags are rejected. The full key
table is in the module docs. `gim_crypto::{encrypt_envelope,
decrypt_to_envelope}` wrap encoding plus MLS application encryption.

**Media** (`gim_crypto::media`): chunked AES-256-GCM with a fresh random key
per blob.

```text
header  = "GIM1" || chunk_size (u32 BE, default 65536) || nonce_prefix (8 random bytes)
blob    = header || chunk_0 || ... || chunk_n
chunk_i = AES-256-GCM(key, nonce = nonce_prefix || i (u32 BE),
                      aad = header || last_flag (1 byte), plaintext_i) with 16-byte tag
```

All chunks but the last carry exactly `chunk_size` plaintext bytes; empty
media is one empty final chunk. The key and the SHA-256 of the whole blob
travel in the envelope's media map, never to gim-server. `encrypt_media` /
`decrypt_media` work on buffers (digest checked in constant time before
decrypting); `MediaEncryptor` / `MediaDecryptor` stream over
`std::io::Read`/`Write`.
