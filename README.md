# gim-core

Protocol core of gim, shared by the clients and gim-hub: wire formats,
identity, MLS end-to-end encryption (OpenMLS) and the client state machine.
Pure Rust without I/O; builds for native targets and `wasm32-unknown-unknown`.

The client runtime, storage, networking and the Swift/Kotlin bindings live in
[gim-client-sdk](https://github.com/gimhq/gim-client-sdk), which pins these
crates by commit.

Dependencies point downwards only (`common ← proto ← identity ← crypto ← base`).

| Crate | Role |
|---|---|
| `crates/gim-common` | ids (`UserId`, `DeviceId`, `GroupId`, `ClientId`, `MessageId`, `DeviceRef`), error helpers, time |
| `crates/gim-proto` | gim-hub API v2 DTOs (`v2`, vendored contract in `contract/hub-v2/`) and the versioned CBOR envelope schema |
| `crates/gim-identity` | root and device Ed25519 keys, `user_id`/`device_id` derivation, signed `DeviceCert` and `DeviceList` (spec: `docs/identity.md`) |
| `crates/gim-crypto` | OpenMLS wrapper (`MlsEngine`), `CryptoStore` trait + `MemoryCryptoStore` |
| `crates/gim-base` | client state machine, `StateStore` trait + `MemoryStore` |
| `testing/gim-test` | fixtures and `FakeDeliveryService` (in-memory gim-hub API v2) |

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
travel in the envelope's media map, never to the hub. `encrypt_media` /
`decrypt_media` work on buffers (digest checked in constant time before
decrypting); `MediaEncryptor` / `MediaDecryptor` stream over
`std::io::Read`/`Write`.

## CI

`.github/workflows/ci.yml`:

- `rust` (every push, pull request, manual run): `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test`.
- `wasm` (every push, pull request, manual run): `cargo clippy -D warnings` for
  `wasm32-unknown-unknown` on each of `gim-common`, `gim-proto`, `gim-identity`,
  `gim-crypto` and `gim-base`.
