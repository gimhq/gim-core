# gim identity formats (v1)

Normative specification of the identity wire formats implemented by
`crates/gim-identity`. Test vectors: `crates/gim-identity/tests/vectors/identity.json`.

The key words MUST, MUST NOT and SHOULD are to be interpreted as in RFC 2119.

## Keys

- **Root key**: an Ed25519 (RFC 8032) key pair per user. It signs device
  certificates and device lists. The private key is a 32-byte seed.
- **Device signing key**: an Ed25519 key pair per device.
- Public keys are 32-byte compressed Edwards points. Decoders MUST reject
  encodings that do not decompress and small-order points.
- Signatures are verified with strict Ed25519 verification
  (`verify_strict`: canonical `S`, no small-order `R` or public key).

## Identifiers

`base32` below is the RFC 4648 §6 alphabet in lowercase (`a-z`, `2-7`)
without padding. Decoders MUST reject uppercase, padding, other characters
and non-zero trailing bits, so every value has exactly one encoding.

- `user_id = "u" || base32(0x12 0x20 || SHA-256(root_pubkey))`: the
  SHA-256 multihash (code `0x12`, length `0x20`) of the 32-byte root public
  key. 34 bytes encode to 55 characters; a user id is 56 characters long.
- `device_id = "d" || base32(SHA-256(device_sig_pubkey)[0..16])`: the first
  16 bytes of the SHA-256 of the device's 32-byte signing public key; a
  device id is 27 characters long.

A parsed id is only syntactically valid; it is bound to a key by recomputing
the derivation.

## Encoding

All structures are CBOR (RFC 8949) using the deterministic encoding of
RFC 8949 §4.2.1 as far as it applies to these types: definite lengths and
shortest-form heads. Integers are unsigned (major type 0). A decoder MUST
reject any input that is not exactly the deterministic encoding of the
decoded item, including trailing bytes.

Every signed body is an array whose first element is the format version,
currently `1`. A decoder MUST reject other versions (checked before the
array length).

### Signed form

```
Signed = [ tbs: bstr, sig: bstr .size 64 ]
sig    = Ed25519(signer, context || 0x00 || tbs)
```

`tbs` carries the exact body bytes. Verification MUST run over the received
`tbs` bytes, never over a re-encoding of the decoded body.

| Structure | Signer | `context` (ASCII) |
|---|---|---|
| `SignedDeviceCert` | root key | `gim/device-cert/v1` |
| `SignedDeviceList` | root key | `gim/device-list/v1` |

## DeviceCert

```
DeviceCertBody = [
  1,                            ; version
  user_id: tstr,
  device_id: tstr,
  device_sig_pubkey: bstr .size 32,
  created_at: uint,             ; Unix time, milliseconds
  seq: uint,
]
SignedDeviceCert = [ tbs: bstr (DeviceCertBody), sig: bstr .size 64 ]
```

Verification of a `SignedDeviceCert` against a root public key:

1. `sig` is a valid signature by the root public key over
   `"gim/device-cert/v1" || 0x00 || tbs`.
2. `tbs` decodes as a `DeviceCertBody` with version `1` and exactly six
   elements; `device_sig_pubkey` is a valid public key.
3. `user_id` equals the user id derived from the root public key.
4. `device_id` equals the device id derived from `device_sig_pubkey`.

## DeviceList

```
DeviceListBody = [
  1,                            ; version
  user_id: tstr,
  root_pubkey: bstr .size 32,
  seq: uint,
  certs: [ * bstr ],            ; each the bytes of a SignedDeviceCert
  revoked: [ * tstr ],          ; device ids
]
SignedDeviceList = [ tbs: bstr (DeviceListBody), sig: bstr .size 64 ]
```

Verification of a `SignedDeviceList` for an expected `user_id`:

1. `tbs` decodes as a `DeviceListBody` with version `1` and exactly six
   elements; `root_pubkey` is a valid public key.
2. The user id derived from `root_pubkey` equals both the expected `user_id`
   and the body's `user_id`.
3. `sig` is a valid signature by `root_pubkey` over
   `"gim/device-list/v1" || 0x00 || tbs`.
4. Every element of `certs` is a `SignedDeviceCert` that verifies under
   `root_pubkey` (and therefore carries the same `user_id`).
5. Every element of `revoked` is a syntactically valid device id.
6. No device id appears twice in `certs`, twice in `revoked`, or in both.

A device is *certified* if a cert for it is in `certs`, and *revoked* if its
id is in `revoked`.

### Ordering and updates

- A list `A` supersedes a list `B` of the same user iff `A.seq > B.seq`.
  Two lists of the same user with equal `seq` and different body bytes are a
  conflict and MUST be reported as an error. Comparing lists of different
  users is an error.
- Adding a device appends its cert to `certs` and increments `seq` by one; a
  device that is already certified or revoked cannot be added.
- Revoking a certified device removes its cert from `certs`, appends its id
  to `revoked` and increments `seq` by one.

## Reserved

Recovery backups and device-link bundles are specified by the following
sections in a later revision.

### Recovery backup

Test vectors: `crates/gim-identity/tests/vectors/recovery.json`.

**Recovery code.** 24 bytes from the operating system CSPRNG. Displayed as
Crockford base32 with the alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`,
uppercase, most significant bit first: 192 bits give 39 characters, the last
one carrying 2 data bits followed by 3 zero bits. The characters are grouped
in blocks of four separated by `-` (the last block has three). A parser:

- is case-insensitive and maps `I` and `L` to `1` and `O` to `0`;
- ignores `-` and ASCII whitespace;
- MUST reject any other character, a length other than 39 symbols, and
  non-zero padding bits.

Implementations MUST zeroize the code when done and MUST NOT log it.

**Key derivation.** `key = Argon2id(password = code bytes (24), salt (16),
m_kib, t, p, output length 32)` (RFC 9106, version `0x13`, no secret, no
associated data).

- Sealing MUST use `m_kib = 65536`, `t = 3`, `p = 1` and a fresh random
  16-byte salt.
- Opening MUST reject parameters below the floor `m_kib >= 19456`, `t >= 2`,
  `p >= 1` before deriving, so a storage provider cannot downgrade the cost.
  The `test-params` cargo feature of `gim-identity` lowers the floor and
  exposes low-cost sealing for tests; production builds MUST NOT enable it.
- Opening MUST reject parameters that exceed the ceiling `m_kib <= 262144`
  (256 MiB), `t <= 16`, `p <= 8` in any field, before deriving, so a storage provider
  cannot make a client spend unbounded memory or CPU. The `test-params`
  feature does not change the ceiling.

**Blob.**

```
RootKeyBackup = [
  1,                            ; version
  user_id: tstr,
  kdf: [ m_kib: uint, t: uint, p: uint ],
  salt: bstr .size 16,
  nonce: bstr .size 12,
  ciphertext: bstr,             ; AES-256-GCM ciphertext || 16-byte tag
]
Plaintext = [ 1, root_seed: bstr .size 32 ]
AAD       = [ 1, user_id, [ m_kib, t, p ], salt ]   ; deterministic CBOR bytes
```

The AEAD is AES-256-GCM with the Argon2id output as key, a fresh random
12-byte nonce, and the deterministic CBOR encoding of `AAD` as associated
data. Because the whole blob MUST be deterministic CBOR, re-encoding the
first four decoded elements reproduces exactly the transmitted header bytes;
the opener computes `AAD` that way.

Opening a blob with a recovery code for an expected `user_id`:

1. The blob is deterministic CBOR, an array of six elements with version `1`.
2. The blob's `user_id` equals the expected `user_id` (otherwise a
   user-mismatch error).
3. The KDF parameters are within the floor and the ceiling.
4. AEAD decryption succeeds (otherwise a decryption error; a wrong code and a
   tampered blob are indistinguishable).
5. The plaintext is a `Plaintext` with version `1`.
6. The user id derived from the root public key of `root_seed` equals the
   expected `user_id`.

### Device link (TBD)
