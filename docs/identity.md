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

### Recovery backup (TBD)

### Device link (TBD)
