# gim identity formats (v1)

Normative specification of the identity wire formats implemented by
`crates/gim-identity`. Test vectors: `crates/gim-identity/tests/vectors/identity.json`,
`hosting.json` and `auth.json` in the same directory.

The key words MUST, MUST NOT and SHOULD are to be interpreted as in RFC 2119.

## Keys

- **Root key**: an Ed25519 (RFC 8032) key pair per user. It signs device
  certificates and device lists. The private key is a 32-byte seed.
- **Device signing key**: an Ed25519 key pair per device.
- **Hub root key**: a long-term Ed25519 key pair per hub. It signs hosting
  entries and hub runtime certificates.
- **Hub runtime key**: a short-lived Ed25519 key pair per hub; it is the
  hub's libp2p host key.
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
- `hub_id = "h" || base32(0x12 0x20 || SHA-256(hub_root_pubkey))`: as
  `user_id`, over the 32-byte hub root public key; 56 characters long.

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
| `SignedHubRuntimeCert` | hub root key | `gim/hub-runtime-cert/v1` |
| `SignedHostingRecord` | user root key | `gim/hosting-record/v1` |

Two signatures are not carried in the signed form but use the same
`context || 0x00 || tbs` input:

| Signature | Signer | `context` (ASCII) | `tbs` |
|---|---|---|---|
| `HostingEntry.hub_sig` | hub root key | `gim/hosting-entry/v1` | `HostingEntryTbs` |
| `AuthResponse.sig` | device signing key | `gim/auth-response/v1` | `AuthResponseTbs` |

Validity times are Unix time in milliseconds. An end time (`not_after`,
`expires_at`) is exclusive: an item is expired when `now >= end`.

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

## Hub runtime certificate

```
HubRuntimeCertBody = [
  1,                            ; version
  hub_root_pubkey: bstr .size 32,
  runtime_pubkey: bstr .size 32,  ; Ed25519 libp2p host key
  not_before: uint,             ; Unix time, milliseconds
  not_after: uint,              ; Unix time, milliseconds, exclusive
]
SignedHubRuntimeCert = [ tbs: bstr (HubRuntimeCertBody), sig: bstr .size 64 ]
```

The hub root key certifies a short-lived runtime key, so the runtime key
(and the libp2p PeerId derived from it) rotates without touching hosting
records.

Verification of a `SignedHubRuntimeCert` against an expected hub root public
key at time `now`:

1. `tbs` decodes as a `HubRuntimeCertBody` with version `1` and exactly five
   elements; `hub_root_pubkey` equals the expected key.
2. `sig` is a valid signature by `hub_root_pubkey` over
   `"gim/hub-runtime-cert/v1" || 0x00 || tbs`.
3. `runtime_pubkey` is a valid public key.
4. `not_before <= now < not_after`.

### libp2p PeerId

The libp2p PeerId of an Ed25519 runtime key is the identity multihash of the
protobuf-encoded libp2p `PublicKey { Type = Ed25519, Data = runtime_pubkey }`:

```
peer_id = 0x00 0x24 0x08 0x01 0x12 0x20 || runtime_pubkey   ; 38 bytes
```

`0x00` is the identity multihash code and `0x24` (36) its length; `0x08 0x01`
is protobuf field 1 (`Type`) = 1 (Ed25519) and `0x12 0x20` field 2 (`Data`)
of 32 bytes. A hub that connects with a runtime key MUST present a
certificate for it; a peer MUST check that the connection's PeerId equals
`peer_id` of the certified `runtime_pubkey`. The vectors carry the PeerId in
hex only.

## Hosting record

```
HostingEntryTbs = [
  1,                            ; version
  user_id: tstr,
  hub_root_pubkey: bstr .size 32,
  priority: uint,               ; 0..=255, lower is preferred
]
HostingEntry = [
  hub_root_pubkey: bstr .size 32,
  priority: uint,
  hub_sig: bstr .size 64,       ; hub root key over HostingEntryTbs
]
HostingRecordBody = [
  1,                            ; version
  user_id: tstr,
  user_root_pubkey: bstr .size 32,
  seq: uint,
  expires_at: uint,             ; Unix time, milliseconds, exclusive
  hubs: [ + HostingEntry ],     ; 1..=16 entries
]
SignedHostingRecord = [ tbs: bstr (HostingRecordBody), sig: bstr .size 64 ]
```

`hub_sig` proves the hub accepted hosting `user_id` at `priority`; the user
signature authorizes the hub list and covers every entry, so a hub cannot add
itself and a hub entry cannot be moved to another user's record.

Verification of a `SignedHostingRecord` at time `now`:

1. `tbs` decodes as a `HostingRecordBody` with version `1` and exactly six
   elements; `user_root_pubkey` is a valid public key.
2. `user_id` equals the user id derived from `user_root_pubkey`.
3. `sig` is a valid signature by `user_root_pubkey` over
   `"gim/hosting-record/v1" || 0x00 || tbs`.
4. `hubs` has 1 to 16 entries, each exactly three elements with a valid
   `hub_root_pubkey` and `priority <= 255`; no `hub_root_pubkey` appears
   twice.
5. Every `hub_sig` is a valid signature by its `hub_root_pubkey` over
   `"gim/hosting-entry/v1" || 0x00 || HostingEntryTbs` built from the
   record's `user_id`, that `hub_root_pubkey` and that `priority`.
6. `now < expires_at`.

A verifier that looked the record up by user id MUST also check that the
record's `user_id` is the one it looked up.

### Ordering and primary hub

- A record `A` supersedes a record `B` of the same user iff `A.seq > B.seq`.
  Two records of the same user with equal `seq` and different body bytes are
  a conflict and MUST be reported as an error. Comparing records of different
  users is an error.
- The primary hub is the entry with the lowest `priority`; ties are broken
  by the lexicographically smallest `hub_id`.

## Device authentication

A device logs in to a hub with a signature challenge.

```
AuthChallenge = [
  1,                            ; version
  audience: tstr,               ; hub_id of the issuing hub
  nonce: bstr .size 32,
  issued_at: uint,              ; Unix time, milliseconds
  expires_at: uint,             ; Unix time, milliseconds, exclusive
]
AuthResponseTbs = [
  challenge: bstr,              ; the exact AuthChallenge bytes received
  user_id: tstr,
  device_id: tstr,
]
AuthResponse = [
  1,                            ; version
  challenge: bstr,              ; the exact AuthChallenge bytes received
  user_id: tstr,
  device_id: tstr,
  sig: bstr .size 64,           ; device signing key over AuthResponseTbs
]
```

The challenge is unsigned: the hub remembers the challenges it issued and
MUST accept each nonce at most once. The device signs the challenge bytes as
received, without re-encoding them.

Verification of an `AuthResponse` by the hub `expected_audience` at time
`now`, given the user's `SignedDeviceList`:

1. The response decodes with version `1` and exactly five elements;
   `user_id` and `device_id` are syntactically valid ids.
2. `challenge` decodes as an `AuthChallenge` with version `1`; its
   `audience` equals `expected_audience` and `now < expires_at`. The hub
   checks that it issued this challenge and that the nonce is unused.
3. The device list verifies for `user_id` (see *DeviceList*).
4. `device_id` is not revoked and is certified in the list.
5. `sig` is a valid signature by the certified `device_sig_pubkey` over
   `"gim/auth-response/v1" || 0x00 || AuthResponseTbs`.

On success the hub has authenticated the device `(user_id, device_id)`.

## Reserved

Recovery backups and device-link bundles are specified by the following
sections in a later revision.

### Recovery backup (TBD)

### Device link (TBD)
