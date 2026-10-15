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
3. The KDF parameters meet the floor.
4. AEAD decryption succeeds (otherwise a decryption error; a wrong code and a
   tampered blob are indistinguishable).
5. The plaintext is a `Plaintext` with version `1`.
6. The user id derived from the root public key of `root_seed` equals the
   expected `user_id`.

### Device link

Adds a new device to a user who already has a device. Implemented in
`gim_identity::link`; test vectors: `crates/gim-identity/tests/vectors/link.json`.

#### Flow

1. The **new** device creates a device signing key, a random 16-byte
   `link_id` and an X25519 (RFC 7748) key pair (`eph_secret`, `eph_pub`), and
   shows a `LinkOffer` as a QR code.
2. The **old** device scans it, issues a `SignedDeviceCert` for
   `device_sig_pubkey`, signs a `DeviceList` that certifies it, seals a
   `LinkBundle` to the offer and posts the sealed bytes through one of the
   offer's hubs.
3. The new device opens and verifies the bundle.
4. Both devices display the SAS; the user confirms they match before either
   device treats the link as complete.

#### LinkOffer

```
LinkOffer = [
  1,                            ; version
  link_id: bstr .size 16,
  eph_pub: bstr .size 32,       ; X25519 public key
  device_sig_pubkey: bstr .size 32,
  hubs: [ * tstr ],
]
```

QR string form: `"gimlink:" || base64url(LinkOffer)`, the RFC 4648 §5
alphabet without padding. Decoders MUST reject a missing or differently cased
prefix, padding and non-zero trailing bits. `offer_bytes` below is the
deterministic encoding of the offer.

#### LinkBundle

```
LinkBundle = [
  1,                            ; version
  root_seed: bstr .size 32,     ; the user's root key seed
  cert: bstr,                   ; SignedDeviceCert of the new device
  device_list: bstr,            ; SignedDeviceList certifying it
  self_group_welcome: bstr / null,
]
```

#### Sealing

The old device:

1. Generates an ephemeral X25519 key pair (`sender_eph`, `sender_eph_pub`).
2. `shared = X25519(sender_eph, eph_pub)`. If `shared` is all zero, it MUST
   abort.
3. `th = SHA-256(offer_bytes || sender_eph_pub)`.
4. `key = HKDF-SHA256(salt = link_id, ikm = shared, info = "gim/link/key/v1" || th)`,
   32 bytes (RFC 5869).
5. Encrypts the `LinkBundle` bytes with AES-256-GCM under `key`, a random
   12-byte `nonce` and AAD `th`.

```
SealedBundle = [
  1,                            ; version
  sender_eph_pub: bstr .size 32,
  nonce: bstr .size 12,
  ciphertext: bstr,             ; includes the 16-byte GCM tag
]
```

#### Opening

The new device recomputes `shared` with `eph_secret` (aborting on an all-zero
value), `th` from its own `offer_bytes` and the received `sender_eph_pub`,
and `key`, then decrypts. It MUST then verify, in order:

1. The plaintext is a `LinkBundle` with version `1`.
2. The root public key derived from `root_seed` verifies `cert`
   (see DeviceCert).
3. `cert.device_sig_pubkey` equals the offer's `device_sig_pubkey`.
4. `device_list` verifies (see DeviceList) for the user id derived from the
   root public key.
5. `device_list` does not revoke the cert's `device_id` and certifies it.

A failure at any step rejects the bundle. Decryption failure, cert mismatch
(step 3), list mismatch (steps 4-5: another user, device missing),
revocation and an unknown version are reported as distinct errors.

#### Short authentication string

```
sas_bytes = HKDF-SHA256(salt = link_id, ikm = shared, info = "gim/link/sas/v1" || th)[0..4]
sas       = uint32_be(sas_bytes) mod 1000000
```

Displayed as six decimal digits with leading zeros, split `"ddd ddd"`
(e.g. `"012 345"`).

#### Threat model

- The QR channel is authentic: the old device reads the new device's
  `eph_pub` and `device_sig_pubkey` unmodified. It need not be confidential.
- The hub relay is not trusted. Only the holder of `eph_secret` can open a
  sealed bundle, and the AAD and key bind it to the exact offer: an offer with
  any changed field (including `device_sig_pubkey`) yields a different `th`
  and the bundle does not decrypt.
- Anyone who learns the offer (e.g. a camera or person that sees the QR
  code) can seal a bundle of their own identity to it. The SAS
  depends on `shared` and `sender_eph_pub`, so such a bundle shows a
  different SAS on the new device than the old device displays; the user
  MUST compare the SAS and reject a mismatch.
- A 6-digit SAS gives a forger a one-in-a-million chance per attempt; the new
  device SHOULD accept a single bundle per offer and create a new offer after
  a mismatch.
