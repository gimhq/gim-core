# gim identity formats (v1)

Normative specification of the identity wire formats implemented by
`crates/gim-identity`. Test vectors: `crates/gim-identity/tests/vectors/identity.json`,
`hosting.json`, `auth.json`, `auth-v2.json`, `hub-proof.json`, `public-url.json`
and `request.json` in the same directory; negative vectors in `negative.json` (see *Negative vectors*).

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

A decoder MUST also reject inputs that are not deterministic CBOR (see
*Encoding*) before trusting any decoded value; such inputs are reported as
`non_canonical_cbor`, distinct from otherwise malformed input
(`decode_error`).

Validity times are Unix time in milliseconds. An end time (`not_after`,
`expires_at`) is exclusive: an item is expired when `now >= end`.

## Verification order

Every signed form (`SignedDeviceCert`, `SignedDeviceList`,
`SignedHubRuntimeCert`, `SignedHostingRecord`, each `HostingEntry` and
`AuthResponse`) MUST be verified in this order, so no field of an
unauthenticated body influences the result beyond selecting the verifying
key:

1. **Envelope.** Strict-decode the outer form (`[tbs, sig]`, or the
   `AuthResponse` array) as deterministic CBOR.
2. **Verifying key.** Take the key from outside the body when the verifier
   has it (device cert: the expected root key; runtime cert: the expected
   hub root key; hosting entry: the entry's `hub_root_pubkey`; auth
   response: the certified key of a verified device list). When the key is
   embedded in the body (device list, hosting record), decode `tbs` only far
   enough to read it (and, for the hosting record, the claimed `user_id`) and
   check that it derives the expected or claimed `user_id` *before* using it.
3. **Signature.** Verify `sig` over the received `tbs` with the form's
   `context`.
4. **Body.** Only then strict-decode and validate the rest of the body:
   version, element count, ids, lists, then validity times.

The first failing step determines the error. Per form:

| Form | Step 2 | Step 4 |
|---|---|---|
| `SignedDeviceCert` | expected root key | version, `user_id`, `device_id` |
| `SignedDeviceList` | `root_pubkey` (element 2) derives the expected `user_id` | version, body `user_id`, certs, revoked, duplicates |
| `SignedHubRuntimeCert` | expected hub root key | version, `hub_root_pubkey` equals it, `runtime_pubkey`, times |
| `SignedHostingRecord` | `user_root_pubkey` (element 2) derives the claimed `user_id` (element 1) | version, hub count, entries (each step 3, then uniqueness, order, not the user key), `expires_at` |
| `HostingEntry` | its `hub_root_pubkey` | uniqueness, canonical order and distinctness from the user root key within the record |
| `AuthResponse` | device list verifies for `user_id`; `device_id` not revoked and certified | challenge version, `audience`, validity window, lifetime, `issued_at`, `expires_at` |

The embedded key position (element 2) is read before the version check;
it is the same for every version of these bodies. A body signed by the right
key with a wrong context, or by another key, fails at step 3 as
`bad_signature`.

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

1. `tbs` is deterministic CBOR; its element 2 (`root_pubkey`) is a valid
   public key whose derived user id equals the expected `user_id`.
2. `sig` is a valid signature by `root_pubkey` over
   `"gim/device-list/v1" || 0x00 || tbs`.
3. `tbs` is a `DeviceListBody` with version `1` and exactly six elements;
   the body's `user_id` equals the expected `user_id`.
4. Every element of `certs` is a `SignedDeviceCert` that verifies under
   `root_pubkey` (and therefore carries the same `user_id`).
5. Every element of `revoked` is a syntactically valid device id.
6. No device id appears twice in `certs`, twice in `revoked`, or in both.

A device is *certified* if a cert for it is in `certs`, and *revoked* if its
id is in `revoked`.

### Ordering and updates

- Replacing a stored list follows *Update and seq rules*.
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

1. `sig` is a valid signature by the expected hub root key over
   `"gim/hub-runtime-cert/v1" || 0x00 || tbs`.
2. `tbs` decodes as a `HubRuntimeCertBody` with version `1` and exactly five
   elements; `hub_root_pubkey` equals the expected key.
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

On the wire (CBOR and the hub API) a PeerId is only these bytes; gim
defines no string encoding for it. Implementations MAY render it as
base58btc (as libp2p does) in logs and UI, but MUST NOT put a string form
on the wire or sign it.

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
  hubs: [ + HostingEntry ],     ; 1..=16 entries, canonical order
]
SignedHostingRecord = [ tbs: bstr (HostingRecordBody), sig: bstr .size 64 ]
```

`hub_sig` proves the hub accepted hosting `user_id` at `priority`; the user
signature authorizes the hub list and covers every entry, so a hub cannot add
itself and a hub entry cannot be moved to another user's record.

The order of `hubs` carries no meaning (`priority` is explicit), but to keep
one canonical encoding the entries MUST be sorted strictly ascending by
`(priority, hub_root_pubkey bytes)`, comparing `priority` numerically and
the keys bytewise. The builder sorts; a verifier rejects any other order.
No `hub_root_pubkey` may appear twice, and none may equal
`user_root_pubkey`.

Verification of a `SignedHostingRecord` at time `now`:

1. `tbs` is deterministic CBOR; its element 1 (`user_id`) is a text string
   and its element 2 (`user_root_pubkey`) a valid public key whose derived
   user id equals that `user_id`.
2. `sig` is a valid signature by `user_root_pubkey` over
   `"gim/hosting-record/v1" || 0x00 || tbs`.
3. `tbs` is a `HostingRecordBody` with version `1` and exactly six elements.
4. `hubs` is an array of 1 to 16 entries (`hub_count`), checked before any
   entry is decoded; then each entry is exactly three elements with a valid
   `hub_root_pubkey` and `priority <= 255`.
5. For each entry in order: its `hub_sig` is a valid signature by its
   `hub_root_pubkey` over `"gim/hosting-entry/v1" || 0x00 || HostingEntryTbs`
   built from the record's `user_id`, that `hub_root_pubkey` and that
   `priority`; then its `hub_root_pubkey` has not appeared before
   (`duplicate_hub`); then its `(priority, hub_root_pubkey)` is greater than
   the previous entry's (`unsorted_hubs`); then its `hub_root_pubkey` is not
   `user_root_pubkey` (`user_key_is_hub_key`).
6. `now < expires_at`.

A verifier that looked the record up by user id MUST also check that the
record's `user_id` is the one it looked up.

### Publication

The client builds and signs the record; the hub never holds the user root
key. It asks its hub for an entry (`HostingEntry` CBOR as above, with the
hub's `hub_id` and `hub_root_pubkey` alongside), checks that the entry's key
is the one named and derives that `hub_id`, and builds the record: `seq` one
above the hub's current record (1 without one), `expires_at` seven days
ahead, the hub signature checked by the builder. Renewals keep the entries
and take the next `seq`. On a `seq` conflict the client reads the current
record, verifies it and rebuilds once.

### Ordering and primary hub

- Replacing a stored record follows *Update and seq rules*.
- The primary hub is the entry with the lowest `priority`; ties are broken
  by the lexicographically smallest `hub_id`.

## Hub URLs

A hub with a public client API URL (`GIM_HUB_PUBLIC_URL`) binds its proof
of possession and its sign-in challenges to that URL in this normalized
form, and a client compares it with the normalized URL it contacted:

1. Inputs longer than 65535 bytes are rejected; surrounding ASCII
   whitespace is trimmed. Non-ASCII input and percent-encoding (`%`) are
   rejected.
2. The scheme, before `://`, is `http` or `https` in any case and is
   lowercased.
3. The authority ends at the first `/`, `?` or `#`. What follows it MUST be
   empty or a single `/` (removed): other paths, a query (even a bare `?`)
   and a fragment are rejected. Userinfo (`@`) is rejected.
4. The host is a bracketed IPv6 address (`[...]`, valid as an IPv6
   address, lowercased; only `:port` may follow the `]`), or else a DNS
   name or IPv4 address: lowercased, non-empty labels of `[a-z0-9-]`
   separated by `.`, without a trailing dot.
5. An optional `:port` is decimal digits only (leading zeros allowed), in
   1..65535; it is dropped when it is 80 for `http` or 443 for `https`.

The result is `scheme://host[:port]`. Vectors: `public-url.json` (40 cases;
the `error` strings are not normative).

## Hub proof of possession

`GET /v2/hub?nonce=<n>` (hub API v2) proves that the hub at the contacted
URL holds the root key of its `hub_id` and serves that URL. The client
picks `n`, 32 fresh random bytes, per check and never reuses it. The hub
answers its `hub_id`, `hub_root_pubkey`, normalized `public_url` and

```
proof = Ed25519(hub root key, "gim-hub-proof-v1" || 0x00 || HubProofTbs)
HubProofTbs = nonce (32 bytes)
  || u16be(len(hub_id)) || hub_id
  || u16be(len(public_url)) || public_url
```

with `hub_id` and `public_url` in UTF-8 and each length a big-endian byte
count. The client accepts the URL `U` for the hub `H` only if `hub_id ==
H`, `hub_id` derives from `hub_root_pubkey` (*Identifiers*), `public_url`
equals the normalization of `U` and `proof` verifies (strict Ed25519) under
`hub_root_pubkey` over the message built from its own nonce, `H` and
`public_url`. A hub that reports no `public_url` cannot prove: gim-core
accepts that only for the home hub it was configured with in single-hub
development (AuthChallenge v1); any other hub stays unverified. A relay at
another URL fails the URL check, a replayed answer the signature check.
Vectors: `hub-proof.json` (`message` is the exact signed input).

## Device authentication

A device logs in to a hub with a signature challenge. A hub with a public
URL issues version 2, bound to that URL; a hub without one (single-hub
development, no federation) issues version 1.

```
AuthChallenge = AuthChallengeV1 / AuthChallengeV2
AuthChallengeV1 = [
  1,                            ; version
  audience: tstr,               ; hub_id of the issuing hub
  nonce: bstr .size 32,
  issued_at: uint,              ; Unix time, milliseconds
  expires_at: uint,             ; Unix time, milliseconds, exclusive
]
AuthChallengeV2 = [
  2,                            ; version
  audience: tstr,               ; hub_id of the issuing hub
  audience_url: tstr,           ; its normalized public URL (*Hub URLs*)
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

A version 1 challenge decodes as exactly five elements, a version 2
challenge as exactly six (`decode_error` otherwise); other versions are
`unsupported_version`. The `AuthResponse` framing is the same for both
versions.

The challenge is unsigned: the hub remembers the challenges it issued and
MUST accept each nonce at most once. The device signs the challenge bytes as
received, without re-encoding them. Before signing, the device checks the
challenge against the hub proof of the URL it contacted: `audience` is
that `hub_id` (`audience_mismatch`) and, if the proof reported a
`public_url`, the challenge is version 2 with `audience_url` equal to it,
or else version 1 (`audience_url_mismatch`). So a device never answers a
version 1 challenge of a hub that reported a public URL, nor a challenge
for another URL.

Verification of an `AuthResponse` by the hub `expected_audience` with the
public URL `expected_audience_url` (if any) at time `now`, given the user's
`SignedDeviceList`:

1. The response decodes with version `1` and exactly five elements;
   `user_id` and `device_id` are syntactically valid ids.
2. The device list verifies for `user_id` (see *DeviceList*).
3. `device_id` is not revoked and is certified in the list.
4. `sig` is a valid signature by the certified `device_sig_pubkey` over
   `"gim/auth-response/v1" || 0x00 || AuthResponseTbs`.
5. `challenge` decodes as an `AuthChallenge`; its `audience` equals
   `expected_audience` (`audience_mismatch`). With an
   `expected_audience_url` it is version 2 with that `audience_url`;
   without one it is version 1 (`audience_url_mismatch` otherwise).
6. `issued_at < expires_at` (`invalid_validity_window`), then
   `expires_at - issued_at <= 300000` (`AUTH_CHALLENGE_MAX_LIFETIME_MS`,
   5 minutes; `lifetime_too_long`), then `issued_at <= now`
   (`not_yet_valid`), then `now < expires_at` (`expired`). The hub checks
   that it issued this challenge and that the nonce is unused.

A hub MUST NOT issue a challenge that fails step 6's window or lifetime
checks.

On success the hub has authenticated the device `(user_id, device_id)`.

## Update and seq rules

A `SignedDeviceList` or `SignedHostingRecord` is mutable state keyed by
`user_id`. A verified received item `R` replaces a verified stored item `S`
only by these rules (implemented by `DeviceList::supersedes` and
`UserHostingRecord::supersedes`, called as `R.supersedes(S)`):

| Condition | Result | `supersedes` |
|---|---|---|
| `R.user_id != S.user_id` | reject (`user_id_mismatch`) | `Err(UserIdMismatch)` |
| `R.seq > S.seq` | replace `S` with `R` | `Ok(true)` |
| `R.seq == S.seq`, identical body bytes | unchanged, idempotent no-op | `Ok(false)` |
| `R.seq == S.seq`, different body bytes | reject (`seq_conflict`) | `Err(SeqConflict)` |
| `R.seq < S.seq` | reject as stale (`stale_seq`) | `Err(StaleSeq)` |

"Identical" compares the signed body (`tbs`) bytes. Both items have passed
verification under the same root key, so two encodings with the same body
authorize the same content; a store keeps the bytes it already has. `seq`
need not increase by exactly one between stored versions.

The hub MUST enforce these rules when a client uploads a list or record,
and clients MUST enforce them on every fetch, against the newest item they
have stored for that user, so neither side can be rolled back or forked.
An expired hosting record fails verification before these rules apply.

## Negative vectors

`crates/gim-identity/tests/vectors/negative.json` holds shared failure
cases for every implementation:

```
{ "description": ..., "cases": [ Case, ... ] }
Case = {
  "name": string,               ; unique
  "kind": "device_cert" | "device_list" | "runtime_cert"
        | "hosting_record" | "auth_response",
  "input_hex": string,          ; the received bytes, lowercase hex
  "context": { ... },           ; verifier inputs, per kind below
  "expected_error": string,     ; a code from the table below
}
```

| `kind` | `input_hex` | `context` | Verification |
|---|---|---|---|
| `device_cert` | `SignedDeviceCert` | `root_pubkey` (hex) | verify against `root_pubkey` |
| `device_list` | `SignedDeviceList` | `user_id`, optional `stored` (hex `SignedDeviceList`) | verify for `user_id`; with `stored`, verify it too and apply *Update and seq rules* |
| `runtime_cert` | `SignedHubRuntimeCert` | `hub_root_pubkey` (hex), `now` | verify against `hub_root_pubkey` at `now` |
| `hosting_record` | `SignedHostingRecord` | `now`, optional `user_id`, optional `stored` | verify at `now`; with `user_id`, the record's `user_id` must equal it; with `stored`, verify it at `now` and apply *Update and seq rules* |
| `auth_response` | `AuthResponse` | `audience`, `now`, `device_list` (hex `SignedDeviceList`) | verify as the hub `audience` at `now` |

Every case MUST fail, and the first failure in *Verification order* MUST map
to `expected_error`. Stable error codes (`IdentityError::code`):

| Code | Meaning |
|---|---|
| `decode_error` | malformed input: not CBOR, wrong type, wrong element count or size |
| `non_canonical_cbor` | valid CBOR that is not the deterministic encoding (non-shortest head, indefinite length, trailing bytes) |
| `unsupported_version` | body version other than `1` |
| `invalid_key` | public key does not decompress or is small-order |
| `invalid_user_id`, `invalid_device_id` | id syntax |
| `bad_signature` | signature does not verify (wrong key, wrong context, tampered bytes) |
| `bad_hub_signature` | a `HostingEntry.hub_sig` does not verify |
| `user_id_mismatch` | a user id does not match the key, the expected user or the stored item |
| `device_id_mismatch` | cert `device_id` does not match its key |
| `hub_key_mismatch` | runtime cert names another hub root key than the signer |
| `root_key_mismatch` | signing with a key other than the item's root key |
| `duplicate_device` | a device id appears twice in a list |
| `duplicate_hub` | a hub appears twice in a hosting record |
| `unsorted_hubs` | hosting record hubs not strictly ascending by `(priority, hub_root_pubkey)` |
| `user_key_is_hub_key` | the user root key is also a hub root key in the hosting record |
| `hub_count` | hosting record without 1..=16 hubs |
| `device_revoked` | device is revoked in the list |
| `unknown_device` | device is not certified in the list |
| `expired` | `now >= not_after` / `expires_at` |
| `not_yet_valid` | `now < not_before` / challenge `issued_at` |
| `invalid_validity_window` | challenge `issued_at >= expires_at` |
| `lifetime_too_long` | challenge `expires_at - issued_at` exceeds 300000 ms |
| `audience_mismatch` | challenge addressed to another hub |
| `seq_conflict` | same `seq`, different body |
| `stale_seq` | lower `seq` than the stored item |
| `seq_overflow` | `seq` cannot be incremented |
| `random` | the OS random number generator failed |

The file is generated by `crates/gim-identity/tests/negative.rs`; after an
intentional change, regenerate it with
`cargo test -p gim-identity --test negative -- --ignored regenerate`.

MLS credential failures are in `crates/gim-crypto/tests/vectors/credential.json`
(`invalid` cases, see *MLS credential*), with the codes
`wrong_credential_type`, `non_canonical_cbor`, `malformed_content`,
`unsupported_version`, `bad_cert_signature`, `user_id_mismatch`,
`device_id_mismatch`, `invalid_cert`, `leaf_key_mismatch`,
`device_list_unknown` (no device list of the user is known),
`revoked_device` and `device_not_in_list` (the latest known list does not
certify the device with the leaf's key).

## MLS credential

Test vectors: `crates/gim-crypto/tests/vectors/credential.json` (same root
and device seeds as `identity.json`).

Every MLS leaf (KeyPackage and group leaf) of a device carries a
self-certifying credential of MLS credential type `0xF001`
(`GIM_CREDENTIAL_TYPE`, in the MLS private-use range). Its
`serialized_content` is:

```
GimCredential = [
  1,                            ; version
  root_pubkey: bstr .size 32,   ; the user's root public key
  signed_device_cert: bstr,     ; SignedDeviceCert of this device
]
```

The content is deterministic CBOR (see *Encoding*): definite lengths,
shortest-form heads, no trailing bytes. A decoder re-encodes the decoded item
and rejects the content unless the result equals the received bytes. Leaf
capabilities list `0xF001` as the only supported credential type.

Validation of a leaf, given its credential, its MLS signature key and the
latest `DeviceList` the validator knows for the user (if any), runs these
steps in order and stops at the first failure (error name in brackets):

1. The credential type is `0xF001` (basic and any other type are rejected)
   [`wrong_credential_type`].
2. The content decodes, in this order (envelope, then version, then body,
   as in *Verification order*): it is CBOR [`malformed_content`] in the
   deterministic encoding [`non_canonical_cbor`]; it is an array whose first
   item is an integer [`malformed_content`]; that version is `1`
   [`unsupported_version`]; then the array has exactly three items with byte
   strings in the key and cert positions and a valid 32-byte Ed25519
   `root_pubkey` [`malformed_content`].
3. `signed_device_cert` verifies under `root_pubkey` following the
   *DeviceCert* rules and their *Verification order*: the signature
   [`bad_cert_signature`], then `user_id` derived from `root_pubkey`
   [`user_id_mismatch`] and `device_id` derived from `device_sig_pubkey`
   [`device_id_mismatch`]; any other certificate failure [`invalid_cert`].
4. The leaf's MLS signature key equals the certified `device_sig_pubkey`
   [`leaf_key_mismatch`].
5. The validator knows a `DeviceList` of `user_id` [`device_list_unknown`];
   validation fails closed, so the validator fetches the latest list of the
   user before validating. In the latest known list, `device_id` is not
   revoked [`revoked_device`], and it is certified with a cert whose
   `device_sig_pubkey` equals the leaf's signature key
   [`device_not_in_list`].

The leaf's device is `(user_id, device_id)` from the certificate.

A device validates: every leaf of the ratchet tree of a Welcome (including
the sender) before joining; the committer's leaf, the update-path leaf, and
every Add and Update proposal of an incoming commit before merging it; Add
and Update proposals before storing them; and the KeyPackages it adds
itself. A rejected Welcome or commit leaves the local group state unchanged.

## Root-signed requests

Test vectors: `crates/gim-identity/tests/vectors/request.json`.

An HTTP request signed with the user's root key proves that the sender
holds the root key of the user id the presented key derives; the verifier
needs no stored state. The gim keep server (gim-keep) authenticates every
request this way, and hubs authenticate account deletion.

```
tbs       = method "\n" path "\n" decimal(timestamp_ms) "\n" hex(SHA-256(body))
signature = Ed25519(root key, "gim/root-request/v1" || 0x00 || tbs)
```

- `method` is the uppercase HTTP method; `path` the request path with its
  query string exactly as sent; `timestamp_ms` Unix milliseconds in decimal
  without leading zeros; the digest is lowercase hex (the empty body for a
  request without one). All UTF-8.
- Headers: `Gim-Key` (the 32-byte root public key), `Gim-Timestamp`
  (`timestamp_ms`) and `Gim-Signature` (64 bytes); keys and signatures in
  unpadded base64url.
- The verifier MUST check the signature with strict verification, MUST
  reject a timestamp more than 5 minutes from its clock (either way), and
  takes `user_id` as derived from `Gim-Key` (see *Identifiers*). A route
  scoped to a user MUST compare that id with the user in the path.

### Keep-server storage

What a user stores on the keep server is sealed with a key the server never
sees:

```
storage_key = HKDF-SHA256(salt = none, ikm = root seed, info = "gim/keep-storage/v1", L = 32)
sealed      = nonce(12) || AES-256-GCM(storage_key, nonce, plaintext, aad = slot name)
```

The slot name (UTF-8) is bound as AAD, so a server cannot swap two slots.
Every own device holds the root key, and a restore from the recovery code
recovers it, so each of them can open the slots.

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

**Restore.** gim-core restores a user on a fresh device by opening the
backup, reading the user's current signed DeviceList from the hub (a public
read; the device cannot sign in yet) and verifying it against the recovered
root key. It then publishes the next list (`seq + 1`) certifying the new
device. When the other devices are revoked, every device the current list
certifies moves to `revoked` (explicitly, not dropped); otherwise they all
stay certified. If a newer list lands concurrently, the list is read and
rebuilt once.

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

#### Device link flow

How gim-core (`gim-sdk`, exposed by gim-ffi) runs the flow against a hub.
The bundle carries the root key seed, the new device's certificate and the
DeviceList certifying it, and **no self-group Welcome**: a Welcome needs a
KeyPackage of the new device, and the new device can only publish
KeyPackages once it holds its certificate, i.e. after it opened the bundle.
gim-core always seals `self_group_welcome = null` and ignores a non-null
one. The new device joins the self group and the chats from Welcomes the
old device sends after the SAS was confirmed.

```
New device (N)                     Hub                         Old device (O)
--------------                     ---                         --------------
start_link: device key, offer
show QR (LinkOffer) ----------------------- scan ----------------------->
                                                               approve_link:
                                                                 cert(seq+1), DeviceList
                                       <-- PUT /v2/users/{u}/device-list
                                       <-- POST /v2/link-bundles {link_id, sealed}
                                                               show SAS
wait_link:
  GET /v2/link-bundles/{link_id}?wait=30 -->  (deleted on first fetch)
  open + verify bundle, store root
  and device keys, sign in, upload
  KeyPackages
show SAS
                   user compares both SAS and confirms on BOTH devices
confirm_link(true)                                             confirm_approval(true):
                                                                 add N to the self group
                                                                 and to every joined chat
                                       <-- commits + Welcomes for N
sync: join the self group and chats
  from the Welcomes  <---------------- Welcomes
```

Who does what:

1. **N** `start_link(hubs)`: creates its device signing key and a
   `LinkOffer` and shows it as a QR code. It must not have a session.
2. **O** `approve_link(qr)`: issues a `SignedDeviceCert` for N, publishes a
   DeviceList (seq + 1) certifying it, seals the bundle to the offer, posts
   it through the hub (lifetime 600 s) and shows the SAS. N is now a listed
   device but in no MLS group.
3. **N** `wait_link`: long-polls the hub for the bundle (up to 10 minutes),
   opens and verifies it, stores the root and device keys, signs in and
   uploads KeyPackages, then shows the SAS.
4. The user compares the two SAS values and confirms on both devices.
5. **O** `confirm_approval(true)`: adds N to the self group (sharing the
   DeviceList and profile) and to every joined chat. N must have finished
   step 3, otherwise it has no KeyPackages to claim.
6. **N** `confirm_link(true)`: completes the link; on its next sync it joins
   the self group and the chats from the Welcomes the hub delivers.

Failure and reject paths:

- **SAS mismatch on N** (`confirm_link(false)`): the bundle may come from
  someone else. N deletes the session, the root and device keys and its
  local database, and must start over with a new offer.
- **SAS mismatch on O** (`confirm_approval(false)`): O revokes N in a new
  DeviceList; the hub drops N's sessions and peers reject its credential.
- The user must reject on both devices; rejecting on one only is not
  enough (an unrevoked N keeps a valid certificate, an unwiped N keeps the
  keys).
- **No bundle** within 10 minutes, or a bundle that does not open or verify:
  `wait_link` fails and stores nothing. A `LinkSession` accepts a single
  bundle; start a new one. If O already approved, the listed but unused N
  should be revoked from O (`revoke_device`).
- The bundle is fetched once: the hub deletes it on the first fetch and
  after its lifetime.

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
