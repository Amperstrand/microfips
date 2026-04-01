# Golden vector format specification

This document defines the JSON file format consumed by `golden_vectors.rs`.
The format is intentionally simple: a single top-level file wrapper containing
metadata and a typed vector list.

## Top-level schema

```json
{
  "version": 1,
  "generator": "fips-golden-gen v0.1.0",
  "generated_at": "2026-04-01T00:00:00Z",
  "vectors": [ ... ]
}
```

### Fields

- `version` — format version. Must be `1`.
- `generator` — free-form generator identity string.
- `generated_at` — RFC3339 timestamp string.
- `vectors` — array of typed test vectors.

## Common rules

- All hex data is encoded as lowercase hex in JSON strings.
- Hex fields are **not** decoded in the JSON schema; they are decoded later by tests.
- Required fields are mandatory for every vector type.
- Unknown vector `type` values must be rejected by deserialization.
- `nonce` and `epoch` are unsigned 64-bit integers.
- `deviations` is always a JSON array of strings.

## Vector types

### `pubkey`

Derives a compressed secp256k1 public key from a secret scalar.

```json
{
  "name": "pubkey-1",
  "type": "pubkey",
  "comment": "secp256k1 scalar 1 → generator point",
  "secret_hex": "0000...0001",
  "pubkey_hex": "0279be..."
}
```

Fields:

- `name` — unique vector name.
- `comment` — human-readable note.
- `secret_hex` — 32-byte secp256k1 secret scalar.
- `pubkey_hex` — 33-byte compressed public key.

### `ecdh`

Performs secp256k1 ECDH and hashes the x-coordinate with SHA-256.

```json
{
  "name": "ecdh-1",
  "type": "ecdh",
  "comment": "DH(scalar_1, pubkey_2) = SHA256(x_coord)",
  "initiator_secret_hex": "...",
  "responder_pubkey_hex": "...",
  "shared_secret_hex": "..."
}
```

Fields:

- `initiator_secret_hex` — initiator secret scalar.
- `responder_pubkey_hex` — responder compressed public key.
- `shared_secret_hex` — SHA-256 result for the ECDH x-coordinate.

### `hkdf`

Standalone HKDF-SHA256 output.

```json
{
  "name": "hkdf-1",
  "type": "hkdf",
  "comment": "HKDF-SHA256(salt, ikm) → 64 bytes",
  "salt_hex": "...",
  "ikm_hex": "...",
  "output_hex": "..."
}
```

Fields:

- `salt_hex` — HKDF salt.
- `ikm_hex` — input key material.
- `output_hex` — derived output bytes.

### `aead`

ChaCha20Poly1305 encryption vector.

```json
{
  "name": "aead-1",
  "type": "aead",
  "comment": "ChaChaPoly1305 encrypt",
  "key_hex": "...",
  "nonce": 0,
  "plaintext_hex": "...",
  "aad_hex": "",
  "ciphertext_hex": "..."
}
```

Fields:

- `key_hex` — 32-byte AEAD key.
- `nonce` — AEAD nonce counter.
- `plaintext_hex` — plaintext bytes.
- `aad_hex` — additional authenticated data.
- `ciphertext_hex` — encrypted output including tag.

### `ik`

Full Noise IK handshake vector.

```json
{
  "name": "ik-1",
  "type": "ik",
  "comment": "IK handshake, initiator even parity",
  "deviations": ["D1_empty_aad", "D2_se_dh_ei_rs"],
  "initiator_static_secret_hex": "...",
  "initiator_static_pubkey_hex": "...",
  "initiator_ephemeral_secret_hex": "...",
  "initiator_ephemeral_pubkey_hex": "...",
  "responder_static_secret_hex": "...",
  "responder_static_pubkey_hex": "...",
  "responder_ephemeral_secret_hex": "...",
  "responder_ephemeral_pubkey_hex": "...",
  "epoch": 1000000,
  "msg1_hex": "...",
  "msg1_payload_hex": "",
  "msg2_hex": "...",
  "msg2_payload_hex": "",
  "handshake_hash_hex": "...",
  "initiator_transport_send_key_hex": "...",
  "initiator_transport_recv_key_hex": "...",
  "responder_transport_send_key_hex": "...",
  "responder_transport_recv_key_hex": "..."
}
```

Fields:

- `deviations` — protocol or implementation deviations recorded for the vector.
- `epoch` — fixed 64-bit epoch value.
- `msg1_hex` / `msg2_hex` — full wire messages.
- `msg1_payload_hex` / `msg2_payload_hex` — inner Noise payload bytes.
- transport keys — final CipherState keys for both directions.

### `xk`

Full Noise XK handshake vector.

```json
{
  "name": "xk-1",
  "type": "xk",
  "comment": "XK handshake",
  "deviations": ["D1_empty_aad"],
  "initiator_static_secret_hex": "...",
  "initiator_static_pubkey_hex": "...",
  "initiator_ephemeral_secret_hex": "...",
  "initiator_ephemeral_pubkey_hex": "...",
  "responder_static_secret_hex": "...",
  "responder_static_pubkey_hex": "...",
  "responder_ephemeral_secret_hex": "...",
  "responder_ephemeral_pubkey_hex": "...",
  "epoch": 1000000,
  "msg1_hex": "...",
  "msg1_payload_hex": "",
  "msg2_hex": "...",
  "msg2_payload_hex": "",
  "msg3_hex": "...",
  "msg3_payload_hex": "",
  "handshake_hash_hex": "...",
  "initiator_transport_send_key_hex": "...",
  "initiator_transport_recv_key_hex": "...",
  "responder_transport_send_key_hex": "...",
  "responder_transport_recv_key_hex": "..."
}
```

Fields:

- `msg3_hex` / `msg3_payload_hex` — third handshake message and payload.

### `transport`

Post-handshake CipherState encryption vectors.

```json
{
  "name": "transport-1",
  "type": "transport",
  "comment": "transport encryption, initiator send direction",
  "derived_from": "ik-1",
  "direction": "initiator_send",
  "key_hex": "...",
  "frames": [
    { "nonce": 0, "plaintext_hex": "...", "aad_hex": "", "ciphertext_hex": "..." },
    { "nonce": 1, "plaintext_hex": "...", "aad_hex": "", "ciphertext_hex": "..." },
    { "nonce": 2, "plaintext_hex": "...", "aad_hex": "", "ciphertext_hex": "..." }
  ]
}
```

Fields:

- `derived_from` — source handshake vector name.
- `direction` — text label for the CipherState direction.
- `key_hex` — transport key used for the frame sequence.
- `frames` — ordered list of encrypted frames.

## Validation expectations

- `pubkey_hex` must be a 33-byte compressed secp256k1 public key.
- `shared_secret_hex` must match the SHA-256 output of the ECDH x-coordinate.
- `output_hex` in HKDF vectors must contain the full derived byte string.
- `ciphertext_hex` includes the Poly1305 tag.
- `msg*_payload_hex` values represent the exact inner payload bytes, not outer wire bytes.
- Handshake vectors must include the final transport keys for both peers so later tests can verify directionality.

## Example file shape

```json
{
  "version": 1,
  "generator": "fips-golden-gen v0.1.0",
  "generated_at": "2026-04-01T00:00:00Z",
  "vectors": [
    { "type": "pubkey", "name": "..." },
    { "type": "ecdh", "name": "..." },
    { "type": "hkdf", "name": "..." },
    { "type": "aead", "name": "..." },
    { "type": "ik", "name": "..." },
    { "type": "xk", "name": "..." },
    { "type": "transport", "name": "..." }
  ]
}
```

This spec is complete for the initial golden-vector scaffold.
