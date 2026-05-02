# ADR 0003: Custom Noise Protocol Implementation

## Status

Accepted

## Context

FIPS implements the Noise Protocol Framework directly, following only the cryptographic
primitives and ordering from the Noise specification. It does not use an existing Noise
library such as `snow`. This is a deliberate choice by the FIPS maintainer (confirmed
2026-04-11), motivated by custom payloads attached to handshake messages (startup epoch,
capability flags, negotiation data). The same approach is used by the Lightning Network.

microfips must produce wire-identical output to FIPS. Any deviation in the Noise
handshake, even a correct one by the spec, breaks interoperability. FIPS makes several
non-standard design choices that a spec-compliant Noise library would not reproduce:

1. **D1 (empty AAD):** Handshake AEAD uses `AEAD_ENCRYPT(k, n, b"", plaintext)` instead
   of passing the running transcript hash `h` as associated data. The Noise spec says to
   use `h`, but FIPS deliberately omits it.
2. **D2 (custom se ordering):** The IK initiator computes `DH(e, rs)` for the `se` token
   rather than `DH(s, re)`. This matches FIPS's own internal convention.
3. **D3 (x-only ECDH):** ECDH shared secrets are hashed as `SHA256(x_coordinate)` instead
   of using the raw ECDH output. Required for Nostr npub compatibility (BIP-340 technique).

These deviations are documented in AGENTS.md under "Noise Protocol Design Choices" and
verified in the microfips parity document (`docs/fips-microfips-parity.md`).

## Decision

microfips implements its own Noise IK and XK handshake types in `microfips-core/src/noise.rs`,
using the same cryptographic primitives as FIPS:

- **ECDH:** secp256k1 via `k256` crate (no external crypto dependency beyond this)
- **AEAD:** ChaCha20-Poly1305 via `chacha20poly1305` crate
- **Hash:** SHA-256 via `sha2` crate
- **Protocol names:** `Noise_IK_secp256k1_ChaChaPoly_SHA256` and
  `Noise_XK_secp256k1_ChaChaPoly_SHA256` (identical to FIPS)

The implementation is split into concrete types per role and pattern:
`NoiseIkInitiator`, `NoiseIkResponder`, `NoiseXkInitiator`, `NoiseXkResponder`.
Each type carries its own state rather than using a single polymorphic `HandshakeState`
like FIPS does. This is simpler for embedded use and avoids dynamic dispatch.

## Consequences

- Wire-compatible with FIPS. Golden vector tests verify byte-identical output across
  IK and XK handshakes (see `tests/golden_vectors.rs`).
- Must track FIPS changes to the Noise layer. FIPS issue #58 (Noise IK/XK to XX migration
  in the `next` branch, 0.4.0-dev) will require a full rewrite of the handshake code.
- No automatic Noise spec compliance. If FIPS deviates further from the spec, microfips
  must follow, not the spec. The parity document serves as the authoritative checklist.
- No `NoiseSession` wrapper type. FIPS exposes a reusable `NoiseSession` for link-level
  encrypt/decrypt with replay windows; microfips returns finalized key tuples from
  `finalize()` and lets callers use `aead_encrypt`/`aead_decrypt` directly. This reduces
  code size but means replay protection is the caller's responsibility.
- The `snow` crate was evaluated and rejected. It would enforce spec-correct AAD handling
  (violating D1) and standard DH ordering (violating D2), making FIPS interop impossible
  without forking snow itself.
