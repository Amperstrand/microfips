# ADR 0004: X-only ECDH Normalization

## Status

Accepted

## Context

The FIPS identity system is built on Nostr (Notes and Other Stuff Transmitted by Relays).
Nostr keys are x-only: they encode only the x-coordinate of a secp256k1 public key,
with no parity information. A node's identity is its npub, derived from an x-only key.

Standard ECDH returns a shared secret point `(x, y)`. The point `P` and its negation `-P`
have the same x-coordinate but different y-coordinates. If the initiator and responder
disagree on which parity of a static key to use, they compute different shared secrets
and the handshake fails.

FIPS resolves this by hashing only the x-coordinate of the ECDH output: `SHA256(x)`.
This makes the shared secret parity-independent, so both sides always agree regardless
of whether they assumed 0x02 or 0x03 prefix for any given public key. This is the same
technique used in BIP-340 (Bitcoin's Schnorr signature scheme) and is documented as
Design Choice D3 in AGENTS.md.

## Decision

microfips implements `x_only_ecdh()` in `microfips-core/src/noise.rs` with identical
behavior:

```rust
pub fn x_only_ecdh(
    my_secret: &[u8; 32],
    their_pub: &[u8; PUBKEY_SIZE],
) -> Result<[u8; 32], NoiseError> {
    let shared = raw_ecdh(sk, pk);
    let x = shared.raw_secret_bytes(); // first 32 bytes = x-coordinate
    Ok(sha256(x))
}
```

The function accepts any compressed public key (0x02 or 0x03 prefix) and returns the
same 32-byte output regardless of prefix parity. This is used for every DH token in
both IK and XK handshakes: `ee`, `es`, `se`, `ss`.

A companion function `parity_normalize()` forces the compressed public key prefix to
0x02 (even) by copying only bytes 1..32 and prepending 0x02. This is used in the
pre-message step where the responder's static key is mixed into the transcript hash
`h`. Both sides must hash identical bytes, so the prefix must be deterministic.

## Consequences

- Incompatible with standard Noise implementations that use the raw ECDH shared secret
  (the full 32-byte x-coordinate without SHA-256 wrapping). Any interop with a
  spec-compliant Noise library requires this normalization step.
- Required for Nostr identity compatibility. Node addresses (`NodeAddr`) are derived
  from x-only public keys. The npub format inherently discards parity information.
- Tested explicitly: `tests/fips_compatibility.rs` verifies that `x_only_ecdh` is
  parity-invariant (same output for even and odd prefix on the same key) and that
  the `es` DH token ordering matches FIPS (not the Noise spec's canonical ordering).
- FIPS issue #58 (Noise XX migration in 0.4.0-dev) does not change this. The x-only
  ECDH normalization is independent of the handshake pattern. microfips will carry
  `x_only_ecdh` forward unchanged when migrating to XX.
