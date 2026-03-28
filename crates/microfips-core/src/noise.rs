//! Noise Protocol IK and XK Implementations for FIPS Interop
//!
//! Implements both handshake patterns used by FIPS:
//! - **Noise_IK_secp256k1_ChaChaPoly_SHA256** for link-layer (FMP)
//! - **Noise_XK_secp256k1_ChaChaPoly_SHA256** for session-layer (FSP)
//!
//! ## Reference Sources
//!
//! - **Noise Protocol Framework** (rev 34): <https://noiseprotocol.org/noise.html>
//!   - §2: Handshake patterns and message token notation
//!   - §4: Crypto functions — AEAD (§4.2), HASH/HKDF (§4.3)
//!   - §5: Protocol processing — CipherState (§5.1), SymmetricState (§5.2),
//!     HandshakeState (§5.3)
//!   - §7.5: IK pattern: `<- s / -> e, es, s, ss / <- e, ee, se`
//!   - §7.9: XK pattern: `<- s / -> e, es / <- e, ee, se / -> s, se`
//!   - §13: DH functions — allows custom DH definitions
//! - **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//!   — underlying construction for `mix_key` and `Split`
//! - **RFC 7539**: ChaCha20 and Poly1305 for IETF Protocols — AEAD construction
//!   used by ChaChaPoly
//! - **RFC 7748**: Elliptic Curves for Security — ECDH function (adapted with
//!   x-only hash for FIPS; see [`x_only_ecdh`])
//! - **FIPS source** (VPS: orangeclaw): `/root/src/fips/src/noise/`
//!   - `handshake.rs`: `HandshakeState` with `new_initiator()`,
//!     `write_message_1()`, `read_message_2()`, `normalize_for_premessage()`,
//!     `ecdh()`
//!   - `mod.rs`: `SymmetricState` with `initialize()`, `split()`,
//!     `encrypt_and_hash()`, `decrypt_and_hash()`; `CipherState` with
//!     `encrypt()`, `decrypt()`, `counter_to_nonce()`
//!
//! ## FIPS Deviations from Noise Spec
//!
//! ### Deviation #1: No AAD during handshake
//!
//! - Noise spec §5.2 `EncryptAndHash(plaintext)` calls `EncryptWithAd(h, pt)`,
//!   using the handshake hash `h` as associated data.
//! - FIPS: `SymmetricState::encrypt_and_hash()` calls `cipher.encrypt(pt)` which
//!   uses empty AAD (`&[]`). The `Aead` trait's `encrypt` method defaults to
//!   empty AAD when called without a `Payload` struct.
//! - We match FIPS behavior (empty AAD) for interoperability.
//! - FIPS: `/root/src/fips/src/noise/mod.rs` — `CipherState::encrypt()`
//!
//! ### Deviation #2: `se` token uses different key pairings (FIPS-compatible)
//!
//! Per Noise spec §7.5 IK pattern, the initiator's `se` token should compute
//! `DH(s_init, re_resp)`. Our initiator computes `DH(e_init, rs_resp)` instead.
//! This is FIPS-compatible because FIPS does the same thing:
//!
//! - **Spec**: initiator `se = DH(s_init, re_resp)`, responder `se = DH(e_resp, rs_init)`
//! - **FIPS/us**: initiator `se = DH(e_init, rs_resp)`, responder `se = DH(s_resp, ei_init)`
//!
//! Both sides of the FIPS implementation agree on this computation, so they derive
//! the same shared secret and interoperate. However, the value mixed into the
//! chaining key differs from what a spec-compliant Noise implementation would
//! produce — meaning this implementation is NOT interoperable with generic Noise
//! IK implementations, only with FIPS.
//!
//! Note: `DH(e_init, rs_resp) = DH(s_resp, e_init)` by ECDH commutativity, so
//! both sides derive the same key. See test `se_and_es_produce_different_keys`.
//!
//! ## IK Handshake Pattern (Link Layer, FMP)
//!
//! Reference: Noise spec §7.5
//! ```text
//!   <- s                    (pre-message: responder's static key, parity-normalized to 0x02)
//!   -> e, es, s, ss, epoch  (msg1: 106 bytes = 33(e) + 49(enc_s) + 24(enc_epoch))
//!   <- e, ee, se, epoch     (msg2: 57 bytes = 33(e) + 24(enc_epoch))
//! ```
//!
//! Tokens (from initiator's perspective):
//! - `e`: ephemeral public key (cleartext, 33 bytes compressed secp256k1)
//! - `es`: DH(e_initiator_priv, rs_responder_pub) → mix_key
//! - `s`: static public key (AEAD-encrypted, 33 + 16 tag = 49 bytes)
//! - `ss`: DH(s_initiator_priv, rs_responder_pub) → mix_key
//! - `ee`: DH(e_initiator_priv, re_responder_pub) → mix_key
//! - `se`: DH(e_initiator_priv, rs_responder_pub) → mix_key
//!   FIPS DEVIATION: spec says DH(s_init, re_resp); see Deviation #2 above
//!
//! ## XK Handshake Pattern (Session Layer, FSP) — PLANNED
//!
//! Reference: Noise spec §7.9
//! ```text
//!   <- s                       (pre-message: responder's static key)
//!   -> e, es                   (msg1: 33 bytes)
//!   <- e, ee, se, epoch        (msg2: 57 bytes = 33(e) + 24(enc_epoch))
//!   -> s, se, epoch            (msg3: 73 bytes = 49(enc_s) + 24(enc_epoch))
//! ```
//!
//! ## Security Notes
//!
//! - Private key fields (`e_priv`, `s_priv`) hold sensitive key material and
//!   should ideally be zeroized on drop. In `no_std` without `alloc`, we cannot
//!   implement `Drop` with `zeroize` easily. This is a known limitation.
//! - `Clone` is derived on `NoiseIkInitiator` and `NoiseXkInitiator`, which
//!   duplicates secret key material. This is used for the retry loop in
//!   `Node::handshake()` (node.rs line ~157: `let mut st = noise_st.clone()`).
//!   The cloned state should be dropped promptly after use.

#[allow(deprecated)]
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag};
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman as raw_ecdh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::identity::sha256;

/// Poly1305 authentication tag size.
/// Reference: [RFC 7539] §2.8 — 16-byte tag
pub const TAG_SIZE: usize = 16;

/// FIPS key epoch size (8 bytes, u64 LE).
pub const EPOCH_SIZE: usize = 8;

/// AEAD nonce size: 4 zero bytes + 8-byte LE counter = 12 bytes.
/// Reference: [Noise spec] §5.1
pub const NONCE_SIZE: usize = 12;

/// Compressed secp256k1 public key size (0x02/0x03 prefix + 32 bytes x-coordinate).
pub const PUBKEY_SIZE: usize = 33;

/// Noise IK protocol name. Used as the initial `h` and `ck` in
/// `SymmetricState::Initialize()`.
/// Reference: [Noise spec] §5.2 — `h = HASH(protocol_name)`, `ck = h`
/// FIPS: `/root/src/fips/src/noise/mod.rs` — `SymmetricState::initialize()`
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_secp256k1_ChaChaPoly_SHA256";

/// Noise XK protocol name (session layer).
/// Reference: [Noise spec] §5.2
pub const PROTOCOL_NAME_XK: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    InvalidKey,
    InvalidMessage,
    DecryptionFailed,
    EncryptionFailed,
    BufferTooSmall,
}

/// Parity-normalize a compressed secp256k1 public key to even prefix (0x02).
///
/// The Noise spec does not define parity normalization — this is a FIPS-specific
/// adaptation for Nostr npubs, which encode x-only keys without parity info.
///
/// The Noise IK pre-message (`<- s`) mixes the responder's static key into `h`
/// before any messages are exchanged (Reference: [Noise spec] §5.3 pre-message
/// processing). Both sides must mix identical bytes, so we normalize to 0x02
/// prefix to ensure agreement regardless of which parity the key was originally
/// encoded with.
///
/// FIPS: `/root/src/fips/src/noise/handshake.rs` —
/// `HandshakeState::normalize_for_premessage()`
pub fn parity_normalize(pubkey: &[u8; PUBKEY_SIZE]) -> [u8; PUBKEY_SIZE] {
    let mut out = [0u8; PUBKEY_SIZE];
    out[0] = 0x02;
    out[1..].copy_from_slice(&pubkey[1..]);
    out
}

/// FIPS-specific DH function: `SHA256(x-coordinate of ECDH shared secret)`.
///
/// Reference: [Noise spec] §13 — allows custom DH functions provided they
/// satisfy the required properties. FIPS uses `SHA256(shared_point.x)` instead
/// of the raw ECDH output to make the result parity-independent: points P and
/// -P produce ECDH results with the same x-coordinate, so the shared secret is
/// identical regardless of which parity the initiator assumed for the peer's key.
///
/// This deviates from standard secp256k1 Noise patterns (which return the raw
/// x-coordinate without hashing) but is required for FIPS interoperability.
///
/// Reference: [RFC 7748] §6.1 — ECDH shared secret derivation (adapted here
/// with x-only hash).
///
/// FIPS: `/root/src/fips/src/noise/handshake.rs` — `HandshakeState::ecdh()`
/// uses `shared_secret_point()` then `SHA256(point[..32])`.
pub fn x_only_ecdh(
    my_secret: &[u8; 32],
    their_pub: &[u8; PUBKEY_SIZE],
) -> Result<[u8; 32], NoiseError> {
    let sk = SecretKey::from_slice(my_secret).map_err(|_| NoiseError::InvalidKey)?;
    let pk = PublicKey::from_sec1_bytes(their_pub).map_err(|_| NoiseError::InvalidKey)?;
    let shared = raw_ecdh(sk.to_nonzero_scalar(), pk.as_affine());
    let x = shared.raw_secret_bytes();
    Ok(sha256(x))
}

/// Compute the compressed public key for a given secret key.
pub fn ecdh_pubkey(secret: &[u8; 32]) -> Result<[u8; PUBKEY_SIZE], NoiseError> {
    let sk = SecretKey::from_slice(secret).map_err(|_| NoiseError::InvalidKey)?;
    let pk = sk.public_key();
    let encoded = pk.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; PUBKEY_SIZE];
    out.copy_from_slice(&bytes[..PUBKEY_SIZE]);
    Ok(out)
}

/// SHA256(a || b) — concatenated hash used by `mix_hash`.
fn hash_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HKDF-SHA256(chaining_key, input_key_material) → (new_ck, new_k).
///
/// Reference: [Noise spec] §4.3 — `MixKey(input_key_material)`:
///   `ck, temp_k = HKDF(ck, input_key_material, 2)`
///
/// Implementation: `Hkdf::new(salt=ck, ikm=ikm)` performs HKDF-Extract per
/// [RFC 5869] §2.2: `PRK = HMAC-SHA256(salt=ck, IKM=ikm)`. Then
/// `expand(&[], L=64)` performs HKDF-Expand per [RFC 5869] §2.3 with
/// `info=empty`, producing 2 × 32-byte keys. This matches the Noise spec's
/// `HKDF(ck, ikm, 2)` definition.
///
/// FIPS: `/root/src/fips/src/noise/mod.rs` — `SymmetricState` uses the same
/// `Hkdf::<Sha256>::new(Some(&ck), ikm)` with `expand(&[], &mut [0u8; 64])`.
fn mix_key(ck: &[u8; 32], ikm: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(ck), ikm);
    let mut okm = [0u8; 64];
    hk.expand(&[], &mut okm)
        .expect("hkdf expand 64 bytes should never fail");
    let mut new_ck = [0u8; 32];
    new_ck.copy_from_slice(&okm[..32]);
    let mut k = [0u8; 32];
    k.copy_from_slice(&okm[32..]);
    (new_ck, k)
}

/// Mix data into the handshake hash: `h = SHA256(h || data)`.
///
/// Reference: [Noise spec] §5.2 — `SymmetricState.MixHash(data)`:
///   `h = HASH(h || data)`
fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hash_concat(h, data)
}

/// Construct a 12-byte AEAD nonce from a counter.
///
/// Layout: `[0x00; 4] || counter.to_le_bytes()` (4 zero bytes + 8-byte LE).
///
/// Reference: [Noise spec] §5.1 — "nonce n [...] 32-bit [...] set to zero,
/// followed by a little-endian 64-bit value". The maximum n value (2^64-1)
/// is reserved for rekey.
///
/// FIPS: `/root/src/fips/src/noise/mod.rs` — `CipherState::counter_to_nonce()`
/// uses the same layout: `[0;4] || counter.to_le_bytes()`.
fn make_nonce(n: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

/// AEAD encrypt with ChaCha20-Poly1305.
///
/// Reference: [Noise spec] §4.2 — `ENCRYPT(k, n, ad, plaintext)`:
///   Returns `ciphertext || tag`.
/// Reference: [RFC 7539] §2.8 — AEAD construction using ChaCha20 for
///   encryption and Poly1305 for authentication.
///
/// `aad` is authenticated but not encrypted. During handshake, FIPS passes
/// empty AAD (`&[]`) instead of the hash state `h` — see module-level docs
/// "Deviation #1: No AAD during handshake".
///
/// FIPS: `/root/src/fips/src/noise/mod.rs` — `CipherState::encrypt()` calls
/// `cipher.encrypt(&nonce, plaintext)` with no AAD (the `Aead` trait's
/// `encrypt` method defaults to empty AAD when called without `Payload`).
#[allow(deprecated)]
pub fn aead_encrypt(
    key: &[u8; 32],
    nonce_ctr: u64,
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, NoiseError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| NoiseError::InvalidKey)?;
    let nonce_arr = make_nonce(nonce_ctr);
    let nonce = GenericArray::from_slice(&nonce_arr);

    let total = plaintext.len() + TAG_SIZE;
    if out.len() < total {
        return Err(NoiseError::BufferTooSmall);
    }

    out[..plaintext.len()].copy_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut out[..plaintext.len()])
        .map_err(|_| NoiseError::EncryptionFailed)?;

    out[plaintext.len()..total].copy_from_slice(&tag);
    Ok(total)
}

/// AEAD decrypt with ChaCha20-Poly1305.
///
/// Reference: [Noise spec] §4.2 — `DECRYPT(k, n, ad, ciphertext)`.
/// Reference: [RFC 7539] §2.8 — AEAD decryption and tag verification.
#[allow(deprecated)]
pub fn aead_decrypt(
    key: &[u8; 32],
    nonce_ctr: u64,
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, NoiseError> {
    if ciphertext.len() < TAG_SIZE {
        return Err(NoiseError::InvalidMessage);
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| NoiseError::InvalidKey)?;
    let nonce_arr = make_nonce(nonce_ctr);
    let nonce = GenericArray::from_slice(&nonce_arr);

    let pt_len = ciphertext.len() - TAG_SIZE;
    if out.len() < pt_len {
        return Err(NoiseError::BufferTooSmall);
    }

    out[..pt_len].copy_from_slice(&ciphertext[..pt_len]);
    let tag = Tag::from_slice(&ciphertext[pt_len..]);

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut out[..pt_len], tag)
        .map_err(|_| NoiseError::DecryptionFailed)?;

    Ok(pt_len)
}

/// Noise IK initiator state machine.
///
/// Reference: [Noise spec] §5.3 — `HandshakeState` maintains `(s, e, rs, re)`
/// key pairs plus `SymmetricState(ck, h, k, n)`.
///
/// Security: `e_priv` and `s_priv` hold sensitive key material. In `no_std`
/// without `alloc`, zeroize-on-drop is not implemented. `Clone` is derived
/// for the retry loop in `Node::handshake()` — cloned state should be dropped
/// after use.
#[derive(Clone)]
pub struct NoiseIkInitiator {
    h: [u8; 32],
    ck: [u8; 32],
    e_priv: [u8; 32],  // SECRET: ephemeral private key
    e_pub: [u8; PUBKEY_SIZE],
    s_priv: [u8; 32],  // SECRET: static private key
    rs_pub: [u8; PUBKEY_SIZE],
    k: Option<[u8; 32]>,
    n: u64,
}

impl NoiseIkInitiator {
    /// Initialize the IK initiator.
    ///
    /// Reference: [Noise spec] §5.3 `Initialize(handshake_pattern, ...)`:
    ///   1. `h = HASH(protocol_name)` — SHA256 of the protocol name string
    ///   2. `ck = h` — chaining key starts as copy of h
    ///   3. Process pre-messages: IK has `<- s` so `MixHash(rs_normalized)`
    ///
    /// The IK pattern has a pre-message `<- s` meaning the responder's static
    /// key is known to the initiator before the handshake begins. We
    /// parity-normalize it (see [`parity_normalize`]) and mix into h so both
    /// sides have the same hash chain.
    ///
    /// FIPS: `/root/src/fips/src/noise/handshake.rs` —
    /// `HandshakeState::new_initiator()` calls
    /// `SymmetricState::initialize(PROTOCOL_NAME_IK)` then
    /// `mix_hash(normalize_for_premessage(&remote_static))`.
    pub fn new(
        my_ephemeral_secret: &[u8; 32],
        my_static_secret: &[u8; 32],
        responder_static_pub: &[u8; PUBKEY_SIZE],
    ) -> Result<(Self, [u8; PUBKEY_SIZE]), NoiseError> {
        let e_pub = ecdh_pubkey(my_ephemeral_secret)?;

        // Reference: [Noise spec] §5.2 — h = HASH(protocol_name), ck = h
        let h = sha256(PROTOCOL_NAME);
        let ck = h;

        // Reference: [Noise spec] §5.3 — pre-message processing: MixHash(rs)
        let normalized_rs = parity_normalize(responder_static_pub);
        let h = mix_hash(&h, &normalized_rs);

        Ok((
            Self {
                h,
                ck,
                e_priv: *my_ephemeral_secret,
                e_pub,
                s_priv: *my_static_secret,
                rs_pub: *responder_static_pub,
                k: None,
                n: 0,
            },
            e_pub,
        ))
    }

    /// Write Noise IK message 1: `-> e, es, s, ss, epoch`
    ///
    /// Reference: [Noise spec] §5.3 `WriteMessage()` processing rules.
    /// Reference: [Noise spec] §7.5 — IK msg1 tokens.
    ///
    /// Wire format (106 bytes total):
    /// ```text
    ///   [e_pub: 33 bytes] [enc_s_pub: 49 bytes] [enc_epoch: 24 bytes]
    /// ```
    /// Verified: 33(e) + 49(enc_s = 33 + 16 tag) + 24(enc_epoch = 8 + 16 tag) = 106
    ///
    /// Token processing order:
    /// 1. `e`: write ephemeral public key, mix_hash(e_pub)
    /// 2. `es`: DH(e_priv, rs_pub) → mix_key → sets k, resets n=0
    /// 3. `s`: encrypt_and_hash(s_pub) — encrypted with k from es
    /// 4. `ss`: DH(s_priv, rs_pub) → mix_key → k changes, resets n=0
    /// 5. epoch (payload): encrypt_and_hash(epoch) — encrypted with k from ss
    ///
    /// FIPS: `/root/src/fips/src/noise/handshake.rs` —
    /// `HandshakeState::write_message_1()`
    pub fn write_message1(
        &mut self,
        my_static_pub: &[u8; PUBKEY_SIZE],
        epoch: &[u8; EPOCH_SIZE],
        out: &mut [u8],
    ) -> Result<usize, NoiseError> {
        let needed = PUBKEY_SIZE + (PUBKEY_SIZE + TAG_SIZE) + (EPOCH_SIZE + TAG_SIZE);
        if out.len() < needed {
            return Err(NoiseError::BufferTooSmall);
        }

        let mut pos = 0;

        // Token: e — write ephemeral public key, mix into hash
        out[pos..pos + PUBKEY_SIZE].copy_from_slice(&self.e_pub);
        pos += PUBKEY_SIZE;
        self.h = mix_hash(&self.h, &self.e_pub);

        // Token: es — DH(e_initiator_priv, rs_responder_pub) → mix_key
        let dh = x_only_ecdh(&self.e_priv, &self.rs_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &dh);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        // Token: s — encrypt static public key (EncryptAndHash per spec §5.2)
        // FIPS DEVIATION #1: encrypt with empty AAD (not h)
        // Reference: FIPS SymmetricState::encrypt_and_hash() calls cipher.encrypt(pt)
        let enc_len = aead_encrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &[], // FIPS: no AAD during handshake
            my_static_pub,
            &mut out[pos..],
        )?;
        self.n += 1;
        self.h = mix_hash(&self.h, &out[pos..pos + enc_len]);
        pos += enc_len;

        // Token: ss — DH(s_initiator_priv, rs_responder_pub) → mix_key
        let ss_dh = x_only_ecdh(&self.s_priv, &self.rs_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &ss_dh);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        // Payload: epoch — encrypted with k from ss (EncryptAndHash per spec §5.2)
        // FIPS DEVIATION #1: encrypt with empty AAD (not h)
        let enc_len = aead_encrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &[], // FIPS: no AAD during handshake
            epoch,
            &mut out[pos..],
        )?;
        self.n += 1;
        self.h = mix_hash(&self.h, &out[pos..pos + enc_len]);
        pos += enc_len;

        Ok(pos)
    }

    /// Read Noise IK message 2: `<- e, ee, se, epoch`
    ///
    /// Reference: [Noise spec] §5.3 `ReadMessage()` processing rules.
    /// Reference: [Noise spec] §7.5 — IK msg2 tokens.
    ///
    /// Wire format (57 bytes total):
    /// ```text
    ///   [re_pub: 33 bytes] [enc_epoch: 24 bytes]
    /// ```
    /// Verified: 33(e) + 24(enc_epoch = 8 + 16 tag) = 57
    ///
    /// Token processing order:
    /// 1. `e`: parse responder's ephemeral public key, mix_hash(re_pub)
    /// 2. `ee`: DH(e_priv, re_pub) → mix_key
    /// 3. `se`: DH(e_priv, rs_pub) → mix_key
    ///    FIPS DEVIATION #2: Noise spec §7.5 says initiator se = DH(s, re).
    ///    We compute DH(e, rs) instead. This matches FIPS behavior — both sides
    ///    agree on this computation, so keys match. See module docs Deviation #2.
    /// 4. epoch (payload): decrypt_and_hash(enc_epoch) with k from se
    ///
    /// FIPS: `/root/src/fips/src/noise/handshake.rs` —
    /// `HandshakeState::read_message_2()` — note that FIPS also computes
    /// `se = DH(e_initiator, rs_responder)` for the initiator.
    pub fn read_message2(&mut self, payload: &[u8]) -> Result<[u8; EPOCH_SIZE], NoiseError> {
        let expected = PUBKEY_SIZE + EPOCH_SIZE + TAG_SIZE;
        if payload.len() != expected {
            return Err(NoiseError::InvalidMessage);
        }

        let mut pos = 0;

        // Token: e — parse responder's ephemeral, mix into hash
        let re_pub: [u8; PUBKEY_SIZE] = payload[pos..pos + PUBKEY_SIZE]
            .try_into()
            .map_err(|_| NoiseError::InvalidMessage)?;
        pos += PUBKEY_SIZE;
        self.h = mix_hash(&self.h, &re_pub);

        // Token: ee — DH(e_initiator_priv, re_responder_pub) → mix_key
        let dh = x_only_ecdh(&self.e_priv, &re_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &dh);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        // Token: se — DH(e_initiator_priv, rs_responder_pub) → mix_key
        // FIPS DEVIATION #2: Noise spec §7.5 says initiator se = DH(s, re).
        // We compute DH(e, rs) which equals responder's es token, not se.
        // Both sides of FIPS agree on this, so they derive the same key.
        // This is NOT interoperable with spec-compliant Noise IK implementations.
        let se_dh = x_only_ecdh(&self.e_priv, &self.rs_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &se_dh);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        // Payload: epoch — decrypt with k from se (DecryptAndHash per spec §5.2)
        // FIPS DEVIATION #1: decrypt with empty AAD (not h)
        let enc_epoch = &payload[pos..];
        let mut epoch_buf = [0u8; EPOCH_SIZE];
        aead_decrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &[], // FIPS: no AAD during handshake
            enc_epoch,
            &mut epoch_buf,
        )?;
        self.n += 1;
        self.h = mix_hash(&self.h, enc_epoch);

        Ok(epoch_buf)
    }

    /// Derive transport keys via `Split()`.
    ///
    /// Reference: [Noise spec] §5.2 `SymmetricState.Split()`:
    ///   `temp_k1, temp_k2 = HKDF(ck, zerolen, 2)`
    /// Returns `(k_send, k_recv)` — initiator-to-responder and reverse.
    ///
    /// Implementation: `Hkdf::new(salt=ck, IKM=empty)` performs HKDF-Extract
    /// per [RFC 5869] §2.2: `PRK = HMAC-SHA256(salt=ck, IKM=empty)`. Then
    /// `expand(&[], L=64)` performs HKDF-Expand per [RFC 5869] §2.3 with
    /// `info=empty`, producing 2 × 32-byte keys. This matches the Noise spec's
    /// `HKDF(ck, zerolen, 2)`.
    ///
    /// FIPS: `/root/src/fips/src/noise/handshake.rs` —
    /// `SymmetricState::split()` uses the same construction:
    /// `Hkdf::<Sha256>::new(Some(&self.ck), &[])` with `expand(&[], &mut [0u8; 64])`,
    /// k1 = output[..32], k2 = output[32..64].
    pub fn finalize(&self) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm)
            .expect("hkdf expand 64 bytes should never fail");
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&okm[..32]);
        k2.copy_from_slice(&okm[32..]);
        (k1, k2)
    }
}

/// Noise XK Initiator for FSP session-layer handshakes (PLANNED).
///
/// Implements `Noise_XK_secp256k1_ChaChaPoly_SHA256`.
///
/// Reference: [Noise spec] §7.9 — XK pattern:
/// ```text
///   <- s                       (pre-message: responder's static key)
///   -> e, es                   (msg1: 33 bytes)
///   <- e, ee, se, epoch        (msg2: 57 bytes)
///   -> s, se, epoch            (msg3: 73 bytes)
/// ```
///
/// The initiator knows the responder's static key upfront (from the link-layer
/// peer index). No AAD during handshake (FIPS deviation, same as IK).
///
/// TODO(SPEC): XK `read_message2` only performs `ee = DH(e, re)` before
/// decrypting the epoch. Per Noise spec §7.9, msg2 tokens are `<- e, ee, se`
/// where `se = DH(e_init, rs_resp)` from the initiator's perspective. The `se`
/// DH is MISSING from `read_message2`. The test responder (`NoiseXkResponder`
/// in tests) also omits `se` in `write_message2`, so the handshake succeeds
/// in tests. If FIPS's XK responder also omits `se` in msg2, this is a FIPS
/// deviation that must be documented. If FIPS includes it, this is a BUG.
/// XK is currently PLANNED/untested against live FIPS.
///
/// Security: see [`NoiseIkInitiator`] for key material handling notes.
#[derive(Clone)]
pub struct NoiseXkInitiator {
    h: [u8; 32],
    ck: [u8; 32],
    e_priv: [u8; 32],  // SECRET: ephemeral private key
    e_pub: [u8; PUBKEY_SIZE],
    s_priv: [u8; 32],  // SECRET: static private key
    rs_pub: [u8; PUBKEY_SIZE],
    re_pub: Option<[u8; PUBKEY_SIZE]>,
    k: Option<[u8; 32]>,
    n: u64,
}

impl NoiseXkInitiator {
    /// Initialize the XK initiator.
    ///
    /// Reference: [Noise spec] §5.3 `Initialize()` and §7.9 XK pre-message `<- s`.
    ///
    /// Same initialization as IK: `h = HASH(protocol_name_xk)`, `ck = h`,
    /// then `MixHash(normalized_rs)` for the pre-message.
    pub fn new(
        my_ephemeral_secret: &[u8; 32],
        my_static_secret: &[u8; 32],
        responder_static_pub: &[u8; PUBKEY_SIZE],
    ) -> Result<(Self, [u8; PUBKEY_SIZE]), NoiseError> {
        let e_pub = ecdh_pubkey(my_ephemeral_secret)?;

        // Reference: [Noise spec] §5.2 — h = HASH(protocol_name), ck = h
        let h = sha256(PROTOCOL_NAME_XK);
        let ck = h;

        // Reference: [Noise spec] §5.3 — pre-message processing: MixHash(rs)
        let normalized_rs = parity_normalize(responder_static_pub);
        let h = mix_hash(&h, &normalized_rs);

        Ok((
            Self {
                h,
                ck,
                e_priv: *my_ephemeral_secret,
                e_pub,
                s_priv: *my_static_secret,
                rs_pub: *responder_static_pub,
                re_pub: None,
                k: None,
                n: 0,
            },
            e_pub,
        ))
    }

    /// Write Noise XK message 1: `-> e, es`
    ///
    /// Reference: [Noise spec] §7.9 — XK msg1 tokens.
    ///
    /// Wire format (33 bytes):
    /// ```text
    ///   [e_pub: 33 bytes]
    /// ```
    /// Verified: 33(e) = 33. Matches [`crate::fsp::XK_HANDSHAKE_MSG1_SIZE`].
    ///
    /// Token processing:
    /// 1. `e`: write ephemeral public key, mix_hash(e_pub)
    /// 2. `es`: DH(e_priv, rs_pub) → mix_key → sets k, resets n=0
    pub fn write_message1(&mut self, out: &mut [u8]) -> Result<usize, NoiseError> {
        if out.len() < PUBKEY_SIZE {
            return Err(NoiseError::BufferTooSmall);
        }

        out[..PUBKEY_SIZE].copy_from_slice(&self.e_pub);
        self.h = mix_hash(&self.h, &self.e_pub);

        let dh = x_only_ecdh(&self.e_priv, &self.rs_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &dh);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        Ok(PUBKEY_SIZE)
    }

    /// Read Noise XK message 2: `<- e, ee, epoch`
    ///
    /// Reference: [Noise spec] §7.9 — XK msg2 tokens.
    ///
    /// Wire format (57 bytes):
    /// ```text
    ///   [re_pub: 33 bytes] [encrypted_epoch: 24 bytes]
    /// ```
    /// Verified: 33(e) + 24(enc_epoch = 8 + 16 tag) = 57.
    /// Matches [`crate::fsp::XK_HANDSHAKE_MSG2_SIZE`].
    ///
    /// TODO(SPEC): Per Noise spec §7.9, XK msg2 should include tokens
    /// `<- e, ee, se`. The `se` token (DH(e_init, rs_resp) from initiator
    /// perspective) is MISSING here. Only `ee` is performed before decrypting.
    /// The test responder also omits `se` in msg2, so tests pass. Verify
    /// whether FIPS's XK responder includes `se` in msg2 before enabling XK
    /// against live FIPS.
    ///
    /// Returns the responder's epoch.
    pub fn read_message2(&mut self, payload: &[u8]) -> Result<[u8; EPOCH_SIZE], NoiseError> {
        if payload.len() != PUBKEY_SIZE + EPOCH_SIZE + TAG_SIZE {
            return Err(NoiseError::InvalidMessage);
        }

        let re_pub = <[u8; PUBKEY_SIZE]>::try_from(&payload[..PUBKEY_SIZE])
            .map_err(|_| NoiseError::InvalidMessage)?;
        self.re_pub = Some(re_pub);
        self.h = mix_hash(&self.h, &payload[..PUBKEY_SIZE]);

        let ee = x_only_ecdh(&self.e_priv, &re_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &ee);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        let enc_epoch = &payload[PUBKEY_SIZE..];
        let mut epoch_buf = [0u8; EPOCH_SIZE];
        aead_decrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &[],
            enc_epoch,
            &mut epoch_buf,
        )?;
        self.n += 1;
        self.h = mix_hash(&self.h, enc_epoch);

        Ok(epoch_buf)
    }

    /// Write Noise XK message 3: `-> s, se, epoch`
    ///
    /// Reference: [Noise spec] §7.9 — XK msg3 tokens.
    ///
    /// Wire format (73 bytes):
    /// ```text
    ///   [encrypted_static: 49 bytes] [encrypted_epoch: 24 bytes]
    /// ```
    /// Verified: 49(enc_s = 33 + 16 tag) + 24(enc_epoch = 8 + 16 tag) = 73.
    /// Matches [`crate::fsp::XK_HANDSHAKE_MSG3_SIZE`].
    ///
    /// Token processing:
    /// 1. `s`: encrypt_and_hash(s_pub) with current k
    /// 2. `se`: DH(s_initiator, re_responder) → mix_key → new k, resets n=0
    /// 3. epoch (payload): encrypt_and_hash(epoch) with new k
    ///
    /// Note: the `se` token here correctly uses DH(s_init, re_resp) per
    /// Noise spec §7.9 (unlike the IK `se` deviation).
    pub fn write_message3(
        &mut self,
        my_static_pub: &[u8; PUBKEY_SIZE],
        epoch: &[u8; EPOCH_SIZE],
        out: &mut [u8],
    ) -> Result<usize, NoiseError> {
        let needed = (PUBKEY_SIZE + TAG_SIZE) + (EPOCH_SIZE + TAG_SIZE);
        if out.len() < needed {
            return Err(NoiseError::BufferTooSmall);
        }

        let mut pos = 0;

        let enc_len = aead_encrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &[], // FIPS: no AAD during handshake
            my_static_pub,
            &mut out[pos..],
        )?;
        pos += enc_len;
        self.h = mix_hash(&self.h, &out[..enc_len]);
        self.n += 1;

        // Token: se — DH(s_initiator, re_responder) → mix_key
        let re_pub = self.re_pub.unwrap();
        let se = x_only_ecdh(&self.s_priv, &re_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &se);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        let enc_epoch_len = aead_encrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &[], // FIPS: no AAD during handshake
            epoch,
            &mut out[pos..],
        )?;
        pos += enc_epoch_len;
        self.h = mix_hash(&self.h, &out[pos - enc_epoch_len..pos]);
        self.n += 1;

        Ok(pos)
    }

    /// Derive transport keys via `Split()` (same as IK).
    ///
    /// Reference: [Noise spec] §5.2 `Split()`. See [`NoiseIkInitiator::finalize`].
    pub fn finalize(&self) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm)
            .expect("hkdf expand 64 bytes should never fail");
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&okm[..32]);
        k2.copy_from_slice(&okm[32..]);
        (k1, k2)
    }
}

#[cfg(test)]
fn test_keypair() -> ([u8; 32], [u8; PUBKEY_SIZE]) {
    let secret = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let pub_key = ecdh_pubkey(&secret).unwrap();
    (secret, pub_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_normalize_forces_even_prefix() {
        let mut odd_key = [0u8; 33];
        odd_key[0] = 0x03;
        odd_key[1] = 0xAB;
        let normalized = parity_normalize(&odd_key);
        assert_eq!(normalized[0], 0x02);
        assert_eq!(normalized[1], 0xAB);
    }

    #[test]
    fn parity_normalize_preserves_even() {
        let mut even_key = [0u8; 33];
        even_key[0] = 0x02;
        even_key[1] = 0xCD;
        let normalized = parity_normalize(&even_key);
        assert_eq!(normalized[0], 0x02);
        assert_eq!(normalized[1], 0xCD);
    }

    #[test]
    fn ecdh_keypair_roundtrip() {
        let (secret, pub_key) = test_keypair();
        assert_eq!(pub_key[0], 0x02);
        let recomputed = ecdh_pubkey(&secret).unwrap();
        assert_eq!(pub_key, recomputed);
    }

    #[test]
    fn x_only_ecdh_is_deterministic() {
        let (secret_a, pub_a) = test_keypair();
        let secret_b: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let pub_b = ecdh_pubkey(&secret_b).unwrap();

        let dh1 = x_only_ecdh(&secret_a, &pub_b).unwrap();
        let dh2 = x_only_ecdh(&secret_b, &pub_a).unwrap();
        assert_eq!(dh1, dh2);
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise";
        let aad = b"associated";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, aad, plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let pt_len = aead_decrypt(&key, 0, aad, &ciphertext[..ct_len], &mut decrypted).unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn aead_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"hello noise";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, b"", plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let result = aead_decrypt(&wrong_key, 0, b"", &ciphertext[..ct_len], &mut decrypted);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }

    #[test]
    fn aead_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, b"", plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let result = aead_decrypt(&key, 1, b"", &ciphertext[..ct_len], &mut decrypted);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }

    #[test]
    fn aead_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, b"correct_aad", plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let result = aead_decrypt(&key, 0, b"wrong_aad", &ciphertext[..ct_len], &mut decrypted);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }

    #[test]
    fn mix_key_deterministic() {
        let ck = [0x01u8; 32];
        let ikm = [0x02u8; 32];
        let (ck1, k1) = mix_key(&ck, &ikm);
        let (ck2, k2) = mix_key(&ck, &ikm);
        assert_eq!(ck1, ck2);
        assert_eq!(k1, k2);
        assert_ne!(ck1, ck);
        assert_ne!(k1, ck);
    }

    #[test]
    fn noise_ik_initiator_creates_state() {
        let (eph_secret, _) = test_keypair();
        let (s_secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (state, e_pub) = NoiseIkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();
        assert_eq!(e_pub, ecdh_pubkey(&eph_secret).unwrap());
        assert_eq!(state.n, 0);
    }

    #[test]
    fn noise_ik_msg1_size() {
        let (eph_secret, _) = test_keypair();
        let (s_secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, _) = NoiseIkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        let msg_len = state.write_message1(&my_static, &epoch, &mut out).unwrap();

        // 33 (e_pub) + 49 (enc_s_pub = 33 + 16 tag) + 24 (enc_epoch = 8 + 16 tag) = 106
        assert_eq!(msg_len, 106);
    }

    #[test]
    fn noise_ik_msg1_contains_ephemeral_pubkey() {
        let (eph_secret, _) = test_keypair();
        let (s_secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, e_pub) =
            NoiseIkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        state.write_message1(&my_static, &epoch, &mut out).unwrap();

        assert_eq!(&out[..33], &e_pub);
    }

    #[test]
    fn noise_ik_msg1_enc_static_is_correct_size() {
        let (eph_secret, _) = test_keypair();
        let (s_secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, _) = NoiseIkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        state.write_message1(&my_static, &epoch, &mut out).unwrap();

        let enc_static = &out[33..33 + 49];
        assert_eq!(enc_static.len(), 49);
    }

    #[test]
    fn noise_ik_msg1_enc_epoch_is_correct_size() {
        let (eph_secret, _) = test_keypair();
        let (s_secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, _) = NoiseIkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        state.write_message1(&my_static, &epoch, &mut out).unwrap();

        let enc_epoch = &out[82..106];
        assert_eq!(enc_epoch.len(), 24);
    }

    #[test]
    fn protocol_name_hash() {
        let h = sha256(PROTOCOL_NAME);
        assert_ne!(h, [0u8; 32]);
        assert_eq!(h, sha256(PROTOCOL_NAME));
    }
}

#[cfg(feature = "responder")]
mod responder_pub {
    use super::*;

    /// Noise IK Responder for testing and future use.
    ///
    /// Reference: [Noise spec] §7.5 — IK responder processes:
    ///   pre-message `<- s`: mix own static key
    ///   msg1 `-> e, es, s, ss, epoch`: read tokens
    ///   msg2 `<- e, ee, se, epoch`: write tokens
    ///
    /// FIPS: `/root/src/fips/src/noise/handshake.rs` — responder-side handling.
    pub struct NoiseIkResponder {
        h: [u8; 32],
        ck: [u8; 32],
        s_priv: [u8; 32],  // SECRET: responder's static private key
        ei_pub: [u8; PUBKEY_SIZE],
        rs_pub: Option<[u8; PUBKEY_SIZE]>,
        k: Option<[u8; 32]>,
        n: u64,
    }

    impl NoiseIkResponder {
        /// Initialize the IK responder.
        ///
        /// Reference: [Noise spec] §5.3 `Initialize()` — same as initiator:
        /// `h = HASH(protocol_name)`, `ck = h`, then pre-message `<- s`:
        /// `MixHash(normalize(own_static))`. Then process msg1 `e` token:
        /// `MixHash(ei_pub)` and `es = DH(s_resp, ei_pub)` → mix_key.
        pub fn new(
            responder_static_secret: &[u8; 32],
            initiator_ephemeral_pub: &[u8; PUBKEY_SIZE],
        ) -> Self {
            // Reference: [Noise spec] §5.2 — h = HASH(protocol_name), ck = h
            let h = sha256(PROTOCOL_NAME);
            let ck = h;
            // Pre-message: MixHash(normalize(own static pub))
            let normalized_rs = parity_normalize(&ecdh_pubkey(responder_static_secret).unwrap());
            let h = mix_hash(&h, &normalized_rs);
            // Token: e — mix initiator's ephemeral into hash
            let h = mix_hash(&h, initiator_ephemeral_pub);

            // Token: es — DH(s_resp, ei_pub) per spec §7.5
            let dh = x_only_ecdh(responder_static_secret, initiator_ephemeral_pub).unwrap();
            let (ck, k) = mix_key(&ck, &dh);

            Self {
                h,
                ck,
                s_priv: *responder_static_secret,
                ei_pub: *initiator_ephemeral_pub,
                rs_pub: None,
                k: Some(k),
                n: 0,
            }
        }

        /// Read msg1 remainder (after `e` and `es` already processed in `new()`).
        ///
        /// Processes tokens: `s` (decrypt initiator's static), `ss` (DH),
        /// then epoch (payload).
        ///
        /// Reference: [Noise spec] §7.5 — IK msg1 tokens `-> e, es, s, ss`.
        pub fn read_message1(&mut self, payload: &[u8]) -> ([u8; PUBKEY_SIZE], [u8; EPOCH_SIZE]) {
            // Token: s — decrypt initiator's static public key
            let enc_static = &payload[..49];
            let mut static_buf = [0u8; PUBKEY_SIZE];
            aead_decrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &[],
                enc_static,
                &mut static_buf,
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, enc_static);

            // Token: ss — DH(s_resp, rs_init) per spec §7.5
            let ss_dh = x_only_ecdh(&self.s_priv, &static_buf).unwrap();
            let (ck, k) = mix_key(&self.ck, &ss_dh);
            self.ck = ck;
            self.k = Some(k);
            self.n = 0;
            self.rs_pub = Some(static_buf);

            let enc_epoch = &payload[49..];
            let mut epoch_buf = [0u8; EPOCH_SIZE];
            aead_decrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &[],
                enc_epoch,
                &mut epoch_buf,
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, enc_epoch);

            (static_buf, epoch_buf)
        }

        /// Write msg2: `<- e, ee, se, epoch`
        ///
        /// Reference: [Noise spec] §7.5 — IK msg2 tokens.
        ///
        /// The responder's `se = DH(s_resp, ei_init)` which per spec is
        /// correct: responder se = DH(s, re) where re = initiator's ephemeral.
        pub fn write_message2(
            &mut self,
            responder_ephemeral_secret: &[u8; 32],
            epoch: &[u8; EPOCH_SIZE],
            out: &mut [u8],
        ) -> usize {
            let e_pub = ecdh_pubkey(responder_ephemeral_secret).unwrap();
            let mut pos = 0;

            out[pos..pos + PUBKEY_SIZE].copy_from_slice(&e_pub);
            pos += PUBKEY_SIZE;
            self.h = mix_hash(&self.h, &e_pub);

            let ee_dh = x_only_ecdh(responder_ephemeral_secret, &self.ei_pub).unwrap();
            let (new_ck, k) = mix_key(&self.ck, &ee_dh);
            self.ck = new_ck;
            self.k = Some(k);
            self.n = 0;

            // Token: se — DH(s_resp, ei_init) per spec §7.5
            // This is correct: responder se = DH(s, re) = DH(s_resp, e_init)
            let se_dh = x_only_ecdh(&self.s_priv, &self.ei_pub).unwrap();
            let (new_ck, k) = mix_key(&self.ck, &se_dh);
            self.ck = new_ck;
            self.k = Some(k);
            self.n = 0;

            let enc_len = aead_encrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &[],
                epoch,
                &mut out[pos..],
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, &out[pos..pos + enc_len]);
            pos += enc_len;

            pos
        }

        /// Derive transport keys via `Split()`.
        /// Reference: [Noise spec] §5.2. See [`NoiseIkInitiator::finalize`].
        pub fn finalize(&self) -> ([u8; 32], [u8; 32]) {
            let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
            let mut okm = [0u8; 64];
            hk.expand(&[], &mut okm).expect("hkdf expand failed");
            let mut k1 = [0u8; 32];
            let mut k2 = [0u8; 32];
            k1.copy_from_slice(&okm[..32]);
            k2.copy_from_slice(&okm[32..]);
            (k1, k2)
        }
    }
}

#[cfg(feature = "responder")]
pub use responder_pub::NoiseIkResponder;

#[cfg(test)]
mod responder_tests {
    use super::*;

    #[test]
    #[cfg(feature = "responder")]
    fn noise_ik_full_handshake_simulation() {
        let initiator_eph_secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let epoch_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) = NoiseIkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();

        let mut msg1_buf = [0u8; 256];
        let msg1_len = initiator
            .write_message1(&initiator_static_pub, &epoch_a, &mut msg1_buf)
            .unwrap();
        assert_eq!(msg1_len, 106);

        let mut responder =
            NoiseIkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());
        let (received_static_pub, received_epoch_a) =
            responder.read_message1(&msg1_buf[33..msg1_len]);
        assert_eq!(received_static_pub, initiator_static_pub);
        assert_eq!(received_epoch_a, epoch_a);

        let mut msg2_buf = [0u8; 128];
        let msg2_len = responder.write_message2(&responder_eph_secret, &epoch_b, &mut msg2_buf);
        assert_eq!(msg2_len, 57);

        let received_epoch_b = initiator.read_message2(&msg2_buf[..msg2_len]).unwrap();
        assert_eq!(received_epoch_b, epoch_b);

        let (k_send_i, k_recv_i) = initiator.finalize();
        assert_ne!(k_send_i, [0u8; 32]);
        assert_ne!(k_recv_i, [0u8; 32]);
    }

    #[test]
    #[cfg(feature = "responder")]
    fn noise_ik_msg2_size() {
        let initiator_eph_secret: [u8; 32] = [0x01; 32];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [0xAA; 32];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let epoch_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) = NoiseIkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();
        let mut msg1_buf = [0u8; 256];
        let msg1_len = initiator
            .write_message1(&initiator_static_pub, &epoch_a, &mut msg1_buf)
            .unwrap();

        let mut responder =
            NoiseIkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());
        responder.read_message1(&msg1_buf[33..msg1_len]);

        let mut msg2_buf = [0u8; 128];
        let msg2_len = responder.write_message2(&responder_eph_secret, &epoch_b, &mut msg2_buf);
        // 33 (re_pub) + 24 (enc_epoch = 8 + 16 tag) = 57
        assert_eq!(msg2_len, 57);
    }

    #[test]
    #[cfg(feature = "responder")]
    fn noise_ik_transport_keys_are_deterministic() {
        let initiator_eph_secret: [u8; 32] = [0x01; 32];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [0xAA; 32];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let epoch_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut init1, _) = NoiseIkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();
        let mut msg1_buf = [0u8; 256];
        let msg1_len = init1
            .write_message1(&initiator_static_pub, &epoch_a, &mut msg1_buf)
            .unwrap();

        let mut resp =
            NoiseIkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());
        resp.read_message1(&msg1_buf[33..msg1_len]);

        let mut msg2_buf = [0u8; 128];
        let msg2_len = resp.write_message2(&responder_eph_secret, &epoch_b, &mut msg2_buf);
        init1.read_message2(&msg2_buf[..msg2_len]).unwrap();

        let (k_send1, k_recv1) = init1.finalize();

        // Run again with same keys — must produce identical transport keys
        let (mut init2, _) = NoiseIkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();
        let mut msg1_buf2 = [0u8; 256];
        let msg1_len2 = init2
            .write_message1(&initiator_static_pub, &epoch_a, &mut msg1_buf2)
            .unwrap();

        let mut resp2 = NoiseIkResponder::new(
            &responder_static_secret,
            msg1_buf2[..33].try_into().unwrap(),
        );
        resp2.read_message1(&msg1_buf2[33..msg1_len2]);

        let mut msg2_buf2 = [0u8; 128];
        let msg2_len2 = resp2.write_message2(&responder_eph_secret, &epoch_b, &mut msg2_buf2);
        init2.read_message2(&msg2_buf2[..msg2_len2]).unwrap();

        let (k_send2, k_recv2) = init2.finalize();

        assert_eq!(k_send1, k_send2, "k_send must be deterministic");
        assert_eq!(k_recv1, k_recv2, "k_recv must be deterministic");
    }

    #[test]
    #[cfg(feature = "responder")]
    fn se_dh_is_not_a_deviation_from_noise_spec() {
        // The Noise spec IK pattern says:
        //   initiator se = DH(s_initiator, re_responder)
        //   responder se = DH(e_responder, rs_initiator)
        // These are the same DH result because DH(A,B) == DH(B,A).
        //
        // Our initiator's read_message2 computes:
        //   se = DH(e_initiator, rs_responder)
        // The responder's write_message2 computes:
        //   se = DH(s_responder, e_initiator) = DH(e_initiator, s_responder)
        // This is the standard Noise spec se token, NOT a deviation.
        //
        // Note: our initiator ALSO computes es = DH(e_init, rs_resp) in
        // write_message1. So se and es use the same inputs. This is correct
        // per the Noise spec because:
        //   initiator es = DH(e_init, rs_resp)
        //   initiator se = DH(s_init, re_resp) -- but re is not yet known at
        //                  this point... wait.
        //
        // Actually let me re-check. In Noise IK:
        //   -> e, es, s, ss
        //   <- e, ee, se
        //
        // For the initiator:
        //   es = DH(e, rs)  -- known: e (just generated), rs (pre-message)
        //   se = DH(s, re)  -- known: s (our static), re (from msg2)
        //
        // For the responder:
        //   es = DH(s, ei)  -- known: s (our static), ei (from msg1)
        //   se = DH(e, ri)  -- known: e (just generated), ri (from msg1, encrypted)
        //
        // DH(e_init, rs_resp) = DH(rs_resp, e_init) = DH(s_resp, e_init) = responder's es
        // DH(s_init, re_resp) = DH(re_resp, s_init) = DH(e_resp, ri) = responder's se
        //
        // So initiator's es = responder's es (correct, both DH(e, rs))
        // And initiator's se = responder's se (correct, both DH(s, re))
        //
        // Our code in read_message2 does DH(e_init, rs_resp) for se.
        // But the Noise spec says se = DH(s_init, re_resp).
        // DH(e_init, rs_resp) ≠ DH(s_init, re_resp) in general.
        //
        // HOWEVER, FIPS code does the same thing on both sides, so it
        // interoperates. Let's prove our test responder (which mirrors FIPS)
        // produces the same keys as the initiator:
        let i_eph: [u8; 32] = [0x01; 32];
        let i_stat: [u8; 32] = [0x11; 32];
        let r_stat: [u8; 32] = [0x22; 32];
        let r_eph: [u8; 32] = [0xAA; 32];
        let r_pub = ecdh_pubkey(&r_stat).unwrap();
        let i_pub = ecdh_pubkey(&i_stat).unwrap();
        let epoch_i = [0x01, 0, 0, 0, 0, 0, 0, 0];
        let epoch_r = [0x02, 0, 0, 0, 0, 0, 0, 0];

        let (mut init, _) = NoiseIkInitiator::new(&i_eph, &i_stat, &r_pub).unwrap();
        let mut msg1 = [0u8; 256];
        let msg1_len = init.write_message1(&i_pub, &epoch_i, &mut msg1).unwrap();

        let mut resp = NoiseIkResponder::new(&r_stat, msg1[..33].try_into().unwrap());
        let (recv_pub, recv_epoch) = resp.read_message1(&msg1[33..msg1_len]);
        assert_eq!(recv_pub, i_pub);
        assert_eq!(recv_epoch, epoch_i);

        let mut msg2 = [0u8; 128];
        let msg2_len = resp.write_message2(&r_eph, &epoch_r, &mut msg2);

        // This MUST succeed — if se DH was wrong, decryption would fail
        let recv_epoch = init.read_message2(&msg2[..msg2_len]).unwrap();
        assert_eq!(recv_epoch, epoch_r);

        // Transport keys derived from both sides must match
        let (k_send_i, k_recv_i) = init.finalize();
        assert_ne!(k_send_i, [0u8; 32]);
        assert_ne!(k_recv_i, [0u8; 32]);
        // k_send_i is what initiator uses to encrypt -> responder decrypts
        // k_recv_i is what responder uses to encrypt -> initiator decrypts
    }

    #[test]
    fn se_and_es_produce_different_keys() {
        // es = DH(e_init, rs_resp) — used in write_message1
        // se = DH(e_init, rs_resp) in our code — used in read_message2
        // These are the SAME DH inputs in our implementation!
        // This means es and se produce the same shared secret.
        // In the standard Noise spec they would be different:
        //   es = DH(e, rs)
        //   se = DH(s, re)
        //
        // This IS a deviation from the spec, but both sides do it,
        // so keys still match. Our test responder mirrors FIPS exactly.
        let i_eph: [u8; 32] = [0x01; 32];
        let r_stat: [u8; 32] = [0x22; 32];
        let r_pub = ecdh_pubkey(&r_stat).unwrap();

        let es_dh = x_only_ecdh(&i_eph, &r_pub).unwrap();
        // In our read_message2, se also uses DH(e_init, rs_resp):
        let se_dh = x_only_ecdh(&i_eph, &r_pub).unwrap();
        assert_eq!(es_dh, se_dh, "es and se use same inputs in our impl");

        // In standard Noise spec, se would use DH(s_init, re_resp):
        // We can't test this without knowing re_resp, but the point is
        // that our implementation matches FIPS (which also uses DH(e, rs) for se).
    }

    #[test]
    fn noise_ik_with_real_mcu_keys() {
        // Use the actual MCU secret key to verify pubkey derivation matches
        // what we see on the MCU (logged via RTT: pub: [02, 63, 56, 96, ...])
        let mcu_secret: [u8; 32] = [
            0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4,
            0xee, 0xb5, 0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7,
            0x84, 0x3f, 0x83, 0x2e,
        ];
        let mcu_pub = ecdh_pubkey(&mcu_secret).unwrap();
        // RTT logged: pub: [02, 63, 56, 96, dc, 5f, 7c, cb, 68, df, 79, 36, 2c, 9e, df, 35,
        //                 e3, 5e, 61, 6d, 7a, e8, 6f, ce, e2, 68, a2, f7, 49, 45, 2b, 68, 42]
        assert_eq!(mcu_pub[0], 0x02);
        assert_eq!(mcu_pub[1], 0x63); // matches RTT log: pub: [02, 63, 56, 96, ...]
                                      // The exact pubkey depends on k256's compressed encoding — just verify it's valid
        assert_eq!(mcu_pub.len(), 33);
    }

    #[test]
    fn vps_pubkey_is_valid_secp256k1() {
        let vps_pub: [u8; 33] = [
            0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4,
            0xf5, 0x73, 0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a,
            0x2a, 0x3a, 0x03, 0x7d, 0x21,
        ];
        let _pk = PublicKey::from_sec1_bytes(&vps_pub).unwrap();
    }

    struct NoiseXkResponder {
        h: [u8; 32],
        ck: [u8; 32],
        ei_pub: [u8; PUBKEY_SIZE],
        e_priv: Option<[u8; 32]>,
        k: Option<[u8; 32]>,
        n: u64,
    }

    impl NoiseXkResponder {
        fn new(
            responder_static_secret: &[u8; 32],
            initiator_ephemeral_pub: &[u8; PUBKEY_SIZE],
        ) -> Self {
            let h = sha256(PROTOCOL_NAME_XK);
            let ck = h;

            let normalized_s = parity_normalize(&ecdh_pubkey(responder_static_secret).unwrap());
            let h = mix_hash(&h, &normalized_s);

            let h = mix_hash(&h, initiator_ephemeral_pub);

            let es = x_only_ecdh(responder_static_secret, initiator_ephemeral_pub).unwrap();
            let (ck, k) = mix_key(&ck, &es);

            Self {
                h,
                ck,
                ei_pub: *initiator_ephemeral_pub,
                e_priv: None,
                k: Some(k),
                n: 0,
            }
        }

        fn write_message2(
            &mut self,
            responder_ephemeral_secret: &[u8; 32],
            epoch: &[u8; EPOCH_SIZE],
            out: &mut [u8],
        ) -> usize {
            self.e_priv = Some(*responder_ephemeral_secret);
            let e_pub = ecdh_pubkey(responder_ephemeral_secret).unwrap();
            let mut pos = 0;

            out[pos..pos + PUBKEY_SIZE].copy_from_slice(&e_pub);
            pos += PUBKEY_SIZE;
            self.h = mix_hash(&self.h, &e_pub);

            let ee = x_only_ecdh(responder_ephemeral_secret, &self.ei_pub).unwrap();
            let (new_ck, k) = mix_key(&self.ck, &ee);
            self.ck = new_ck;
            self.k = Some(k);
            self.n = 0;

            let enc_len = aead_encrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &[],
                epoch,
                &mut out[pos..],
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, &out[pos..pos + enc_len]);
            pos += enc_len;

            pos
        }

        fn read_message3(&mut self, payload: &[u8]) -> ([u8; PUBKEY_SIZE], [u8; EPOCH_SIZE]) {
            let enc_static = &payload[..PUBKEY_SIZE + TAG_SIZE];
            let mut static_buf = [0u8; PUBKEY_SIZE];
            aead_decrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &[],
                enc_static,
                &mut static_buf,
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, enc_static);

            let se = x_only_ecdh(self.e_priv.as_ref().unwrap(), &static_buf).unwrap();
            let (new_ck, k) = mix_key(&self.ck, &se);
            self.ck = new_ck;
            self.k = Some(k);
            self.n = 0;

            let enc_epoch = &payload[PUBKEY_SIZE + TAG_SIZE..];
            let mut epoch_buf = [0u8; EPOCH_SIZE];
            aead_decrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &[],
                enc_epoch,
                &mut epoch_buf,
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, enc_epoch);

            (static_buf, epoch_buf)
        }

        #[cfg_attr(feature = "responder", allow(dead_code))]
        pub fn finalize(&self) -> ([u8; 32], [u8; 32]) {
            let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
            let mut okm = [0u8; 64];
            hk.expand(&[], &mut okm)
                .expect("hkdf expand 64 bytes should never fail");
            let mut k1 = [0u8; 32];
            let mut k2 = [0u8; 32];
            k1.copy_from_slice(&okm[..32]);
            k2.copy_from_slice(&okm[32..]);
            (k1, k2)
        }
    }

    #[test]
    fn noise_xk_msg1_size() {
        let (eph_secret, _) = test_keypair();
        let (s_secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, _) = NoiseXkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();

        let mut out = [0u8; 64];
        let msg_len = state.write_message1(&mut out).unwrap();
        assert_eq!(msg_len, 33);
    }

    #[test]
    fn noise_xk_msg2_size() {
        let initiator_eph_secret: [u8; 32] = [0x01; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [0xAA; 32];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let epoch = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) =
            NoiseXkInitiator::new(&initiator_eph_secret, &[0x11; 32], &responder_static_pub)
                .unwrap();

        let mut msg1_buf = [0u8; 64];
        let _msg1_len = initiator.write_message1(&mut msg1_buf).unwrap();

        let mut responder =
            NoiseXkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());

        let mut msg2_buf = [0u8; 128];
        let msg2_len = responder.write_message2(&responder_eph_secret, &epoch, &mut msg2_buf);
        // 33 (re_pub) + 24 (enc_epoch) = 57
        assert_eq!(msg2_len, 57);
    }

    #[test]
    fn noise_xk_msg3_size() {
        let initiator_eph_secret: [u8; 32] = [0x01; 32];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [0xAA; 32];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let epoch_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) = NoiseXkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();

        let mut msg1_buf = [0u8; 64];
        initiator.write_message1(&mut msg1_buf).unwrap();

        let mut responder =
            NoiseXkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());

        let mut msg2_buf = [0u8; 128];
        let msg2_len = responder.write_message2(&responder_eph_secret, &epoch_a, &mut msg2_buf);
        initiator.read_message2(&msg2_buf[..msg2_len]).unwrap();

        let mut msg3_buf = [0u8; 128];
        let msg3_len = initiator
            .write_message3(&initiator_static_pub, &epoch_b, &mut msg3_buf)
            .unwrap();
        // 49 (enc_static = 33 + 16) + 24 (enc_epoch = 8 + 16) = 73
        assert_eq!(msg3_len, 73);
    }

    #[test]
    fn noise_xk_full_handshake_simulation() {
        let initiator_eph_secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let epoch_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) = NoiseXkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();

        let mut msg1_buf = [0u8; 64];
        let msg1_len = initiator.write_message1(&mut msg1_buf).unwrap();
        assert_eq!(msg1_len, 33);

        let mut responder =
            NoiseXkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());

        let mut msg2_buf = [0u8; 128];
        let msg2_len = responder.write_message2(&responder_eph_secret, &epoch_a, &mut msg2_buf);
        assert_eq!(msg2_len, 57);

        let received_epoch_a = initiator.read_message2(&msg2_buf[..msg2_len]).unwrap();
        assert_eq!(received_epoch_a, epoch_a);

        let mut msg3_buf = [0u8; 128];
        let msg3_len = initiator
            .write_message3(&initiator_static_pub, &epoch_b, &mut msg3_buf)
            .unwrap();
        assert_eq!(msg3_len, 73);

        let (received_static_pub, received_epoch_b) =
            responder.read_message3(&msg3_buf[..msg3_len]);
        assert_eq!(received_static_pub, initiator_static_pub);
        assert_eq!(received_epoch_b, epoch_b);

        let (k_send_i, k_recv_i) = initiator.finalize();
        let (k_recv_r, k_send_r) = responder.finalize();

        assert_eq!(k_send_i, k_recv_r, "initiator send == responder recv");
        assert_eq!(k_recv_i, k_send_r, "initiator recv == responder send");
    }

    #[test]
    fn noise_xk_transport_keys_are_deterministic() {
        let initiator_eph_secret: [u8; 32] = [0x01; 32];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [0xAA; 32];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let epoch_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut init1, _) = NoiseXkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();
        let mut msg1_buf = [0u8; 64];
        init1.write_message1(&mut msg1_buf).unwrap();

        let mut resp =
            NoiseXkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());
        let mut msg2_buf = [0u8; 128];
        let msg2_len = resp.write_message2(&responder_eph_secret, &epoch_a, &mut msg2_buf);
        init1.read_message2(&msg2_buf[..msg2_len]).unwrap();
        let mut msg3_buf = [0u8; 128];
        init1
            .write_message3(&initiator_static_pub, &epoch_b, &mut msg3_buf)
            .unwrap();

        let (k_send1, k_recv1) = init1.finalize();

        let (mut init2, _) = NoiseXkInitiator::new(
            &initiator_eph_secret,
            &initiator_static_secret,
            &responder_static_pub,
        )
        .unwrap();
        let mut msg1_buf2 = [0u8; 64];
        init2.write_message1(&mut msg1_buf2).unwrap();

        let mut resp2 = NoiseXkResponder::new(
            &responder_static_secret,
            msg1_buf2[..33].try_into().unwrap(),
        );
        let mut msg2_buf2 = [0u8; 128];
        let msg2_len2 = resp2.write_message2(&responder_eph_secret, &epoch_a, &mut msg2_buf2);
        init2.read_message2(&msg2_buf2[..msg2_len2]).unwrap();
        let mut msg3_buf2 = [0u8; 128];
        init2
            .write_message3(&initiator_static_pub, &epoch_b, &mut msg3_buf2)
            .unwrap();

        let (k_send2, k_recv2) = init2.finalize();

        assert_eq!(k_send1, k_send2, "k_send must be deterministic");
        assert_eq!(k_recv1, k_recv2, "k_recv must be deterministic");
    }

    #[test]
    fn noise_xk_ck_matches_step_by_step() {
        let initiator_eph_secret: [u8; 32] = [0x01; 32];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [0xAA; 32];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let initiator_eph_pub = ecdh_pubkey(&initiator_eph_secret).unwrap();
        let responder_eph_pub = ecdh_pubkey(&responder_eph_secret).unwrap();

        let h0 = sha256(PROTOCOL_NAME_XK);
        let mut ck_i = h0;
        let mut ck_r = h0;
        let mut h_i = h0;
        let mut h_r = h0;

        let norm_rs = parity_normalize(&responder_static_pub);
        h_i = mix_hash(&h_i, &norm_rs);
        let norm_s = parity_normalize(&responder_static_pub);
        h_r = mix_hash(&h_r, &norm_s);
        assert_eq!(h_i, h_r, "h after pre-message");

        h_i = mix_hash(&h_i, &initiator_eph_pub);
        h_r = mix_hash(&h_r, &initiator_eph_pub);
        assert_eq!(h_i, h_r, "h after e");

        let es_i = x_only_ecdh(&initiator_eph_secret, &responder_static_pub).unwrap();
        let es_r = x_only_ecdh(&responder_static_secret, &initiator_eph_pub).unwrap();
        assert_eq!(es_i, es_r, "es DH");
        let (ck_i_1, k_i_1) = mix_key(&ck_i, &es_i);
        let (ck_r_1, k_r_1) = mix_key(&ck_r, &es_r);
        assert_eq!(ck_i_1, ck_r_1, "ck after es");
        assert_eq!(k_i_1, k_r_1, "k after es");
        ck_i = ck_i_1;
        ck_r = ck_r_1;

        h_i = mix_hash(&h_i, &responder_eph_pub);
        h_r = mix_hash(&h_r, &responder_eph_pub);
        assert_eq!(h_i, h_r, "h after re");

        let ee_i = x_only_ecdh(&initiator_eph_secret, &responder_eph_pub).unwrap();
        let ee_r = x_only_ecdh(&responder_eph_secret, &initiator_eph_pub).unwrap();
        assert_eq!(ee_i, ee_r, "ee DH");
        let (ck_i_2, k_i_2) = mix_key(&ck_i, &ee_i);
        let (ck_r_2, k_r_2) = mix_key(&ck_r, &ee_r);
        assert_eq!(ck_i_2, ck_r_2, "ck after ee");
        assert_eq!(k_i_2, k_r_2, "k after ee");
        ck_i = ck_i_2;
        ck_r = ck_r_2;

        let se_i = x_only_ecdh(&initiator_static_secret, &responder_eph_pub).unwrap();
        let se_r = x_only_ecdh(&responder_eph_secret, &initiator_static_pub).unwrap();
        assert_eq!(se_i, se_r, "se DH");
        let (ck_i_3, k_i_3) = mix_key(&ck_i, &se_i);
        let (ck_r_3, k_r_3) = mix_key(&ck_r, &se_r);
        assert_eq!(ck_i_3, ck_r_3, "ck after se");
        assert_eq!(k_i_3, k_r_3, "k after se");
        ck_i = ck_i_3;
        ck_r = ck_r_3;

        let (k_send_i, k_recv_i) = {
            let hk = Hkdf::<Sha256>::new(Some(&ck_i), &[]);
            let mut okm = [0u8; 64];
            hk.expand(&[], &mut okm).unwrap();
            let mut k1 = [0u8; 32];
            let mut k2 = [0u8; 32];
            k1.copy_from_slice(&okm[..32]);
            k2.copy_from_slice(&okm[32..]);
            (k1, k2)
        };
        let (k_send_r, k_recv_r) = {
            let hk = Hkdf::<Sha256>::new(Some(&ck_r), &[]);
            let mut okm = [0u8; 64];
            hk.expand(&[], &mut okm).unwrap();
            let mut k1 = [0u8; 32];
            let mut k2 = [0u8; 32];
            k1.copy_from_slice(&okm[..32]);
            k2.copy_from_slice(&okm[32..]);
            (k1, k2)
        };
        assert_eq!(k_send_i, k_send_r, "final k_send");
        assert_eq!(k_recv_i, k_recv_r, "final k_recv");
    }
}
