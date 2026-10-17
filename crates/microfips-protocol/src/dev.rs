//! Host/test development utilities (#235): the runtime's real entropy
//! draw helpers, reachable by std consumers — the facade's seam tests
//! exercise `generate_valid_eph` as the actual path the Node handshake
//! uses for its ephemerals. Pure code, no dependencies beyond the crate
//! itself; bare-metal images never compile this module.

use crate::transport::{CryptoRng, RngCore};
use microfips_core::noise::ecdh_pubkey;
use microfips_core::wire;

/// Deterministic test secret: 31 zero bytes + `last` (the bench's G·N
/// scheme — secp256k1 generator times N as a big-endian scalar).
pub fn deterministic_secret(last: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[31] = last;
    secret
}

/// Draw a cryptographically valid ephemeral scalar: keep drawing until
/// `ecdh_pubkey` accepts it. This is the same loop the Node runtime's
/// handshake runs (`node::Node::generate_valid_eph`).
pub fn generate_valid_eph<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    loop {
        let mut eph = [0u8; 32];
        rng.fill_bytes(&mut eph);
        if ecdh_pubkey(&eph).is_ok() {
            return eph;
        }
    }
}

/// Draw a nonzero session index — the runtime's `allocate_session_index`
/// loop.
pub fn allocate_session_index<R: RngCore>(rng: &mut R) -> wire::SessionIndex {
    loop {
        let idx = rng.next_u32();
        if idx != 0 {
            return wire::SessionIndex::new(idx);
        }
    }
}
