//! fips-core canary (microfips #219).
//!
//! Thin, build-only API-surface exercise against the pinned Amperstrand/fips
//! ref named in this crate's `Cargo.toml`. It proves three things per target:
//!
//! 1. the no_std + alloc dependency tree of `fips-core` compiles — including
//!    `secp256k1-sys`, whose C must cross-compile per target (the xtensa leg
//!    is the strategically interesting one: nobody has proven it);
//! 2. the API surfaces a leaf library would consume still exist: the
//!    host-entropy seam, identity construction from secret bytes, and the
//!    link-layer message catalog;
//! 3. the IK wire sizes are still what microfips implements (compile-time
//!    sentinels — an upstream wire change fails this canary loudly).
//!
//! Nothing here runs on hardware; a `cargo build --target <t>` is the check.

#![no_std]

use fips_core::entropy::EntropySource;
use fips_core::identity::Identity;
use fips_core::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, PUBKEY_SIZE, TAG_SIZE};
use fips_core::proto::link::LinkMessageType;

/// Stand-in for the host's entropy source. The core never reads randomness of
/// its own — the embedder supplies it through this trait (upstream's seam).
pub struct HostEntropy;

impl EntropySource for HostEntropy {
    fn fill(dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = 0x5A;
        }
    }
}

// Wire-shape sentinels (IK era). If the pinned tree changes the handshake
// sizes, the canary fails at compile time instead of at a bench session.
const _: () = assert!(HANDSHAKE_MSG1_SIZE == 106);
const _: () = assert!(HANDSHAKE_MSG2_SIZE == 57);
const _: () = assert!(TAG_SIZE == 16 && PUBKEY_SIZE == 33);

/// Identity construction through the secp machinery: init the (host-blinded)
/// context, derive an identity from secret bytes, read back its NodeAddr.
pub fn identity_from_secret_bytes(secp_seed: &[u8; 32], secret: &[u8; 32]) -> Option<[u8; 16]> {
    if !fips_core::identity::init_secp(secp_seed) {
        return None;
    }
    let identity = Identity::<HostEntropy>::from_secret_bytes(secret).ok()?;
    Some(*identity.node_addr().as_bytes())
}

/// The link-layer message catalog a leaf consumes (heartbeat, datagrams).
pub fn link_message_type(byte: u8) -> Option<LinkMessageType> {
    LinkMessageType::from_byte(byte)
}
