//! Ported from fips v0.4.0: `src/lib.rs` (module structure subset for no_std leaf node).
//!
//! Deviation: this is a barrel module re-exporting a subset of the upstream
//! crate root. Modules absent here (e.g. full transport, runtime, config) are
//! intentionally omitted for the no_std embedded leaf-node target.
//!
//! Ported from fips v0.4.0: `src/lib.rs` (module structure subset for no_std leaf node).
//!
//! no_std FIPS protocol primitives: Noise IK/XK handshake, FMP link framing, FSP session protocol, identity derivation, and MMP metrics algorithms.

#![no_std]

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod fsp;
pub mod generated;
pub mod hex;
pub mod identity;
pub mod mmp;
pub mod noise;
pub mod wire;
