//! no_std FIPS protocol primitives: Noise IK/XK handshake, FMP link framing, FSP session protocol, identity derivation, and MMP metrics algorithms.

#![no_std]

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod fsp;
pub mod hex;
pub mod identity;
pub mod mmp;
pub mod noise;
pub mod wire;
