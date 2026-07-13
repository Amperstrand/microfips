//! Noise protocol re-exports from the `fips-noise` crate.
//!
//! All Noise types, constants, and helper functions now live in the
//! standalone `fips-noise` crate. This module re-exports everything
//! for backward compatibility with existing `crate::noise::` imports.
pub use fips_noise::*;
