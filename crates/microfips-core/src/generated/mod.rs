//! FIPS compatibility constants and wire types.
//!
//! `fips_compat` re-exports the `fips-proto-defs` crate
//! (Amperstrand/fips-protocol-defs-mvp), extracted from canonical
//! jmcorgan/fips@v0.4.0. `fips_protocol_types` holds wire-format types
//! generated from upstream fips v0.4.0.

pub mod fips_compat;
pub mod fips_protocol_types;
