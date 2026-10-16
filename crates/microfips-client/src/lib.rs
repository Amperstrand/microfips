//! microfips-client: the single-dependency library for talking to FIPS
//! devices from any Rust project on an ESP32 (or host).
//!
//! This crate is the M3 library boundary (#220): it re-exports the
//! protocol stack (Noise, FMP, FSP, identity, MMP, the leaf Node, and
//! the service layer) behind one `use microfips_client::*` so external
//! consumers never need to know the internal crate names, and it adds
//! the host seams (entropy + clock) that let the same code run on
//! bare-metal ESP32, esp-idf std, or a host test runner.
//!
//! ## Quick start
//!
//! ```no_run
//! use microfips_client::{Node, Transport, EntropySource, Clock};
//!
//! // 1. Implement the two host seams (or use the std feature for OS defaults)
//! // 2. Provide a byte-shaped Transport (UART, UDP, BLE, anything)
//! // 3. Construct a Node and drive it
//! ```
//!
//! ## Feature flags
//!
//! | Feature | What it does | Default |
//! |---------|-------------|---------|
//! | `std` | OS entropy + wall clock; enables `std::rng` and `std::time` seam impls | off |
//! | `mmp` | MMP metrics reporting layer | off |
//! | `noise-xx` | Noise XX wire (forward-compat with upstream `next`) | off |
//!
//! ## Relationship to upstream
//!
//! This crate is the Amperstrand surface that will converge onto
//! upstream's `fips-core` as the adoption triggers fire (see
//! `docs/ROADMAP.md`). Each internal crate here has an adoption path;
//! the facade means consumers see one name that survives the swaps.

#![no_std]

#[cfg(any(test, feature = "std"))]
extern crate std;

// ============================================================================
// Host seams — the traits an embedder implements
// ============================================================================

/// Fill a buffer with cryptographically secure random bytes.
///
/// Mirrors upstream fips-core's `EntropySource` (d208a9db): the host
/// supplies entropy because the library itself has no way to reach a
/// TRNG on every target. On ESP32 hardware, pass the TRNG; in a `std`
/// build, the OS RNG satisfies this automatically.
pub trait EntropySource {
    fn fill(dest: &mut [u8]);
}

/// A monotonic timestamp source.
///
/// The library needs elapsed-time measurements (rekey timers, heartbeat
/// intervals, probe cooldowns) but not wall-clock time. On ESP32,
/// `embassy-time`'s ticker satisfies this; on a host, `std::time::Instant`.
pub trait Clock {
    /// Milliseconds since an arbitrary epoch (must be monotonic).
    fn now_ms(&self) -> u64;
}

// ============================================================================
// std implementations of the host seams
// ============================================================================

#[cfg(feature = "std")]
pub mod std_seams {
    use super::{Clock, EntropySource};

    /// OS-provided entropy via `rand::rng()`.
    pub struct OsEntropy;

    impl EntropySource for OsEntropy {
        fn fill(dest: &mut [u8]) {
            use rand::RngCore;
            rand::rng().fill_bytes(dest);
        }
    }

    /// Wall-clock via `std::time::Instant` (monotonic).
    pub struct MonotonicClock {
        start: std::time::Instant,
    }

    impl MonotonicClock {
        pub fn new() -> Self {
            Self {
                start: std::time::Instant::now(),
            }
        }
    }

    impl Default for MonotonicClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for MonotonicClock {
        fn now_ms(&self) -> u64 {
            self.start.elapsed().as_millis() as u64
        }
    }
}

// ============================================================================
// Re-exports — the library surface
// ============================================================================

// Protocol building blocks
pub use fips_noise;
pub use fips_fmp;
pub use fips_identity;

// Core protocol primitives (FSP, wire, MMP, identity derivation)
pub use microfips_core;

// The leaf Node runtime + Transport trait
pub use microfips_protocol;

// The service layer (request/response envelope over FSP)
pub use microfips_service;

// Convenience re-exports for the most-used types
pub use microfips_protocol::node::{Node, NodeHandler, NodeTiming, HandleResult};
pub use microfips_protocol::transport::Transport;
pub use microfips_service::{ServiceHandler, ServiceRequest, ServiceReply, ServiceMethod, ServiceStatus};
