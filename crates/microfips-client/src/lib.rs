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
// Facade adapters — make the seams consumable by the re-exported runtime
// (#235)
// ============================================================================

/// `RngCore + CryptoRng` adapter over a host [`EntropySource`] — the form
/// the re-exported `Node` accepts (`Node::new(transport, rng, ..)` draws
/// handshake ephemerals and session indices through `RngCore`, so this
/// adapter puts the embedder's entropy on that real path).
///
/// The upstream fips-core pattern fixes `EntropySource` as a type
/// parameter; our `Node` is generic over `RngCore` instead, so the facade
/// bridges rather than rewires — zero-sized, stateless, `Default`.
///
/// ```
/// use microfips_client::{EntropySource, EntropyRng};
///
/// struct MyEntropy;
/// impl EntropySource for MyEntropy {
///     fn fill(dest: &mut [u8]) { /* TRNG read here */ }
/// }
///
/// let mut rng = EntropyRng::<MyEntropy>::new();
/// let mut bytes = [0u8; 32];
/// use microfips_client::RngCore;
/// rng.fill_bytes(&mut bytes);
/// ```
pub struct EntropyRng<E: EntropySource> {
    _entropy: core::marker::PhantomData<E>,
}

impl<E: EntropySource> EntropyRng<E> {
    pub fn new() -> Self {
        Self {
            _entropy: core::marker::PhantomData,
        }
    }
}

impl<E: EntropySource> Default for EntropyRng<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: EntropySource> microfips_protocol::transport::RngCore for EntropyRng<E> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        E::fill(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        E::fill(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        E::fill(dst)
    }

    // The EntropySource contract is infallible ("must not fail"), so the
    // fallible variant cannot fail either.
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        E::fill(dst);
        Ok(())
    }
}

// rand_core 0.9's CryptoRng is a marker: "the output of this generator is
// cryptographically secure" — the EntropySource contract states exactly
// that ("cryptographically secure random bytes"), so the adapter upholds it.
impl<E: EntropySource> microfips_protocol::transport::CryptoRng for EntropyRng<E> {}

/// Install a clock provider into the protocol runtime (#235): every
/// runtime time read (drain windows, rekey cadences, activity ages)
/// routes through it instead of the linked embassy-time driver. Boot-time
/// or single-threaded-test use; [`reset_default_clock`] restores the
/// driver.
///
/// Stateful `Clock` implementations adapt via a static (standard embedded
/// practice — a `fn() -> u64` pointer cannot capture):
///
/// ```
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use microfips_client::Clock;
///
/// struct StepClock;
/// static STEP: AtomicU64 = AtomicU64::new(0);
/// impl Clock for StepClock {
///     fn now_ms(&self) -> u64 { STEP.load(Ordering::Relaxed) }
/// }
/// fn step_now_ms() -> u64 { StepClock.now_ms() }
/// # microfips_client::install_clock(step_now_ms);
/// # microfips_client::reset_default_clock();
/// ```
pub fn install_clock(now: fn() -> u64) {
    microfips_protocol::clock::install(now);
}

/// Restore the default embassy-time reads (undo [`install_clock`]).
pub fn reset_default_clock() {
    microfips_protocol::clock::reset_default();
}

/// #235 ESP32-image acceptance proof: force monomorphization of the
/// re-exported `Node` with BOTH custom seams on every target this crate
/// compiles for — bare metal included. Never called; `doc(hidden)` keeps
/// it out of the advertised surface. The placeholder entropy is NOT
/// secure (a real image reads its TRNG here).
#[doc(hidden)]
pub mod esp32_construction_proof {
    use super::{Clock, EntropyRng, EntropySource, Node, Transport};

    pub struct TrngPlaceholder;
    impl EntropySource for TrngPlaceholder {
        fn fill(dest: &mut [u8]) {
            // NOT secure — stand-in for the target's TRNG read.
            dest.fill(7);
        }
    }

    pub struct StaticClockMs;
    impl super::Clock for StaticClockMs {
        fn now_ms(&self) -> u64 {
            0
        }
    }

    pub fn now_ms_fn() -> u64 {
        StaticClockMs.now_ms()
    }

    pub fn build<T: Transport>(
        transport: T,
        nsec: [u8; 32],
        peer_npub: [u8; 33],
    ) -> Node<T, EntropyRng<TrngPlaceholder>> {
        Node::new(transport, EntropyRng::new(), nsec, peer_npub)
    }
}

// ============================================================================
// Re-exports — the library surface
// ============================================================================

// Protocol building blocks
pub use fips_fmp;
pub use fips_identity;
pub use fips_noise;

// Core protocol primitives (FSP, wire, MMP, identity derivation)
pub use microfips_core;

// The leaf Node runtime + Transport trait
pub use microfips_protocol;

// The service layer (request/response envelope over FSP)
pub use microfips_service;

// Convenience re-exports for the most-used types
pub use microfips_protocol::node::{HandleResult, Node, NodeHandler, NodeTiming};
pub use microfips_protocol::transport::{CryptoRng, RngCore, Transport};
pub use microfips_service::{
    ServiceHandler, ServiceMethod, ServiceReply, ServiceRequest, ServiceStatus,
};
