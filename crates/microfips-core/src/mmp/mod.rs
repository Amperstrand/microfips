//! MMP — Metrics Measurement Protocol, link-layer instantiation.
//!
//! Ported from FIPS upstream: `src/mmp/`.
//! Measures link quality between adjacent peers: RTT, loss, jitter,
//! throughput, one-way delay trend, and ETX.

pub mod algorithms;
pub mod report;

pub use algorithms::{compute_etx, DualEwma, JitterEstimator, OwdTrendDetector, SrttEstimator};
pub use report::{ReceiverReport, SenderReport, RECEIVER_REPORT_SIZE, SENDER_REPORT_SIZE};

// Timing constants (milliseconds)
pub const DEFAULT_COLD_START_INTERVAL_MS: u64 = 200;
pub const MIN_REPORT_INTERVAL_MS: u64 = 1_000;
pub const MAX_REPORT_INTERVAL_MS: u64 = 5_000;
pub const COLD_START_SAMPLES: u32 = 5;
pub const DEFAULT_OWD_WINDOW_SIZE: usize = 32;

// EWMA shift constants (integer arithmetic, matching FIPS upstream)
pub const JITTER_ALPHA_SHIFT: u32 = 4;
pub const SRTT_ALPHA_SHIFT: u32 = 3;
pub const RTTVAR_BETA_SHIFT: u32 = 2;

// EWMA parameters (floating-point, for DualEwma trends)
pub const EWMA_SHORT_ALPHA: f64 = 0.25;
pub const EWMA_LONG_ALPHA: f64 = 1.0 / 32.0;
