//! MMP — Metrics Measurement Protocol, link-layer instantiation.
//! Ported from FIPS upstream: src/mmp/

pub mod algorithms;
pub mod report;

pub use algorithms::{compute_etx, DualEwma, JitterEstimator, SrttEstimator};
pub use report::{ReceiverReport, SenderReport};

// Timing constants (milliseconds)
pub const DEFAULT_COLD_START_INTERVAL_MS: u64 = 200;
pub const MIN_REPORT_INTERVAL_MS: u64 = 1_000;
pub const MAX_REPORT_INTERVAL_MS: u64 = 5_000;
pub const COLD_START_SAMPLES: u32 = 5;
pub const DEFAULT_OWD_WINDOW_SIZE: usize = 32;
