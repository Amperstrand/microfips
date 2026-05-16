//! MMP — Metrics Measurement Protocol, link-layer instantiation.
//! Ported from FIPS upstream: src/mmp/

pub mod algorithms;
pub mod report;

pub use algorithms::{compute_etx, DualEwma, JitterEstimator, SpinBitState, SrttEstimator};
pub use report::{ReceiverReport, SenderReport};

// Timing constants (milliseconds)
pub const DEFAULT_COLD_START_INTERVAL_MS: u64 = 200;
// Ported from fips: lowered MIN_REPORT_INTERVAL_MS from 1000 to 500 for BLE links.
// Experiments show RTT grows ~167ms/s, so 1s floor means the first report already
// has bloated RTT. At 500ms, more samples/sec keep SRTT closer to actual link RTT.
pub const MIN_REPORT_INTERVAL_MS: u64 = 500;
pub const MAX_REPORT_INTERVAL_MS: u64 = 3_000;
pub const COLD_START_SAMPLES: u32 = 8;
pub const DEFAULT_OWD_WINDOW_SIZE: usize = 32;

// Ported from fips
/// MMP operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmpMode {
    /// Sender + receiver reports at RTT-adaptive intervals.
    Full,
    /// Receiver reports only.
    Lightweight,
    /// Spin bit + CE echo only.
    Minimal,
}
