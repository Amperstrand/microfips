//! MMP algorithmic building blocks.
//!
//! Ported from FIPS upstream: `src/mmp/algorithms.rs`.
//! Pure computational types with no dependency on peer or node state.

use crate::mmp::{DEFAULT_OWD_WINDOW_SIZE, EWMA_LONG_ALPHA, EWMA_SHORT_ALPHA};

// ============================================================================
// Jitter Estimator (RFC 3550 §6.4.1)
// ============================================================================

/// Interarrival jitter estimator using RFC 3550 algorithm.
/// Maintains smoothed jitter estimate (α = 1/16) from absolute difference
/// in one-way transit times. Uses integer arithmetic scaled by 16.
pub struct JitterEstimator {
    jitter_q4: i64,
}

impl JitterEstimator {
    pub fn new() -> Self {
        Self { jitter_q4: 0 }
    }

    /// Update with transit time delta between consecutive frames (microseconds).
    pub fn update(&mut self, transit_delta: i32) {
        let abs_d = (transit_delta as i64).unsigned_abs() as i64;
        self.jitter_q4 += abs_d - (self.jitter_q4 >> 4);
    }

    pub fn jitter_us(&self) -> u32 {
        (self.jitter_q4 >> 4) as u32
    }
}

impl Default for JitterEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SRTT Estimator (Jacobson, RFC 6298)
// ============================================================================

/// Smoothed RTT estimator using Jacobson's algorithm.
/// SRTT and RTTVAR in microseconds, integer arithmetic.
pub struct SrttEstimator {
    srtt_us: i64,
    rttvar_us: i64,
    initialized: bool,
}

impl SrttEstimator {
    pub fn new() -> Self {
        Self {
            srtt_us: 0,
            rttvar_us: 0,
            initialized: false,
        }
    }

    pub fn update(&mut self, rtt_us: i64) {
        if !self.initialized {
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
            self.initialized = true;
        } else {
            let err = (self.srtt_us - rtt_us).abs();
            self.rttvar_us = self.rttvar_us - (self.rttvar_us >> 2) + (err >> 2);
            self.srtt_us = self.srtt_us - (self.srtt_us >> 3) + (rtt_us >> 3);
        }
    }

    pub fn srtt_us(&self) -> i64 {
        self.srtt_us
    }

    pub fn initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for SrttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Dual EWMA Trend Detector
// ============================================================================

/// Dual EWMA for trend detection. Short-term (α=1/4) tracks recent conditions;
/// long-term (α=1/32) establishes stable baseline. Divergence indicates trend.
pub struct DualEwma {
    short: f64,
    long: f64,
    initialized: bool,
}

impl DualEwma {
    pub fn new() -> Self {
        Self {
            short: 0.0,
            long: 0.0,
            initialized: false,
        }
    }

    pub fn update(&mut self, sample: f64) {
        if !self.initialized {
            self.short = sample;
            self.long = sample;
            self.initialized = true;
        } else {
            self.short += EWMA_SHORT_ALPHA * (sample - self.short);
            self.long += EWMA_LONG_ALPHA * (sample - self.long);
        }
    }

    pub fn short(&self) -> f64 {
        self.short
    }

    pub fn long(&self) -> f64 {
        self.long
    }

    pub fn initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for DualEwma {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// One-Way Delay Trend Detector
// ============================================================================

/// OWD trend detector using linear regression over a fixed-size ring buffer.
/// Stores (sequence, owd_us) samples, computes slope via least-squares regression.
pub struct OwdTrendDetector {
    samples: [(u32, i64); DEFAULT_OWD_WINDOW_SIZE],
    len: usize,
    head: usize,
}

impl OwdTrendDetector {
    pub fn new() -> Self {
        Self {
            samples: [(0, 0); DEFAULT_OWD_WINDOW_SIZE],
            len: 0,
            head: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.head = 0;
    }

    pub fn push(&mut self, seq: u32, owd_us: i64) {
        self.samples[self.head] = (seq, owd_us);
        self.head = (self.head + 1) % DEFAULT_OWD_WINDOW_SIZE;
        if self.len < DEFAULT_OWD_WINDOW_SIZE {
            self.len += 1;
        }
    }

    /// Compute OWD trend as slope in µs/second via linear regression.
    /// Returns 0 if fewer than 2 samples.
    pub fn trend_us_per_sec(&self) -> i32 {
        if self.len < 2 {
            return 0;
        }

        let n_f = self.len as f64;
        let start = if self.len < DEFAULT_OWD_WINDOW_SIZE {
            0
        } else {
            self.head
        };

        let mut sum_x: f64 = 0.0;
        let mut sum_y: f64 = 0.0;
        for i in 0..self.len {
            let idx = (start + i) % DEFAULT_OWD_WINDOW_SIZE;
            sum_x += self.samples[idx].0 as f64;
            sum_y += self.samples[idx].1 as f64;
        }
        let mean_x = sum_x / n_f;
        let mean_y = sum_y / n_f;

        let mut num = 0.0;
        let mut den = 0.0;
        for i in 0..self.len {
            let idx = (start + i) % DEFAULT_OWD_WINDOW_SIZE;
            let dx = self.samples[idx].0 as f64 - mean_x;
            let dy = self.samples[idx].1 as f64 - mean_y;
            num += dx * dy;
            den += dx * dx;
        }

        if den.abs() < f64::EPSILON {
            return 0;
        }

        let slope_per_packet = num / den;
        (slope_per_packet * 1000.0) as i32
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for OwdTrendDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ETX
// ============================================================================

/// Compute Expected Transmission Count from bidirectional delivery ratios.
/// ETX = 1 / (d_f × d_r), clamped to [1.0, 100.0].
pub fn compute_etx(d_forward: f64, d_reverse: f64) -> f64 {
    let product = d_forward * d_reverse;
    if product <= 0.0 {
        return 100.0;
    }
    (1.0 / product).clamp(1.0, 100.0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_zero_input() {
        let mut j = JitterEstimator::new();
        j.update(0);
        assert_eq!(j.jitter_us(), 0);
    }

    #[test]
    fn test_jitter_convergence() {
        let mut j = JitterEstimator::new();
        for _ in 0..200 {
            j.update(1000);
        }
        let jitter = j.jitter_us();
        assert!(
            jitter > 900 && jitter < 1100,
            "jitter={jitter}, expected ~1000"
        );
    }

    #[test]
    fn test_srtt_first_sample() {
        let mut s = SrttEstimator::new();
        s.update(10_000);
        assert_eq!(s.srtt_us(), 10_000);
        assert!(s.initialized());
    }

    #[test]
    fn test_srtt_convergence() {
        let mut s = SrttEstimator::new();
        for _ in 0..100 {
            s.update(50_000);
        }
        let srtt = s.srtt_us();
        assert!((srtt - 50_000).abs() < 1000, "srtt={srtt}, expected ~50000");
    }

    #[test]
    fn test_dual_ewma_initialization() {
        let mut e = DualEwma::new();
        assert!(!e.initialized());
        e.update(100.0);
        assert!(e.initialized());
        assert_eq!(e.short(), 100.0);
        assert_eq!(e.long(), 100.0);
    }

    #[test]
    fn test_dual_ewma_short_tracks_faster() {
        let mut e = DualEwma::new();
        e.update(0.0);
        for _ in 0..20 {
            e.update(100.0);
        }
        assert!(
            e.short() > e.long(),
            "short={} long={}",
            e.short(),
            e.long()
        );
    }

    #[test]
    fn test_owd_trend_flat() {
        let mut d = OwdTrendDetector::new();
        for i in 0..20 {
            d.push(i, 5000);
        }
        assert_eq!(d.trend_us_per_sec(), 0);
    }

    #[test]
    fn test_owd_trend_increasing() {
        let mut d = OwdTrendDetector::new();
        for i in 0..20 {
            d.push(i, 5000 + (i as i64) * 100);
        }
        let trend = d.trend_us_per_sec();
        assert!(
            trend > 0,
            "increasing OWD should have positive trend, got {trend}"
        );
    }

    #[test]
    fn test_owd_trend_insufficient_samples() {
        let mut d = OwdTrendDetector::new();
        d.push(0, 5000);
        assert_eq!(d.trend_us_per_sec(), 0);
    }

    #[test]
    fn test_owd_trend_ring_buffer_wrap() {
        let mut d = OwdTrendDetector::new();
        // Fill beyond capacity (DEFAULT_OWD_WINDOW_SIZE = 32)
        for i in 0..40 {
            d.push(i, (i as i64) * 100);
        }
        // Should only have last 32 samples; trend should still be positive
        assert!(d.trend_us_per_sec() > 0);
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn test_etx_perfect_link() {
        assert!((compute_etx(1.0, 1.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_etx_lossy_link() {
        let etx = compute_etx(0.9, 0.95);
        assert!(etx > 1.0 && etx < 2.0, "etx={etx}");
    }

    #[test]
    fn test_etx_zero_delivery() {
        assert_eq!(compute_etx(0.0, 1.0), 100.0);
        assert_eq!(compute_etx(1.0, 0.0), 100.0);
    }
}
