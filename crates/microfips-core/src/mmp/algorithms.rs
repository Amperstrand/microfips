//! MMP algorithmic building blocks.
//!
//! Pure computational types with no dependency on peer or node state.

use crate::mmp::DEFAULT_OWD_WINDOW_SIZE;

pub struct JitterEstimator {
    jitter_q4: i64,
}

impl JitterEstimator {
    pub fn new() -> Self {
        Self { jitter_q4: 0 }
    }

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
            self.short += 0.25 * (sample - self.short);
            self.long += (1.0 / 32.0) * (sample - self.long);
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

pub struct OwdTrendDetector {
    samples: [(u32, i64); DEFAULT_OWD_WINDOW_SIZE],
    len: usize,
    head: usize,
    capacity: usize,
}

impl OwdTrendDetector {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_OWD_WINDOW_SIZE)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.clamp(1, DEFAULT_OWD_WINDOW_SIZE);
        Self {
            samples: [(0, 0); DEFAULT_OWD_WINDOW_SIZE],
            len: 0,
            head: 0,
            capacity,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.head = 0;
    }

    pub fn push(&mut self, seq: u32, owd_us: i64) {
        self.samples[self.head] = (seq, owd_us);
        self.head = (self.head + 1) % self.capacity;
        if self.len < self.capacity {
            self.len += 1;
        }
    }

    pub fn trend_us_per_sec(&self) -> i32 {
        if self.len < 2 {
            return 0;
        }

        let n_f = self.len as f64;
        let start = if self.len < self.capacity {
            0
        } else {
            self.head
        };

        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        for i in 0..self.len {
            let idx = (start + i) % self.capacity;
            sum_x += self.samples[idx].0 as f64;
            sum_y += self.samples[idx].1 as f64;
        }

        let mean_x = sum_x / n_f;
        let mean_y = sum_y / n_f;

        let mut num = 0.0;
        let mut den = 0.0;
        for i in 0..self.len {
            let idx = (start + i) % self.capacity;
            let dx = self.samples[idx].0 as f64 - mean_x;
            let dy = self.samples[idx].1 as f64 - mean_y;
            num += dx * dy;
            den += dx * dx;
        }

        if den.abs() < f64::EPSILON {
            return 0;
        }

        ((num / den) * 1000.0) as i32
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

pub fn compute_etx(d_forward: f64, d_reverse: f64) -> f64 {
    let product = d_forward * d_reverse;
    if product <= 0.0 {
        return 100.0;
    }
    (1.0 / product).clamp(1.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_zero_input() {
        let mut jitter = JitterEstimator::new();
        jitter.update(0);
        assert_eq!(jitter.jitter_us(), 0);
    }

    #[test]
    fn jitter_converges() {
        let mut jitter = JitterEstimator::new();
        for _ in 0..200 {
            jitter.update(1_000);
        }
        let value = jitter.jitter_us();
        assert!(value > 900 && value < 1_100, "jitter={value}");
    }

    #[test]
    fn srtt_first_sample_initializes() {
        let mut srtt = SrttEstimator::new();
        srtt.update(10_000);
        assert_eq!(srtt.srtt_us(), 10_000);
        assert_eq!(srtt.rttvar_us, 5_000);
        assert!(srtt.initialized());
    }

    #[test]
    fn srtt_converges() {
        let mut srtt = SrttEstimator::new();
        for _ in 0..100 {
            srtt.update(50_000);
        }
        let value = srtt.srtt_us();
        assert!((value - 50_000).abs() < 1_000, "srtt={value}");
    }

    #[test]
    fn dual_ewma_initializes() {
        let mut ewma = DualEwma::new();
        ewma.update(100.0);
        assert_eq!(ewma.short(), 100.0);
        assert_eq!(ewma.long(), 100.0);
    }

    #[test]
    fn dual_ewma_short_tracks_faster() {
        let mut ewma = DualEwma::new();
        ewma.update(0.0);
        for _ in 0..20 {
            ewma.update(100.0);
        }
        assert!(ewma.short() > ewma.long());
    }

    #[test]
    fn owd_trend_flat_is_zero() {
        let mut detector = OwdTrendDetector::new();
        for i in 0..20 {
            detector.push(i, 5_000);
        }
        assert_eq!(detector.trend_us_per_sec(), 0);
    }

    #[test]
    fn owd_trend_increasing_is_positive() {
        let mut detector = OwdTrendDetector::new();
        for i in 0..20 {
            detector.push(i, 5_000 + (i as i64) * 100);
        }
        assert!(detector.trend_us_per_sec() > 0);
    }

    #[test]
    fn owd_trend_insufficient_samples_is_zero() {
        let mut detector = OwdTrendDetector::new();
        detector.push(0, 5_000);
        assert_eq!(detector.trend_us_per_sec(), 0);
    }

    #[test]
    fn owd_trend_ring_buffer_wrap() {
        let mut detector = OwdTrendDetector::with_capacity(8);
        for i in 0..16 {
            detector.push(i, (i as i64) * 100);
        }
        assert_eq!(detector.len(), 8);
        assert!(detector.trend_us_per_sec() > 0);
    }

    #[test]
    fn etx_perfect_link() {
        assert!((compute_etx(1.0, 1.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn etx_lossy_link() {
        let etx = compute_etx(0.9, 0.95);
        assert!(etx > 1.0 && etx < 2.0, "etx={etx}");
    }

    #[test]
    fn etx_zero_delivery_clamps() {
        assert_eq!(compute_etx(0.0, 1.0), 100.0);
        assert_eq!(compute_etx(1.0, 0.0), 100.0);
    }

    #[test]
    fn test_srtt_negative_rtt() {
        let mut srtt = SrttEstimator::new();
        srtt.update(0);
        assert!(srtt.initialized());
        assert_eq!(srtt.srtt_us(), 0);
        assert!(srtt.rttvar_us >= 0);
    }

    #[test]
    fn test_srtt_very_large_rtt() {
        let mut srtt = SrttEstimator::new();
        srtt.update(i64::MAX / 2);
        assert!(srtt.initialized());
        assert!(srtt.srtt_us() > 0);
    }

    #[test]
    fn test_jitter_zero_transit_delta() {
        let mut jitter = JitterEstimator::new();
        jitter.update(0);
        jitter.update(0);
        assert_eq!(jitter.jitter_us(), 0);
    }

    #[test]
    fn test_jitter_very_large_values() {
        let mut jitter = JitterEstimator::new();
        jitter.update(i32::MAX);
        jitter.update(i32::MIN + 1);
        assert!(jitter.jitter_us() > 0);
    }

    #[test]
    fn test_dual_ewma_identical_values() {
        let mut ewma = DualEwma::new();
        for _ in 0..256 {
            ewma.update(42.5);
        }
        assert!((ewma.short() - 42.5).abs() < f64::EPSILON);
        assert!((ewma.long() - 42.5).abs() < 1e-9);
    }

    #[test]
    fn test_owd_trend_all_same_values() {
        let mut detector = OwdTrendDetector::new();
        for i in 0..16 {
            detector.push(i, 123_456);
        }
        assert_eq!(detector.trend_us_per_sec(), 0);
    }

    #[test]
    fn test_owd_trend_with_capacity() {
        let mut detector = OwdTrendDetector::with_capacity(8);
        for i in 0..16 {
            detector.push(i, (i as i64) * 10);
        }
        assert_eq!(detector.len(), 8);
        assert!(detector.trend_us_per_sec() > 0);
    }

    #[test]
    fn test_compute_etx_edge_cases() {
        assert!((compute_etx(1.0, 1.0) - 1.0).abs() < f64::EPSILON);
        assert_eq!(compute_etx(0.0, 1.0), 100.0);
        assert_eq!(compute_etx(1.0, 0.0), 100.0);

        let etx_half = compute_etx(0.5, 0.5);
        assert!((etx_half - 4.0).abs() < f64::EPSILON);
    }
}
