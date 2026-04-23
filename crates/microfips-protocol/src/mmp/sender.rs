use embassy_time::{Duration, Instant};
use microfips_core::mmp::report::SenderReport;
use microfips_core::mmp::{
    COLD_START_SAMPLES, DEFAULT_COLD_START_INTERVAL_MS, MAX_REPORT_INTERVAL_MS,
    MIN_REPORT_INTERVAL_MS,
};

pub struct SenderState {
    cumulative_packets_sent: u64,
    cumulative_bytes_sent: u64,
    interval_start_counter: u64,
    interval_start_timestamp: u32,
    interval_bytes_sent: u32,
    last_counter: u64,
    last_timestamp: u32,
    interval_has_data: bool,
    last_report_time: Option<Instant>,
    report_interval: Duration,
    consecutive_send_failures: u32,
    srtt_sample_count: u32,
}

impl SenderState {
    pub fn new() -> Self {
        Self::new_with_cold_start(DEFAULT_COLD_START_INTERVAL_MS)
    }

    pub fn new_with_cold_start(cold_start_ms: u64) -> Self {
        Self {
            cumulative_packets_sent: 0,
            cumulative_bytes_sent: 0,
            interval_start_counter: 0,
            interval_start_timestamp: 0,
            interval_bytes_sent: 0,
            last_counter: 0,
            last_timestamp: 0,
            interval_has_data: false,
            last_report_time: None,
            report_interval: Duration::from_millis(cold_start_ms),
            consecutive_send_failures: 0,
            srtt_sample_count: 0,
        }
    }

    pub fn record_sent(&mut self, counter: u64, timestamp: u32, bytes: usize) {
        if !self.interval_has_data {
            self.interval_start_counter = counter;
            self.interval_start_timestamp = timestamp;
            self.interval_has_data = true;
        }
        self.last_counter = counter;
        self.last_timestamp = timestamp;
        self.interval_bytes_sent = self.interval_bytes_sent.saturating_add(bytes as u32);
        self.cumulative_packets_sent += 1;
        self.cumulative_bytes_sent += bytes as u64;
    }

    pub fn build_report(&mut self, now: Instant) -> Option<SenderReport> {
        if !self.interval_has_data {
            return None;
        }

        let report = SenderReport {
            interval_start_counter: self.interval_start_counter,
            interval_end_counter: self.last_counter,
            interval_start_timestamp: self.interval_start_timestamp,
            interval_end_timestamp: self.last_timestamp,
            interval_bytes_sent: self.interval_bytes_sent,
            cumulative_packets_sent: self.cumulative_packets_sent,
            cumulative_bytes_sent: self.cumulative_bytes_sent,
        };

        self.interval_has_data = false;
        self.interval_bytes_sent = 0;
        self.last_report_time = Some(now);

        Some(report)
    }

    pub fn should_send_report(&self, now: Instant) -> bool {
        if !self.interval_has_data {
            return false;
        }
        match self.last_report_time {
            None => true,
            Some(last) => {
                let effective_ms = self.report_interval.as_millis() as f64
                    * self.send_failure_backoff_multiplier();
                now.duration_since(last).as_millis() as f64 >= effective_ms
            }
        }
    }

    pub fn record_send_failure(&mut self) -> u32 {
        self.consecutive_send_failures += 1;
        self.consecutive_send_failures
    }

    pub fn record_send_success(&mut self) -> u32 {
        let prev = self.consecutive_send_failures;
        self.consecutive_send_failures = 0;
        prev
    }

    pub fn send_failure_backoff_multiplier(&self) -> f64 {
        if self.consecutive_send_failures == 0 {
            1.0
        } else {
            let shift = self.consecutive_send_failures.min(5);
            (1u32 << shift) as f64
        }
    }

    pub fn update_report_interval_from_srtt(&mut self, srtt_us: i64) {
        self.srtt_sample_count = self.srtt_sample_count.saturating_add(1);
        let floor = if self.srtt_sample_count <= COLD_START_SAMPLES {
            DEFAULT_COLD_START_INTERVAL_MS
        } else {
            MIN_REPORT_INTERVAL_MS
        };
        self.update_report_interval_with_bounds(srtt_us, floor, MAX_REPORT_INTERVAL_MS);
    }

    pub fn update_report_interval_with_bounds(&mut self, srtt_us: i64, min_ms: u64, max_ms: u64) {
        if srtt_us <= 0 {
            return;
        }
        let interval_us = (srtt_us * 2) as u64;
        let interval_ms = (interval_us / 1000).clamp(min_ms, max_ms);
        self.report_interval = Duration::from_millis(interval_ms);
    }

    pub fn cumulative_packets_sent(&self) -> u64 {
        self.cumulative_packets_sent
    }

    pub fn cumulative_bytes_sent(&self) -> u64 {
        self.cumulative_bytes_sent
    }

    pub fn report_interval(&self) -> Duration {
        self.report_interval
    }

    pub fn consecutive_send_failures(&self) -> u32 {
        self.consecutive_send_failures
    }
}

impl Default for SenderState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_sender_state() {
        let s = SenderState::new();
        assert_eq!(s.cumulative_packets_sent(), 0);
        assert_eq!(s.cumulative_bytes_sent(), 0);
    }

    #[test]
    fn test_record_sent() {
        let mut s = SenderState::new();
        s.record_sent(1, 100, 500);
        s.record_sent(2, 200, 600);
        assert_eq!(s.cumulative_packets_sent(), 2);
        assert_eq!(s.cumulative_bytes_sent(), 1100);
    }

    #[test]
    fn test_build_report_empty() {
        let mut s = SenderState::new();
        assert!(s.build_report(Instant::now()).is_none());
    }

    #[test]
    fn test_build_report() {
        let mut s = SenderState::new();
        s.record_sent(10, 1000, 500);
        s.record_sent(11, 1100, 600);
        s.record_sent(12, 1200, 400);

        let report = s.build_report(Instant::now()).unwrap();
        assert_eq!(report.interval_start_counter, 10);
        assert_eq!(report.interval_end_counter, 12);
        assert_eq!(report.interval_start_timestamp, 1000);
        assert_eq!(report.interval_end_timestamp, 1200);
        assert_eq!(report.interval_bytes_sent, 1500);
        assert_eq!(report.cumulative_packets_sent, 3);
        assert_eq!(report.cumulative_bytes_sent, 1500);
    }

    #[test]
    fn test_build_report_resets_interval() {
        let mut s = SenderState::new();
        s.record_sent(1, 100, 500);
        let _ = s.build_report(Instant::now());
        assert!(s.build_report(Instant::now()).is_none());

        s.record_sent(2, 200, 300);
        let report = s.build_report(Instant::now()).unwrap();
        assert_eq!(report.interval_start_counter, 2);
        assert_eq!(report.interval_bytes_sent, 300);
        assert_eq!(report.cumulative_packets_sent, 2);
        assert_eq!(report.cumulative_bytes_sent, 800);
    }

    #[test]
    fn test_should_send_report_no_data() {
        let s = SenderState::new();
        assert!(!s.should_send_report(Instant::now()));
    }

    #[test]
    fn test_should_send_report_first_time() {
        let mut s = SenderState::new();
        s.record_sent(1, 100, 500);
        assert!(s.should_send_report(Instant::now()));
    }

    #[test]
    fn test_update_report_interval_cold_start() {
        let mut s = SenderState::new();
        s.update_report_interval_from_srtt(50_000);
        assert_eq!(s.report_interval(), Duration::from_millis(200));

        s.update_report_interval_from_srtt(500_000);
        assert_eq!(s.report_interval(), Duration::from_millis(1000));
    }

    #[test]
    fn test_update_report_interval_after_cold_start() {
        let mut s = SenderState::new();
        for _ in 0..COLD_START_SAMPLES {
            s.update_report_interval_from_srtt(500_000);
        }
        s.update_report_interval_from_srtt(50_000);
        assert_eq!(
            s.report_interval(),
            Duration::from_millis(MIN_REPORT_INTERVAL_MS)
        );

        s.update_report_interval_from_srtt(3_000_000);
        assert_eq!(
            s.report_interval(),
            Duration::from_millis(MAX_REPORT_INTERVAL_MS)
        );
    }

    #[test]
    fn test_backoff_multiplier_progression() {
        let mut s = SenderState::new();
        assert_eq!(s.send_failure_backoff_multiplier(), 1.0);

        let expected = [2.0, 4.0, 8.0, 16.0, 32.0];
        for (i, &exp) in expected.iter().enumerate() {
            let count = s.record_send_failure();
            assert_eq!(count, (i + 1) as u32);
            assert_eq!(s.send_failure_backoff_multiplier(), exp);
        }

        s.record_send_failure();
        assert_eq!(s.send_failure_backoff_multiplier(), 32.0);
    }

    #[test]
    fn test_backoff_reset_on_success() {
        let mut s = SenderState::new();
        s.record_send_failure();
        s.record_send_failure();
        s.record_send_failure();
        assert_eq!(s.consecutive_send_failures(), 3);

        let prev = s.record_send_success();
        assert_eq!(prev, 3);
        assert_eq!(s.consecutive_send_failures(), 0);
        assert_eq!(s.send_failure_backoff_multiplier(), 1.0);
    }
}
