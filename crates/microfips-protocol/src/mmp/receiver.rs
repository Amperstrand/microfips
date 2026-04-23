use embassy_time::{Duration, Instant};
use microfips_core::mmp::algorithms::{JitterEstimator, OwdTrendDetector};
use microfips_core::mmp::report::ReceiverReport;
use microfips_core::mmp::{
    COLD_START_SAMPLES, DEFAULT_COLD_START_INTERVAL_MS, DEFAULT_OWD_WINDOW_SIZE,
    MAX_REPORT_INTERVAL_MS, MIN_REPORT_INTERVAL_MS,
};

const REKEY_JITTER_GRACE_SECS: u64 = 15;

struct GapTracker {
    expected_next: Option<u64>,
    in_burst: bool,
    current_burst_len: u16,
    burst_count: u32,
    max_burst_len: u16,
    total_burst_len: u64,
}

impl GapTracker {
    fn new() -> Self {
        Self {
            expected_next: None,
            in_burst: false,
            current_burst_len: 0,
            burst_count: 0,
            max_burst_len: 0,
            total_burst_len: 0,
        }
    }

    fn observe(&mut self, counter: u64) -> u64 {
        let Some(expected) = self.expected_next else {
            self.expected_next = Some(counter + 1);
            return 0;
        };

        let lost = if counter > expected {
            let gap = counter - expected;
            if self.in_burst {
                self.current_burst_len = self.current_burst_len.saturating_add(gap as u16);
            } else {
                self.in_burst = true;
                self.current_burst_len = gap as u16;
                self.burst_count += 1;
            }
            gap
        } else {
            if self.in_burst {
                self.finish_burst();
            }
            0
        };

        if counter >= expected {
            self.expected_next = Some(counter + 1);
        }

        lost
    }

    fn finish_burst(&mut self) {
        if self.in_burst {
            self.max_burst_len = self.max_burst_len.max(self.current_burst_len);
            self.total_burst_len += self.current_burst_len as u64;
            self.in_burst = false;
            self.current_burst_len = 0;
        }
    }

    fn take_interval_stats(&mut self) -> (u32, u16, u16) {
        self.finish_burst();

        let count = self.burst_count;
        let max_len = self.max_burst_len;
        let mean_len = if count > 0 {
            let mean_f = (self.total_burst_len as f64) / (count as f64);
            (mean_f * 256.0) as u16
        } else {
            0
        };

        self.burst_count = 0;
        self.max_burst_len = 0;
        self.total_burst_len = 0;

        (count, max_len, mean_len)
    }
}

pub struct ReceiverState {
    cumulative_packets_recv: u64,
    cumulative_bytes_recv: u64,
    cumulative_reorder_count: u64,
    highest_counter: u64,
    interval_packets_recv: u32,
    interval_bytes_recv: u32,
    jitter: JitterEstimator,
    owd_trend: OwdTrendDetector,
    owd_seq: u32,
    gap_tracker: GapTracker,
    ecn_ce_count: u32,
    last_sender_timestamp: u32,
    last_recv_time: Option<Instant>,
    rekey_jitter_grace_until: Option<Instant>,
    last_report_time: Option<Instant>,
    report_interval: Duration,
    interval_has_data: bool,
    srtt_sample_count: u32,
}

impl ReceiverState {
    pub fn new(owd_window_size: usize) -> Self {
        Self::new_with_cold_start(owd_window_size, DEFAULT_COLD_START_INTERVAL_MS)
    }

    pub fn new_with_cold_start(_owd_window_size: usize, cold_start_ms: u64) -> Self {
        Self {
            cumulative_packets_recv: 0,
            cumulative_bytes_recv: 0,
            cumulative_reorder_count: 0,
            highest_counter: 0,
            interval_packets_recv: 0,
            interval_bytes_recv: 0,
            jitter: JitterEstimator::new(),
            owd_trend: OwdTrendDetector::new(),
            owd_seq: 0,
            gap_tracker: GapTracker::new(),
            ecn_ce_count: 0,
            last_sender_timestamp: 0,
            last_recv_time: None,
            rekey_jitter_grace_until: None,
            last_report_time: None,
            report_interval: Duration::from_millis(cold_start_ms),
            interval_has_data: false,
            srtt_sample_count: 0,
        }
    }

    pub fn reset_for_rekey(&mut self, now: Instant) {
        self.highest_counter = 0;
        self.cumulative_reorder_count = 0;
        self.gap_tracker = GapTracker::new();
        self.interval_packets_recv = 0;
        self.interval_bytes_recv = 0;
        self.jitter = JitterEstimator::new();
        self.owd_trend.clear();
        self.owd_seq = 0;
        self.last_sender_timestamp = 0;
        self.last_recv_time = None;
        self.rekey_jitter_grace_until = Some(now + Duration::from_secs(REKEY_JITTER_GRACE_SECS));
        self.ecn_ce_count = 0;
        self.interval_has_data = false;
    }

    pub fn record_recv(
        &mut self,
        counter: u64,
        sender_timestamp_ms: u32,
        bytes: usize,
        ce_flag: bool,
        now: Instant,
    ) {
        self.interval_has_data = true;
        self.cumulative_packets_recv += 1;
        self.cumulative_bytes_recv += bytes as u64;
        self.interval_packets_recv = self.interval_packets_recv.saturating_add(1);
        self.interval_bytes_recv = self.interval_bytes_recv.saturating_add(bytes as u32);

        if counter < self.highest_counter {
            self.cumulative_reorder_count += 1;
        } else {
            self.highest_counter = counter;
        }

        let _lost = self.gap_tracker.observe(counter);

        if ce_flag {
            self.ecn_ce_count = self.ecn_ce_count.saturating_add(1);
        }

        let sender_us = (sender_timestamp_ms as i64) * 1000;
        let in_grace = self
            .rekey_jitter_grace_until
            .is_some_and(|deadline| now < deadline);
        if !in_grace {
            self.rekey_jitter_grace_until = None;
            if let Some(prev_recv) = self.last_recv_time {
                let recv_delta_us = now.duration_since(prev_recv).as_micros() as i64;
                let send_delta_us = sender_us - (self.last_sender_timestamp as i64 * 1000);
                let transit_delta = (recv_delta_us - send_delta_us) as i32;
                self.jitter.update(transit_delta);
            }
        }

        if let Some(first_recv) = self.last_recv_time.or(Some(now)) {
            let recv_offset_us = now.duration_since(first_recv).as_micros() as i64;
            let owd_us = recv_offset_us - sender_us;
            self.owd_seq = self.owd_seq.wrapping_add(1);
            self.owd_trend.push(self.owd_seq, owd_us);
        }

        self.last_sender_timestamp = sender_timestamp_ms;
        self.last_recv_time = Some(now);
    }

    pub fn build_report(&mut self, now: Instant) -> Option<ReceiverReport> {
        if !self.interval_has_data {
            return None;
        }

        let dwell_time = self
            .last_recv_time
            .map(|t| now.duration_since(t).as_millis() as u16)
            .unwrap_or(0);

        let (burst_count, max_burst, mean_burst) = self.gap_tracker.take_interval_stats();

        let report = ReceiverReport {
            highest_counter: self.highest_counter,
            cumulative_packets_recv: self.cumulative_packets_recv,
            cumulative_bytes_recv: self.cumulative_bytes_recv,
            timestamp_echo: self.last_sender_timestamp,
            dwell_time,
            max_burst_loss: max_burst,
            mean_burst_loss: mean_burst,
            jitter: self.jitter.jitter_us(),
            ecn_ce_count: self.ecn_ce_count,
            owd_trend: self.owd_trend.trend_us_per_sec(),
            burst_loss_count: burst_count,
            cumulative_reorder_count: self.cumulative_reorder_count as u32,
            interval_packets_recv: self.interval_packets_recv,
            interval_bytes_recv: self.interval_bytes_recv,
        };

        self.interval_packets_recv = 0;
        self.interval_bytes_recv = 0;
        self.interval_has_data = false;
        self.last_report_time = Some(now);

        Some(report)
    }

    pub fn should_send_report(&self, now: Instant) -> bool {
        if !self.interval_has_data {
            return false;
        }
        match self.last_report_time {
            None => true,
            Some(last) => now.duration_since(last) >= self.report_interval,
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
        let interval_ms = ((srtt_us as u64) / 1000).clamp(min_ms, max_ms);
        self.report_interval = Duration::from_millis(interval_ms);
    }

    pub fn cumulative_packets_recv(&self) -> u64 {
        self.cumulative_packets_recv
    }

    pub fn cumulative_bytes_recv(&self) -> u64 {
        self.cumulative_bytes_recv
    }

    pub fn highest_counter(&self) -> u64 {
        self.highest_counter
    }

    pub fn jitter_us(&self) -> u32 {
        self.jitter.jitter_us()
    }

    pub fn report_interval(&self) -> Duration {
        self.report_interval
    }
}

impl Default for ReceiverState {
    fn default() -> Self {
        Self::new(DEFAULT_OWD_WINDOW_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_receiver_state() {
        let r = ReceiverState::new(32);
        assert_eq!(r.cumulative_packets_recv(), 0);
        assert_eq!(r.cumulative_bytes_recv(), 0);
        assert_eq!(r.highest_counter(), 0);
    }

    #[test]
    fn test_record_recv_basic() {
        let mut r = ReceiverState::new(32);
        let now = Instant::now();
        r.record_recv(1, 100, 500, false, now);
        r.record_recv(2, 200, 600, false, now + Duration::from_millis(100));

        assert_eq!(r.cumulative_packets_recv(), 2);
        assert_eq!(r.cumulative_bytes_recv(), 1100);
        assert_eq!(r.highest_counter(), 2);
    }

    #[test]
    fn test_reorder_detection() {
        let mut r = ReceiverState::new(32);
        let now = Instant::now();
        r.record_recv(5, 500, 100, false, now);
        r.record_recv(3, 300, 100, false, now + Duration::from_millis(10));

        assert_eq!(r.cumulative_reorder_count, 1);
        assert_eq!(r.highest_counter(), 5);
    }

    #[test]
    fn test_ecn_counting() {
        let mut r = ReceiverState::new(32);
        let now = Instant::now();
        r.record_recv(1, 100, 100, true, now);
        r.record_recv(2, 200, 100, false, now);
        r.record_recv(3, 300, 100, true, now);

        assert_eq!(r.ecn_ce_count, 2);
    }

    #[test]
    fn test_build_report_empty() {
        let mut r = ReceiverState::new(32);
        assert!(r.build_report(Instant::now()).is_none());
    }

    #[test]
    fn test_build_report() {
        let mut r = ReceiverState::new(32);
        let t0 = Instant::now();
        r.record_recv(1, 100, 500, false, t0);
        r.record_recv(2, 200, 600, false, t0 + Duration::from_millis(100));

        let report = r.build_report(t0 + Duration::from_millis(150)).unwrap();
        assert_eq!(report.highest_counter, 2);
        assert_eq!(report.cumulative_packets_recv, 2);
        assert_eq!(report.cumulative_bytes_recv, 1100);
        assert_eq!(report.timestamp_echo, 200);
        assert_eq!(report.interval_packets_recv, 2);
        assert_eq!(report.interval_bytes_recv, 1100);
    }

    #[test]
    fn test_build_report_resets_interval() {
        let mut r = ReceiverState::new(32);
        let t0 = Instant::now();
        r.record_recv(1, 100, 500, false, t0);
        let _ = r.build_report(t0);

        assert!(r.build_report(t0).is_none());

        r.record_recv(2, 200, 300, false, t0 + Duration::from_millis(100));
        let report = r.build_report(t0 + Duration::from_millis(150)).unwrap();
        assert_eq!(report.interval_packets_recv, 1);
        assert_eq!(report.interval_bytes_recv, 300);
        assert_eq!(report.cumulative_packets_recv, 2);
    }

    #[test]
    fn test_should_send_report_timing() {
        let mut r = ReceiverState::new(32);
        let t0 = Instant::now();

        assert!(!r.should_send_report(t0));

        r.record_recv(1, 100, 500, false, t0);
        assert!(r.should_send_report(t0));

        let _ = r.build_report(t0);
        r.record_recv(2, 200, 500, false, t0);
        assert!(!r.should_send_report(t0));

        let t1 = t0 + r.report_interval() + Duration::from_millis(1);
        assert!(r.should_send_report(t1));
    }

    #[test]
    fn test_update_report_interval_cold_start() {
        let mut r = ReceiverState::new(32);
        r.update_report_interval_from_srtt(50_000);
        assert_eq!(r.report_interval(), Duration::from_millis(200));

        r.update_report_interval_from_srtt(500_000);
        assert_eq!(r.report_interval(), Duration::from_millis(500));
    }

    #[test]
    fn test_update_report_interval_after_cold_start() {
        let mut r = ReceiverState::new(32);
        for _ in 0..COLD_START_SAMPLES {
            r.update_report_interval_from_srtt(500_000);
        }

        r.update_report_interval_from_srtt(50_000);
        assert_eq!(
            r.report_interval(),
            Duration::from_millis(MIN_REPORT_INTERVAL_MS)
        );

        r.update_report_interval_from_srtt(3_000_000);
        assert_eq!(r.report_interval(), Duration::from_millis(3000));
    }

    #[test]
    fn test_gap_tracker_no_loss() {
        let mut g = GapTracker::new();
        g.observe(1);
        g.observe(2);
        g.observe(3);
        let (count, max, mean) = g.take_interval_stats();
        assert_eq!(count, 0);
        assert_eq!(max, 0);
        assert_eq!(mean, 0);
    }

    #[test]
    fn test_gap_tracker_single_burst() {
        let mut g = GapTracker::new();
        g.observe(1);
        g.observe(4);
        g.observe(5);
        let (count, max, _mean) = g.take_interval_stats();
        assert_eq!(count, 1);
        assert_eq!(max, 2);
    }

    #[test]
    fn test_gap_tracker_multiple_bursts() {
        let mut g = GapTracker::new();
        g.observe(1);
        g.observe(4);
        g.observe(5);
        g.observe(8);
        g.observe(9);
        let (count, max, mean) = g.take_interval_stats();
        assert_eq!(count, 2);
        assert_eq!(max, 2);
        assert_eq!(mean, 512);
    }
}
