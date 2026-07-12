//! Ported from fips v0.4.0: `src/mmp/metrics.rs`.

use embassy_time::Instant;
use microfips_core::mmp::algorithms::{compute_etx, DualEwma, SrttEstimator};
use microfips_core::mmp::report::ReceiverReport;

pub struct MmpMetrics {
    pub srtt: SrttEstimator,
    pub rtt_trend: DualEwma,
    pub loss_trend: DualEwma,
    pub goodput_trend: DualEwma,
    pub jitter_trend: DualEwma,
    pub etx_trend: DualEwma,
    pub delivery_ratio_forward: f64,
    pub delivery_ratio_reverse: f64,
    pub etx: f64,
    pub goodput_bps: f64,

    prev_rr_cum_packets: u64,
    prev_rr_cum_bytes: u64,
    prev_rr_highest_counter: u64,
    prev_rr_ecn_ce: u32,
    prev_rr_reorder: u32,
    prev_rr_time: Option<Instant>,
    has_prev_rr: bool,

    prev_reverse_packets: u64,
    prev_reverse_highest: u64,
    has_prev_reverse: bool,
}

impl MmpMetrics {
    pub fn new() -> Self {
        Self {
            srtt: SrttEstimator::new(),
            rtt_trend: DualEwma::new(),
            loss_trend: DualEwma::new(),
            goodput_trend: DualEwma::new(),
            jitter_trend: DualEwma::new(),
            etx_trend: DualEwma::new(),
            delivery_ratio_forward: 1.0,
            delivery_ratio_reverse: 1.0,
            etx: 1.0,
            goodput_bps: 0.0,
            prev_rr_cum_packets: 0,
            prev_rr_cum_bytes: 0,
            prev_rr_highest_counter: 0,
            prev_rr_ecn_ce: 0,
            prev_rr_reorder: 0,
            prev_rr_time: None,
            has_prev_rr: false,
            prev_reverse_packets: 0,
            prev_reverse_highest: 0,
            has_prev_reverse: false,
        }
    }

    pub fn reset_for_rekey(&mut self) {
        self.prev_rr_cum_packets = 0;
        self.prev_rr_cum_bytes = 0;
        self.prev_rr_highest_counter = 0;
        self.prev_rr_ecn_ce = 0;
        self.prev_rr_reorder = 0;
        self.prev_rr_time = None;
        self.has_prev_rr = false;
        self.delivery_ratio_forward = 1.0;
        self.prev_reverse_packets = 0;
        self.prev_reverse_highest = 0;
        self.has_prev_reverse = false;
    }

    pub fn process_receiver_report(
        &mut self,
        rr: &ReceiverReport,
        our_timestamp_ms: u32,
        now: Instant,
    ) -> bool {
        let had_srtt = self.srtt.initialized();

        // Bugfix 1 (fips v0.4): Reject stale or duplicate ReceiverReports.
        // Reports are only built after interval data, so a fresh report
        // always advances at least one cumulative counter. A duplicate or
        // regressed report would produce a bogus RTT sample.
        if self.has_prev_rr && self.is_stale_or_duplicate(rr) {
            return false;
        }

        // Bugfix 2 (fips v0.4): RTT from timestamp echo with checked arithmetic
        // to prevent underflow on corrupt or stale echo values.
        if rr.timestamp_echo > 0 {
            let echo_ms = rr.timestamp_echo;
            let dwell_ms = u32::from(rr.dwell_time);
            let rtt_sample_ms = echo_ms
                .checked_add(dwell_ms)
                .and_then(|send_done_ms| our_timestamp_ms.checked_sub(send_done_ms));
            if let Some(rtt_ms) = rtt_sample_ms {
                if rtt_ms > 0 {
                    let rtt_us = (rtt_ms as i64) * 1000;
                    self.srtt.update(rtt_us);
                    self.rtt_trend.update(rtt_us as f64);
                }
            }
        }

        if self.has_prev_rr {
            let counter_span = rr
                .highest_counter
                .saturating_sub(self.prev_rr_highest_counter);
            let packets_delta = rr
                .cumulative_packets_recv
                .saturating_sub(self.prev_rr_cum_packets);

            if counter_span > 0 {
                let delivery = (packets_delta as f64) / (counter_span as f64);
                self.delivery_ratio_forward = delivery.clamp(0.0, 1.0);
                let loss_rate = 1.0 - self.delivery_ratio_forward;
                self.loss_trend.update(loss_rate);
                self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
                self.etx_trend.update(self.etx);
            }
        }

        if self.has_prev_rr {
            let bytes_delta = rr
                .cumulative_bytes_recv
                .saturating_sub(self.prev_rr_cum_bytes);
            self.goodput_trend.update(bytes_delta as f64);

            if let Some(prev_time) = self.prev_rr_time {
                let elapsed = now.duration_since(prev_time);
                let secs = elapsed.as_millis() as f64 / 1000.0;
                if secs > 0.0 {
                    let bps = bytes_delta as f64 / secs;
                    if self.goodput_bps == 0.0 {
                        self.goodput_bps = bps;
                    } else {
                        self.goodput_bps += (bps - self.goodput_bps) * 0.25;
                    }
                }
            }
        }

        self.jitter_trend.update(rr.jitter as f64);

        self.prev_rr_cum_packets = rr.cumulative_packets_recv;
        self.prev_rr_cum_bytes = rr.cumulative_bytes_recv;
        self.prev_rr_highest_counter = rr.highest_counter;
        self.prev_rr_ecn_ce = rr.ecn_ce_count;
        self.prev_rr_reorder = rr.cumulative_reorder_count;
        self.prev_rr_time = Some(now);
        self.has_prev_rr = true;

        !had_srtt && self.srtt.initialized()
    }

    /// Check if a ReceiverReport's counters regressed or are exact duplicates
    /// of the previous report. Ported from fips v0.4.
    fn is_stale_or_duplicate(&self, rr: &ReceiverReport) -> bool {
        let counters_regressed = rr.highest_counter < self.prev_rr_highest_counter
            || rr.cumulative_packets_recv < self.prev_rr_cum_packets
            || rr.cumulative_bytes_recv < self.prev_rr_cum_bytes
            || rr.ecn_ce_count < self.prev_rr_ecn_ce
            || rr.cumulative_reorder_count < self.prev_rr_reorder;
        let duplicate_counters = rr.highest_counter == self.prev_rr_highest_counter
            && rr.cumulative_packets_recv == self.prev_rr_cum_packets
            && rr.cumulative_bytes_recv == self.prev_rr_cum_bytes
            && rr.ecn_ce_count == self.prev_rr_ecn_ce
            && rr.cumulative_reorder_count == self.prev_rr_reorder;
        counters_regressed || duplicate_counters
    }

    pub fn update_reverse_delivery(&mut self, our_recv_packets: u64, peer_highest: u64) {
        if self.has_prev_reverse {
            let counter_span = peer_highest.saturating_sub(self.prev_reverse_highest);
            let packets_delta = our_recv_packets.saturating_sub(self.prev_reverse_packets);

            if counter_span > 0 {
                let delivery = (packets_delta as f64) / (counter_span as f64);
                self.delivery_ratio_reverse = delivery.clamp(0.0, 1.0);
                self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
                self.etx_trend.update(self.etx);
            }
        }

        self.prev_reverse_packets = our_recv_packets;
        self.prev_reverse_highest = peer_highest;
        self.has_prev_reverse = true;
    }

    pub fn srtt_ms(&self) -> Option<f64> {
        if self.srtt.initialized() {
            Some(self.srtt.srtt_us() as f64 / 1000.0)
        } else {
            None
        }
    }

    pub fn loss_rate(&self) -> f64 {
        1.0 - self.delivery_ratio_forward
    }

    pub fn goodput_bps(&self) -> f64 {
        self.goodput_bps
    }

    pub fn smoothed_etx(&self) -> Option<f64> {
        if self.etx_trend.initialized() {
            Some(self.etx_trend.long())
        } else {
            None
        }
    }

    // Ported from fips
    /// Minimum observed RTT in milliseconds.
    /// Per RFC 9002 §5.2: min_rtt provides baseline for detecting queuing delay inflation.
    pub fn min_rtt_ms(&self) -> Option<f64> {
        if self.srtt.initialized() {
            Some(self.srtt.min_rtt_us() as f64 / 1000.0)
        } else {
            None
        }
    }

    // Ported from fips
    /// RTT inflation ratio (SRTT / min_rtt). Returns None until 5+ RTT samples.
    pub fn inflation_ratio(&self) -> Option<f64> {
        if self.srtt.sample_count() < 5 {
            return None;
        }
        let srtt = self.srtt_ms()?;
        let min = self.min_rtt_ms()?;
        if min > 0.0 {
            Some(srtt / min)
        } else {
            None
        }
    }

    // Ported from fips
    /// Smoothed loss rate (long-term EWMA).
    pub fn smoothed_loss(&self) -> Option<f64> {
        if self.loss_trend.initialized() {
            Some(self.loss_trend.long())
        } else {
            None
        }
    }

    // Ported from fips
    /// Reset SRTT estimator for path change (proactive reconnect).
    /// Per RFC 9002 §5.3: RTT measurements MUST be reset on path change.
    pub fn reset_srtt(&mut self) {
        self.srtt.reset();
    }

    // Ported from fips
    /// Cumulative ECN CE count from the most recent ReceiverReport.
    pub fn last_ecn_ce_count(&self) -> u32 {
        self.prev_rr_ecn_ce
    }
}

impl Default for MmpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_time::Duration;

    fn make_rr(
        highest_counter: u64,
        cum_packets: u64,
        cum_bytes: u64,
        timestamp_echo: u32,
        dwell: u16,
        jitter: u32,
    ) -> ReceiverReport {
        ReceiverReport {
            highest_counter,
            cumulative_packets_recv: cum_packets,
            cumulative_bytes_recv: cum_bytes,
            timestamp_echo,
            dwell_time: dwell,
            max_burst_loss: 0,
            mean_burst_loss: 0,
            jitter,
            ecn_ce_count: 0,
            owd_trend: 0,
            burst_loss_count: 0,
            cumulative_reorder_count: 0,
            interval_packets_recv: 0,
            interval_bytes_recv: 0,
        }
    }

    #[test]
    fn test_rtt_from_echo() {
        let mut m = MmpMetrics::new();
        let now = Instant::now();
        let rr = make_rr(10, 10, 5000, 1000, 5, 0);
        m.process_receiver_report(&rr, 1050, now);

        assert!(m.srtt.initialized());
        let srtt_ms = m.srtt_ms().unwrap();
        assert!((srtt_ms - 45.0).abs() < 1.0, "srtt={srtt_ms}, expected ~45");
    }

    #[test]
    fn test_loss_rate_computation() {
        let mut m = MmpMetrics::new();
        let t0 = Instant::now();

        let rr1 = make_rr(100, 100, 50_000, 0, 0, 0);
        m.process_receiver_report(&rr1, 0, t0);

        let rr2 = make_rr(300, 290, 145_000, 0, 0, 0);
        m.process_receiver_report(&rr2, 0, t0 + Duration::from_secs(1));

        let loss = m.loss_rate();
        assert!((loss - 0.05).abs() < 0.01, "loss={loss}, expected ~0.05");
    }

    #[test]
    fn test_no_rtt_without_echo() {
        let mut m = MmpMetrics::new();
        let now = Instant::now();
        let rr = make_rr(10, 10, 5000, 0, 0, 0);
        m.process_receiver_report(&rr, 1000, now);
        assert!(m.srtt_ms().is_none());
    }

    #[test]
    fn test_goodput_bps() {
        let mut m = MmpMetrics::new();
        let t0 = Instant::now();

        let rr1 = make_rr(100, 100, 50_000, 0, 0, 0);
        m.process_receiver_report(&rr1, 0, t0);
        assert_eq!(m.goodput_bps(), 0.0);

        let rr2 = make_rr(300, 290, 150_000, 0, 0, 0);
        m.process_receiver_report(&rr2, 0, t0 + Duration::from_secs(1));
        assert!(
            m.goodput_bps() > 90_000.0,
            "goodput={}, expected ~100000",
            m.goodput_bps()
        );
        assert!(
            m.goodput_bps() < 110_000.0,
            "goodput={}, expected ~100000",
            m.goodput_bps()
        );
    }

    #[test]
    fn test_reverse_delivery_delta() {
        let mut m = MmpMetrics::new();

        m.update_reverse_delivery(100, 100);
        assert_eq!(m.delivery_ratio_reverse, 1.0);

        m.update_reverse_delivery(300, 300);
        assert!((m.delivery_ratio_reverse - 1.0).abs() < 0.001);

        m.update_reverse_delivery(350, 400);
        assert!(
            (m.delivery_ratio_reverse - 0.5).abs() < 0.001,
            "reverse={}, expected 0.5",
            m.delivery_ratio_reverse
        );
    }

    #[test]
    fn test_ignores_duplicate_receiver_report_after_valid_sample() {
        let mut m = MmpMetrics::new();
        let t0 = Instant::now();

        let rr1 = make_rr(10, 10, 5_000, 1_000, 5, 0);
        m.process_receiver_report(&rr1, 1_050, t0);

        let rr2 = make_rr(20, 18, 14_000, 1_100, 5, 0);
        m.process_receiver_report(&rr2, 1_150, t0 + Duration::from_secs(1));
        let baseline_srtt_ms = m.srtt_ms().unwrap();
        let baseline_loss = m.loss_rate();
        let baseline_goodput = m.goodput_bps();

        assert!(baseline_loss > 0.0);
        assert!(baseline_goodput > 0.0);

        // A duplicate of rr2 arriving later would be a ~4.9s RTT sample
        // if accepted. It must not move any metrics.
        m.process_receiver_report(&rr2, 6_000, t0 + Duration::from_secs(5));

        assert_eq!(m.srtt_ms().unwrap(), baseline_srtt_ms);
        assert_eq!(m.loss_rate(), baseline_loss);
        assert_eq!(m.goodput_bps(), baseline_goodput);
    }
}
