// Ported from fips: src/mmp/mod.rs MmpPeerState
use crate::mmp::{MmpMetrics, ReceiverState, SenderState};
use embassy_time::{Duration, Instant};
use microfips_core::mmp::{MmpMode, SpinBitState, DEFAULT_OWD_WINDOW_SIZE};

pub const DEFAULT_LOG_INTERVAL_SECS: u64 = 30;

/// Combined MMP state for a single peer link.
/// Ported from fips: wraps sender, receiver, metrics, and spin bit state.
#[cfg(feature = "mmp")]
pub struct MmpPeerState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
    pub spin_bit: SpinBitState,
    mode: MmpMode,
    log_interval: Duration,
    last_log_time: Option<Instant>,
}

#[cfg(feature = "mmp")]
impl Default for MmpPeerState {
    fn default() -> Self {
        Self::new(MmpMode::Full, true)
    }
}

#[cfg(feature = "mmp")]
impl MmpPeerState {
    pub fn new(mode: MmpMode, is_initiator: bool) -> Self {
        Self {
            sender: SenderState::new(),
            receiver: ReceiverState::new(DEFAULT_OWD_WINDOW_SIZE),
            metrics: MmpMetrics::new(),
            spin_bit: SpinBitState::new(is_initiator),
            mode,
            log_interval: Duration::from_secs(DEFAULT_LOG_INTERVAL_SECS),
            last_log_time: None,
        }
    }

    /// Reset counter-dependent state for rekey cutover.
    // Ported from fips
    pub fn reset_for_rekey(&mut self, now: Instant) {
        self.receiver.reset_for_rekey(now);
        self.metrics.reset_for_rekey();
    }

    /// Current operating mode.
    // Ported from fips
    pub fn mode(&self) -> MmpMode {
        self.mode
    }

    /// Check if it's time to emit a periodic metrics log.
    // Ported from fips
    pub fn should_log(&self, now: Instant) -> bool {
        match self.last_log_time {
            None => true,
            Some(last) => now.duration_since(last) >= self.log_interval,
        }
    }

    /// Mark that a periodic log was emitted.
    // Ported from fips
    pub fn mark_logged(&mut self, now: Instant) {
        self.last_log_time = Some(now);
    }

    pub fn snapshot_stats(&self) {
        let srtt_ms = self.metrics.srtt_ms().map(|v| v as u32).unwrap_or(0);
        let loss_permil = (self.metrics.loss_rate() * 1000.0).min(1000.0) as u32;
        let goodput_kbps = ((self.metrics.goodput_bps() / 1000.0).min(u32::MAX as f64)) as u32;
        let jitter_us = self.receiver.jitter_us();
        crate::mmp::stats::update(srtt_ms, loss_permil, goodput_kbps, jitter_us);
    }
}
