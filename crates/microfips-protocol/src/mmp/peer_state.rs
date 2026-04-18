use crate::mmp::{MmpMetrics, ReceiverState, SenderState};
use microfips_core::mmp::DEFAULT_OWD_WINDOW_SIZE;

#[cfg(feature = "mmp")]
pub struct MmpPeerState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
}

#[cfg(feature = "mmp")]
impl MmpPeerState {
    pub fn new() -> Self {
        Self {
            sender: SenderState::new(),
            receiver: ReceiverState::new(DEFAULT_OWD_WINDOW_SIZE),
            metrics: MmpMetrics::new(),
        }
    }

    pub fn snapshot_stats(&self) {
        let srtt_ms = self.metrics.srtt_ms().map(|v| v as u32).unwrap_or(0);
        let loss_permil = (self.metrics.loss_rate() * 1000.0).min(1000.0) as u32;
        let goodput_kbps = ((self.metrics.goodput_bps() / 1000.0).min(u32::MAX as f64)) as u32;
        let jitter_us = self.receiver.jitter_us();
        crate::mmp::stats::update(srtt_ms, loss_permil, goodput_kbps, jitter_us);
    }
}
