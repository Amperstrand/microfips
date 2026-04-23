use core::sync::atomic::{AtomicU32, Ordering};

#[used]
pub static STATS: NodeStats = NodeStats::new();

pub struct NodeStats {
    pub msg1_tx: AtomicU32,
    pub msg2_rx: AtomicU32,
    pub hb_tx: AtomicU32,
    pub hb_rx: AtomicU32,
    pub data_tx: AtomicU32,
    pub data_rx: AtomicU32,
    pub state: AtomicU32,
    pub boot_tick_ms: AtomicU32,
}

impl NodeStats {
    pub const fn new() -> Self {
        Self {
            msg1_tx: AtomicU32::new(0),
            msg2_rx: AtomicU32::new(0),
            hb_tx: AtomicU32::new(0),
            hb_rx: AtomicU32::new(0),
            data_tx: AtomicU32::new(0),
            data_rx: AtomicU32::new(0),
            state: AtomicU32::new(0),
            boot_tick_ms: AtomicU32::new(0),
        }
    }
}

pub struct StatsSnapshot {
    pub state: u32,
    pub msg1_tx: u32,
    pub msg2_rx: u32,
    pub hb_tx: u32,
    pub hb_rx: u32,
    pub data_tx: u32,
    pub data_rx: u32,
    pub uptime_secs: u32,
}

impl StatsSnapshot {
    pub fn capture() -> Self {
        let boot_ms = STATS.boot_tick_ms.load(Ordering::Relaxed) as u64;
        let now_ms = embassy_time::Instant::now().as_millis();
        let uptime_secs = if now_ms > boot_ms {
            ((now_ms - boot_ms) / 1000) as u32
        } else {
            0
        };
        StatsSnapshot {
            state: STATS.state.load(Ordering::Relaxed),
            msg1_tx: STATS.msg1_tx.load(Ordering::Relaxed),
            msg2_rx: STATS.msg2_rx.load(Ordering::Relaxed),
            hb_tx: STATS.hb_tx.load(Ordering::Relaxed),
            hb_rx: STATS.hb_rx.load(Ordering::Relaxed),
            data_tx: STATS.data_tx.load(Ordering::Relaxed),
            data_rx: STATS.data_rx.load(Ordering::Relaxed),
            uptime_secs,
        }
    }

    pub fn state_str(&self) -> &'static str {
        match self.state {
            0 => "boot",
            1 => "connected",
            2 => "handshake",
            3 => "handshake_ok",
            4 => "steady",
            5 => "disconnected",
            6 => "error",
            _ => "unknown",
        }
    }
}
