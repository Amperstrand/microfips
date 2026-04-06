use core::sync::atomic::{AtomicU32, Ordering};

#[used]
pub static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_DATA_TX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_DATA_RX: AtomicU32 = AtomicU32::new(0);

#[used]
pub static STAT_STATE: AtomicU32 = AtomicU32::new(0);
#[used]
pub static BOOT_TICK_MS: AtomicU32 = AtomicU32::new(0);

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
        let boot_ms = BOOT_TICK_MS.load(Ordering::Relaxed) as u64;
        let now_ms = embassy_time::Instant::now().as_millis();
        let uptime_secs = if now_ms > boot_ms {
            ((now_ms - boot_ms) / 1000) as u32
        } else {
            0
        };
        StatsSnapshot {
            state: STAT_STATE.load(Ordering::Relaxed),
            msg1_tx: STAT_MSG1_TX.load(Ordering::Relaxed),
            msg2_rx: STAT_MSG2_RX.load(Ordering::Relaxed),
            hb_tx: STAT_HB_TX.load(Ordering::Relaxed),
            hb_rx: STAT_HB_RX.load(Ordering::Relaxed),
            data_tx: STAT_DATA_TX.load(Ordering::Relaxed),
            data_rx: STAT_DATA_RX.load(Ordering::Relaxed),
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

#[cfg(feature = "ble")]
#[used]
pub static STAT_BLE_CONNECT: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "ble")]
#[used]
pub static STAT_BLE_DISCONNECT: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "ble")]
#[used]
pub static STAT_BLE_TX: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "ble")]
#[used]
pub static STAT_BLE_RX: AtomicU32 = AtomicU32::new(0);
