#[cfg(feature = "ble")]
use core::sync::atomic::AtomicU32;

pub use microfips_esp_common::stats::*;

#[cfg(feature = "ble")]
#[used]
pub static BLE_STATS: BleStats = BleStats::new();

#[cfg(feature = "ble")]
pub struct BleStats {
    pub connect: AtomicU32,
    pub disconnect: AtomicU32,
    pub tx: AtomicU32,
    pub rx: AtomicU32,
}

#[cfg(feature = "ble")]
impl BleStats {
    pub const fn new() -> Self {
        Self {
            connect: AtomicU32::new(0),
            disconnect: AtomicU32::new(0),
            tx: AtomicU32::new(0),
            rx: AtomicU32::new(0),
        }
    }
}
