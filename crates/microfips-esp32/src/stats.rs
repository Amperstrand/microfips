#[cfg(feature = "ble")]
use core::sync::atomic::AtomicU32;

pub use microfips_esp_common::stats::*;

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
