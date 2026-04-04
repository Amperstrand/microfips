use core::sync::atomic::AtomicU32;

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
