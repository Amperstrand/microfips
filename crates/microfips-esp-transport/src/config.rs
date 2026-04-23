pub const LED_OFF: u32 = 0;
pub const LED_ON: u32 = 2;

pub const WAIT_READY_DELAY_MS: u64 = 500;
pub const RECV_RETRY_DELAY_MS: u64 = 10;

#[cfg(feature = "ble")]
pub const BLE_MAX_FRAME: usize = 256;

#[cfg(feature = "l2cap")]
pub const L2CAP_FRAME_CAP: usize = 512;
