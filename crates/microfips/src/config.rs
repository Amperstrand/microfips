pub const CDC_PKT: usize = 64;
pub const PANIC_BLINK_CYCLES: u32 = 500_000;
pub const USB_DESC_BUF_SIZE: usize = 256;
pub const USB_CTL_BUF_SIZE: usize = 64;

pub const S_BOOT: u32 = 0;
pub const S_USB_READY: u32 = 1;
pub const S_MSG1_SENT: u32 = 2;
pub const S_HANDSHAKE_OK: u32 = 3;
pub const S_HB_TX: u32 = 4;
pub const S_HB_RX: u32 = 5;
pub const S_ERR: u32 = 6;
pub const S_DISCONNECTED: u32 = 7;

pub use microfips_core::identity::{ESP32_NODE_ADDR, ESP32_PEER_PUB};
