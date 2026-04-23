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

/// ESP32 peer pubkey (ESP32_SECRET -> ecdh_pubkey -> compressed point).
/// FIPS cross-reference: bd08505 src/node/handlers/session.rs:handle_session_setup()
/// node_addr: 0135da2f8acf7b9e3090939432e47684
pub const ESP32_PEER_PUB: [u8; 33] = [
    0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c,
    0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e,
    0xe5,
];

pub const ESP32_NODE_ADDR: [u8; 16] = [
    0x01, 0x35, 0xda, 0x2f, 0x8a, 0xcf, 0x7b, 0x9e, 0x30, 0x90, 0x93, 0x94, 0x32, 0xe4, 0x76, 0x84,
];
