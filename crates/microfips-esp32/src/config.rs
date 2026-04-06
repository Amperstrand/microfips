pub const LED_OFF: u32 = 0;
pub const LED_ON: u32 = 2;
pub const PANIC_BLINK_CYCLES: u32 = 5_000_000;

pub const UART_FIFO_THRESHOLD: u16 = 64;
pub const UART_BAUDRATE: u32 = 115200;
pub const WAIT_READY_DELAY_MS: u64 = 500;
pub const RECV_RETRY_DELAY_MS: u64 = 10;

/// ESP32 identity secret key: 31 zero bytes + 0x02 (secp256k1 generator * 2).
/// npub: npub1ccz8l9zpa47k6vz9gphftsrumpw80rjt3nhnefat4symjhrsnmjs38mnyd
/// node_addr: 0135da2f8acf7b9e3090939432e47684
pub const ESP32_SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// STM32 peer pubkey (DEFAULT_SECRET -> ecdh_pubkey -> compressed point).
/// node_addr: 132f39a98c31baaddba6525f5d43f295
pub const STM32_PEER_PUB: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

pub const STM32_NODE_ADDR: [u8; 16] = [
    0x13, 0x2f, 0x39, 0xa9, 0x8c, 0x31, 0xba, 0xad, 0xdb, 0xa6, 0x52, 0x5f, 0x5d, 0x43, 0xf2, 0x95,
];

#[cfg(feature = "ble")]
pub const BLE_DEVICE_NAME: &str = "microfips-esp32";
#[cfg(feature = "ble")]
pub const BLE_MAX_FRAME: usize = 252;

#[cfg(feature = "ble")]
pub mod ble_uuids {
    pub const FIPS_SERVICE_UUID: u128 = 0x6f696670_7300_4265_8001_000000000001;
    pub const FIPS_RX_UUID: u128 = 0x6f696670_7300_4265_8002_000000000002;
    pub const FIPS_TX_UUID: u128 = 0x6f696670_7300_4265_8003_000000000003;
}

#[cfg(feature = "ble")]
pub const FIPS_SERVICE_UUID_LE: [[u8; 16]; 1] = [[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x65, 0x42, 0x00, 0x73, 0x70, 0x66, 0x69, 0x6f,
]];

#[cfg(feature = "l2cap")]
pub const L2CAP_FRAME_CAP: usize = 512;
#[cfg(feature = "l2cap")]
pub const L2CAP_PSM: u16 = 0x0085;
#[cfg(feature = "l2cap")]
pub const L2CAP_FIPS_SERVICE_UUID_LE: [[u8; 16]; 1] = [[
    0x4c, 0x8f, 0x64, 0x40, 0xcc, 0xc9, 0x87, 0x9f, 0xc0, 0x42, 0xc5, 0x2c, 0x90, 0xb7, 0x90, 0x9c,
]];
#[cfg(feature = "l2cap")]
pub const L2CAP_SCAN_DURATION_SECS: u64 = 3;
#[cfg(feature = "l2cap")]
pub const AD_TYPE_COMPLETE_UUID128: u8 = 0x07;

#[cfg(feature = "wifi")]
pub const WIFI_SSID: &str = env!("WIFI_SSID");
#[cfg(feature = "wifi")]
pub const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
#[cfg(feature = "wifi")]
pub use microfips_esp_common::config::{
    DNS_PORT, DNS_QUERY_ID, DNS_TIMEOUT_SECS, VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS,
};
