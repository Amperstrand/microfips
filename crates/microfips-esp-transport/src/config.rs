pub const LED_OFF: u32 = 0;
pub const LED_ON: u32 = 2;

pub const WAIT_READY_DELAY_MS: u64 = 500;
pub const RECV_RETRY_DELAY_MS: u64 = 10;
pub const PANIC_BLINK_CYCLES: u32 = 5_000_000;
pub const UART_FIFO_THRESHOLD: u16 = 64;
pub const UART_BAUDRATE: u32 = 115200;

#[cfg(feature = "ble")]
pub const BLE_MAX_FRAME: usize = 256;

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

/// When true, the ESP32 uses its factory IEEE public BLE address (matches FIPS 3621e4b
/// LePublic connect). When false, a random static address is derived from DEVICE_SECRET.
/// Set to false when upstream FIPS switches to LeRandom for L2CAP connections.
#[cfg(feature = "l2cap")]
pub const USE_PUBLIC_BLE_ADDRESS: bool = true;

#[cfg(feature = "l2cap")]
pub const L2CAP_FRAME_CAP: usize = 512;

#[cfg(feature = "l2cap")]
pub const L2CAP_PSM: u16 = 133;

#[cfg(feature = "l2cap")]
pub const FIPS_BLE_ADDR: [u8; 6] = [0x24, 0xC2, 0x49, 0xFC, 0x5A, 0x14];

/// Expected FIPS daemon x-only pubkey (32 bytes). Used to validate BLE L2CAP connections
/// and reject non-FIPS peers (e.g., other ESP32 devices advertising the same service UUID).
#[cfg(feature = "l2cap")]
pub const FIPS_EXPECTED_PUBKEY: [u8; 32] = [
    0xb3, 0x98, 0x90, 0x43, 0xc6, 0x8d, 0x9c, 0x2d, 0x3c, 0x8f, 0x94, 0x9d, 0x73, 0xe6, 0x1c, 0xae,
    0x27, 0x99, 0x79, 0x93, 0x43, 0x2c, 0x3d, 0xbb, 0xd8, 0x49, 0x81, 0x17, 0xd9, 0x2d, 0x95, 0xbb,
];

#[cfg(feature = "l2cap")]
pub mod ble_caps {
    pub const LEAF_ONLY: u8 = 0x01;
    pub const HAS_TUN: u8 = 0x02;
    pub const HAS_INTERNET: u8 = 0x04;
}

#[cfg(feature = "l2cap")]
pub const FIPS_CAPS_SERVICE_UUID: [u8; 2] = [0x46, 0x49];

#[cfg(feature = "l2cap")]
pub const L2CAP_FIPS_SERVICE_UUID_LE: [[u8; 16]; 1] = [[
    0x4c, 0x8f, 0x64, 0x40, 0xcc, 0xc9, 0x87, 0x9f, 0xc0, 0x42, 0xc5, 0x2c, 0x90, 0xb7, 0x90, 0x9c,
]];

// Device identity secret key (populated from env var at compile time)
#[cfg(feature = "esp32")]
pub const DEVICE_SECRET: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_esp32"));
#[cfg(feature = "esp32s3")]
pub const DEVICE_SECRET: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_esp32s3"));

#[cfg(all(feature = "esp32", feature = "ble"))]
pub const BLE_DEVICE_NAME: &str = "microfips-esp32";
#[cfg(all(feature = "esp32s3", feature = "ble"))]
pub const BLE_DEVICE_NAME: &str = "microfips-esp32s3";

#[cfg(feature = "esp32")]
pub const DEVICE_NAME: &str = "microfips-esp32";
#[cfg(feature = "esp32s3")]
pub const DEVICE_NAME: &str = "microfips-esp32s3";

#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32")]
pub const UART0_BASE: usize = 0x3FF4_0000;
#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32s3")]
pub const UART0_BASE: usize = 0x6000_0000;

#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32")]
pub const GPIO_FUNC_IN_SEL_BASE: usize = 0x3FF4_4350;
#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32s3")]
pub const GPIO_FUNC_IN_SEL_BASE: usize = 0x6000_9000;

#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32")]
pub const UART_RX_GPIO_NUM: u32 = 3;
#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32s3")]
pub const UART_RX_GPIO_NUM: u32 = 44;

// Reset register address (RTC_CNTL_OPTIONS0_REG)
#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32")]
pub const RESET_REGISTER: usize = 0x3FF4_8000;
#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
#[cfg(feature = "esp32s3")]
pub const RESET_REGISTER: usize = 0x6000_8000;
