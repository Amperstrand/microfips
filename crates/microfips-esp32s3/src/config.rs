pub const LED_OFF: u32 = 0;
pub const LED_ON: u32 = 2;
pub const PANIC_BLINK_CYCLES: u32 = 5_000_000;

pub const UART_FIFO_THRESHOLD: u16 = 64;
pub const UART_BAUDRATE: u32 = 115200;

/// ESP32-S3 identity secret key (from keys.json device "esp32s3").
pub const ESP32S3_SECRET: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_esp32s3"));

pub const ESP32_SECRET: [u8; 32] = ESP32S3_SECRET;

pub use microfips_core::identity::{STM32_NODE_ADDR, STM32_PEER_PUB};

#[cfg(feature = "ble")]
pub const BLE_DEVICE_NAME: &str = "microfips-esp32s3";

#[cfg(feature = "ble")]
pub use microfips_esp_transport::config::ble_uuids;
#[cfg(feature = "ble")]
pub use microfips_esp_transport::config::{BLE_MAX_FRAME, FIPS_SERVICE_UUID_LE};

#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::config::ble_caps;
pub use microfips_esp_transport::config::RECV_RETRY_DELAY_MS;
#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::config::{FIPS_CAPS_SERVICE_UUID, L2CAP_FIPS_SERVICE_UUID_LE};
#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::config::{L2CAP_FRAME_CAP, L2CAP_PSM};

#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::config::WAIT_READY_DELAY_MS;

#[cfg(feature = "wifi")]
pub const WIFI_SSID: &str = env!("WIFI_SSID");
#[cfg(feature = "wifi")]
pub const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
#[cfg(feature = "wifi")]
pub use microfips_esp_common::config::{
    DNS_PORT, DNS_QUERY_ID, DNS_TIMEOUT_SECS, VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS,
};
