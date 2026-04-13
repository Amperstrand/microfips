/// ESP32-S3 identity secret key (from keys.json device "esp32s3").
pub const ESP32S3_NSEC: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_NSEC_HEX_esp32s3"));

pub const ESP32_NSEC: [u8; 32] = ESP32S3_NSEC;

#[cfg(feature = "wifi")]
pub const WIFI_SSID: &str = env!("WIFI_SSID");
#[cfg(feature = "wifi")]
pub const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
