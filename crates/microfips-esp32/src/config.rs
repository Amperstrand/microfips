/// ESP32 identity secret key (from keys.json device "esp32").
/// npub: npub1ccz8l9zpa47k6vz9gphftsrumpw80rjt3nhnefat4symjhrsnmjs38mnyd
/// node_addr: 0135da2f8acf7b9e3090939432e47684
pub const ESP32_NSEC: [u8; 32] = microfips_core::hex::hex_bytes_32(env!("DEVICE_NSEC_HEX_esp32"));

#[cfg(feature = "wifi")]
pub const WIFI_SSID: &str = env!("WIFI_SSID");
#[cfg(feature = "wifi")]
pub const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
