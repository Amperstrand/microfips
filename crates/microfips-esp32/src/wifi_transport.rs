#![cfg(feature = "wifi")]

use esp_hal::peripherals::WIFI;
use esp_hal::rng::Trng;

use crate::config::{WIFI_PASSWORD, WIFI_SSID};

pub use microfips_esp_transport::wifi_transport::WifiTransport;

pub async fn build_wifi_transport(
    spawner: embassy_executor::Spawner,
    wifi: WIFI<'static>,
    trng: &mut Trng,
) -> WifiTransport {
    microfips_esp_transport::wifi_transport::build_wifi_transport(
        spawner,
        wifi,
        trng,
        WIFI_SSID,
        WIFI_PASSWORD,
    )
    .await
}
