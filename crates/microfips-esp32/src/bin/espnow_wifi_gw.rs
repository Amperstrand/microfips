#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();
microfips_esp_transport::panic_blink_print!();

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    microfips_esp_transport::espnow_wifi_gateway::run_espnow_wifi_gateway(
        spawner,
        peripherals.GPIO2,
        peripherals.WIFI,
        peripherals.RNG,
        peripherals.ADC1,
    )
    .await;
}
