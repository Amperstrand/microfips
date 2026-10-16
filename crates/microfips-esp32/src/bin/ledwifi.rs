#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();
microfips_esp_transport::panic_blink_print!();

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let sw_ints =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_ints.software_interrupt0);
    let rmt = esp_hal::rmt::Rmt::new(peripherals.RMT, esp_hal::time::Rate::from_mhz(80))
        .expect("RMT for the matrix pixel");
    let matrix_pin = esp_hal::gpio::Output::new(
        peripherals.GPIO27,
        esp_hal::gpio::Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    );
    microfips_esp32::run::run_led_wifi_node(
        spawner,
        rmt,
        peripherals.GPIO2,
        matrix_pin,
        peripherals.WIFI,
        peripherals.RNG,
        peripherals.ADC1,
    )
    .await;
}
