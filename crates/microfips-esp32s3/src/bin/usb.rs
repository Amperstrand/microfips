#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();
microfips_esp_transport::panic_blink!();

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let sw_ints =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_ints.software_interrupt0);
    microfips_esp32s3::run::run_usb_node(
        peripherals.GPIO2,
        peripherals.USB_DEVICE,
        peripherals.RNG,
        peripherals.ADC1,
    )
    .await;
}
