use microfips_core::identity::VPS_NPUB;
use microfips_esp_transport::config::{UART_BAUDRATE, UART_FIFO_THRESHOLD};
use microfips_esp_transport::runner::{self, NodeOpts};
use microfips_esp_transport::uart_transport::UartTransport;

pub async fn run_uart_node(
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    uart0: esp_hal::peripherals::UART0<'static>,
    gpio1: esp_hal::peripherals::GPIO1<'static>,
    gpio3: esp_hal::peripherals::GPIO3<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    // Deliberately NO `logger::init()` here. This chip has no USB-Serial-JTAG
    // peripheral, so the transport's `esp32` feature resolves esp-println to its UART
    // printer (`esp-println/auto` -> `uart_printer`), which writes every byte through
    // the ROM routine `uart_tx_one_char` (0x4000_9200) — i.e. UART0, the same
    // peripheral this binary's frames leave on (GPIO1/GPIO3). A backend here would
    // interleave log text into the FIPS frame stream, so the ESP32 `uart` image is a
    // console-free image by design (docs/console-channels.md). The `wifi`/`esp-now`
    // images log as usual: their transport is UDP over Wi-Fi, not this UART. The
    // silence is guarded: `scripts/check-console-policy.sh` declares this entry point
    // `silent` and fails CI if a `logger::init()` call appears here.
    microfips_esp_transport::heap::init();
    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);

    let uart_config = esp_hal::uart::Config::default()
        .with_rx(esp_hal::uart::RxConfig::default().with_fifo_full_threshold(UART_FIFO_THRESHOLD))
        .with_baudrate(UART_BAUDRATE);
    let uart = esp_hal::uart::Uart::new(uart0, uart_config)
        .unwrap()
        .with_tx(gpio1)
        .with_rx(gpio3)
        .into_async();
    let (rx, tx) = uart.split();
    let transport = UartTransport { tx, rx };

    runner::run_node(
        transport,
        trng_source,
        trng,
        &mut led,
        VPS_NPUB,
        NodeOpts::default(),
    )
    .await
}

#[cfg(feature = "ble")]
pub use microfips_esp_transport::run_tasks::run_ble_node;

#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::run_tasks::run_l2cap_node;

#[cfg(feature = "wifi")]
pub use microfips_esp_transport::run_tasks::run_wifi_node;
