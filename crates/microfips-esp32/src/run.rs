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

    runner::run_node(transport, trng_source, trng, &mut led, VPS_NPUB, NodeOpts::default()).await
}

#[cfg(feature = "ble")]
pub use microfips_esp_transport::run_tasks::run_ble_node;

#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::run_tasks::run_l2cap_node;

#[cfg(feature = "wifi")]
pub use microfips_esp_transport::run_tasks::run_wifi_node;
