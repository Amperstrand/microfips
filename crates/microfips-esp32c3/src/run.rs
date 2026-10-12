use microfips_core::identity::VPS_NPUB;
use microfips_esp_transport::config::{UART_BAUDRATE, UART_FIFO_THRESHOLD};
use microfips_esp_transport::runner::{self, NodeOpts};
use microfips_esp_transport::uart_transport::UartTransport;

pub async fn run_uart_node(
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    uart0: esp_hal::peripherals::UART0<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    // Install the global log backend before anything can log. `run_uart_node` is the
    // only entry point of this image (`src/bin/uart.rs`), it is called once from
    // `main`, and no other entry point is reachable from here, so the backend is
    // installed exactly once — never twice.
    //
    // Note the C3 default binaries differ in where their frames go: this one sends
    // FIPS frames on UART0 while the esp-println backend prints on the
    // USB-Serial-JTAG FIFO, so logs cannot corrupt the link. See `run_usb_node` for
    // the mirror-image case.
    microfips_esp_transport::logger::init();
    microfips_esp_transport::heap::init();
    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);

    let uart_config = esp_hal::uart::Config::default()
        .with_rx(esp_hal::uart::RxConfig::default().with_fifo_full_threshold(UART_FIFO_THRESHOLD))
        .with_baudrate(UART_BAUDRATE);
    let uart = esp_hal::uart::Uart::new(uart0, uart_config)
        .unwrap()
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

pub async fn run_usb_node(
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    usb_device: esp_hal::peripherals::USB_DEVICE<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use esp_hal::usb_serial_jtag::UsbSerialJtag;
    use microfips_esp_transport::usb_transport::UsbTransport;

    // Deliberately NO `logger::init()` here: this binary's transport *is* the
    // esp-println channel, so logs would corrupt the FIPS frame stream — see
    // AGENTS.md "Console (ESP32-C3)" (panics too: this bin uses `panic_blink!`).

    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);

    let usb = UsbSerialJtag::new(usb_device).into_async();
    let (rx, tx) = usb.split();
    let transport = UsbTransport { tx, rx };

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

#[cfg(feature = "wifi")]
pub use microfips_esp_transport::run_tasks::run_wifi_node;

#[cfg(feature = "esp-now")]
pub use microfips_esp_transport::run_tasks::run_esp_now_node;
