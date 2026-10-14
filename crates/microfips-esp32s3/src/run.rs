use microfips_core::identity::VPS_NPUB;
use microfips_esp_transport::config::{UART_BAUDRATE, UART_FIFO_THRESHOLD};
use microfips_esp_transport::runner::{self, NodeOpts};
use microfips_esp_transport::uart_transport::UartTransport;

pub async fn run_uart_node(
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    uart0: esp_hal::peripherals::UART0<'static>,
    gpio43: esp_hal::peripherals::GPIO43<'static>,
    gpio44: esp_hal::peripherals::GPIO44<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    // Install the global log backend before anything can log. This is the only entry
    // point of this image (`src/bin/uart.rs`), it is called once from `main`, and no
    // other entry point is reachable from here, so the backend is installed exactly
    // once — never twice. That invariant is a property of the bins, not something the
    // compiler checks: a second install would panic inside `logger::init` (its
    // `set_logger` result is `unwrap`ped), and that is the intended behaviour — not a
    // silent double-install.
    //
    // Frames leave on UART0 (GPIO43/GPIO44) while the S3 esp-println backend prints on
    // the USB-Serial-JTAG FIFO (`esp-println/jtag-serial`, selected by the transport's
    // `esp32s3` feature), so logs cannot corrupt the link. See `run_usb_node` for the
    // mirror-image case.
    microfips_esp_transport::logger::init();
    microfips_esp_transport::heap::init();
    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);

    let uart_config = esp_hal::uart::Config::default()
        .with_rx(esp_hal::uart::RxConfig::default().with_fifo_full_threshold(UART_FIFO_THRESHOLD))
        .with_baudrate(UART_BAUDRATE);
    let uart = esp_hal::uart::Uart::new(uart0, uart_config)
        .unwrap()
        .with_tx(gpio43)
        .with_rx(gpio44)
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
    // USB-Serial-JTAG peripheral, i.e. the same FIFO esp-println prints on for the S3,
    // so a backend would inject log text into the FIPS frame stream
    // (docs/console-channels.md). The silence is guarded, not just commented:
    // `scripts/check-console-policy.sh` fails the CI job on a `logger::init()` call in
    // this body (section A), in any file it declares silent — `src/bin/usb.rs` for this
    // image (section B) — or anywhere that guard's repo-wide call-site census does not
    // expect one (section C).

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

#[cfg(feature = "ble")]
pub use microfips_esp_transport::run_tasks::run_ble_node;

#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::run_tasks::run_l2cap_node;

#[cfg(feature = "wifi")]
pub use microfips_esp_transport::run_tasks::run_wifi_node;

#[cfg(feature = "esp-now")]
pub use microfips_esp_transport::espnow_gateway::run_espnow_gateway;
#[cfg(all(feature = "esp-now", feature = "wifi"))]
pub use microfips_esp_transport::espnow_wifi_gateway::run_espnow_wifi_gateway;
#[cfg(feature = "esp-now")]
pub use microfips_esp_transport::run_tasks::run_esp_now_node;
#[cfg(all(feature = "esp-now", feature = "wifi"))]
pub use microfips_esp_transport::run_tasks::run_hybrid_node;

#[cfg(feature = "relay-ap")]
pub use microfips_esp_transport::relay_ap::{run_relay_ap, run_relay_ap_peer};
