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

    runner::run_node(transport, trng_source, trng, &mut led, VPS_NPUB, NodeOpts::default()).await
}

pub async fn run_usb_node(
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    usb_device: esp_hal::peripherals::USB_DEVICE<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use esp_hal::usb_serial_jtag::UsbSerialJtag;
    use microfips_esp_transport::usb_transport::UsbTransport;

    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);

    let usb = UsbSerialJtag::new(usb_device).into_async();
    let (rx, tx) = usb.split();
    let transport = UsbTransport { tx, rx };

    runner::run_node(transport, trng_source, trng, &mut led, VPS_NPUB, NodeOpts::default()).await
}

#[cfg(feature = "wifi")]
pub use microfips_esp_transport::run_tasks::run_wifi_node;

#[cfg(feature = "espnow")]
pub async fn run_espnow_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use microfips_esp_transport::esp_now_transport::{self, EspNowTransport, MacAddress};
    use microfips_esp_transport::logger;
    use microfips_esp_transport::runner;
    use microfips_esp_transport::control::{self, init_control};

    #[cfg(feature = "log")]
    logger::init(log::LevelFilter::Info);

    microfips_esp_transport::heap::init();
    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);

    // Initialize ESP-NOW
    let (mut transport, local_mac) = EspNowTransport::init()
        .expect("ESP-NOW init failed");

    #[cfg(feature = "log")]
    log::info!("ESP-NOW initialized. MAC: {}", local_mac);

    // Print MAC via GPIO blink pattern (3 fast blinks = ready)
    for _ in 0..3 {
        led.toggle();
        embassy_time::Timer::after_millis(100).await;
        led.toggle();
        embassy_time::Timer::after_millis(100).await;
    }

    // Add self as broadcast peer (send/receive broadcast messages)
    transport.add_peer(MacAddress::BROADCAST)
        .expect("Failed to add broadcast peer");

    #[cfg(feature = "log")]
    log::info!("ESP-NOW mesh node ready on channel {}", esp_now_transport::ESPNOW_CHANNEL);

    // Initialize control interface
    use microfips_esp_transport::node_info::NodeIdentity;
    let identity = NodeIdentity::compute();
    init_control(&identity, "esp-now");

    // Start control task for UART CLI
    spawner.spawn(control::control_task().unwrap());

    // Run as a FIPS node using the existing runner
    runner::run_node(transport, trng_source, trng, &mut led, VPS_NPUB, NodeOpts::default()).await
}