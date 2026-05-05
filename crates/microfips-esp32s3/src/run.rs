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

#[cfg(feature = "ble")]
pub async fn run_ble_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use core::sync::atomic::Ordering;
    use microfips_esp_transport::config::BLE_DEVICE_NAME;
    use microfips_esp_transport::node_info::NodeIdentity;
    use microfips_esp_transport::stats::STATS;

    crate::logger::init();
    STATS.boot_tick_ms.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Relaxed,
    );

    let identity = NodeIdentity::compute();
    crate::control::init_control(&identity, "ble_gatt");
    crate::control::set_peer_pub(VPS_NPUB);

    log::info!("BLE mode starting");

    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);
    log::info!("trng ready");

    let transport = crate::ble_transport::BleTransport::new();
    spawner.spawn(crate::control::control_task()).unwrap();

    log::info!("BLE advertising as '{}'", BLE_DEVICE_NAME);

    runner::run_node(transport, trng_source, trng, &mut led, VPS_NPUB, NodeOpts::default()).await
}

#[cfg(feature = "l2cap")]
pub async fn run_l2cap_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use core::sync::atomic::Ordering;
    use microfips_esp_transport::config::RECV_RETRY_DELAY_MS;
    use microfips_esp_transport::node_info::NodeIdentity;
    use microfips_esp_transport::stats::STATS;

    crate::logger::init();
    STATS.boot_tick_ms.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Relaxed,
    );

    let identity = NodeIdentity::compute();
    crate::control::init_control(&identity, "ble_l2cap");

    log::info!("L2CAP mode starting");

    let mut led = runner::make_led(gpio2);
    let (trng_source, trng) = runner::init_trng(rng_periph, adc1);
    log::info!("trng ready");

    let mut transport = crate::l2cap_transport::L2capTransport::new();

    spawner.spawn(crate::control::control_task()).unwrap();

    let peer_pub = match transport.wait_for_peer_pub().await {
        Ok(pk) => pk,
        Err(_) => {
            log::error!("ERROR: no peer pubkey from exchange");
            loop {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RECV_RETRY_DELAY_MS,
                ))
                .await;
            }
        }
    };
    log::info!("L2CAP transport ready");
    crate::control::set_peer_pub(peer_pub);
    log::info!("pubkey exchange complete; starting node");

    runner::run_node(
        transport,
        trng_source,
        trng,
        &mut led,
        peer_pub,
        NodeOpts {
            raw_framing: true,
            peer_sent_first: true,
        },
    )
    .await
}

#[cfg(feature = "wifi")]
pub async fn run_wifi_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    wifi: esp_hal::peripherals::WIFI<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use core::sync::atomic::Ordering;
    use microfips_esp_transport::node_info::NodeIdentity;
    use microfips_esp_transport::rng::EspRng;
    use microfips_esp_transport::stats::STATS;
    use microfips_esp_transport::config;
    use microfips_esp_transport::wifi_transport::build_wifi_transport;
    use rand_core::RngCore;

    let mut led = runner::make_led(gpio2);
    let (_trng_source, mut trng) = runner::init_trng(rng_periph, adc1);

    let identity = NodeIdentity::compute();
    crate::logger::init();
    STATS.boot_tick_ms.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Relaxed,
    );
    log::info!("WiFi mode starting");

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let transport = match build_wifi_transport(
        spawner,
        wifi,
        &mut trng,
        config::WIFI_SSID,
        config::WIFI_PASSWORD,
    )
    .await
    {
        Ok(transport) => transport,
        Err(err) => {
            log::error!("WiFi: max retries exceeded, entering error state: {:?}", err);
            led.set_state(microfips_esp_transport::config::LED_OFF);
            loop {
                led.set_state(microfips_esp_transport::config::LED_ON);
                embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
                led.set_state(microfips_esp_transport::config::LED_OFF);
                embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
            }
        }
    };

    use microfips_core::identity::{STM32_NODE_ADDR, STM32_NPUB};
    use microfips_esp_transport::handler::{build_demo_fsp, SharedEspHandler};
    use microfips_protocol::node::Node;

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, crate::config::ESP32S3_NSEC, VPS_NPUB);
    node.set_raw_framing(true);

    let fsp = build_demo_fsp(
        &crate::config::ESP32S3_NSEC,
        resp_eph,
        init_eph,
        &STM32_NPUB,
        STM32_NODE_ADDR,
        1u64.to_le_bytes(),
    );
    let mut handler = SharedEspHandler { led: &mut led, fsp };

    crate::control::init_control(&identity, "wifi");
    crate::control::set_peer_pub(VPS_NPUB);
    spawner.spawn(crate::control::control_task()).ok();

    log::info!("Node running over WiFi...");
    node.run(&mut handler).await;
    #[allow(unreachable_code)]
    #[allow(clippy::empty_loop)]
    loop {}
}
