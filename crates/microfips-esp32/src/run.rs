//! Shared async entry-point logic for ESP32-D0WD binary variants.
//!
//! Each binary (uart, ble, l2cap, wifi) calls the corresponding `run_*_node`
//! function after chip init and panic-handler setup. This keeps every bin file
//! to ~20 lines (panic handler + one call here).

use esp_hal::gpio::Level;
use esp_hal::rng::{Trng, TrngSource};
use rand_core::RngCore;

use microfips_core::identity::VPS_NPUB;
use microfips_protocol::node::Node;
use microfips_esp_transport::config::{UART_BAUDRATE, UART_FIFO_THRESHOLD};
use microfips_esp_transport::node_info::NodeIdentity;

use crate::config::ESP32_NSEC;
use crate::handler::{build_demo_fsp_default as build_demo_fsp, EspHandler};
use crate::led::Led;
use crate::rng::EspRng;
use crate::uart_transport::UartTransport;

/// Run the UART transport node.
///
/// GPIO1 = UART0 TX, GPIO3 = UART0 RX, GPIO2 = LED (all D0WD-specific).
pub async fn run_uart_node(
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    uart0: esp_hal::peripherals::UART0<'static>,
    gpio1: esp_hal::peripherals::GPIO1<'static>,
    gpio3: esp_hal::peripherals::GPIO3<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    let mut led = Led(esp_hal::gpio::Output::new(
        gpio2,
        Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    ));

    let _trng_source = TrngSource::new(rng_periph, adc1);
    let mut trng = Trng::try_new().unwrap();

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

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

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32_NSEC, VPS_NPUB);

    let fsp = build_demo_fsp(resp_eph, init_eph, 1u64.to_le_bytes());
    let mut handler = EspHandler { led: &mut led, fsp };

    node.run(&mut handler).await;
    #[allow(unreachable_code)]
    loop {}
}

/// Run the BLE GATT transport node.
#[cfg(feature = "ble")]
pub async fn run_ble_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use crate::ble_transport::BleTransport;
    use microfips_esp_transport::config::BLE_DEVICE_NAME;
    use microfips_esp_transport::stats::BOOT_TICK_MS;
    use core::sync::atomic::Ordering;

    crate::logger::init();
    BOOT_TICK_MS.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Relaxed,
    );

    let identity = NodeIdentity::compute();
    crate::control::init_control(&identity, "ble_gatt");
    crate::control::set_peer_pub(VPS_NPUB);

    log::info!("BLE mode starting");

    let mut led = Led(esp_hal::gpio::Output::new(
        gpio2,
        Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    ));

    let _trng_source = TrngSource::new(rng_periph, adc1);
    let mut trng = Trng::try_new().unwrap();
    log::info!("trng ready");

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let transport = BleTransport::new();
    spawner.spawn(crate::control::control_task()).unwrap();

    log::info!("BLE advertising as '{}'", BLE_DEVICE_NAME);

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32_NSEC, VPS_NPUB);

    let fsp = build_demo_fsp(resp_eph, init_eph, 1u64.to_le_bytes());
    let mut handler = EspHandler { led: &mut led, fsp };

    log::info!("Node running...");
    node.run(&mut handler).await;
    #[allow(unreachable_code)]
    loop {}
}

/// Run the BLE L2CAP transport node.
#[cfg(feature = "l2cap")]
pub async fn run_l2cap_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use crate::l2cap_transport::L2capTransport;
    use microfips_esp_transport::config::RECV_RETRY_DELAY_MS;
    use microfips_esp_transport::stats::BOOT_TICK_MS;
    use core::sync::atomic::Ordering;

    crate::logger::init();
    BOOT_TICK_MS.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Relaxed,
    );

    let identity = NodeIdentity::compute();
    crate::control::init_control(&identity, "ble_l2cap");

    log::info!("L2CAP mode starting");

    let mut led = Led(esp_hal::gpio::Output::new(
        gpio2,
        Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    ));

    let _trng_source = TrngSource::new(rng_periph, adc1);
    let mut trng = Trng::try_new().unwrap();
    log::info!("trng ready");

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let rng = EspRng(trng);
    let mut transport = L2capTransport::new();

    spawner.spawn(crate::control::control_task()).unwrap();

    let peer_pub = match transport.wait_for_peer_pub().await {
        Ok(pk) => pk,
        Err(_) => {
            log::error!("ERROR: L2CAP transport init failed");
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

    let mut node = Node::new(transport, rng, ESP32_NSEC, peer_pub);
    node.set_raw_framing(true);
    // FIPS connects as BLE central and sends MSG1 first. As peripheral,
    // we skip our own MSG1 and enter responder path to avoid cross-connection.
    node.set_peer_sent_first(true);

    let fsp = build_demo_fsp(resp_eph, init_eph, 1u64.to_le_bytes());
    let mut handler = EspHandler { led: &mut led, fsp };

    log::info!("Node starting (L2CAP)...");
    node.run(&mut handler).await;
    #[allow(unreachable_code)]
    loop {}
}

/// Run the WiFi transport node.
#[cfg(feature = "wifi")]
pub async fn run_wifi_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    wifi: esp_hal::peripherals::WIFI<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use crate::config::{WIFI_PASSWORD, WIFI_SSID};
    use microfips_esp_transport::wifi_transport::build_wifi_transport;

    let mut led = Led(esp_hal::gpio::Output::new(
        gpio2,
        Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    ));

    let _trng_source = TrngSource::new(rng_periph, adc1);
    let mut trng = Trng::try_new().unwrap();

    let identity = NodeIdentity::compute();
    crate::logger::init();
    log::info!("WiFi mode starting");

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let transport = build_wifi_transport(spawner, wifi, &mut trng, WIFI_SSID, WIFI_PASSWORD).await;

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32_NSEC, VPS_NPUB);
    node.set_raw_framing(true);

    let fsp = build_demo_fsp(resp_eph, init_eph, 1u64.to_le_bytes());
    let mut handler = EspHandler { led: &mut led, fsp };

    crate::control::init_control(&identity, "wifi");
    spawner.spawn(crate::control::control_task()).ok();

    log::info!("Node running over WiFi...");
    node.run(&mut handler).await;
    #[allow(unreachable_code)]
    loop {}
}
