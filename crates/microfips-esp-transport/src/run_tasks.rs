#[cfg(any(feature = "ble", feature = "wifi"))]
use microfips_core::identity::VPS_NPUB;

#[cfg(feature = "ble")]
pub async fn run_ble_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    use crate::config::BLE_DEVICE_NAME;
    use crate::node_info::NodeIdentity;
    use crate::stats::STATS;
    use core::sync::atomic::Ordering;

    crate::logger::init();
    STATS.boot_tick_ms.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Relaxed,
    );

    let identity = NodeIdentity::compute();
    crate::control::init_control(&identity, "ble_gatt");
    crate::control::set_peer_pub(VPS_NPUB);

    log::info!("BLE mode starting");

    let mut led = crate::runner::make_led(gpio2);
    let (trng_source, trng) = crate::runner::init_trng(rng_periph, adc1);
    log::info!("trng ready");

    let transport = crate::ble_transport::BleTransport::new();
    spawner.spawn(crate::control::control_task().expect("spawn control task failed"));

    log::info!("BLE advertising as '{}'", BLE_DEVICE_NAME);

    crate::runner::run_node(
        transport,
        trng_source,
        trng,
        &mut led,
        VPS_NPUB,
        crate::runner::NodeOpts::default(),
    )
    .await
}

#[cfg(feature = "l2cap")]
pub async fn run_l2cap_node(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
    peer_sent_first: bool,
) -> ! {
    use crate::config::RECV_RETRY_DELAY_MS;
    use crate::node_info::NodeIdentity;
    use crate::stats::STATS;
    use core::sync::atomic::Ordering;

    crate::logger::init();
    STATS.boot_tick_ms.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Relaxed,
    );

    let identity = NodeIdentity::compute();
    crate::control::init_control(&identity, "ble_l2cap");

    log::info!("L2CAP mode starting");

    let mut led = crate::runner::make_led(gpio2);
    let (trng_source, trng) = crate::runner::init_trng(rng_periph, adc1);
    log::info!("trng ready");

    let mut transport = crate::l2cap_transport::L2capTransport::new();

    spawner.spawn(crate::control::control_task().expect("spawn control task failed"));

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

    crate::runner::run_node(
        transport,
        trng_source,
        trng,
        &mut led,
        peer_pub,
        crate::runner::NodeOpts {
            raw_framing: true,
            peer_sent_first,
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
    use crate::config;
    use crate::handler::{build_demo_fsp, SharedEspHandler};
    use crate::node_info::NodeIdentity;
    use crate::rng::EspRng;
    use crate::stats::STATS;
    use crate::wifi_transport::build_wifi_transport;
    use core::sync::atomic::Ordering;
    use microfips_core::identity::{STM32_NODE_ADDR, STM32_NPUB};
    use microfips_protocol::node::Node;
    use rand_core::RngCore;

    let mut led = crate::runner::make_led(gpio2);
    let (_trng_source, mut trng) = crate::runner::init_trng(rng_periph, adc1);

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
            log::error!(
                "WiFi: max retries exceeded, entering error state: {:?}",
                err
            );
            led.set_state(config::LED_OFF);
            loop {
                led.set_state(config::LED_ON);
                embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
                led.set_state(config::LED_OFF);
                embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
            }
        }
    };

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, config::DEVICE_NSEC, VPS_NPUB);
    node.set_raw_framing(true);

    let fsp = build_demo_fsp(
        &config::DEVICE_NSEC,
        resp_eph,
        init_eph,
        &STM32_NPUB,
        STM32_NODE_ADDR,
        1u64.to_le_bytes(),
    );
    let mut handler = SharedEspHandler { led: &mut led, fsp };

    crate::control::init_control(&identity, "wifi");
    crate::control::set_peer_pub(VPS_NPUB);
    if let Ok(token) = crate::control::control_task() {
        spawner.spawn(token);
    }

    log::info!("Node running over WiFi...");
    node.run(&mut handler).await;
    #[allow(unreachable_code)]
    #[allow(clippy::empty_loop)]
    loop {}
}
