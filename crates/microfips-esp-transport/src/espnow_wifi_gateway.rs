//! Standalone ESP-NOW ↔ WiFi/UDP gateway (not a FIPS node).
//!
//! Joins the configured AP as a station, discovers the pinned FIPS daemon
//! via mDNS (DNS fallback), and relays FMP frames between ESP-NOW leaf
//! nodes and the daemon's UDP port — no host machine, no serial bridge.
//!
//! While associated, the radio is pinned to the AP's channel and ESP-NOW
//! rides on it; leaf nodes find the channel via their discovery sweep.
//! Single-peer like the USB gateway: unicasts to whichever node's frame
//! it saw last, broadcasts until it has seen one. Logging is enabled —
//! the USB console carries no frames here.

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Runner, Stack, StackResources};
use embassy_time::{with_timeout, Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_radio::esp_now::{
    EspNowManager, EspNowReceiver, EspNowSender, EspNowWifiInterface, PeerInfo, BROADCAST_ADDRESS,
};
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config as WifiConfig, Interface, WifiController};
use microfips_esp_common::config::{VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS};
use microfips_esp_common::dns::resolve_vps_ipv4;
use microfips_esp_common::espnow_frag::{
    pack_mac, unpack_mac, Fragmenter, SrcReassembler, ESP_NOW_MAX_PAYLOAD, MAX_MESSAGE,
};
use microfips_esp_common::mdns::{discover_fips, DiscoveryFilter};
use portable_atomic::{AtomicU64, Ordering};
use static_cell::StaticCell;

/// Last-seen node MAC, shared between the two relay directions.
static PEER_MAC: AtomicU64 = AtomicU64::new(0);

#[embassy_executor::task]
async fn gw_net_task(mut runner: Runner<'static, Interface<'static>>) {
    runner.run().await;
}

/// Daemon → radio: fragment each UDP datagram and send it to the node.
#[embassy_executor::task]
async fn udp_to_espnow_task(
    socket: &'static UdpSocket<'static>,
    mut sender: EspNowSender<'static>,
    daemon: IpEndpoint,
) {
    let mut fragmenter = Fragmenter::new();
    let mut buf = [0u8; MAX_MESSAGE];
    loop {
        let (n, meta) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => {
                Timer::after(Duration::from_millis(10)).await;
                continue;
            }
        };
        if meta.endpoint != daemon {
            continue;
        }
        let dst = unpack_mac(PEER_MAC.load(Ordering::Relaxed)).unwrap_or(BROADCAST_ADDRESS);
        let Some(fragments) = fragmenter.fragments(&buf[..n]) else {
            continue;
        };
        for (header, chunk) in fragments {
            let mut payload = [0u8; ESP_NOW_MAX_PAYLOAD];
            payload[..header.len()].copy_from_slice(&header);
            payload[header.len()..header.len() + chunk.len()].copy_from_slice(chunk);
            // best-effort: a lost frame is datagram loss, upper layers retry
            let _ = sender
                .send_async(&dst, &payload[..header.len() + chunk.len()])
                .await;
        }
    }
}

/// Re-associates and waits for DHCP whenever the AP drops the station;
/// esp-radio does not auto-reconnect.
#[embassy_executor::task]
async fn wifi_supervisor_task(mut controller: WifiController<'static>, stack: Stack<'static>) {
    loop {
        Timer::after(Duration::from_secs(5)).await;
        if controller.is_connected() {
            continue;
        }
        log::info!("gateway: WiFi association lost, reconnecting");
        match with_timeout(Duration::from_secs(30), controller.connect_async()).await {
            Ok(Ok(_)) => {
                let dhcp = with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
                    loop {
                        if let Some(c) = stack.config_v4() {
                            break c;
                        }
                        Timer::after(Duration::from_millis(500)).await;
                    }
                })
                .await;
                match dhcp {
                    Ok(config_v4) => {
                        log::info!("gateway: WiFi reconnected, IP: {}", config_v4.address)
                    }
                    Err(_) => log::error!("gateway: WiFi reconnected but DHCP timed out"),
                }
            }
            _ => log::error!("gateway: WiFi reconnect failed, retrying"),
        }
    }
}

pub async fn run_espnow_wifi_gateway(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    wifi: WIFI<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    crate::heap::init();
    crate::logger::init();
    let mut led = crate::runner::make_led(gpio2);
    // TrngSource must outlive the WiFi driver; this function never returns.
    let (_trng_source, mut trng) = crate::runner::init_trng(rng_periph, adc1);

    log::info!("ESP-NOW WiFi gateway starting");

    static GW_RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    static GW_RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static GW_RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static GW_TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static GW_TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static GW_SOCKET: StaticCell<UdpSocket<'static>> = StaticCell::new();

    let (mut wifi_controller, interfaces) =
        esp_radio::wifi::new(wifi, Default::default()).expect("wifi::new failed");
    let esp_now = interfaces.esp_now;

    let resources = GW_RESOURCES.init(StackResources::new());
    let seed = trng.random() as u64 | ((trng.random() as u64) << 32);
    let (stack, runner) = embassy_net::new(
        interfaces.station,
        Config::dhcpv4(Default::default()),
        resources,
        seed,
    );
    spawner.spawn(gw_net_task(runner).expect("spawn net task failed"));

    let station_config = StationConfig::default()
        .with_ssid(crate::config::WIFI_SSID)
        .with_password(alloc::string::String::from(crate::config::WIFI_PASSWORD));
    wifi_controller
        .set_config(&WifiConfig::Station(station_config))
        .expect("set wifi station config");

    Timer::after(Duration::from_secs(2)).await;

    // Associate + DHCP; retry forever with capped backoff — an unattended
    // gateway must outlive AP reboots.
    let mut backoff_secs = 5u64;
    let _config_v4 = loop {
        match with_timeout(Duration::from_secs(30), wifi_controller.connect_async()).await {
            Ok(Ok(_)) => {
                let dhcp = with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
                    loop {
                        if let Some(c) = stack.config_v4() {
                            break c;
                        }
                        Timer::after(Duration::from_millis(500)).await;
                    }
                })
                .await;
                if let Ok(config_v4) = dhcp {
                    log::info!("gateway: WiFi connected, IP: {}", config_v4.address);
                    break config_v4;
                }
                log::error!("gateway: DHCP timed out");
                let _ = wifi_controller.disconnect_async().await;
            }
            _ => {
                log::error!("gateway: WiFi connect failed");
                let _ = wifi_controller.disconnect_async().await;
            }
        }
        Timer::after(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    };

    // Locate the daemon: mDNS pinned to the compiled-in peer key, DNS
    // fallback. The npub only routes here — the leaf node runs Noise IK
    // end-to-end through this relay, so a wrong endpoint cannot fake it.
    let pinned: [u8; 32] = microfips_core::identity::VPS_NPUB[1..33]
        .try_into()
        .unwrap();
    let daemon = match discover_fips(stack, DiscoveryFilter::Pinned(&pinned)).await {
        Some((ip, port, _)) => {
            log::info!("gateway: mDNS pinned FIPS daemon at {}:{}", ip, port);
            IpEndpoint::new(IpAddress::Ipv4(ip), port)
        }
        None => {
            log::info!("gateway: no mDNS advert, resolving {}", VPS_HOST);
            let dns_server = stack.config_v4().map(|c| c.dns_servers[0]);
            let ip = loop {
                if let Some(dns) = dns_server {
                    if let Ok(ip) = resolve_vps_ipv4(stack, dns, VPS_HOST).await {
                        break ip;
                    }
                }
                log::error!(
                    "gateway: DNS resolve failed for {}, retrying in 10s",
                    VPS_HOST
                );
                Timer::after(Duration::from_secs(10)).await;
            };
            IpEndpoint::new(IpAddress::Ipv4(ip), VPS_PORT)
        }
    };

    let mut socket = UdpSocket::new(
        stack,
        GW_RX_META.init([PacketMetadata::EMPTY; 4]),
        GW_RX_BUF.init([0u8; 2048]),
        GW_TX_META.init([PacketMetadata::EMPTY; 4]),
        GW_TX_BUF.init([0u8; 2048]),
    );
    socket.bind(0).expect("udp bind");
    let socket: &'static UdpSocket<'static> = GW_SOCKET.init(socket);

    // Do NOT set an ESP-NOW channel: the station association pins the
    // radio to the AP's channel and ESP-NOW rides on it.
    let (manager, sender, receiver) = esp_now.split();

    spawner.spawn(udp_to_espnow_task(socket, sender, daemon).expect("spawn udp task failed"));
    spawner
        .spawn(wifi_supervisor_task(wifi_controller, stack).expect("spawn supervisor task failed"));

    led.set_state(crate::config::LED_ON);
    log::info!("gateway: relaying ESP-NOW <-> {}", daemon);

    // Radio → daemon: reassemble fragments, forward, learn the node's MAC.
    espnow_to_udp(receiver, socket, manager, daemon).await
}

async fn espnow_to_udp(
    mut receiver: EspNowReceiver<'static>,
    socket: &'static UdpSocket<'static>,
    manager: EspNowManager<'static>,
    daemon: IpEndpoint,
) -> ! {
    let mut reassembler = SrcReassembler::new();
    loop {
        let received = receiver.receive_async().await;
        let src = received.info.src_address;
        let Some(frame) = reassembler.push(src, received.data()) else {
            continue;
        };
        if unpack_mac(PEER_MAC.load(Ordering::Relaxed)) != Some(src) {
            if !manager.peer_exists(&src) {
                let _ = manager.add_peer(PeerInfo {
                    interface: EspNowWifiInterface::Station,
                    peer_address: src,
                    lmk: None,
                    channel: None,
                    encrypt: false,
                });
            }
            PEER_MAC.store(pack_mac(src), Ordering::Relaxed);
            log::info!(
                "gateway: node locked {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                src[0],
                src[1],
                src[2],
                src[3],
                src[4],
                src[5]
            );
        }
        let _ = socket.send_to(frame, daemon).await;
    }
}
