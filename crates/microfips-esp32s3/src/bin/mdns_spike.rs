//! Milestone-1 spike: verify mDNS viability on ESP32-S3 (Walter board).
//!
//! Phase A: one-shot "legacy" PTR query for `_fips._udp.local.` sent from an
//! ephemeral port to 224.0.0.251:5353 — RFC 6762 responders answer these by
//! UNICAST, so this needs multicast TX only.
//!
//! Phase B: join the 224.0.0.251 group, bind port 5353, and count multicast
//! packets — proves (or disproves) that esp-radio's RX MAC filter passes the
//! mDNS group. Loops forever so host-side avahi-browse can generate traffic.
//!
//! Diagnostic tool only — not part of the FIPS node firmware.
#![no_std]
#![no_main]

extern crate alloc;

esp_bootloader_esp_idf::esp_app_desc!();
microfips_esp_transport::panic_blink_print!();

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Ipv4Address, Runner, StackResources};
use embassy_time::{with_timeout, Duration, Instant, Timer};
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config as WifiConfig, Interface};
use microfips_esp_transport::config;
use static_cell::StaticCell;

const MDNS_GROUP: Ipv4Address = Ipv4Address::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const EPHEMERAL_PORT: u16 = 5350;

// Standard query, QD=1: PTR _fips._udp.local. IN
const PTR_QUERY: &[u8] =
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_fips\x04_udp\x05local\x00\x00\x0c\x00\x01";

/// Find an ASCII `npub1...` run in a raw DNS packet (TXT payload scan).
fn scan_npub(data: &[u8]) -> Option<&str> {
    let is_bech32 = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let start = data.windows(5).position(|w| w == b"npub1")?;
    let mut end = start + 5;
    while end < data.len() && end - start < 63 && is_bech32(data[end]) {
        end += 1;
    }
    core::str::from_utf8(&data[start..end]).ok()
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface<'static>>) {
    runner.run().await;
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let sw_ints =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_ints.software_interrupt0);

    microfips_esp_transport::heap::init();
    microfips_esp_transport::logger::init();
    let (_trng_source, mut trng) =
        microfips_esp_transport::runner::init_trng(peripherals.RNG, peripherals.ADC1);
    log::info!("=== mDNS spike starting ===");

    static RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let (mut wifi_controller, interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, Default::default()).expect("wifi::new failed");
    let seed = {
        use rand_core::RngCore;
        let mut s = [0u8; 8];
        trng.fill_bytes(&mut s);
        u64::from_le_bytes(s)
    };
    let (stack, runner) = embassy_net::new(
        interfaces.station,
        Config::dhcpv4(Default::default()),
        RESOURCES.init(StackResources::new()),
        seed,
    );
    spawner.spawn(net_task(runner).expect("spawn net task"));

    let station_config = StationConfig::default()
        .with_ssid(config::WIFI_SSID)
        .with_password(alloc::string::String::from(config::WIFI_PASSWORD));
    wifi_controller
        .set_config(&WifiConfig::Station(station_config))
        .expect("set wifi station config");
    Timer::after(Duration::from_secs(2)).await;
    wifi_controller
        .connect_async()
        .await
        .expect("wifi connect failed");
    log::info!("WiFi connected, waiting for DHCP");
    let config_v4 = loop {
        if let Some(c) = stack.config_v4() {
            break c;
        }
        Timer::after(Duration::from_millis(500)).await;
    };
    log::info!("DHCP: {}", config_v4.address);

    static RX_META: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 1024]> = StaticCell::new();
    let mdns_dest = IpEndpoint::new(IpAddress::Ipv4(MDNS_GROUP), MDNS_PORT);

    // ---- Phase A: legacy one-shot query, unicast response expected ----
    {
        let mut socket = UdpSocket::new(
            stack,
            RX_META.init([PacketMetadata::EMPTY; 8]),
            RX_BUF.init([0u8; 2048]),
            TX_META.init([PacketMetadata::EMPTY; 8]),
            TX_BUF.init([0u8; 1024]),
        );
        socket.bind(EPHEMERAL_PORT).expect("bind ephemeral");

        for round in 1..=3u32 {
            match socket.send_to(PTR_QUERY, mdns_dest).await {
                Ok(()) => log::info!("A{}: PTR query sent (multicast TX ok)", round),
                Err(e) => {
                    log::error!("A{}: multicast TX FAILED: {:?}", round, e);
                    continue;
                }
            }
            let mut responses = 0u32;
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut buf = [0u8; 1024];
            while Instant::now() < deadline {
                match with_timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
                    Ok(Ok((n, meta))) => {
                        responses += 1;
                        log::info!(
                            "A{}: RESPONSE {}B from {} npub={}",
                            round,
                            n,
                            meta.endpoint,
                            scan_npub(&buf[..n]).unwrap_or("<none>")
                        );
                    }
                    Ok(Err(e)) => log::warn!("A{}: recv error {:?}", round, e),
                    Err(_) => {}
                }
            }
            log::info!("A{}: {} unicast responses", round, responses);
            Timer::after(Duration::from_secs(1)).await;
        }
    }

    // ---- Phase B: join group, listen on 5353 for multicast RX ----
    match stack.join_multicast_group(MDNS_GROUP) {
        Ok(()) => log::info!("B: joined 224.0.0.251 (IGMP ok)"),
        Err(e) => log::error!("B: join_multicast_group FAILED: {:?}", e),
    }
    static RX_META2: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static RX_BUF2: StaticCell<[u8; 2048]> = StaticCell::new();
    static TX_META2: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static TX_BUF2: StaticCell<[u8; 1024]> = StaticCell::new();
    let mut socket = UdpSocket::new(
        stack,
        RX_META2.init([PacketMetadata::EMPTY; 8]),
        RX_BUF2.init([0u8; 2048]),
        TX_META2.init([PacketMetadata::EMPTY; 8]),
        TX_BUF2.init([0u8; 1024]),
    );
    socket.bind(MDNS_PORT).expect("bind 5353");

    let mut round = 0u32;
    loop {
        round += 1;
        let _ = socket.send_to(PTR_QUERY, mdns_dest).await;
        let mut packets = 0u32;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut buf = [0u8; 1024];
        while Instant::now() < deadline {
            match with_timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
                Ok(Ok((n, meta))) => {
                    packets += 1;
                    log::info!(
                        "B{}: MULTICAST-RX {}B from {} npub={}",
                        round,
                        n,
                        meta.endpoint,
                        scan_npub(&buf[..n]).unwrap_or("<none>")
                    );
                }
                Ok(Err(e)) => log::warn!("B{}: recv error {:?}", round, e),
                Err(_) => {}
            }
        }
        log::info!("B{}: {} multicast packets in 15s window", round, packets);
    }
}
