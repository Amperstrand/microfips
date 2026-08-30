//! FIPS relay access point (not a FIPS node).
//!
//! Runs the radio in AP+STA mode: an open access point (default SSID
//! `!FIPS`) for clients, and a station uplink toward the network where the
//! FIPS daemon lives. On the AP side it serves DHCP, advertises the
//! daemon's identity via mDNS (`_fips._udp.local.`) with its own address as
//! endpoint, and relays each client's UDP flow to the daemon found on the
//! uplink. Noise IK runs end-to-end between client and daemon — the relay
//! cannot read or forge anything, so the open AP exposes no more than the
//! daemon's LAN already does.
//!
//! Roles are just uplink configuration:
//! - Router: uplink = the LAN with the daemon (`RELAY_UPLINK_SSID`, default
//!   `WIFI_SSID`); daemon found by pinned mDNS (DNS fallback).
//! - Extender: uplink = another relay's `!FIPS` (`RELAY_UPLINK_SSID=!FIPS`,
//!   empty password); it discovers the upstream relay's advert and
//!   re-advertises it, so relays chain. The station never picks its own AP
//!   as uplink (BSSID selection excludes our AP MAC).
//!
//! Clients get FIPS connectivity only — no IP forwarding or NAT.
//!
//! Peer mode (`run_relay_ap_peer`): additionally runs a full FIPS `Node`
//! with the compiled-in device identity over the same uplink, toward
//! whatever `uplink_task` published as upstream (the daemon directly on a
//! Router, the upstream relay on an Extender — Noise IK is pinned to the
//! daemon npub either way). The relay path stays FIPS-blind; the node is
//! just one more UDP flow on the station interface. In peer mode the LED
//! shows the node's session state rather than the uplink state.

use core::cell::RefCell;

use embassy_futures::select::{select, Either};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{
    Config, IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr, Runner, Stack, StackResources,
    StaticConfigV4,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::{with_timeout, Duration, Instant, Timer};
use esp_hal::peripherals::WIFI;
use esp_radio::wifi::ap::AccessPointConfig;
use esp_radio::wifi::scan::ScanConfig;
use esp_radio::wifi::{AuthenticationMethod, Config as WifiConfig, Interface, WifiController};
use microfips_esp_common::config::{VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS};
use microfips_esp_common::dhcp_server::{DhcpServer, DhcpServerConfig, MAX_REPLY_LEN};
use microfips_esp_common::dns::resolve_vps_ipv4;
use microfips_esp_common::mdns::{
    discover_fips_advert, DiscoveryFilter, MAX_SCOPE_LEN, MDNS_GROUP, MDNS_PORT,
};
use microfips_esp_common::mdns_responder::{
    build_fips_response, parse_fips_query, MAX_RESPONSE_LEN,
};
use microfips_esp_common::udp_transport::UdpTransportError;
use microfips_protocol::node::MAX_FRAME_SIZE;
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;

/// AP-side addressing.
const AP_IP: [u8; 4] = [192, 168, 4, 1];
const AP_PREFIX: u8 = 24;
const DHCP_POOL_START: [u8; 4] = [192, 168, 4, 10];
const DHCP_POOL_SIZE: usize = 8;
const DHCP_LEASE_SECS: u32 = 3600;
/// UDP port the relay listens on for clients (same as a daemon).
const RELAY_PORT: u16 = 2121;
/// Concurrent client flows relayed.
const RELAY_SLOTS: usize = 4;
/// A client flow idle this long can be evicted for a new client.
const SLOT_IDLE_SECS: u64 = 120;
/// Unsolicited mDNS announce interval.
const ANNOUNCE_SECS: u64 = 60;
/// Re-run upstream discovery this often (follows daemon/relay moves).
const REDISCOVER_SECS: u64 = 600;

/// What we advertise on the AP side once the uplink found the daemon.
#[derive(Clone, Copy)]
struct Upstream {
    endpoint: IpEndpoint,
    npub: [u8; 63],
    scope: [u8; MAX_SCOPE_LEN],
    scope_len: u8,
}

impl Upstream {
    fn scope(&self) -> Option<&str> {
        if self.scope_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.scope[..self.scope_len as usize]).ok()
        }
    }
}

static UPSTREAM: Mutex<CriticalSectionRawMutex, RefCell<Option<Upstream>>> =
    Mutex::new(RefCell::new(None));

fn upstream() -> Option<Upstream> {
    UPSTREAM.lock(|u| *u.borrow())
}

#[derive(Clone, Copy)]
struct Slot {
    client: Option<IpEndpoint>,
    last_active: Instant,
}

static SLOTS: Mutex<CriticalSectionRawMutex, RefCell<[Slot; RELAY_SLOTS]>> =
    Mutex::new(RefCell::new(
        [Slot {
            client: None,
            last_active: Instant::from_ticks(0),
        }; RELAY_SLOTS],
    ));

/// Find the slot serving `client`, or claim a free / idle one.
fn slot_for(client: IpEndpoint, now: Instant) -> Option<usize> {
    SLOTS.lock(|s| {
        let mut slots = s.borrow_mut();
        if let Some(i) = slots.iter().position(|x| x.client == Some(client)) {
            slots[i].last_active = now;
            return Some(i);
        }
        let idle = |x: &Slot| {
            x.client.is_none()
                || now.saturating_duration_since(x.last_active).as_secs() >= SLOT_IDLE_SECS
        };
        let i = slots.iter().position(idle)?;
        slots[i] = Slot {
            client: Some(client),
            last_active: now,
        };
        Some(i)
    })
}

fn slot_client(i: usize) -> Option<IpEndpoint> {
    SLOTS.lock(|s| s.borrow()[i].client)
}

fn touch_slot(i: usize, now: Instant) {
    SLOTS.lock(|s| s.borrow_mut()[i].last_active = now);
}

/// Single DNS label identifying this relay, e.g. `fips-relay-9408`.
struct Labels {
    instance: heapless_label::Label,
    host: heapless_label::Label,
}

mod heapless_label {
    pub struct Label {
        buf: [u8; 24],
        len: usize,
    }
    impl Label {
        pub fn new(prefix: &str, mac: [u8; 6]) -> Self {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut buf = [0u8; 24];
            let p = prefix.as_bytes();
            buf[..p.len()].copy_from_slice(p);
            let mut len = p.len();
            for b in &mac[4..] {
                buf[len] = HEX[(b >> 4) as usize];
                buf[len + 1] = HEX[(b & 0xf) as usize];
                len += 2;
            }
            Self { buf, len }
        }
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("fips-relay")
        }
    }
}

#[embassy_executor::task(pool_size = 2)]
async fn net_task(mut runner: Runner<'static, Interface>) {
    runner.run().await;
}

/// DHCP server on the AP side.
#[embassy_executor::task]
async fn dhcp_task(stack: Stack<'static>) {
    static RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 1536]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 1024]> = StaticCell::new();
    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 4]),
        RX_BUF.init([0u8; 1536]),
        TX_META.init([PacketMetadata::EMPTY; 4]),
        TX_BUF.init([0u8; 1024]),
    );
    socket.bind(67).expect("dhcp bind");
    let mut server: DhcpServer<DHCP_POOL_SIZE> = DhcpServer::new(DhcpServerConfig {
        server_ip: AP_IP,
        subnet_mask: [255, 255, 255, 0],
        pool_start: DHCP_POOL_START,
        lease_secs: DHCP_LEASE_SECS,
    });
    let broadcast = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::BROADCAST), 68);
    let mut rx = [0u8; 1024];
    let mut reply = [0u8; MAX_REPLY_LEN];
    loop {
        let Ok((n, _)) = socket.recv_from(&mut rx).await else {
            continue;
        };
        let now = Instant::now().as_secs();
        if let Some(len) = server.handle(&rx[..n], now, &mut reply) {
            if socket.send_to(&reply[..len], broadcast).await.is_ok() {
                log::info!(
                    "relay: DHCP reply to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {}.{}.{}.{} ({} leases)",
                    rx[28], rx[29], rx[30], rx[31], rx[32], rx[33],
                    reply[16], reply[17], reply[18], reply[19],
                    server.active_leases(now)
                );
            }
        }
    }
}

/// mDNS responder on the AP side: answers FIPS queries and announces
/// periodically, as long as an upstream daemon is known.
#[embassy_executor::task]
async fn mdns_task(stack: Stack<'static>, labels: &'static Labels) {
    static RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 1024]> = StaticCell::new();
    let group = Ipv4Address::from(MDNS_GROUP);
    if let Err(e) = stack.join_multicast_group(group) {
        log::error!("relay: mDNS group join failed: {:?}", e);
    }
    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 4]),
        RX_BUF.init([0u8; 2048]),
        TX_META.init([PacketMetadata::EMPTY; 4]),
        TX_BUF.init([0u8; 1024]),
    );
    socket.bind(MDNS_PORT).expect("mdns bind");
    let multicast = IpEndpoint::new(IpAddress::Ipv4(group), MDNS_PORT);
    let mut rx = [0u8; 1024];
    let mut out = [0u8; MAX_RESPONSE_LEN];
    let mut next_announce = Instant::now() + Duration::from_secs(5);
    loop {
        match select(socket.recv_from(&mut rx), Timer::at(next_announce)).await {
            Either::First(Ok((n, meta))) => {
                let Some(query) =
                    parse_fips_query(&rx[..n], labels.instance.as_str(), labels.host.as_str())
                else {
                    continue;
                };
                let Some(up) = upstream() else {
                    continue;
                };
                let npub = core::str::from_utf8(&up.npub).unwrap_or("");
                // Legacy one-shot queries (not from 5353) get a unicast reply
                // carrying their id (RFC 6762 §6.7); standard ones multicast.
                let legacy = meta.endpoint.port != MDNS_PORT;
                let id = if legacy { query.id } else { 0 };
                let Some(len) = build_fips_response(
                    &mut out,
                    id,
                    labels.instance.as_str(),
                    labels.host.as_str(),
                    AP_IP,
                    RELAY_PORT,
                    npub,
                    up.scope(),
                ) else {
                    continue;
                };
                let dest = if legacy { meta.endpoint } else { multicast };
                let _ = socket.send_to(&out[..len], dest).await;
            }
            Either::First(Err(_)) => {}
            Either::Second(()) => {
                next_announce = Instant::now() + Duration::from_secs(ANNOUNCE_SECS);
                let Some(up) = upstream() else {
                    continue;
                };
                let npub = core::str::from_utf8(&up.npub).unwrap_or("");
                if let Some(len) = build_fips_response(
                    &mut out,
                    0,
                    labels.instance.as_str(),
                    labels.host.as_str(),
                    AP_IP,
                    RELAY_PORT,
                    npub,
                    up.scope(),
                ) {
                    let _ = socket.send_to(&out[..len], multicast).await;
                }
            }
        }
    }
}

/// Client → daemon: each client flow gets its own uplink socket.
#[embassy_executor::task]
async fn ap_rx_task(
    ap_socket: &'static UdpSocket<'static>,
    up_sockets: &'static [UdpSocket<'static>; RELAY_SLOTS],
) {
    let mut buf = [0u8; MAX_FRAME_SIZE];
    loop {
        let Ok((n, meta)) = ap_socket.recv_from(&mut buf).await else {
            continue;
        };
        let Some(up) = upstream() else {
            continue;
        };
        let now = Instant::now();
        let Some(i) = slot_for(meta.endpoint, now) else {
            log::warn!("relay: no free slot for client {}", meta.endpoint);
            continue;
        };
        let _ = up_sockets[i].send_to(&buf[..n], up.endpoint).await;
    }
}

/// Daemon → client for one slot.
#[embassy_executor::task(pool_size = RELAY_SLOTS)]
async fn up_rx_task(
    slot: usize,
    up_socket: &'static UdpSocket<'static>,
    ap_socket: &'static UdpSocket<'static>,
) {
    let mut buf = [0u8; MAX_FRAME_SIZE];
    loop {
        let Ok((n, meta)) = up_socket.recv_from(&mut buf).await else {
            continue;
        };
        if !matches!(upstream(), Some(up) if up.endpoint == meta.endpoint) {
            continue;
        }
        let Some(client) = slot_client(slot) else {
            continue;
        };
        touch_slot(slot, Instant::now());
        let _ = ap_socket.send_to(&buf[..n], client).await;
    }
}

/// Pick the strongest BSSID for `ssid` that is not our own AP.
async fn pick_uplink_bssid(
    controller: &mut WifiController<'static>,
    ssid: &str,
    own_ap_mac: [u8; 6],
) -> Option<[u8; 6]> {
    let config = ScanConfig::default().with_ssid(ssid).with_max(8);
    let results = with_timeout(Duration::from_secs(10), controller.scan_async(&config))
        .await
        .ok()?
        .ok()?;
    results
        .iter()
        .filter(|ap| ap.bssid != own_ap_mac)
        .max_by_key(|ap| ap.signal_strength)
        .map(|ap| ap.bssid)
}

fn apply_config(
    controller: &mut WifiController<'static>,
    uplink_ssid: &str,
    uplink_password: &str,
    bssid: Option<[u8; 6]>,
) {
    let mut sta = crate::wifi_transport::station_config(uplink_ssid, uplink_password);
    if let Some(b) = bssid {
        sta = sta.with_bssid(b);
    }
    let ap = AccessPointConfig::default()
        .with_ssid(crate::config::RELAY_AP_SSID)
        .with_auth_method(AuthenticationMethod::None)
        .with_max_connections(DHCP_POOL_SIZE as u16);
    if let Err(e) = controller.set_config(&WifiConfig::AccessPointStation(sta, ap)) {
        log::error!("relay: set_config failed: {:?}", e);
    }
}

/// Uplink supervisor: associate (re-associate on loss), DHCP, discover
/// the daemon or upstream relay, publish it for the AP-side tasks.
#[embassy_executor::task]
async fn uplink_task(
    mut controller: &'static mut WifiController<'static>,
    sta_stack: Stack<'static>,
    own_ap_mac: [u8; 6],
    led: Option<&'static Mutex<CriticalSectionRawMutex, RefCell<crate::led::Led>>>,
) {
    let ssid = crate::config::RELAY_UPLINK_SSID;
    let password = crate::config::RELAY_UPLINK_PASSWORD;
    let pinned: [u8; 32] = microfips_core::identity::VPS_NPUB[1..33]
        .try_into()
        .unwrap();
    let mut backoff = 2u64;
    let mut next_rediscover = Instant::now();
    loop {
        if !controller.is_connected() {
            UPSTREAM.lock(|u| *u.borrow_mut() = None);
            if let Some(led) = led {
                led.lock(|l| l.borrow_mut().set_state(crate::config::LED_OFF));
            }
            let bssid = pick_uplink_bssid(&mut controller, ssid, own_ap_mac).await;
            match bssid {
                Some(b) => log::info!(
                    "relay: uplink '{}' via {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ssid,
                    b[0],
                    b[1],
                    b[2],
                    b[3],
                    b[4],
                    b[5]
                ),
                None => log::info!("relay: uplink '{}' not in scan, trying anyway", ssid),
            }
            apply_config(&mut controller, ssid, password, bssid);
            match with_timeout(Duration::from_secs(30), controller.connect_async()).await {
                Ok(Ok(_)) => {}
                _ => {
                    log::error!("relay: uplink association failed, retry in {}s", backoff);
                    let _ = controller.disconnect_async().await;
                    Timer::after(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(60);
                    continue;
                }
            }
            let dhcp = with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
                loop {
                    if let Some(c) = sta_stack.config_v4() {
                        break c;
                    }
                    Timer::after(Duration::from_millis(500)).await;
                }
            })
            .await;
            let Ok(cfg) = dhcp else {
                log::error!("relay: uplink DHCP timed out");
                let _ = controller.disconnect_async().await;
                continue;
            };
            log::info!("relay: uplink connected, IP: {}", cfg.address);
            backoff = 2;
            next_rediscover = Instant::now();
        }

        if Instant::now() >= next_rediscover {
            next_rediscover = Instant::now() + Duration::from_secs(REDISCOVER_SECS);
            let found =
                match discover_fips_advert(sta_stack, DiscoveryFilter::Pinned(&pinned)).await {
                    Some(d) => {
                        let mut scope = [0u8; MAX_SCOPE_LEN];
                        let mut scope_len = 0u8;
                        if let Some(s) = d.scope() {
                            scope[..s.len()].copy_from_slice(s.as_bytes());
                            scope_len = s.len() as u8;
                        }
                        Some((
                            IpEndpoint::new(IpAddress::Ipv4(d.ip), d.port),
                            d.key,
                            scope,
                            scope_len,
                        ))
                    }
                    None => {
                        let dns = sta_stack.config_v4().map(|c| c.dns_servers[0]);
                        match dns {
                            Some(dns) => match resolve_vps_ipv4(sta_stack, dns, VPS_HOST).await {
                                Ok(ip) => Some((
                                    IpEndpoint::new(IpAddress::Ipv4(ip), VPS_PORT),
                                    pinned,
                                    [0u8; MAX_SCOPE_LEN],
                                    0,
                                )),
                                Err(_) => None,
                            },
                            None => None,
                        }
                    }
                };
            match found {
                Some((endpoint, key, scope, scope_len)) => {
                    let npub = microfips_core::identity::bech32::x_only_to_npub(&key);
                    let changed = upstream().map(|u| u.endpoint != endpoint).unwrap_or(true);
                    UPSTREAM.lock(|u| {
                        *u.borrow_mut() = Some(Upstream {
                            endpoint,
                            npub,
                            scope,
                            scope_len,
                        })
                    });
                    if let Some(led) = led {
                        led.lock(|l| l.borrow_mut().set_state(crate::config::LED_ON));
                    }
                    if changed {
                        log::info!("relay: upstream FIPS endpoint {}", endpoint);
                    }
                }
                None => {
                    log::warn!("relay: no upstream daemon found (mDNS + DNS), retrying in 30s");
                    next_rediscover = Instant::now() + Duration::from_secs(30);
                }
            }
        }
        Timer::after(Duration::from_secs(5)).await;
    }
}

/// Node transport for peer mode: one UDP flow on the station stack toward
/// the upstream endpoint published by `uplink_task`. Each session waits
/// for an upstream to exist and re-reads it, so the node follows daemon
/// moves and uplink re-associations without owning the WiFi controller.
pub struct RelayPeerTransport {
    socket: &'static UdpSocket<'static>,
    peer: Option<IpEndpoint>,
}

impl Transport for RelayPeerTransport {
    type Error = UdpTransportError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        let endpoint = loop {
            if let Some(u) = upstream() {
                break u.endpoint;
            }
            Timer::after(Duration::from_secs(1)).await;
        };
        if self.peer != Some(endpoint) {
            log::info!("relay peer: node session toward {}", endpoint);
            self.peer = Some(endpoint);
        }
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let peer = self.peer.ok_or(UdpTransportError::NotReady)?;
        self.socket
            .send_to(data, peer)
            .await
            .map_err(|_| UdpTransportError::Send)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let peer = self.peer.ok_or(UdpTransportError::NotReady)?;
        loop {
            let (n, meta) = self
                .socket
                .recv_from(buf)
                .await
                .map_err(|_| UdpTransportError::Recv)?;
            if meta.endpoint == peer {
                return Ok(n);
            }
        }
    }
}

pub async fn run_relay_ap(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    wifi: WIFI<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    run_relay_ap_opts(spawner, gpio2, wifi, rng_periph, adc1, false).await
}

/// Relay AP that is also a FIPS peer (see module docs).
pub async fn run_relay_ap_peer(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    wifi: WIFI<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    run_relay_ap_opts(spawner, gpio2, wifi, rng_periph, adc1, true).await
}

async fn run_relay_ap_opts(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    wifi: WIFI<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
    peer: bool,
) -> ! {
    crate::heap::init();
    crate::logger::init();
    let led = crate::runner::make_led(gpio2);
    static LED: StaticCell<Mutex<CriticalSectionRawMutex, RefCell<crate::led::Led>>> =
        StaticCell::new();
    // Relay-only: the uplink task drives the LED. Peer: the node does.
    let (relay_led, mut node_led) = if peer {
        (None, Some(led))
    } else {
        (Some(&*LED.init(Mutex::new(RefCell::new(led)))), None)
    };
    let (trng_source, trng) = crate::runner::init_trng(rng_periph, adc1);

    log::info!(
        "FIPS relay AP starting: AP '{}' open, uplink '{}', peer {}",
        crate::config::RELAY_AP_SSID,
        crate::config::RELAY_UPLINK_SSID,
        if peer { "yes" } else { "no" }
    );

    static STA_RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
    static AP_RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    static AP_RX_META: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static AP_RX_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
    static AP_TX_META: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static AP_TX_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
    static AP_SOCKET: StaticCell<UdpSocket<'static>> = StaticCell::new();
    static UP_META: StaticCell<[[PacketMetadata; 4]; RELAY_SLOTS * 2]> = StaticCell::new();
    static UP_BUF: StaticCell<[[u8; 2048]; RELAY_SLOTS * 2]> = StaticCell::new();
    static UP_SOCKETS: StaticCell<[UdpSocket<'static>; RELAY_SLOTS]> = StaticCell::new();
    static LABELS: StaticCell<Labels> = StaticCell::new();
    static PEER_META: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static PEER_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
    static PEER_SOCKET: StaticCell<UdpSocket<'static>> = StaticCell::new();

    static WCTRL: StaticCell<esp_radio::wifi::WifiController> = StaticCell::new();
    let mut controller =
        WCTRL.init(esp_radio::wifi::WifiController::new(wifi, Default::default()).expect("WifiController::new failed"));
    let ap_if = esp_radio::wifi::Interface::access_point();
    let sta_if = esp_radio::wifi::Interface::station();
    let own_ap_mac = ap_if.mac_address();
    let labels: &'static Labels = LABELS.init(Labels {
        instance: heapless_label::Label::new("fips-relay-", own_ap_mac),
        host: heapless_label::Label::new("fips-relay-", own_ap_mac),
    });

    let seed = trng.random() as u64 | ((trng.random() as u64) << 32);
    let (sta_stack, sta_runner) = embassy_net::new(
        sta_if,
        Config::dhcpv4(Default::default()),
        STA_RESOURCES.init(StackResources::new()),
        seed,
    );
    let ap_config = Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::from(AP_IP), AP_PREFIX),
        gateway: None,
        dns_servers: Default::default(),
    });
    let (ap_stack, ap_runner) = embassy_net::new(
        ap_if,
        ap_config,
        AP_RESOURCES.init(StackResources::new()),
        seed ^ 0x9e37_79b9_7f4a_7c15,
    );
    spawner.spawn(net_task(sta_runner).expect("spawn sta net task"));
    spawner.spawn(net_task(ap_runner).expect("spawn ap net task"));

    // AP up immediately (clients can associate and get DHCP before the
    // uplink is ready; the mDNS advert appears once the daemon is known).
    apply_config(
        &mut controller,
        crate::config::RELAY_UPLINK_SSID,
        crate::config::RELAY_UPLINK_PASSWORD,
        None,
    );

    // Relay sockets.
    let mut ap_socket = UdpSocket::new(
        ap_stack,
        AP_RX_META.init([PacketMetadata::EMPTY; 8]),
        AP_RX_BUF.init([0u8; 4096]),
        AP_TX_META.init([PacketMetadata::EMPTY; 8]),
        AP_TX_BUF.init([0u8; 4096]),
    );
    ap_socket.bind(RELAY_PORT).expect("relay bind");
    let ap_socket: &'static UdpSocket<'static> = AP_SOCKET.init(ap_socket);

    let up_meta = UP_META.init([[PacketMetadata::EMPTY; 4]; RELAY_SLOTS * 2]);
    let up_buf = UP_BUF.init([[0u8; 2048]; RELAY_SLOTS * 2]);
    let (rx_meta, tx_meta) = up_meta.split_at_mut(RELAY_SLOTS);
    let (rx_buf, tx_buf) = up_buf.split_at_mut(RELAY_SLOTS);
    let mut rx_meta = rx_meta.iter_mut();
    let mut tx_meta = tx_meta.iter_mut();
    let mut rx_buf = rx_buf.iter_mut();
    let mut tx_buf = tx_buf.iter_mut();
    let up_sockets: &'static [UdpSocket<'static>; RELAY_SLOTS] =
        UP_SOCKETS.init(core::array::from_fn(|_| {
            let mut s = UdpSocket::new(
                sta_stack,
                rx_meta.next().unwrap(),
                rx_buf.next().unwrap(),
                tx_meta.next().unwrap(),
                tx_buf.next().unwrap(),
            );
            s.bind(0).expect("uplink bind");
            s
        }));

    spawner.spawn(dhcp_task(ap_stack).expect("spawn dhcp"));
    spawner.spawn(mdns_task(ap_stack, labels).expect("spawn mdns"));
    spawner.spawn(ap_rx_task(ap_socket, up_sockets).expect("spawn ap rx"));
    for (i, s) in up_sockets.iter().enumerate() {
        spawner.spawn(up_rx_task(i, s, ap_socket).expect("spawn up rx"));
    }
    spawner.spawn(uplink_task(controller, sta_stack, own_ap_mac, relay_led).expect("spawn uplink"));

    log::info!(
        "relay: AP {}.{}.{}.{}/{} up, advert instance '{}'",
        AP_IP[0],
        AP_IP[1],
        AP_IP[2],
        AP_IP[3],
        AP_PREFIX,
        labels.instance.as_str()
    );
    if !peer {
        loop {
            Timer::after(Duration::from_secs(3600)).await;
        }
    }

    // Peer mode: the relay keeps running in its tasks; this task becomes
    // the FIPS node over the uplink.
    let meta = PEER_META.init([PacketMetadata::EMPTY; 8]);
    let buf = PEER_BUF.init([0u8; 4096]);
    let (rx_meta, tx_meta) = meta.split_at_mut(4);
    let (rx_buf, tx_buf) = buf.split_at_mut(2048);
    let mut socket = UdpSocket::new(sta_stack, rx_meta, rx_buf, tx_meta, tx_buf);
    socket.bind(0).expect("peer bind");
    let socket: &'static UdpSocket<'static> = PEER_SOCKET.init(socket);
    let transport = RelayPeerTransport { socket, peer: None };
    let led = node_led.as_mut().expect("peer mode owns the LED");
    crate::runner::run_node(
        transport,
        trng_source,
        trng,
        led,
        microfips_core::identity::VPS_NPUB,
        // FIPS UDP carries raw FMP frames (no length prefix).
        crate::runner::NodeOpts {
            raw_framing: true,
            peer_sent_first: false,
        },
    )
    .await
}
