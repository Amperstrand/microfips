//! Hybrid WiFi/ESP-NOW transport: direct UDP to the daemon when the AP and
//! daemon are reachable, ESP-NOW via a gateway otherwise.
//!
//! Both paths pin the same daemon npub and run Noise IK end-to-end, so
//! switching paths never changes the trust model — only the route. All
//! switching happens at session boundaries through `wait_ready` (the Node
//! calls it once per connection attempt):
//!
//! - WiFi mode: `wait_ready` re-associates and mDNS-re-discovers like the
//!   plain WiFi transport. After `WIFI_FAILURES_BEFORE_FALLBACK`
//!   consecutive failed attempts it falls back to ESP-NOW discovery.
//! - ESP-NOW mode: every `HYBRID_WIFI_PROBE_SECS`, `recv` runs a cheap
//!   SSID-filtered scan (no association). Only if the AP is visible does
//!   the session end and `wait_ready` attempt the full WiFi path — and it
//!   switches only when mDNS also confirms the daemon, so a reachable AP
//!   without a reachable daemon keeps the working ESP-NOW link.

use embassy_futures::select::{select, Either};
use embassy_net::udp::UdpSocket;
use embassy_net::{IpAddress, IpEndpoint, Stack};
use embassy_time::{with_timeout, Duration, Instant, Timer};
use esp_radio::wifi::scan::ScanConfig;
use esp_radio::wifi::WifiController;
use microfips_esp_common::config::WIFI_DHCP_TIMEOUT_SECS;
use microfips_esp_common::mdns::{discover_fips, DiscoveryFilter};
use microfips_esp_common::udp_transport::{UdpTransport, UdpTransportError};
use microfips_protocol::transport::Transport;

use crate::esp_now_transport::EspNowTransport;

/// Consecutive failed WiFi-mode connection attempts before falling back.
const WIFI_FAILURES_BEFORE_FALLBACK: u32 = 2;
/// A session that lived at least this long proves the path was healthy;
/// the failure counter restarts from zero afterwards.
const HEALTHY_SESSION_SECS: u64 = 120;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Wifi,
    EspNow,
}

pub struct HybridTransport {
    controller: &'static mut WifiController<'static>,
    stack: Stack<'static>,
    udp: UdpTransport<'static>,
    espnow: EspNowTransport,
    /// x-only daemon key both paths are pinned to.
    peer_key: [u8; 32],
    wifi_ssid: &'static str,
    mode: Mode,
    sessions: u32,
    wifi_failures: u32,
    /// Set when an ESP-NOW-mode scan saw the AP; the next `wait_ready`
    /// attempts the WiFi path first.
    prefer_wifi: bool,
    next_wifi_probe: Instant,
    last_ready: Instant,
}

impl HybridTransport {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        controller: &'static mut WifiController<'static>,
        stack: Stack<'static>,
        socket: UdpSocket<'static>,
        daemon: IpEndpoint,
        espnow: EspNowTransport,
        peer_key: [u8; 32],
        wifi_ssid: &'static str,
        start_on_wifi: bool,
    ) -> Self {
        Self {
            controller,
            stack,
            udp: UdpTransport {
                socket,
                peer: daemon,
            },
            espnow,
            peer_key,
            wifi_ssid,
            mode: if start_on_wifi {
                Mode::Wifi
            } else {
                Mode::EspNow
            },
            sessions: 0,
            wifi_failures: 0,
            prefer_wifi: false,
            next_wifi_probe: Instant::now()
                + Duration::from_secs(crate::config::HYBRID_WIFI_PROBE_SECS),
            last_ready: Instant::now(),
        }
    }

    fn test_wifi_forced_down() -> bool {
        crate::config::HYBRID_TEST_WIFI_DOWN_SECS != 0
            && Instant::now().as_secs() < crate::config::HYBRID_TEST_WIFI_DOWN_SECS
    }

    /// Bring the WiFi path up: associate + DHCP if needed, then mDNS-locate
    /// the pinned daemon. `strict` requires a fresh mDNS confirmation (used
    /// when deciding to switch away from a working ESP-NOW link); otherwise
    /// a missing advert keeps the previously known endpoint.
    async fn try_wifi_ready(&mut self, strict: bool) -> bool {
        if Self::test_wifi_forced_down() {
            #[cfg(feature = "log")]
            log::info!("hybrid: WiFi path forced down (test knob)");
            return false;
        }
        if !self.controller.is_connected() {
            #[cfg(feature = "log")]
            log::info!("hybrid: associating to '{}'", self.wifi_ssid);
            match with_timeout(Duration::from_secs(30), self.controller.connect_async()).await {
                Ok(Ok(_)) => {}
                _ => {
                    #[cfg(feature = "log")]
                    log::info!("hybrid: association failed");
                    let _ = self.controller.disconnect_async().await;
                    return false;
                }
            }
        }
        let dhcp = with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
            loop {
                if let Some(c) = self.stack.config_v4() {
                    break c;
                }
                Timer::after(Duration::from_millis(500)).await;
            }
        })
        .await;
        if dhcp.is_err() {
            #[cfg(feature = "log")]
            log::info!("hybrid: DHCP timed out");
            return false;
        }
        match discover_fips(self.stack, DiscoveryFilter::Pinned(&self.peer_key)).await {
            Some((ip, port, _)) => {
                let endpoint = IpEndpoint::new(IpAddress::Ipv4(ip), port);
                if endpoint != self.udp.peer {
                    #[cfg(feature = "log")]
                    log::info!("hybrid: daemon at {} (was {})", endpoint, self.udp.peer);
                    self.udp.peer = endpoint;
                }
                true
            }
            None => {
                #[cfg(feature = "log")]
                log::info!("hybrid: no mDNS advert for pinned daemon");
                !strict
            }
        }
    }

    async fn enter_espnow(&mut self) {
        if self.controller.is_connected() {
            // The channel sweep needs an unassociated radio.
            let _ = self.controller.disconnect_async().await;
        }
        self.espnow.reset_discovery();
        self.next_wifi_probe =
            Instant::now() + Duration::from_secs(crate::config::HYBRID_WIFI_PROBE_SECS);
        if self.mode != Mode::EspNow {
            self.mode = Mode::EspNow;
            #[cfg(feature = "log")]
            log::info!("hybrid: switched to ESP-NOW path");
        }
    }

    /// Cheap AP presence check: SSID-filtered scan, no association.
    async fn ap_visible(&mut self) -> bool {
        if Self::test_wifi_forced_down() {
            return false;
        }
        let config = ScanConfig::default().with_ssid(self.wifi_ssid).with_max(1);
        match with_timeout(Duration::from_secs(10), self.controller.scan_async(&config)).await {
            Ok(Ok(results)) => !results.is_empty(),
            _ => false,
        }
    }
}

#[embassy_executor::task]
async fn hybrid_net_task(
    mut runner: embassy_net::Runner<'static, esp_radio::wifi::Interface>,
) {
    runner.run().await;
}

/// Build the hybrid transport. Tries the WiFi path at boot (associate,
/// DHCP, mDNS with DNS fallback); if unavailable, starts on ESP-NOW —
/// either way the returned transport is ready and self-heals from there.
/// Also returns the peer npub (the compiled-in daemon key, common to both
/// paths).
pub async fn build_hybrid_transport(
    spawner: embassy_executor::Spawner,
    wifi: esp_hal::peripherals::WIFI<'static>,
    trng: &mut esp_hal::rng::Trng,
    wifi_ssid: &'static str,
    wifi_password: &str,
) -> (HybridTransport, [u8; 33]) {
    use embassy_net::udp::PacketMetadata;
    use embassy_net::{Config, StackResources};
    use esp_radio::wifi::Config as WifiConfig;
    use microfips_esp_common::config::{VPS_HOST, VPS_PORT};
    use microfips_esp_common::dns::resolve_vps_ipv4;
    use static_cell::StaticCell;

    crate::heap::init();

    static HY_RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    static HY_RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static HY_RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static HY_TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static HY_TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();

    static WCTRL: static_cell::StaticCell<esp_radio::wifi::WifiController> =
        static_cell::StaticCell::new();
    let mut controller =
        WCTRL.init(esp_radio::wifi::WifiController::new(wifi, Default::default()).expect("WifiController::new failed"));
    let esp_now = controller.esp_now();

    let resources = HY_RESOURCES.init(StackResources::new());
    let seed = trng.random() as u64 | ((trng.random() as u64) << 32);
    let (stack, runner) = embassy_net::new(
        esp_radio::wifi::Interface::station(),
        Config::dhcpv4(Default::default()),
        resources,
        seed,
    );
    spawner.spawn(hybrid_net_task(runner).expect("spawn net task failed"));

    let station_config = crate::wifi_transport::station_config(wifi_ssid, wifi_password);
    controller
        .set_config(&WifiConfig::Station(station_config))
        .expect("set wifi station config");

    Timer::after(Duration::from_secs(2)).await;

    // Boot-time path selection: give WiFi two attempts, then start on
    // ESP-NOW. Whatever fails here heals later through wait_ready/probes.
    let mut daemon = IpEndpoint::new(
        IpAddress::Ipv4(embassy_net::Ipv4Address::UNSPECIFIED),
        VPS_PORT,
    );
    let mut start_on_wifi = false;
    let pinned: [u8; 32] = microfips_core::identity::VPS_NPUB[1..33]
        .try_into()
        .unwrap();
    for attempt in 0..2u32 {
        if HybridTransport::test_wifi_forced_down() {
            #[cfg(feature = "log")]
            log::info!("hybrid: boot WiFi skipped (test knob)");
            break;
        }
        let associated =
            match with_timeout(Duration::from_secs(30), controller.connect_async()).await {
                Ok(Ok(_)) => true,
                _ => false,
            };
        if !associated {
            #[cfg(feature = "log")]
            log::info!("hybrid: boot association attempt {} failed", attempt + 1);
            let _ = controller.disconnect_async().await;
            Timer::after(Duration::from_secs(2)).await;
            continue;
        }
        let dhcp = with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
            loop {
                if let Some(c) = stack.config_v4() {
                    break c;
                }
                Timer::after(Duration::from_millis(500)).await;
            }
        })
        .await;
        let Ok(config_v4) = dhcp else {
            #[cfg(feature = "log")]
            log::info!("hybrid: boot DHCP timed out");
            let _ = controller.disconnect_async().await;
            continue;
        };
        #[cfg(feature = "log")]
        log::info!("hybrid: WiFi connected, IP: {}", config_v4.address);

        if let Some((ip, port, _)) = discover_fips(stack, DiscoveryFilter::Pinned(&pinned)).await {
            daemon = IpEndpoint::new(IpAddress::Ipv4(ip), port);
            start_on_wifi = true;
            #[cfg(feature = "log")]
            log::info!("hybrid: mDNS pinned daemon at {}", daemon);
        } else {
            let dns_server = config_v4.dns_servers[0];
            match resolve_vps_ipv4(stack, dns_server, VPS_HOST).await {
                Ok(ip) => {
                    daemon = IpEndpoint::new(IpAddress::Ipv4(ip), VPS_PORT);
                    start_on_wifi = true;
                    #[cfg(feature = "log")]
                    log::info!("hybrid: DNS fallback daemon at {}", daemon);
                }
                Err(_e) => {
                    #[cfg(feature = "log")]
                    log::info!("hybrid: no mDNS advert and DNS failed: {:?}", _e);
                }
            }
        }
        break;
    }

    let mut socket = UdpSocket::new(
        stack,
        HY_RX_META.init([PacketMetadata::EMPTY; 4]),
        HY_RX_BUF.init([0u8; 2048]),
        HY_TX_META.init([PacketMetadata::EMPTY; 4]),
        HY_TX_BUF.init([0u8; 2048]),
    );
    socket.bind(0).expect("udp bind");

    if !start_on_wifi && controller.is_connected() {
        // ESP-NOW discovery needs an unassociated radio for the sweep.
        let _ = controller.disconnect_async().await;
    }
    #[cfg(feature = "log")]
    log::info!(
        "hybrid: starting on {} path",
        if start_on_wifi { "WiFi" } else { "ESP-NOW" }
    );

    let espnow = EspNowTransport::new_shared(esp_now, crate::config::ESP_NOW_CHANNEL);
    let transport = HybridTransport::new(
        controller,
        stack,
        socket,
        daemon,
        espnow,
        pinned,
        wifi_ssid,
        start_on_wifi,
    );
    (transport, microfips_core::identity::VPS_NPUB)
}

impl Transport for HybridTransport {
    type Error = UdpTransportError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        let first = self.sessions == 0;
        self.sessions = self.sessions.wrapping_add(1);
        let since_last = Instant::now().saturating_duration_since(self.last_ready);
        self.last_ready = Instant::now();
        if first {
            // The constructor already established the initial path.
            return Ok(());
        }
        if since_last.as_secs() >= HEALTHY_SESSION_SECS {
            self.wifi_failures = 0;
        }

        match self.mode {
            Mode::Wifi => {
                if self.try_wifi_ready(false).await {
                    self.wifi_failures = 0;
                    Ok(())
                } else {
                    self.wifi_failures += 1;
                    if self.wifi_failures >= WIFI_FAILURES_BEFORE_FALLBACK {
                        self.wifi_failures = 0;
                        self.enter_espnow().await;
                        Ok(())
                    } else {
                        // Stay on WiFi for another Node retry/backoff round.
                        Err(UdpTransportError::NotReady)
                    }
                }
            }
            Mode::EspNow => {
                if self.prefer_wifi {
                    self.prefer_wifi = false;
                    if self.try_wifi_ready(true).await {
                        self.mode = Mode::Wifi;
                        self.wifi_failures = 0;
                        #[cfg(feature = "log")]
                        log::info!("hybrid: switched to WiFi path");
                        return Ok(());
                    }
                }
                self.enter_espnow().await;
                Ok(())
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        match self.mode {
            Mode::Wifi => self.udp.send(data).await,
            Mode::EspNow => self
                .espnow
                .send(data)
                .await
                .map_err(|_| UdpTransportError::Send),
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.mode {
            Mode::Wifi => self.udp.recv(buf).await,
            Mode::EspNow => loop {
                if Instant::now() >= self.next_wifi_probe {
                    self.next_wifi_probe =
                        Instant::now() + Duration::from_secs(crate::config::HYBRID_WIFI_PROBE_SECS);
                    if self.ap_visible().await {
                        #[cfg(feature = "log")]
                        log::info!("hybrid: AP visible again, ending session to try WiFi");
                        self.prefer_wifi = true;
                        // Surfacing an error ends the session; wait_ready
                        // then attempts the WiFi path.
                        return Err(UdpTransportError::Recv);
                    }
                }
                match select(self.espnow.recv(buf), Timer::at(self.next_wifi_probe)).await {
                    Either::First(result) => {
                        return result.map_err(|_| UdpTransportError::Recv);
                    }
                    Either::Second(()) => continue,
                }
            },
        }
    }
}
