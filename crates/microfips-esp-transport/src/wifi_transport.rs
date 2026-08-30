use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Runner, Stack, StackResources};
use embassy_time::{with_timeout, Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_hal::rng::Trng;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config as WifiConfig, Interface, WifiController};
use microfips_esp_common::config::{VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS};
use microfips_esp_common::dns::resolve_vps_ipv4;
use microfips_esp_common::mdns::{discover_fips, DiscoveryFilter};
use microfips_esp_common::udp_transport::{UdpTransport, UdpTransportError};
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;

/// Station config for `ssid`/`password`. An empty password means an open
/// network: esp-radio's default auth threshold is WPA2, which would reject
/// the AP with `NoAccessPointFoundInAuthmodeThreshold`.
pub(crate) fn station_config(ssid: &str, password: &str) -> StationConfig {
    let cfg = StationConfig::default()
        .with_ssid(ssid)
        .with_password(alloc::string::String::from(password));
    if password.is_empty() {
        cfg.with_auth_method(esp_radio::wifi::AuthenticationMethod::None)
    } else {
        cfg
    }
}

#[derive(Debug)]
pub enum WifiInitError {
    ConnectFailed,
    ConnectTimeout,
    DhcpTimeout,
    DnsFailed,
}

pub struct WifiTransport {
    wifi_controller: WifiController<'static>,
    stack: Stack<'static>,
    /// x-only key of the peer this transport is bound to (compiled-in, or
    /// taken from the mDNS advert in open mode). Re-discovery pins to it.
    peer_key: [u8; 32],
    /// Number of `wait_ready` calls so far; the Node calls it once per
    /// connection attempt, so >0 means the previous session ended.
    sessions: u32,
    inner: UdpTransport<'static>,
}

impl Transport for WifiTransport {
    type Error = <UdpTransport<'static> as Transport>::Error;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        if self.sessions > 0 {
            // The previous session ended (link dead or handshake failure).
            // First make sure WiFi is still associated — an AP reboot or
            // roam drops the association and esp-radio does not reconnect
            // by itself. One attempt per call; on failure the Node's
            // retry/backoff loop brings us back here.
            if !self.wifi_controller.is_connected() {
                #[cfg(feature = "log")]
                log::info!("WiFi: association lost, reconnecting");
                match with_timeout(
                    Duration::from_secs(30),
                    self.wifi_controller.connect_async(),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        let dhcp =
                            with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
                                loop {
                                    if let Some(c) = self.stack.config_v4() {
                                        break c;
                                    }
                                    Timer::after(Duration::from_millis(500)).await;
                                }
                            })
                            .await;
                        match dhcp {
                            Ok(config_v4) => {
                                #[cfg(feature = "log")]
                                log::info!("WiFi reconnected, IP: {}", config_v4.address);
                            }
                            Err(_) => {
                                #[cfg(feature = "log")]
                                log::error!("WiFi reconnected but DHCP timed out");
                                return Err(UdpTransportError::NotReady);
                            }
                        }
                    }
                    _ => {
                        #[cfg(feature = "log")]
                        log::error!("WiFi reconnect failed");
                        return Err(UdpTransportError::NotReady);
                    }
                }
            }

            // The daemon may have moved (DHCP lease change, restart on a
            // different host) — re-discover the bound peer key on the LAN
            // and follow it before retrying.
            match discover_fips(self.stack, DiscoveryFilter::Pinned(&self.peer_key)).await {
                Some((ip, port, _)) => {
                    let endpoint = IpEndpoint::new(IpAddress::Ipv4(ip), port);
                    if endpoint != self.inner.peer {
                        #[cfg(feature = "log")]
                        log::info!(
                            "mDNS re-discovery: peer moved {} -> {}:{}",
                            self.inner.peer,
                            ip,
                            port
                        );
                        self.inner.peer = endpoint;
                    } else {
                        #[cfg(feature = "log")]
                        log::info!("mDNS re-discovery: peer still at {}", endpoint);
                    }
                }
                None => {
                    #[cfg(feature = "log")]
                    log::info!("mDNS re-discovery: no advert, keeping {}", self.inner.peer);
                }
            }
        }
        self.sessions = self.sessions.wrapping_add(1);
        self.inner.wait_ready().await
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.inner.send(data).await
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.recv(buf).await
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface<'static>>) {
    runner.run().await;
}

/// Build the WiFi transport. Also returns the peer npub actually in
/// effect: the compiled-in key, or — with the `mdns-open` feature — the
/// key taken from the discovered daemon's mDNS advert.
pub async fn build_wifi_transport(
    spawner: embassy_executor::Spawner,
    wifi: WIFI<'static>,
    trng: &mut Trng,
    wifi_ssid: &str,
    wifi_password: &str,
) -> Result<(WifiTransport, [u8; 33]), WifiInitError> {
    crate::heap::init();

    const MAX_WIFI_RETRIES: u32 = 5;
    const WIFI_RETRY_BASE_SECS: u64 = 5;

    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    static RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();

    // Init-config power-save workaround (#91): apply the station config as esp-radio's
    // `initial_config` instead of a separate post-init `set_config`. esp-radio's `new()`
    // runs `set_power_saving(None)` and then `set_config(initial_config)` as one init with a
    // single `esp_wifi_start`, so PS=None is not clobbered by a second `set_config`/start.
    // Calling `set_power_saving(None)` ourselves after `set_config` instead broke the FSP
    // data path on esp-radio 0.18/esp32s3 (link up, session datagrams stalled).
    let controller_config = esp_radio::wifi::ControllerConfig::default().with_initial_config(
        WifiConfig::Station(station_config(wifi_ssid, wifi_password)),
    );
    let (mut wifi_controller, interfaces) =
        esp_radio::wifi::new(wifi, controller_config).expect("wifi::new failed");
    let wifi_device = interfaces.station;

    let resources = RESOURCES.init(StackResources::new());
    let seed = trng.random() as u64 | ((trng.random() as u64) << 32);
    let (stack, runner) = embassy_net::new(
        wifi_device,
        Config::dhcpv4(Default::default()),
        resources,
        seed,
    );
    spawner.spawn(net_task(runner).expect("spawn net task failed"));

    Timer::after(Duration::from_secs(2)).await;
    let (_, vps_ip, vps_port, peer_npub) = {
        let mut retry = 0u32;
        loop {
            let init_result: Result<_, WifiInitError> = match with_timeout(
                Duration::from_secs(30),
                wifi_controller.connect_async(),
            )
            .await
            {
                Ok(Ok(_connected_info)) => {
                    #[cfg(feature = "log")]
                    log::info!("WiFi connected");

                    let config_v4 =
                        match with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
                            loop {
                                if let Some(c) = stack.config_v4() {
                                    break c;
                                }
                                Timer::after(Duration::from_millis(500)).await;
                            }
                        })
                        .await
                        {
                            Ok(config) => config,
                            Err(_) => {
                                #[cfg(feature = "log")]
                                log::error!(
                                    "WiFi DHCP timed out after {}s",
                                    WIFI_DHCP_TIMEOUT_SECS
                                );
                                let _ = wifi_controller.disconnect_async().await;
                                Err(WifiInitError::DhcpTimeout)?
                            }
                        };

                    #[cfg(feature = "log")]
                    log::info!("IP: {} (target: {})", config_v4.address, VPS_HOST);

                    // LAN discovery via mDNS. Pinned mode (default): only an
                    // advert matching the compiled-in peer key supplies the
                    // endpoint. Open mode (`mdns-open`): the first scope- and
                    // version-compatible advert supplies endpoint AND peer
                    // key — trust-on-first-advert, still proven by Noise IK.
                    #[cfg(feature = "mdns-open")]
                    let discovered = {
                        let scope = crate::config::FIPS_DISCOVERY_SCOPE;
                        let scope = if scope.is_empty() { None } else { Some(scope) };
                        discover_fips(stack, DiscoveryFilter::Open { scope })
                            .await
                            .map(|(ip, port, key)| {
                                let mut npub = [0u8; 33];
                                npub[0] = 0x02;
                                npub[1..].copy_from_slice(&key);
                                #[cfg(feature = "log")]
                                log::info!(
                                    "mDNS open: FIPS peer discovered at {}:{} (npub from advert)",
                                    ip,
                                    port
                                );
                                (ip, port, npub)
                            })
                    };
                    #[cfg(not(feature = "mdns-open"))]
                    let discovered = {
                        let pinned: [u8; 32] = microfips_core::identity::VPS_NPUB[1..33]
                            .try_into()
                            .unwrap();
                        discover_fips(stack, DiscoveryFilter::Pinned(&pinned))
                            .await
                            .map(|(ip, port, _)| {
                                #[cfg(feature = "log")]
                                log::info!("mDNS: pinned FIPS peer discovered at {}:{}", ip, port);
                                (ip, port, microfips_core::identity::VPS_NPUB)
                            })
                    };

                    if let Some((ip, port, npub)) = discovered {
                        Ok((config_v4, ip, port, npub))
                    } else {
                        #[cfg(feature = "log")]
                        log::info!("mDNS: no matching advert, resolving {}", VPS_HOST);
                        let dns_server = config_v4.dns_servers[0];
                        match resolve_vps_ipv4(stack, dns_server, VPS_HOST).await {
                            Ok(vps_ip) => Ok((
                                config_v4,
                                vps_ip,
                                VPS_PORT,
                                microfips_core::identity::VPS_NPUB,
                            )),
                            Err(e) => {
                                #[cfg(feature = "log")]
                                log::error!("DNS resolve failed for {}: {:?}", VPS_HOST, e);
                                let _ = wifi_controller.disconnect_async().await;
                                Err(WifiInitError::DnsFailed)
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    #[cfg(feature = "log")]
                    log::error!("WiFi connect failed: {:?}", e);
                    let _ = wifi_controller.disconnect_async().await;
                    Err(WifiInitError::ConnectFailed)
                }
                Err(_) => {
                    #[cfg(feature = "log")]
                    log::error!("WiFi connect timed out after 30s");
                    let _ = wifi_controller.disconnect_async().await;
                    Err(WifiInitError::ConnectTimeout)
                }
            };

            match init_result {
                Ok(values) => break values,
                Err(err) => {
                    #[cfg(feature = "log")]
                    log::error!(
                        "WiFi init failed (attempt {}/{}): {:?}",
                        retry + 1,
                        MAX_WIFI_RETRIES,
                        err
                    );

                    retry += 1;
                    if retry >= MAX_WIFI_RETRIES {
                        return Err(err);
                    }

                    let backoff = WIFI_RETRY_BASE_SECS * (1u64 << (retry - 1));
                    #[cfg(feature = "log")]
                    log::info!("Retrying WiFi init in {}s", backoff);
                    Timer::after(Duration::from_secs(backoff)).await;
                }
            }
        }
    };

    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 4]),
        RX_BUF.init([0u8; 2048]),
        TX_META.init([PacketMetadata::EMPTY; 4]),
        TX_BUF.init([0u8; 2048]),
    );
    socket.bind(0).expect("udp bind");

    #[cfg(feature = "log")]
    log::info!("FIPS target: {}:{}", vps_ip, vps_port);

    let peer = IpEndpoint::new(IpAddress::Ipv4(vps_ip), vps_port);
    let inner = UdpTransport { socket, peer };

    let peer_key: [u8; 32] = peer_npub[1..33].try_into().unwrap();
    Ok((
        WifiTransport {
            wifi_controller,
            stack,
            peer_key,
            sessions: 0,
            inner,
        },
        peer_npub,
    ))
}
