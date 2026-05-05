extern crate alloc;

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Runner, StackResources};
use embassy_time::{with_timeout, Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_hal::rng::Trng;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config as WifiConfig, WifiController};
use microfips_esp_common::config::{VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS};
use microfips_esp_common::dns::resolve_vps_ipv4;
use microfips_esp_common::udp_transport::UdpTransport;
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;

#[derive(Debug)]
pub enum WifiInitError {
    ConnectFailed,
    ConnectTimeout,
    DhcpTimeout,
    DnsFailed,
}

pub struct WifiTransport {
    _wifi_controller: WifiController<'static>,
    inner: UdpTransport<'static>,
}

impl Transport for WifiTransport {
    type Error = <UdpTransport<'static> as Transport>::Error;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
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
async fn net_task(mut runner: Runner<'static, esp_radio::wifi::Interface<'static>>) {
    runner.run().await;
}

pub async fn build_wifi_transport(
    spawner: embassy_executor::Spawner,
    wifi: WIFI<'static>,
    trng: &mut Trng,
    wifi_ssid: &str,
    wifi_password: &str,
) -> Result<WifiTransport, WifiInitError> {
    const MAX_WIFI_RETRIES: u32 = 5;
    const WIFI_RETRY_BASE_SECS: u64 = 5;

    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    static RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();

    let (mut wifi_controller, interfaces) =
        esp_radio::wifi::new(wifi, Default::default()).expect("wifi::new failed");
    let wifi_device = interfaces.station;

    let resources = RESOURCES.init(StackResources::new());
    let seed = trng.random() as u64 | ((trng.random() as u64) << 32);
    let (stack, runner) = embassy_net::new(
        wifi_device,
        Config::dhcpv4(Default::default()),
        resources,
        seed,
    );
    spawner.spawn(net_task(runner).expect("spawn net task"));

    let station_config = StationConfig::default()
        .with_ssid(wifi_ssid)
        .with_password(alloc::string::String::from(wifi_password));
    wifi_controller
        .set_config(&WifiConfig::Station(station_config))
        .expect("set wifi station config");

    Timer::after(Duration::from_secs(2)).await;
    let (_, vps_ip) = {
        let mut retry = 0u32;
        loop {
            let init_result: Result<_, WifiInitError> = match with_timeout(
                Duration::from_secs(30),
                wifi_controller.connect_async(),
            )
            .await
            {
                Ok(Ok(_)) => {
                    #[cfg(feature = "log")]
                    log::info!("WiFi connected");

                    let config_v4 = match with_timeout(
                        Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS),
                        async {
                            loop {
                                if let Some(c) = stack.config_v4() {
                                    break c;
                                }
                                Timer::after(Duration::from_millis(500)).await;
                            }
                        },
                    )
                    .await
                    {
                        Ok(config) => config,
                        Err(_) => {
                            #[cfg(feature = "log")]
                            log::error!("WiFi DHCP timed out after {}s", WIFI_DHCP_TIMEOUT_SECS);
                            let _ = wifi_controller.disconnect_async().await;
                            Err(WifiInitError::DhcpTimeout)?
                        }
                    };

                    #[cfg(feature = "log")]
                    log::info!("IP: {} (target: {})", config_v4.address, VPS_HOST);

                    let dns_server = config_v4.dns_servers[0];
                    match resolve_vps_ipv4(stack, dns_server, VPS_HOST).await {
                        Ok(vps_ip) => Ok((config_v4, vps_ip)),
                        Err(e) => {
                            #[cfg(feature = "log")]
                            log::error!("DNS resolve failed for {}: {:?}", VPS_HOST, e);
                            let _ = wifi_controller.disconnect_async().await;
                            Err(WifiInitError::DnsFailed)
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
    log::info!("Resolved {} -> {}", VPS_HOST, vps_ip);

    let peer = IpEndpoint::new(IpAddress::Ipv4(vps_ip), VPS_PORT);
    let inner = UdpTransport { socket, peer };

    Ok(WifiTransport {
        _wifi_controller: wifi_controller,
        inner,
    })
}
