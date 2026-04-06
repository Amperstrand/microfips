#![cfg(feature = "wifi")]

extern crate alloc;

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Runner, StackResources};
use embassy_time::{with_timeout, Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_hal::rng::Trng;
use esp_radio::wifi::{ClientConfig, ModeConfig, WifiController, WifiDevice};
use microfips_esp_common::config::{VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS};
use microfips_esp_common::dns::resolve_vps_ipv4;
use microfips_esp_common::udp_transport::UdpTransport;
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;

use crate::config::{WIFI_PASSWORD, WIFI_SSID};

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
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await;
}

pub async fn build_wifi_transport(
    spawner: embassy_executor::Spawner,
    wifi: WIFI<'static>,
    trng: &mut Trng,
) -> WifiTransport {
    esp_alloc::heap_allocator!(size: 72_000);

    static RADIO: StaticCell<esp_radio::Controller> = StaticCell::new();
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    static RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();

    let radio = RADIO.init(esp_radio::init().expect("esp_radio::init failed"));
    let (mut wifi_controller, interfaces) =
        esp_radio::wifi::new(radio, wifi, esp_radio::wifi::Config::default())
            .expect("wifi::new failed");
    let wifi_device = interfaces.sta;

    let resources = RESOURCES.init(StackResources::new());
    let seed = trng.random() as u64 | ((trng.random() as u64) << 32);
    let (stack, runner) = embassy_net::new(
        wifi_device,
        Config::dhcpv4(Default::default()),
        resources,
        seed,
    );
    spawner.spawn(net_task(runner)).expect("spawn net task");

    let client_config = ClientConfig::default()
        .with_ssid(alloc::string::String::from(WIFI_SSID))
        .with_password(alloc::string::String::from(WIFI_PASSWORD));
    wifi_controller
        .set_config(&ModeConfig::Client(client_config))
        .expect("set wifi client config");
    wifi_controller.start().expect("wifi start");
    wifi_controller.connect().expect("wifi connect");

    let config_v4 = match with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
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
            log::error!("WiFi DHCP timed out after {}s", WIFI_DHCP_TIMEOUT_SECS);
            panic!("dhcp timeout");
        }
    };
    log::info!("IP: {} (target: {})", config_v4.address, VPS_HOST);

    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 4]),
        RX_BUF.init([0u8; 2048]),
        TX_META.init([PacketMetadata::EMPTY; 4]),
        TX_BUF.init([0u8; 2048]),
    );
    socket.bind(0).expect("udp bind");

    let dns_server = config_v4.dns_servers[0];
    let vps_ip = resolve_vps_ipv4(stack, dns_server, VPS_HOST)
        .await
        .unwrap_or_else(|e| {
            log::error!("DNS resolve failed for {}: {:?}", VPS_HOST, e);
            panic!("DNS resolve failed for {}", VPS_HOST);
        });
    log::info!("Resolved {} -> {}", VPS_HOST, vps_ip);

    let peer = IpEndpoint::new(IpAddress::Ipv4(vps_ip), VPS_PORT);
    let inner = UdpTransport { socket, peer };

    WifiTransport {
        _wifi_controller: wifi_controller,
        inner,
    }
}
