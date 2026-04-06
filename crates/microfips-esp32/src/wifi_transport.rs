#![cfg(feature = "wifi")]

extern crate alloc;

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Ipv4Address, Runner, StackResources};
use embassy_time::{Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_hal::rng::Trng;
use esp_radio::wifi::{ClientConfig, ModeConfig, WifiController, WifiDevice};
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;

use crate::config::{WIFI_DHCP_POLL_MS, WIFI_FIPS_IPV4, WIFI_FIPS_PORT, WIFI_PASS, WIFI_SSID};

#[derive(Debug)]
pub enum WifiError {
    Send,
    Recv,
}

pub struct WifiTransport {
    _wifi_controller: WifiController<'static>,
    socket: UdpSocket<'static>,
    peer: IpEndpoint,
}

impl Transport for WifiTransport {
    type Error = WifiError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.socket
            .send_to(data, self.peer)
            .await
            .map_err(|_| WifiError::Send)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let (n, _) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|_| WifiError::Recv)?;
        Ok(n)
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await;
}

pub async fn build_wifi_transport(
    spawner: embassy_executor::Spawner,
    wifi: WIFI,
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
        .with_password(alloc::string::String::from(WIFI_PASS));
    wifi_controller
        .set_config(&ModeConfig::Client(client_config))
        .expect("set wifi client config");
    wifi_controller.start().expect("wifi start");
    wifi_controller.connect().expect("wifi connect");

    loop {
        if stack.config_v4().is_some() {
            break;
        }
        Timer::after(Duration::from_millis(WIFI_DHCP_POLL_MS)).await;
    }

    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 4]),
        RX_BUF.init([0u8; 2048]),
        TX_META.init([PacketMetadata::EMPTY; 4]),
        TX_BUF.init([0u8; 2048]),
    );
    socket.bind(0).expect("udp bind");

    let peer = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(
            WIFI_FIPS_IPV4[0],
            WIFI_FIPS_IPV4[1],
            WIFI_FIPS_IPV4[2],
            WIFI_FIPS_IPV4[3],
        )),
        WIFI_FIPS_PORT,
    );

    WifiTransport {
        _wifi_controller: wifi_controller,
        socket,
        peer,
    }
}
