#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

extern crate alloc;

use core::panic::PanicInfo;

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Runner, StackResources};
use embassy_time::{with_timeout, Duration, Timer};
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use esp_radio::wifi::{ClientConfig, ModeConfig};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_esp_common::dns::resolve_vps_ipv4;
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;

use microfips_esp32s3::config::{
    ESP32S3_SECRET, PANIC_BLINK_CYCLES, VPS_HOST, VPS_PORT, WIFI_DHCP_TIMEOUT_SECS, WIFI_PASSWORD,
    WIFI_SSID,
};
use microfips_esp32s3::rng::EspRng;

#[derive(Debug)]
enum UdpTransportError {
    Send,
    Recv,
}

struct UdpTransport<'a> {
    socket: UdpSocket<'a>,
    peer: IpEndpoint,
}

impl Transport for UdpTransport<'_> {
    type Error = UdpTransportError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.socket
            .send_to(data, self.peer)
            .await
            .map_err(|_| UdpTransportError::Send)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let (n, _meta) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|_| UdpTransportError::Recv)?;
        Ok(n)
    }
}

struct EspHandler;

impl NodeHandler for EspHandler {
    async fn on_event(&mut self, event: NodeEvent) {
        esp_println::println!("node event: {:?}", event);
    }

    fn on_message(&mut self, _msg_type: u8, _payload: &[u8], _resp: &mut [u8]) -> HandleResult {
        HandleResult::None
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, esp_radio::wifi::WifiDevice<'static>>) {
    runner.run().await;
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        for _ in 0..PANIC_BLINK_CYCLES {
            core::hint::spin_loop();
        }
    }
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let _sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_alloc::heap_allocator!(size: 72_000);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().unwrap();

    let esp_radio_ctrl = alloc::boxed::Box::leak(alloc::boxed::Box::new(esp_radio::init().unwrap()));
    let (mut wifi_controller, interfaces) = esp_radio::wifi::new(
        esp_radio_ctrl,
        peripherals.WIFI,
        esp_radio::wifi::Config::default(),
    )
    .unwrap();
    let wifi_device = interfaces.sta;

    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let resources = RESOURCES.init(StackResources::new());

    let config = Config::dhcpv4(Default::default());
    let seed = trng.random() as u64 | ((trng.random() as u64) << 32);
    let (stack, runner) = embassy_net::new(wifi_device, config, resources, seed);
    spawner.spawn(net_task(runner)).unwrap();

    let client_config = ClientConfig::default()
        .with_ssid(alloc::string::String::from(WIFI_SSID))
        .with_password(alloc::string::String::from(WIFI_PASSWORD));
    wifi_controller
        .set_config(&ModeConfig::Client(client_config))
        .unwrap();
    wifi_controller.start().unwrap();
    wifi_controller.connect().unwrap();

    let config_v4 = match with_timeout(Duration::from_secs(WIFI_DHCP_TIMEOUT_SECS), async {
        loop {
            if let Some(config_v4) = stack.config_v4() {
                break config_v4;
            }
            Timer::after(Duration::from_millis(500)).await;
        }
    })
    .await
    {
        Ok(config) => config,
        Err(_) => {
            esp_println::println!("ERROR: WiFi DHCP timed out after {}s", WIFI_DHCP_TIMEOUT_SECS);
            panic!("dhcp timeout");
        }
    };

    esp_println::println!("IP: {} (target host: {})", config_v4.address, VPS_HOST);

    let dns_server = match config_v4.dns_servers.first() {
        Some(server) => *server,
        None => {
            esp_println::println!("ERROR: DHCP did not provide any DNS server");
            panic!("missing dns server");
        }
    };

    let vps_ip = match resolve_vps_ipv4(stack, dns_server, VPS_HOST).await {
        Ok(ip) => ip,
        Err(err) => {
            esp_println::println!(
                "ERROR: DNS resolution failed for {} via {}: {:?}",
                VPS_HOST,
                dns_server,
                err
            );
            panic!("dns resolution failed");
        }
    };

    esp_println::println!("Resolved {} to {}", VPS_HOST, vps_ip);

    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut rx_buffer = [0u8; 2048];
    let mut tx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_buffer = [0u8; 2048];

    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    socket.bind(0).unwrap();

    let peer = IpEndpoint::new(IpAddress::Ipv4(vps_ip), VPS_PORT);
    let transport = UdpTransport { socket, peer };

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32S3_SECRET, DEFAULT_PEER_PUB);
    node.set_raw_framing(true);

    let mut handler = EspHandler;
    node.run(&mut handler).await;
}
