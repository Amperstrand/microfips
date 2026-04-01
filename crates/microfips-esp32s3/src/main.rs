#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

extern crate alloc;

use core::panic::PanicInfo;

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Ipv4Address, Runner, StackResources};
use embassy_time::{Duration, Timer};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use esp_radio::wifi::{ClientConfig, ModeConfig};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};
use microfips_protocol::transport::Transport;
use rand_core::RngCore;
use static_cell::StaticCell;

const SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
];

const SSID: &str = "2";
const PASSWORD: &str = "apekattensatilgutten";

const VPS_HOST: &str = "orangeclaw.dns4sats.xyz";
const VPS_PORT: u16 = 2121;
const VPS_IP: Ipv4Address = Ipv4Address::new(91, 99, 211, 197);

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

struct EspRng(esp_hal::rng::Trng);

impl RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EspRng {}

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
        core::hint::spin_loop();
    }
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let _sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_alloc::heap_allocator!(size: 72_000);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    let _trng_source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = esp_hal::rng::Trng::try_new().unwrap();

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
    let seed = 12345;
    let (stack, runner) = embassy_net::new(wifi_device, config, resources, seed);
    spawner.spawn(net_task(runner)).unwrap();

    let client_config = ClientConfig::default()
        .with_ssid(alloc::string::String::from(SSID))
        .with_password(alloc::string::String::from(PASSWORD));
    wifi_controller
        .set_config(&ModeConfig::Client(client_config))
        .unwrap();
    wifi_controller.start().unwrap();
    wifi_controller.connect().unwrap();

    loop {
        if let Some(config_v4) = stack.config_v4() {
            esp_println::println!("IP: {} (target host: {})", config_v4.address, VPS_HOST);
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

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

    let peer = IpEndpoint::new(IpAddress::Ipv4(VPS_IP), VPS_PORT);
    let transport = UdpTransport { socket, peer };

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, SECRET, DEFAULT_PEER_PUB);
    node.set_raw_framing(true);

    let mut handler = EspHandler;
    node.run(&mut handler).await;
}
