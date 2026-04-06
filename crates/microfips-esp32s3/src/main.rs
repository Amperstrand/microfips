#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

extern crate alloc;

use core::panic::PanicInfo;

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Ipv4Address, Runner, Stack, StackResources};
use embassy_time::{Duration, Timer, with_timeout};
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

// Set via env vars at build time:
//   WIFI_SSID=... WIFI_PASSWORD=... cargo build -p microfips-esp32s3 ...
const WIFI_SSID: &str = env!("WIFI_SSID");
const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");

const VPS_HOST: &str = "orangeclaw.dns4sats.xyz";
const VPS_PORT: u16 = 2121;

const WIFI_DHCP_TIMEOUT_SECS: u64 = 30;
const DNS_TIMEOUT_SECS: u64 = 5;
const DNS_PORT: u16 = 53;
const DNS_QUERY_ID: u16 = 0x4D46;

#[derive(Debug)]
enum DnsResolveError {
    Encode,
    Socket,
    Timeout,
    InvalidResponse,
    NoAnswer,
}

fn write_u16_be(buf: &mut [u8], offset: usize, value: u16) -> Result<(), DnsResolveError> {
    let end = offset + 2;
    if end > buf.len() {
        return Err(DnsResolveError::Encode);
    }
    buf[offset..end].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn read_u16_be(buf: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(offset)?, *buf.get(offset + 1)?]))
}

fn skip_dns_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *buf.get(offset)?;
        if len & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }
        if len == 0 {
            return Some(offset + 1);
        }
        offset += 1 + len as usize;
    }
}

fn encode_dns_a_query(host: &str, out: &mut [u8]) -> Result<usize, DnsResolveError> {
    if out.len() < 12 {
        return Err(DnsResolveError::Encode);
    }

    write_u16_be(out, 0, DNS_QUERY_ID)?;
    write_u16_be(out, 2, 0x0100)?;
    write_u16_be(out, 4, 1)?;
    write_u16_be(out, 6, 0)?;
    write_u16_be(out, 8, 0)?;
    write_u16_be(out, 10, 0)?;

    let mut cursor = 12;
    for label in host.split('.') {
        let label_bytes = label.as_bytes();
        if label_bytes.is_empty() || label_bytes.len() > 63 {
            return Err(DnsResolveError::Encode);
        }

        if cursor + 1 + label_bytes.len() > out.len() {
            return Err(DnsResolveError::Encode);
        }

        out[cursor] = label_bytes.len() as u8;
        cursor += 1;
        out[cursor..cursor + label_bytes.len()].copy_from_slice(label_bytes);
        cursor += label_bytes.len();
    }

    if cursor + 5 > out.len() {
        return Err(DnsResolveError::Encode);
    }

    out[cursor] = 0;
    cursor += 1;
    write_u16_be(out, cursor, 1)?;
    cursor += 2;
    write_u16_be(out, cursor, 1)?;
    cursor += 2;

    Ok(cursor)
}

fn parse_dns_a_response(resp: &[u8]) -> Result<Ipv4Address, DnsResolveError> {
    if resp.len() < 12 {
        return Err(DnsResolveError::InvalidResponse);
    }

    let id = read_u16_be(resp, 0).ok_or(DnsResolveError::InvalidResponse)?;
    if id != DNS_QUERY_ID {
        return Err(DnsResolveError::InvalidResponse);
    }

    let flags = read_u16_be(resp, 2).ok_or(DnsResolveError::InvalidResponse)?;
    if flags & 0x8000 == 0 {
        return Err(DnsResolveError::InvalidResponse);
    }
    if (flags & 0x000F) != 0 {
        return Err(DnsResolveError::NoAnswer);
    }

    let qdcount = read_u16_be(resp, 4).ok_or(DnsResolveError::InvalidResponse)? as usize;
    let ancount = read_u16_be(resp, 6).ok_or(DnsResolveError::InvalidResponse)? as usize;

    let mut cursor = 12;
    for _ in 0..qdcount {
        cursor = skip_dns_name(resp, cursor).ok_or(DnsResolveError::InvalidResponse)?;
        if cursor + 4 > resp.len() {
            return Err(DnsResolveError::InvalidResponse);
        }
        cursor += 4;
    }

    for _ in 0..ancount {
        cursor = skip_dns_name(resp, cursor).ok_or(DnsResolveError::InvalidResponse)?;
        if cursor + 10 > resp.len() {
            return Err(DnsResolveError::InvalidResponse);
        }

        let rtype = read_u16_be(resp, cursor).ok_or(DnsResolveError::InvalidResponse)?;
        cursor += 2;
        let class = read_u16_be(resp, cursor).ok_or(DnsResolveError::InvalidResponse)?;
        cursor += 2;
        cursor += 4;
        let rdlen = read_u16_be(resp, cursor).ok_or(DnsResolveError::InvalidResponse)? as usize;
        cursor += 2;

        if cursor + rdlen > resp.len() {
            return Err(DnsResolveError::InvalidResponse);
        }

        if rtype == 1 && class == 1 && rdlen == 4 {
            let octets = &resp[cursor..cursor + 4];
            return Ok(Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]));
        }

        cursor += rdlen;
    }

    Err(DnsResolveError::NoAnswer)
}

async fn resolve_vps_ipv4(
    stack: Stack<'static>,
    dns_server: Ipv4Address,
    host: &str,
) -> Result<Ipv4Address, DnsResolveError> {
    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_buffer = [0u8; 512];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_buffer = [0u8; 512];

    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    socket.bind(0).map_err(|_| DnsResolveError::Socket)?;

    let mut query = [0u8; 256];
    let query_len = encode_dns_a_query(host, &mut query)?;

    socket
        .send_to(
            &query[..query_len],
            IpEndpoint::new(IpAddress::Ipv4(dns_server), DNS_PORT),
        )
        .await
        .map_err(|_| DnsResolveError::Socket)?;

    let mut response = [0u8; 512];
    let (n, from) = with_timeout(
        Duration::from_secs(DNS_TIMEOUT_SECS),
        socket.recv_from(&mut response),
    )
    .await
    .map_err(|_| DnsResolveError::Timeout)?
    .map_err(|_| DnsResolveError::Socket)?;

    if from.endpoint.addr != IpAddress::Ipv4(dns_server) {
        return Err(DnsResolveError::InvalidResponse);
    }

    parse_dns_a_response(&response[..n])
}

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
            esp_println::println!(
                "ERROR: WiFi DHCP timed out after {}s",
                WIFI_DHCP_TIMEOUT_SECS
            );
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
    let mut node = Node::new(transport, rng, SECRET, DEFAULT_PEER_PUB);
    node.set_raw_framing(true);

    let mut handler = EspHandler;
    node.run(&mut handler).await;
}
