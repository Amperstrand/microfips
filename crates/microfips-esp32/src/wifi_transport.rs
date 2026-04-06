#![cfg(feature = "wifi")]

extern crate alloc;

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpAddress, IpEndpoint, Ipv4Address, Runner, StackResources};
use embassy_time::{with_timeout, Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_hal::rng::Trng;
use esp_radio::wifi::{ClientConfig, ModeConfig, WifiController, WifiDevice};
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;

use crate::config::*;

#[derive(Debug)]
pub enum WifiError {
    Send,
    Recv,
}

#[derive(Debug)]
pub enum DnsResolveError {
    Encode,
    Socket,
    Timeout,
    InvalidResponse,
    NoAnswer,
}

fn write_u16_be(buf: &mut [u8], offset: usize, val: u16) -> Result<(), DnsResolveError> {
    if offset + 2 > buf.len() {
        return Err(DnsResolveError::Encode);
    }
    buf[offset] = (val >> 8) as u8;
    buf[offset + 1] = val as u8;
    Ok(())
}

fn read_u16_be(buf: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > buf.len() {
        return None;
    }
    Some(((buf[offset] as u16) << 8) | (buf[offset + 1] as u16))
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
    stack: embassy_net::Stack<'static>,
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
            panic!("WiFi DHCP timed out after {}s", WIFI_DHCP_TIMEOUT_SECS);
        }
    };
    esp_println::println!("IP: {} (target: {})", config_v4.address, VPS_HOST);

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
            panic!("DNS resolve failed for {}: {:?}", VPS_HOST, e);
        });
    esp_println::println!("Resolved {} -> {}", VPS_HOST, vps_ip);

    let peer = IpEndpoint::new(IpAddress::Ipv4(vps_ip), VPS_PORT);

    WifiTransport {
        _wifi_controller: wifi_controller,
        socket,
        peer,
    }
}
