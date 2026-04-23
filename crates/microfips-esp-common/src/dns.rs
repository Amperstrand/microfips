use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Ipv4Address, Stack};
use embassy_time::{with_timeout, Duration};

use crate::config::*;

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

pub async fn resolve_vps_ipv4(
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
