//! DNS A-record resolution over the embassy-net stack (smoltcp DNS socket).
//!
//! Replaces the hand-rolled query encoder/response parser (retired 2026-09-01,
//! issue #184): the maintained smoltcp parser handles compression pointers
//! and truncation edges, and the DNS server address flows in automatically
//! from DHCP via the stack config. Kept: the IPv4-literal short-circuit and
//! the bounded-retry shape the callers rely on.

use embassy_net::{IpAddress, Ipv4Address, Stack};
use embassy_time::{with_timeout, Duration};

use crate::config::DNS_TIMEOUT_SECS;

#[derive(Debug)]
pub enum DnsResolveError {
    Timeout,
    NoAnswer,
}

const DNS_ATTEMPTS: usize = 3;

/// Resolve `host` to an IPv4 address. IPv4 literals pass through without a
/// DNS round-trip. Each attempt is bounded by DNS_TIMEOUT_SECS.
pub async fn resolve_vps_ipv4(
    stack: Stack<'static>,
    host: &str,
) -> Result<Ipv4Address, DnsResolveError> {
    if let Ok(ip) = host.parse::<Ipv4Address>() {
        return Ok(ip);
    }

    for _ in 0..DNS_ATTEMPTS {
        let query = stack.dns_query(host, embassy_net::dns::DnsQueryType::A);
        match with_timeout(Duration::from_secs(DNS_TIMEOUT_SECS), query).await {
            Ok(Ok(addrs)) => {
                if let Some(IpAddress::Ipv4(ip)) = addrs.first() {
                    return Ok(*ip);
                }
                // Resolved but no A record (e.g. AAAA-only): retry won't help.
                return Err(DnsResolveError::NoAnswer);
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    Err(DnsResolveError::Timeout)
}
