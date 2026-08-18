//! Minimal mDNS-SD (RFC 6762/6763) client for FIPS LAN peer discovery.
//!
//! The FIPS daemon (>= 0.4.x with `lan-mdns`) advertises `_fips._udp.local.`
//! with TXT keys `npub=<bech32>`, `scope=<mesh name>`, and `v=<protocol
//! version>`. This module builds the one-shot PTR query and parses the
//! response into the daemon's endpoint + identity hint.
//!
//! Queries sent from an ephemeral port (not 5353) are "legacy" one-shot
//! queries per RFC 6762 §6.7 — responders answer by unicast to the source
//! port, so plain UDP send/recv is sufficient (multicast TX only, no group
//! join). Hardware-verified against fips 0.5.0-dev mdns-sd responders.
//!
//! Trust model (matches the daemon's own): the advert is a routing hint,
//! never identity — the Noise IK handshake against the discovered endpoint
//! is what authenticates the peer.

/// One-shot PTR question for `_fips._udp.local.` (IN class, QM).
pub const FIPS_PTR_QUERY: &[u8] =
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_fips\x04_udp\x05local\x00\x00\x0c\x00\x01";

/// mDNS multicast group / port the query is sent to.
pub const MDNS_GROUP: [u8; 4] = [224, 0, 0, 251];
pub const MDNS_PORT: u16 = 5353;

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;

/// A FIPS daemon advert parsed out of one mDNS response packet.
///
/// Borrows the TXT strings from the packet buffer. Identity is unverified
/// at this point — treat `npub` as a hint until the handshake proves it.
#[derive(Debug, PartialEq, Eq)]
pub struct FipsAdvert<'a> {
    pub addr: [u8; 4],
    pub port: u16,
    pub npub: &'a str,
    pub scope: Option<&'a str>,
    pub version: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MdnsParseError {
    Truncated,
    NotAResponse,
    /// Response parsed, but SRV port, A record, or TXT npub was missing.
    IncompleteAdvert,
}

fn read_u16(packet: &[u8], off: usize) -> Result<u16, MdnsParseError> {
    match packet.get(off..off + 2) {
        Some(b) => Ok(((b[0] as u16) << 8) | b[1] as u16),
        None => Err(MdnsParseError::Truncated),
    }
}

/// Skip an (possibly compressed) DNS name, returning the offset just past it.
fn skip_name(packet: &[u8], mut off: usize) -> Result<usize, MdnsParseError> {
    loop {
        let len = *packet.get(off).ok_or(MdnsParseError::Truncated)? as usize;
        if len == 0 {
            return Ok(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer terminates the name (2 bytes total).
            if off + 2 > packet.len() {
                return Err(MdnsParseError::Truncated);
            }
            return Ok(off + 2);
        }
        if len > 63 {
            return Err(MdnsParseError::Truncated);
        }
        off += 1 + len;
    }
}

fn txt_value<'a>(entry: &'a [u8], key: &str) -> Option<&'a str> {
    let entry = core::str::from_utf8(entry).ok()?;
    entry.strip_prefix(key)?.strip_prefix('=').or_else(|| {
        // `key` alone with no '=' is a present-but-empty boolean per RFC 6763.
        if entry == key {
            Some("")
        } else {
            None
        }
    })
}

/// Parse one mDNS response packet into a [`FipsAdvert`].
///
/// Scans answer + authority + additional records uniformly (mdns-sd puts
/// SRV/TXT/A in additionals) and takes the first SRV port, A address, and
/// TXT `npub`. This assumes one advert per packet, which holds for the
/// daemon's unicast responses; a packet without all three yields
/// [`MdnsParseError::IncompleteAdvert`].
pub fn parse_fips_response(packet: &[u8]) -> Result<FipsAdvert<'_>, MdnsParseError> {
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 {
        return Err(MdnsParseError::NotAResponse);
    }
    let qd = read_u16(packet, 4)?;
    let records = read_u16(packet, 6)?
        .saturating_add(read_u16(packet, 8)?)
        .saturating_add(read_u16(packet, 10)?);

    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_name(packet, off)?;
        off += 4; // qtype + qclass
    }

    let mut addr: Option<[u8; 4]> = None;
    let mut port: Option<u16> = None;
    let mut npub: Option<&str> = None;
    let mut scope: Option<&str> = None;
    let mut version: Option<&str> = None;

    for _ in 0..records {
        off = skip_name(packet, off)?;
        let rtype = read_u16(packet, off)?;
        let rdlen = read_u16(packet, off + 8)? as usize;
        let rdata = packet
            .get(off + 10..off + 10 + rdlen)
            .ok_or(MdnsParseError::Truncated)?;
        off += 10 + rdlen;

        match rtype {
            TYPE_SRV if rdlen >= 6 && port.is_none() => {
                port = Some(((rdata[4] as u16) << 8) | rdata[5] as u16);
            }
            TYPE_A if rdlen == 4 && addr.is_none() => {
                addr = Some([rdata[0], rdata[1], rdata[2], rdata[3]]);
            }
            TYPE_TXT => {
                let mut t = 0usize;
                while t < rdata.len() {
                    let len = rdata[t] as usize;
                    let Some(entry) = rdata.get(t + 1..t + 1 + len) else {
                        break;
                    };
                    if npub.is_none() {
                        npub = txt_value(entry, "npub");
                    }
                    if scope.is_none() {
                        scope = txt_value(entry, "scope");
                    }
                    if version.is_none() {
                        version = txt_value(entry, "v");
                    }
                    t += 1 + len;
                }
            }
            _ => {}
        }
    }

    match (addr, port, npub) {
        (Some(addr), Some(port), Some(npub)) => Ok(FipsAdvert {
            addr,
            port,
            npub,
            scope,
            version,
        }),
        _ => Err(MdnsParseError::IncompleteAdvert),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Real unicast response from fips 0.5.0-dev (mdns-sd) captured on
    /// 2026-08-18: PTR answer + SRV/TXT/A additionals for the daemon at
    /// 192.168.1.97:2121.
    const FIXTURE_HEX: &str = "000084000001000100000003055f66697073045f756470056c6f63616c00000c0001c00c000c000100001194001815666970732d6e7075623176726b757338396a6a7330c00cc02e0021000100000078001e00000000084915666970732d6e7075623176726b757338396a6a7330c017c02e0010000100001194005f446e7075623d6e7075623176726b757338396a6a73303330717a333464663665386e6d7264393672777064653663336563777361667165687677376d346171743770376d6e03763d311573636f70653d666970732d6f7665726c61792d7631c05800010001000000780004c0a80161";

    fn fixture() -> Vec<u8> {
        (0..FIXTURE_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&FIXTURE_HEX[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_real_daemon_response() {
        let packet = fixture();
        let advert = parse_fips_response(&packet).unwrap();
        assert_eq!(advert.addr, [192, 168, 1, 97]);
        assert_eq!(advert.port, 2121);
        assert_eq!(
            advert.npub,
            "npub1vrkus89jjs030qz34df6e8nmrd96rwpde6c3ecwsafqehvw7m4aqt7p7mn"
        );
        assert_eq!(advert.scope, Some("fips-overlay-v1"));
        assert_eq!(advert.version, Some("1"));
    }

    #[test]
    fn advert_npub_decodes_via_bech32() {
        let packet = fixture();
        let advert = parse_fips_response(&packet).unwrap();
        let key = microfips_core::identity::bech32::npub_to_x_only(advert.npub);
        assert!(key.is_some());
        assert_eq!(key.unwrap()[0], 0x60);
    }

    #[test]
    fn rejects_query_packets() {
        assert_eq!(
            parse_fips_response(FIPS_PTR_QUERY),
            Err(MdnsParseError::NotAResponse)
        );
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        let packet = fixture();
        for n in 0..packet.len() {
            // Must never panic, and must never succeed on a truncated packet.
            assert!(parse_fips_response(&packet[..n]).is_err(), "len {}", n);
        }
    }

    #[test]
    fn rejects_response_without_npub() {
        let mut packet = fixture();
        // Corrupt the "npub=" TXT key so no identity hint is found.
        let pos = packet.windows(5).position(|w| w == b"npub=").unwrap();
        packet[pos] = b'x';
        assert_eq!(
            parse_fips_response(&packet),
            Err(MdnsParseError::IncompleteAdvert)
        );
    }
}
