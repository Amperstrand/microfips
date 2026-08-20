//! Minimal mDNS-SD responder advertising a FIPS endpoint (`_fips._udp.local.`)
//! on behalf of a relay access point.
//!
//! Mirrors what the FIPS daemon itself advertises (PTR + SRV + TXT + A with
//! TXT keys `npub`, `scope`, `v`), so the same discovery code — microfips
//! nodes' one-shot queries and the daemon's mdns-sd browser — finds the relay
//! exactly like it would find a daemon. Pure codec; the caller owns the
//! socket and decides unicast (legacy query from a non-5353 port) vs
//! multicast delivery.

use crate::mdns::{read_u16, skip_name, TYPE_A, TYPE_ANY, TYPE_PTR, TYPE_SRV, TYPE_TXT};

const SERVICE_LABELS: [&[u8]; 3] = [b"_fips", b"_udp", b"local"];
/// Upper bound on a response built by [`build_fips_response`].
pub const MAX_RESPONSE_LEN: usize = 512;
const TTL_SHORT: u32 = 120;
const TTL_LONG: u32 = 4500;
const CLASS_IN: u16 = 1;
const CLASS_IN_FLUSH: u16 = 0x8001;

/// What a received mDNS query asked for, if it concerns us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FipsQuery {
    /// Transaction id to echo in a unicast (legacy) response.
    pub id: u16,
}

/// Compare the DNS name at `off` (compression-aware) against `labels`
/// optionally prefixed by `first` (the instance/host label).
fn name_is(packet: &[u8], mut off: usize, first: Option<&[u8]>, labels: &[&[u8]]) -> bool {
    let mut expect: [Option<&[u8]>; 4] = [None; 4];
    let mut n = 0;
    if let Some(f) = first {
        expect[n] = Some(f);
        n += 1;
    }
    for l in labels {
        expect[n] = Some(l);
        n += 1;
    }
    let mut idx = 0;
    let mut hops = 0;
    loop {
        let Some(&len) = packet.get(off) else {
            return false;
        };
        if len == 0 {
            return idx == n;
        }
        if len & 0xC0 == 0xC0 {
            let Some(&lo) = packet.get(off + 1) else {
                return false;
            };
            off = (((len & 0x3F) as usize) << 8) | lo as usize;
            hops += 1;
            if hops > 8 {
                return false;
            }
            continue;
        }
        let len = len as usize;
        let Some(label) = packet.get(off + 1..off + 1 + len) else {
            return false;
        };
        if idx >= n {
            return false;
        }
        let want = expect[idx].unwrap();
        if label.len() != want.len() || !label.eq_ignore_ascii_case(want) {
            return false;
        }
        idx += 1;
        off += 1 + len;
    }
}

/// Inspect a packet received on the mDNS port. Returns `Some` if it is a
/// query that our FIPS advert answers: the service PTR, our instance
/// record set, or our host's A record.
pub fn parse_fips_query(packet: &[u8], instance: &str, host: &str) -> Option<FipsQuery> {
    let id = read_u16(packet, 0).ok()?;
    let flags = read_u16(packet, 2).ok()?;
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    let qd = read_u16(packet, 4).ok()?;
    let mut off = 12usize;
    let mut hit = false;
    for _ in 0..qd {
        let qtype = read_u16(packet, skip_name(packet, off).ok()?).ok()?;
        let service = name_is(packet, off, None, &SERVICE_LABELS);
        let inst = name_is(packet, off, Some(instance.as_bytes()), &SERVICE_LABELS);
        let hst = name_is(packet, off, Some(host.as_bytes()), &[b"local"]);
        if (service && (qtype == TYPE_PTR || qtype == TYPE_ANY))
            || (inst && matches!(qtype, TYPE_SRV | TYPE_TXT | TYPE_ANY))
            || (hst && (qtype == TYPE_A || qtype == TYPE_ANY))
        {
            hit = true;
        }
        off = skip_name(packet, off).ok()? + 4;
    }
    hit.then_some(FipsQuery { id })
}

struct Writer<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl Writer<'_> {
    fn put(&mut self, b: &[u8]) -> Option<()> {
        self.buf
            .get_mut(self.off..self.off + b.len())?
            .copy_from_slice(b);
        self.off += b.len();
        Some(())
    }
    fn u16(&mut self, v: u16) -> Option<()> {
        self.put(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> Option<()> {
        self.put(&v.to_be_bytes())
    }
    fn name(&mut self, first: Option<&[u8]>, labels: &[&[u8]]) -> Option<()> {
        if let Some(f) = first {
            self.put(&[f.len() as u8])?;
            self.put(f)?;
        }
        for l in labels {
            self.put(&[l.len() as u8])?;
            self.put(l)?;
        }
        self.put(&[0])
    }
    /// Record header; returns the offset of the RDLENGTH field to patch.
    fn rr_header(&mut self, rtype: u16, class: u16, ttl: u32) -> Option<usize> {
        self.u16(rtype)?;
        self.u16(class)?;
        self.u32(ttl)?;
        let len_at = self.off;
        self.u16(0)?;
        Some(len_at)
    }
    fn patch_len(&mut self, len_at: usize) {
        let rdlen = (self.off - len_at - 2) as u16;
        self.buf[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    }
}

/// Build a FIPS advert response: PTR answer plus SRV/TXT/A additionals.
/// `id` is the query id for a unicast reply (0 for multicast/announce).
/// `instance` and `host` are single DNS labels (no dots). Returns the
/// packet length, or `None` if the buffer or a label is too small/long.
#[allow(clippy::too_many_arguments)]
pub fn build_fips_response(
    out: &mut [u8],
    id: u16,
    instance: &str,
    host: &str,
    ip: [u8; 4],
    port: u16,
    npub: &str,
    scope: Option<&str>,
) -> Option<usize> {
    if instance.len() > 63 || host.len() > 63 || instance.is_empty() || host.is_empty() {
        return None;
    }
    let inst = instance.as_bytes();
    let hst = host.as_bytes();
    let mut w = Writer { buf: out, off: 0 };
    w.u16(id)?;
    w.u16(0x8400)?; // response, authoritative
    w.u16(0)?; // QD
    w.u16(1)?; // AN: PTR
    w.u16(0)?; // NS
    w.u16(3)?; // AR: SRV, TXT, A

    // PTR _fips._udp.local -> <instance>._fips._udp.local
    w.name(None, &SERVICE_LABELS)?;
    let l = w.rr_header(TYPE_PTR, CLASS_IN, TTL_LONG)?;
    w.name(Some(inst), &SERVICE_LABELS)?;
    w.patch_len(l);

    // SRV <instance>._fips._udp.local -> <host>.local:port
    w.name(Some(inst), &SERVICE_LABELS)?;
    let l = w.rr_header(TYPE_SRV, CLASS_IN_FLUSH, TTL_SHORT)?;
    w.u16(0)?;
    w.u16(0)?;
    w.u16(port)?;
    w.name(Some(hst), &[b"local"])?;
    w.patch_len(l);

    // TXT <instance>._fips._udp.local
    w.name(Some(inst), &SERVICE_LABELS)?;
    let l = w.rr_header(TYPE_TXT, CLASS_IN_FLUSH, TTL_LONG)?;
    let mut txt = |key: &str, value: &str| -> Option<()> {
        let len = key.len() + 1 + value.len();
        if len > 255 {
            return None;
        }
        w.put(&[len as u8])?;
        w.put(key.as_bytes())?;
        w.put(b"=")?;
        w.put(value.as_bytes())
    };
    txt("npub", npub)?;
    if let Some(s) = scope {
        txt("scope", s)?;
    }
    txt("v", "1")?;
    w.patch_len(l);

    // A <host>.local -> ip
    w.name(Some(hst), &[b"local"])?;
    let l = w.rr_header(TYPE_A, CLASS_IN_FLUSH, TTL_SHORT)?;
    w.put(&ip)?;
    w.patch_len(l);

    Some(w.off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdns::{parse_fips_response, FIPS_PTR_QUERY};

    const NPUB: &str = "npub1979aung6qusfx4d55ujs5hz39r5ghp9am3se4d7t4r2knvjqaljqevzcrp";

    #[test]
    fn response_roundtrips_through_parser() {
        let mut buf = [0u8; MAX_RESPONSE_LEN];
        let n = build_fips_response(
            &mut buf,
            0x1234,
            "fips-relay-9408",
            "fips-relay",
            [192, 168, 4, 1],
            2121,
            NPUB,
            Some("fips-overlay-v1"),
        )
        .unwrap();
        let advert = parse_fips_response(&buf[..n]).unwrap();
        assert_eq!(advert.addr, [192, 168, 4, 1]);
        assert_eq!(advert.port, 2121);
        assert_eq!(advert.npub, NPUB);
        assert_eq!(advert.scope, Some("fips-overlay-v1"));
        assert_eq!(advert.version, Some("1"));
        assert_eq!(&buf[..2], &[0x12, 0x34]);
        // decoded npub is the gen*5 key
        let key = microfips_core::identity::bech32::npub_to_x_only(advert.npub).unwrap();
        assert_eq!(key[0], 0x2f);
        // a response must never be mistaken for a query
        assert!(parse_fips_query(&buf[..n], "fips-relay-9408", "fips-relay").is_none());
    }

    #[test]
    fn response_without_scope() {
        let mut buf = [0u8; MAX_RESPONSE_LEN];
        let n = build_fips_response(&mut buf, 0, "r", "h", [10, 0, 0, 1], 1, NPUB, None).unwrap();
        let advert = parse_fips_response(&buf[..n]).unwrap();
        assert_eq!(advert.scope, None);
        assert_eq!(advert.version, Some("1"));
    }

    #[test]
    fn oversize_inputs_rejected() {
        let mut buf = [0u8; MAX_RESPONSE_LEN];
        let long = "x".repeat(64);
        assert!(build_fips_response(&mut buf, 0, &long, "h", [0; 4], 1, NPUB, None).is_none());
        assert!(build_fips_response(&mut buf, 0, "", "h", [0; 4], 1, NPUB, None).is_none());
        let mut tiny = [0u8; 40];
        assert!(build_fips_response(&mut tiny, 0, "r", "h", [0; 4], 1, NPUB, None).is_none());
    }

    #[test]
    fn detects_service_ptr_query() {
        let q = parse_fips_query(FIPS_PTR_QUERY, "inst", "host").unwrap();
        assert_eq!(q.id, 0);
    }

    #[test]
    fn detects_instance_and_host_queries_case_insensitively() {
        // SRV query for INST._fips._udp.local
        let mut q = alloc::vec![0u8, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in [&b"INST"[..], b"_FIPS", b"_udp", b"local"] {
            q.push(l.len() as u8);
            q.extend_from_slice(l);
        }
        q.extend_from_slice(&[0, 0, 33, 0, 1]);
        assert_eq!(
            parse_fips_query(&q, "inst", "host"),
            Some(FipsQuery { id: 7 })
        );
        // A query for host.local
        let mut a = alloc::vec![0u8, 9, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in [&b"host"[..], b"local"] {
            a.push(l.len() as u8);
            a.extend_from_slice(l);
        }
        a.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert_eq!(
            parse_fips_query(&a, "inst", "host"),
            Some(FipsQuery { id: 9 })
        );
        // unrelated service
        let mut o = alloc::vec![0u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in [&b"_http"[..], b"_tcp", b"local"] {
            o.push(l.len() as u8);
            o.extend_from_slice(l);
        }
        o.extend_from_slice(&[0, 0, 12, 0, 1]);
        assert!(parse_fips_query(&o, "inst", "host").is_none());
        // truncated
        assert!(parse_fips_query(&q[..20], "inst", "host").is_none());
    }

    #[test]
    fn compressed_name_in_query_is_followed() {
        // question 1: _fips._udp.local PTR; question 2: pointer to offset 12, type ANY
        let mut q = alloc::vec![0u8, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
        for l in [&b"_fips"[..], b"_udp", b"local"] {
            q.push(l.len() as u8);
            q.extend_from_slice(l);
        }
        q.extend_from_slice(&[0, 0, 12, 0, 1]);
        q.extend_from_slice(&[0xC0, 12, 0, 255, 0, 1]);
        assert_eq!(parse_fips_query(&q, "i", "h"), Some(FipsQuery { id: 2 }));
    }
}
