//! Minimal IPv6 shim support (FSP port 256): ICMPv6 echo responder.
//!
//! FIPS carries mesh-internal IPv6 over FSP `DataPacket`s addressed to port 256
//! with a compressed header (FIPS `upper/ipv6_shim.rs`):
//!
//! ```text
//! [src_port:2 LE][dst_port:2 LE]                         FSP port header
//! [format:1=0x00][ver_tc_flow:4][next_header:1][hop_limit:1][upper-layer payload]
//! ```
//!
//! Source/destination addresses are stripped; the daemon reconstructs them from
//! the session's node addresses. A leaf node has no IP stack, but answering
//! ICMPv6 echo requests lets `ping <fips-addr>` reach it. Because the only
//! change between request and reply is the ICMPv6 type (128 → 129) and the
//! pseudo-header addresses merely swap (sum-invariant), the checksum is updated
//! incrementally (RFC 1624) without knowing the addresses.

use crate::fsp::FSP_PORT_IPV6_SHIM;

/// `[src_port:2][dst_port:2]` in front of every FSP DataPacket service payload.
pub const FSP_PORT_HEADER_SIZE: usize = 4;
/// Compressed-header format byte.
pub const IPV6_SHIM_FORMAT_COMPRESSED: u8 = 0x00;
/// `format + ver_tc_flow + next_header + hop_limit`.
pub const IPV6_SHIM_HEADER_SIZE: usize = 7;
/// Minimum ICMPv6 message: type, code, checksum, id, seq.
const ICMPV6_ECHO_MIN: usize = 8;

pub const IPPROTO_ICMPV6: u8 = 58;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
const REPLY_HOP_LIMIT: u8 = 64;

/// If `service_payload` (port header included) is an ICMPv6 echo request on the
/// IPv6 shim port, write the matching echo reply (port header included) into
/// `out` and return its length. Returns `None` for anything else or if `out`
/// is too small.
pub fn icmpv6_echo_reply(service_payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let min = FSP_PORT_HEADER_SIZE + IPV6_SHIM_HEADER_SIZE + ICMPV6_ECHO_MIN;
    if service_payload.len() < min || out.len() < service_payload.len() {
        return None;
    }
    let dst_port = u16::from_le_bytes([service_payload[2], service_payload[3]]);
    if dst_port != FSP_PORT_IPV6_SHIM {
        return None;
    }
    let shim = &service_payload[FSP_PORT_HEADER_SIZE..];
    if shim[0] != IPV6_SHIM_FORMAT_COMPRESSED || shim[1] >> 4 != 6 || shim[5] != IPPROTO_ICMPV6 {
        return None;
    }
    let icmp = &shim[IPV6_SHIM_HEADER_SIZE..];
    if icmp[0] != ICMPV6_ECHO_REQUEST || icmp[1] != 0 {
        return None;
    }

    let n = service_payload.len();
    let reply = &mut out[..n];
    reply.copy_from_slice(service_payload);
    // Swap ports (both 256 in practice; keep it symmetric anyway).
    reply[0..2].copy_from_slice(&service_payload[2..4]);
    reply[2..4].copy_from_slice(&service_payload[0..2]);
    let shim_out = &mut reply[FSP_PORT_HEADER_SIZE..];
    shim_out[6] = REPLY_HOP_LIMIT;
    let icmp_out = &mut shim_out[IPV6_SHIM_HEADER_SIZE..];
    icmp_out[0] = ICMPV6_ECHO_REPLY;
    let old_word = u16::from_be_bytes([ICMPV6_ECHO_REQUEST, 0]);
    let new_word = u16::from_be_bytes([ICMPV6_ECHO_REPLY, 0]);
    let old_sum = u16::from_be_bytes([icmp_out[2], icmp_out[3]]);
    let new_sum = checksum_update(old_sum, old_word, new_word);
    icmp_out[2..4].copy_from_slice(&new_sum.to_be_bytes());
    Some(n)
}

/// RFC 1624 incremental checksum update: `HC' = ~(~HC + ~m + m')`.
fn checksum_update(hc: u16, m: u16, m_new: u16) -> u16 {
    let mut sum = (!hc) as u32 + (!m) as u32 + m_new as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full ICMPv6 checksum over pseudo-header + message (RFC 8200 §8.1).
    fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut add = |b: &[u8]| {
            for c in b.chunks(2) {
                let w = ((c[0] as u32) << 8) | (*c.get(1).unwrap_or(&0) as u32);
                sum += w;
            }
        };
        add(src);
        add(dst);
        add(&(icmp.len() as u32).to_be_bytes());
        add(&[0, 0, 0, IPPROTO_ICMPV6]);
        add(icmp);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn build_request(src: &[u8; 16], dst: &[u8; 16], data: &[u8]) -> std::vec::Vec<u8> {
        let mut icmp = std::vec![ICMPV6_ECHO_REQUEST, 0, 0, 0, 0x25, 0x9a, 0, 1];
        icmp.extend_from_slice(data);
        let c = icmpv6_checksum(src, dst, &icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let mut p = std::vec![
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x60,
            0x03,
            0xd3,
            0xeb,
            IPPROTO_ICMPV6,
            0x40
        ];
        p.extend_from_slice(&icmp);
        p
    }

    #[test]
    fn reply_has_valid_checksum_with_swapped_addresses() {
        let src = [0xfd; 16];
        let mut dst = [0xab; 16];
        dst[15] = 0x01;
        let req = build_request(&src, &dst, &[0x10, 0x11, 0x12, 0x13, 0x14]);
        let mut out = [0u8; 128];
        let n = icmpv6_echo_reply(&req, &mut out).expect("echo request recognised");
        assert_eq!(n, req.len());
        let reply = &out[..n];
        assert_eq!(&reply[..4], &[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(reply[4], IPV6_SHIM_FORMAT_COMPRESSED);
        assert_eq!(&reply[5..9], &req[5..9], "ver/tc/flow preserved");
        assert_eq!(reply[9], IPPROTO_ICMPV6);
        assert_eq!(reply[10], REPLY_HOP_LIMIT);
        let icmp = &reply[11..];
        assert_eq!(icmp[0], ICMPV6_ECHO_REPLY);
        assert_eq!(&icmp[4..], &req[15..], "id/seq/data preserved");
        // Reply travels dst -> src; verify the checksum from scratch.
        assert_eq!(icmpv6_checksum(&dst, &src, icmp), 0, "checksum must verify");
    }

    #[test]
    fn ignores_non_echo_and_other_ports() {
        let src = [1u8; 16];
        let dst = [2u8; 16];
        let mut req = build_request(&src, &dst, &[]);
        let mut out = [0u8; 64];
        assert!(icmpv6_echo_reply(&req, &mut out).is_some());
        req[11] = ICMPV6_ECHO_REPLY;
        assert!(icmpv6_echo_reply(&req, &mut out).is_none());
        req[11] = ICMPV6_ECHO_REQUEST;
        req[2] = 0x02;
        assert!(icmpv6_echo_reply(&req, &mut out).is_none());
        req[2] = 0x00;
        assert!(icmpv6_echo_reply(&req, &mut [0u8; 8]).is_none());
        assert!(icmpv6_echo_reply(&req[..10], &mut out).is_none());
    }
}
