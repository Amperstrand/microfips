//! Minimal DHCPv4 server (RFC 2131) for the relay access point.
//!
//! Pure codec + lease table, no sockets: feed a received request plus the
//! current time, get the reply to broadcast. Handles DISCOVER/OFFER,
//! REQUEST/ACK (NAK on a conflicting request), RELEASE, and lease expiry.
//! Fixed pool of `N` addresses starting at `pool_start`; clients are keyed
//! by MAC (chaddr) so a rebooting client gets its previous address back.

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const OP_REQUEST: u8 = 1;
const OP_REPLY: u8 = 2;
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_END: u8 = 255;
const MSG_DISCOVER: u8 = 1;
const MSG_OFFER: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_ACK: u8 = 5;
const MSG_NAK: u8 = 6;
const MSG_RELEASE: u8 = 7;
const HEADER_LEN: usize = 236;
/// BOOTP-compatible minimum reply length.
pub const MIN_REPLY_LEN: usize = 300;
/// Large enough for any reply this server builds.
pub const MAX_REPLY_LEN: usize = 320;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpServerConfig {
    pub server_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    /// First address handed out; the pool is `N` consecutive addresses.
    pub pool_start: [u8; 4],
    pub lease_secs: u32,
}

#[derive(Clone, Copy, Debug)]
struct Lease {
    mac: [u8; 6],
    expires_at: u64,
}

pub struct DhcpServer<const N: usize> {
    cfg: DhcpServerConfig,
    leases: [Option<Lease>; N],
}

struct Request<'a> {
    xid: [u8; 4],
    flags: [u8; 2],
    chaddr: [u8; 6],
    ciaddr: [u8; 4],
    msg_type: u8,
    requested_ip: Option<[u8; 4]>,
    server_id: Option<[u8; 4]>,
    _raw: &'a [u8],
}

fn parse_request(packet: &[u8]) -> Option<Request<'_>> {
    if packet.len() < HEADER_LEN + 4 || packet[0] != OP_REQUEST {
        return None;
    }
    if packet[HEADER_LEN..HEADER_LEN + 4] != MAGIC_COOKIE {
        return None;
    }
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&packet[28..34]);
    let mut req = Request {
        xid: [packet[4], packet[5], packet[6], packet[7]],
        flags: [packet[10], packet[11]],
        chaddr,
        ciaddr: [packet[12], packet[13], packet[14], packet[15]],
        msg_type: 0,
        requested_ip: None,
        server_id: None,
        _raw: packet,
    };
    let mut off = HEADER_LEN + 4;
    while off < packet.len() {
        let code = packet[off];
        if code == OPT_END {
            break;
        }
        if code == 0 {
            off += 1;
            continue;
        }
        let len = *packet.get(off + 1)? as usize;
        let value = packet.get(off + 2..off + 2 + len)?;
        match code {
            OPT_MSG_TYPE if len == 1 => req.msg_type = value[0],
            OPT_REQUESTED_IP if len == 4 => {
                req.requested_ip = Some([value[0], value[1], value[2], value[3]])
            }
            OPT_SERVER_ID if len == 4 => {
                req.server_id = Some([value[0], value[1], value[2], value[3]])
            }
            _ => {}
        }
        off += 2 + len;
    }
    if req.msg_type == 0 {
        return None;
    }
    Some(req)
}

impl<const N: usize> DhcpServer<N> {
    pub const fn new(cfg: DhcpServerConfig) -> Self {
        Self {
            cfg,
            leases: [None; N],
        }
    }

    fn ip_for(&self, idx: usize) -> [u8; 4] {
        let mut ip = self.cfg.pool_start;
        let host = u32::from_be_bytes(ip) + idx as u32;
        ip = host.to_be_bytes();
        ip
    }

    fn idx_for_ip(&self, ip: [u8; 4]) -> Option<usize> {
        let start = u32::from_be_bytes(self.cfg.pool_start);
        let v = u32::from_be_bytes(ip);
        if v >= start && ((v - start) as usize) < N {
            Some((v - start) as usize)
        } else {
            None
        }
    }

    fn find_lease(&self, mac: &[u8; 6], now: u64) -> Option<usize> {
        self.leases
            .iter()
            .position(|l| matches!(l, Some(l) if l.mac == *mac && l.expires_at > now))
    }

    /// Existing lease for this MAC, else a free (or expired) slot.
    fn allocate(&mut self, mac: &[u8; 6], now: u64, preferred: Option<[u8; 4]>) -> Option<usize> {
        if let Some(idx) = self.find_lease(mac, now) {
            return Some(idx);
        }
        let free = |l: &Option<Lease>| match l {
            None => true,
            Some(l) => l.expires_at <= now,
        };
        if let Some(idx) = preferred.and_then(|ip| self.idx_for_ip(ip)) {
            if free(&self.leases[idx]) {
                return Some(idx);
            }
        }
        self.leases.iter().position(free)
    }

    fn commit(&mut self, idx: usize, mac: [u8; 6], now: u64) {
        self.leases[idx] = Some(Lease {
            mac,
            expires_at: now + self.cfg.lease_secs as u64,
        });
    }

    /// Number of live leases at `now`.
    pub fn active_leases(&self, now: u64) -> usize {
        self.leases
            .iter()
            .filter(|l| matches!(l, Some(l) if l.expires_at > now))
            .count()
    }

    /// Process one request. Returns the reply length written into `out`
    /// (broadcast it to 255.255.255.255:68), or `None` if no reply is due.
    pub fn handle(&mut self, packet: &[u8], now: u64, out: &mut [u8]) -> Option<usize> {
        let req = parse_request(packet)?;
        match req.msg_type {
            MSG_DISCOVER => {
                let idx = self.allocate(&req.chaddr, now, req.requested_ip)?;
                let ip = self.ip_for(idx);
                Some(self.build_reply(&req, MSG_OFFER, ip, out))
            }
            MSG_REQUEST => {
                if let Some(sid) = req.server_id {
                    if sid != self.cfg.server_ip {
                        // Client chose another server's offer.
                        return None;
                    }
                }
                let wanted = req.requested_ip.or(if req.ciaddr != [0; 4] {
                    Some(req.ciaddr)
                } else {
                    None
                });
                let idx = match wanted.and_then(|ip| self.idx_for_ip(ip)) {
                    Some(idx) => {
                        let ok = match &self.leases[idx] {
                            None => true,
                            Some(l) => l.mac == req.chaddr || l.expires_at <= now,
                        };
                        if !ok {
                            return Some(self.build_reply(&req, MSG_NAK, [0; 4], out));
                        }
                        idx
                    }
                    None => match self.allocate(&req.chaddr, now, None) {
                        Some(idx) if wanted.is_none() => idx,
                        _ => return Some(self.build_reply(&req, MSG_NAK, [0; 4], out)),
                    },
                };
                self.commit(idx, req.chaddr, now);
                let ip = self.ip_for(idx);
                Some(self.build_reply(&req, MSG_ACK, ip, out))
            }
            MSG_RELEASE => {
                if let Some(idx) = self.find_lease(&req.chaddr, now) {
                    self.leases[idx] = None;
                }
                None
            }
            _ => None,
        }
    }

    fn build_reply(
        &self,
        req: &Request<'_>,
        msg_type: u8,
        yiaddr: [u8; 4],
        out: &mut [u8],
    ) -> usize {
        let cfg = &self.cfg;
        for b in out.iter_mut().take(MIN_REPLY_LEN) {
            *b = 0;
        }
        out[0] = OP_REPLY;
        out[1] = 1; // ethernet
        out[2] = 6;
        out[4..8].copy_from_slice(&req.xid);
        // Always set the broadcast flag: the client has no address yet and
        // we reply to 255.255.255.255 without needing ARP.
        out[10] = req.flags[0] | 0x80;
        out[11] = req.flags[1];
        out[16..20].copy_from_slice(&yiaddr);
        out[20..24].copy_from_slice(&cfg.server_ip);
        out[28..34].copy_from_slice(&req.chaddr);
        out[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&MAGIC_COOKIE);
        let mut off = HEADER_LEN + 4;
        let mut put = |code: u8, value: &[u8]| {
            out[off] = code;
            out[off + 1] = value.len() as u8;
            out[off + 2..off + 2 + value.len()].copy_from_slice(value);
            off += 2 + value.len();
        };
        put(OPT_MSG_TYPE, &[msg_type]);
        put(OPT_SERVER_ID, &cfg.server_ip);
        if msg_type != MSG_NAK {
            put(OPT_LEASE_TIME, &cfg.lease_secs.to_be_bytes());
            put(OPT_SUBNET, &cfg.subnet_mask);
            put(OPT_ROUTER, &cfg.server_ip);
            put(OPT_DNS, &cfg.server_ip);
        }
        out[off] = OPT_END;
        off += 1;
        off.max(MIN_REPLY_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: DhcpServerConfig = DhcpServerConfig {
        server_ip: [192, 168, 4, 1],
        subnet_mask: [255, 255, 255, 0],
        pool_start: [192, 168, 4, 10],
        lease_secs: 600,
    };

    fn request(msg_type: u8, mac: [u8; 6], requested: Option<[u8; 4]>) -> alloc::vec::Vec<u8> {
        let mut p = alloc::vec![0u8; HEADER_LEN];
        p[0] = OP_REQUEST;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        p[28..34].copy_from_slice(&mac);
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
        if let Some(ip) = requested {
            p.extend_from_slice(&[OPT_REQUESTED_IP, 4]);
            p.extend_from_slice(&ip);
        }
        p.push(OPT_END);
        p
    }

    fn reply_type(reply: &[u8]) -> u8 {
        let mut off = HEADER_LEN + 4;
        loop {
            let code = reply[off];
            if code == OPT_MSG_TYPE {
                return reply[off + 2];
            }
            off += 2 + reply[off + 1] as usize;
        }
    }

    fn yiaddr(reply: &[u8]) -> [u8; 4] {
        [reply[16], reply[17], reply[18], reply[19]]
    }

    #[test]
    fn discover_offer_request_ack() {
        let mut srv: DhcpServer<4> = DhcpServer::new(CFG);
        let mac = [2, 0, 0, 0, 0, 1];
        let mut out = [0u8; MAX_REPLY_LEN];
        let n = srv
            .handle(&request(MSG_DISCOVER, mac, None), 0, &mut out)
            .unwrap();
        assert!(n >= MIN_REPLY_LEN);
        assert_eq!(out[0], OP_REPLY);
        assert_eq!(reply_type(&out), MSG_OFFER);
        assert_eq!(yiaddr(&out), [192, 168, 4, 10]);
        assert_eq!(out[10] & 0x80, 0x80, "broadcast flag set");
        assert_eq!(&out[28..34], &mac);

        let n = srv
            .handle(
                &request(MSG_REQUEST, mac, Some([192, 168, 4, 10])),
                1,
                &mut out,
            )
            .unwrap();
        assert!(n >= MIN_REPLY_LEN);
        assert_eq!(reply_type(&out), MSG_ACK);
        assert_eq!(yiaddr(&out), [192, 168, 4, 10]);
        assert_eq!(srv.active_leases(1), 1);
    }

    #[test]
    fn second_client_gets_next_address_and_pool_exhausts() {
        let mut srv: DhcpServer<2> = DhcpServer::new(CFG);
        let mut out = [0u8; MAX_REPLY_LEN];
        for (i, last) in [1u8, 2].iter().enumerate() {
            let mac = [2, 0, 0, 0, 0, *last];
            srv.handle(&request(MSG_DISCOVER, mac, None), 0, &mut out)
                .unwrap();
            let ip = yiaddr(&out);
            assert_eq!(ip, [192, 168, 4, 10 + i as u8]);
            srv.handle(&request(MSG_REQUEST, mac, Some(ip)), 0, &mut out)
                .unwrap();
            assert_eq!(reply_type(&out), MSG_ACK);
        }
        let mac3 = [2, 0, 0, 0, 0, 3];
        assert!(srv
            .handle(&request(MSG_DISCOVER, mac3, None), 0, &mut out)
            .is_none());
    }

    #[test]
    fn rebooting_client_keeps_its_lease_and_expiry_frees_it() {
        let mut srv: DhcpServer<1> = DhcpServer::new(CFG);
        let mut out = [0u8; MAX_REPLY_LEN];
        let a = [2, 0, 0, 0, 0, 0xa];
        let b = [2, 0, 0, 0, 0, 0xb];
        srv.handle(&request(MSG_DISCOVER, a, None), 0, &mut out)
            .unwrap();
        srv.handle(
            &request(MSG_REQUEST, a, Some([192, 168, 4, 10])),
            0,
            &mut out,
        )
        .unwrap();
        // same client again: same address, no NAK
        srv.handle(&request(MSG_DISCOVER, a, None), 100, &mut out)
            .unwrap();
        assert_eq!(yiaddr(&out), [192, 168, 4, 10]);
        // other client while lease live: pool full
        assert!(srv
            .handle(&request(MSG_DISCOVER, b, None), 100, &mut out)
            .is_none());
        // after expiry the slot is reusable
        srv.handle(&request(MSG_DISCOVER, b, None), 700, &mut out)
            .unwrap();
        assert_eq!(yiaddr(&out), [192, 168, 4, 10]);
    }

    #[test]
    fn conflicting_request_is_nakked() {
        let mut srv: DhcpServer<2> = DhcpServer::new(CFG);
        let mut out = [0u8; MAX_REPLY_LEN];
        let a = [2, 0, 0, 0, 0, 0xa];
        let b = [2, 0, 0, 0, 0, 0xb];
        srv.handle(
            &request(MSG_REQUEST, a, Some([192, 168, 4, 10])),
            0,
            &mut out,
        )
        .unwrap();
        assert_eq!(reply_type(&out), MSG_ACK);
        srv.handle(
            &request(MSG_REQUEST, b, Some([192, 168, 4, 10])),
            0,
            &mut out,
        )
        .unwrap();
        assert_eq!(reply_type(&out), MSG_NAK);
        // address outside the pool is refused too
        srv.handle(&request(MSG_REQUEST, b, Some([10, 0, 0, 5])), 0, &mut out)
            .unwrap();
        assert_eq!(reply_type(&out), MSG_NAK);
    }

    #[test]
    fn release_frees_lease_and_garbage_ignored() {
        let mut srv: DhcpServer<1> = DhcpServer::new(CFG);
        let mut out = [0u8; MAX_REPLY_LEN];
        let a = [2, 0, 0, 0, 0, 0xa];
        srv.handle(
            &request(MSG_REQUEST, a, Some([192, 168, 4, 10])),
            0,
            &mut out,
        )
        .unwrap();
        assert_eq!(srv.active_leases(0), 1);
        assert!(srv
            .handle(&request(MSG_RELEASE, a, None), 0, &mut out)
            .is_none());
        assert_eq!(srv.active_leases(0), 0);
        assert!(srv.handle(&[], 0, &mut out).is_none());
        assert!(srv.handle(&[0u8; 300], 0, &mut out).is_none());
        let mut no_type = request(MSG_DISCOVER, a, None);
        no_type.truncate(HEADER_LEN + 4);
        no_type.push(OPT_END);
        assert!(srv.handle(&no_type, 0, &mut out).is_none());
    }
}
