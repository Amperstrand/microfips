//! Ported from fips v0.4.0: `src/node/handlers/session.rs`, `src/node/session_wire.rs`.
//!
//! FspDualHandler / FspAppHandler are microfips-only wrappers not in upstream.

use embassy_time::{Duration, Instant};

use microfips_core::fsp::{
    FspInitiatorSession, FspInitiatorState, FspSession, FspSessionState, FSP_HEADER_SIZE,
    FSP_INNER_HEADER_SIZE, SESSION_DATAGRAM_BODY_SIZE,
};
use microfips_core::identity::NodeAddr;
use microfips_core::noise;
use microfips_core::wire;

use crate::node::{HandleResult, NodeEvent, NodeHandler};

const FSP_START_DELAY_SECS: u64 = 5;
const FSP_RETRY_SECS: u64 = 8;
const FSP_MSG3_TIMEOUT_SECS: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspAppResult {
    None,
    Reply { msg_type: u8, len: usize },
    Disconnect,
}

/// Identity context for an inbound FSP application message (#198).
///
/// `link_pubkey` is the x-only secp256k1 key of the link peer this
/// handler is bound to. Under Noise IK it is cryptographically verified
/// in both roles (the initiator encrypts toward the pinned `rs`; the
/// responder rejects any other MSG1 static). Under Noise XX it is
/// verified in both roles as of #203: the responder verifies the
/// initiator at MSG3, and the initiator compares the responder static
/// learned in MSG2 against the pinned `peer_npub` (mismatch aborts the
/// handshake / abandons the rekey). All-zero is the unprovisioned
/// sentinel — `link_pubkey_is_provisioned()` detects it.
///
/// `src_addr` is the FSP datagram's src NodeAddr — routing-only, set by
/// whichever node forwarded the datagram (typically the daemon); not
/// authenticated unless the application binds it to a trusted key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerContext {
    pub link_pubkey: [u8; 32],
    pub src_addr: Option<NodeAddr>,
}

impl PeerContext {
    /// False while `link_pubkey` is the all-zero unprovisioned sentinel.
    pub fn link_pubkey_is_provisioned(&self) -> bool {
        self.link_pubkey != [0u8; 32]
    }
}

pub trait FspAppHandler {
    fn on_fsp_message(
        &mut self,
        msg_type: u8,
        payload: &[u8],
        response: &mut [u8],
        peer: &PeerContext,
    ) -> FspAppResult;
}

pub struct NoopFspApp;

impl FspAppHandler for NoopFspApp {
    fn on_fsp_message(
        &mut self,
        _msg_type: u8,
        _payload: &[u8],
        _response: &mut [u8],
        _peer: &PeerContext,
    ) -> FspAppResult {
        FspAppResult::None
    }
}

pub struct FspDualHandler<A = NoopFspApp, const APP_BUF: usize = 1024> {
    pub nsec: [u8; 32],
    /// Link peer's x-only pubkey stamped into every PeerContext (#
    /// 198). Derived from `target_pub` in dual mode; `[0u8; 32]` (the
    /// unprovisioned sentinel) in responder mode until
    /// `set_link_pubkey` stamps the pinned peer.
    pub link_pubkey: [u8; 32],
    pub fsp_session: FspSession,
    pub fsp_ephemeral: [u8; 32],
    /// FSP session-layer epoch. Aligned with upstream FIPS which reuses its
    /// `startup_epoch` for both IK (link-layer) and FSP (session-layer) handshakes.
    /// Microfips passes the link-layer epoch from `Node::advance_epoch()` so that
    /// each session attempt uses a unique epoch, enabling upstream restart detection.
    pub fsp_epoch: [u8; 8],
    pub initiator: Option<FspInitiatorSession>,
    pub target_addr: Option<[u8; 16]>,
    pub fsp_timer: Option<Instant>,
    pub test_ping: bool,
    pub app: A,
    app_buf: [u8; APP_BUF],
}

impl<A, const APP_BUF: usize> FspDualHandler<A, APP_BUF> {
    pub fn new_responder(nsec: [u8; 32], ephemeral: [u8; 32], fsp_epoch: [u8; 8], app: A) -> Self {
        Self {
            nsec,
            link_pubkey: [0u8; 32],
            fsp_session: FspSession::new(),
            fsp_ephemeral: ephemeral,
            fsp_epoch,
            initiator: None,
            target_addr: None,
            fsp_timer: None,
            test_ping: false,
            app,
            app_buf: [0u8; APP_BUF],
        }
    }

    /// Create a dual-mode handler: can both respond to incoming FSP sessions
    /// AND initiate outgoing FSP sessions to a specific target.
    ///
    /// Uses separate ephemeral keys for responder and initiator paths
    /// (cryptographic requirement — reusing the same ephemeral in both
    /// directions leaks key material).
    pub fn new_dual(
        nsec: [u8; 32],
        responder_ephemeral: [u8; 32],
        initiator_ephemeral: [u8; 32],
        target_pub: &[u8; 33],
        target_addr: [u8; 16],
        fsp_epoch: [u8; 8],
        app: A,
    ) -> Self {
        let initiator = FspInitiatorSession::new(&nsec, &initiator_ephemeral, target_pub).ok();
        Self {
            nsec,
            link_pubkey: target_pub[1..33]
                .try_into()
                .expect("33-byte compressed pubkey"),
            fsp_session: FspSession::new(),
            fsp_ephemeral: responder_ephemeral,
            fsp_epoch,
            initiator,
            target_addr: Some(target_addr),
            fsp_timer: None,
            test_ping: false,
            app,
            app_buf: [0u8; APP_BUF],
        }
    }

    /// Stamp the link peer's x-only pubkey for responder-mode handlers
    /// (`new_dual` derives it automatically from its target). Composition
    /// roots that pin the link peer (IK deployments always do) should
    /// call this so `PeerContext.link_pubkey` is meaningful.
    pub fn set_link_pubkey(&mut self, pk: [u8; 32]) {
        self.link_pubkey = pk;
    }

    pub fn on_event_default(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => {}
            NodeEvent::Msg1Sent => {}
            NodeEvent::HandshakeOk => {
                self.fsp_session.reset();
                if self.initiator.is_some() {
                    self.fsp_timer =
                        Some(Instant::now() + Duration::from_secs(FSP_START_DELAY_SECS));
                }
            }
            NodeEvent::HeartbeatSent => {}
            NodeEvent::HeartbeatRecv => {}
            NodeEvent::Disconnected => {
                self.initiator = None;
                self.fsp_timer = None;
            }
            NodeEvent::Error => {
                self.initiator = None;
                self.fsp_timer = None;
            }
        }
    }

    fn handle_responder(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult
    where
        A: FspAppHandler,
    {
        if msg_type != wire::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        if payload.len() < SESSION_DATAGRAM_BODY_SIZE {
            return HandleResult::None;
        }

        let Ok(src_addr) = payload[3..19].try_into() else {
            return HandleResult::None;
        };
        let Ok(dst_addr) = payload[19..35].try_into() else {
            return HandleResult::None;
        };
        let reply_body = microfips_core::fsp::build_session_datagram_body(&dst_addr, &src_addr);
        let fsp_data = &payload[SESSION_DATAGRAM_BODY_SIZE..];
        if fsp_data.is_empty() {
            return HandleResult::None;
        }

        match fsp_data[0] & 0x0F {
            0x01 => {
                if resp.len() <= SESSION_DATAGRAM_BODY_SIZE {
                    return HandleResult::None;
                }
                let ack_len = match self.fsp_session.handle_setup(
                    &self.nsec,
                    &self.fsp_ephemeral,
                    &self.fsp_epoch,
                    fsp_data,
                    &mut resp[SESSION_DATAGRAM_BODY_SIZE..],
                ) {
                    Ok(len) => len,
                    Err(microfips_core::fsp::FspSessionError::InvalidState) => {
                        self.fsp_session.reset();
                        match self.fsp_session.handle_setup(
                            &self.nsec,
                            &self.fsp_ephemeral,
                            &self.fsp_epoch,
                            fsp_data,
                            &mut resp[SESSION_DATAGRAM_BODY_SIZE..],
                        ) {
                            Ok(len) => len,
                            Err(_) => return HandleResult::None,
                        }
                    }
                    Err(_) => return HandleResult::None,
                };
                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&reply_body);
                HandleResult::SendDatagram(SESSION_DATAGRAM_BODY_SIZE + ack_len)
            }
            0x03 => {
                if self.fsp_session.handle_msg3(fsp_data).is_err() {
                    return HandleResult::None;
                }
                HandleResult::None
            }
            0x00 => {
                if self.fsp_session.state() != FspSessionState::Established {
                    return HandleResult::None;
                }
                let Some((flags, counter, header, encrypted)) =
                    microfips_core::fsp::parse_fsp_encrypted_header(fsp_data)
                else {
                    return HandleResult::None;
                };
                if flags & microfips_core::fsp::FLAG_UNENCRYPTED != 0 {
                    return HandleResult::None;
                }

                let Some((k_recv, k_send)) = self.fsp_session.session_keys() else {
                    return HandleResult::None;
                };
                let Ok(decrypted_len) =
                    noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut self.app_buf)
                else {
                    return HandleResult::None;
                };
                let Some((_ts, inner_msg_type, _inner_flags, inner_payload)) =
                    microfips_core::fsp::fsp_strip_inner_header(&self.app_buf[..decrypted_len])
                else {
                    return HandleResult::None;
                };

                let app_offset =
                    SESSION_DATAGRAM_BODY_SIZE + FSP_HEADER_SIZE + FSP_INNER_HEADER_SIZE;
                if resp.len() <= app_offset {
                    return HandleResult::None;
                }
                // Mesh IPv6 (shim port 256): answer ICMPv6 echo so `ping <fips-addr>`
                // reaches a leaf without an IP stack. Everything else goes to the app.
                let shim_reply = if inner_msg_type == microfips_core::fsp::FSP_MSG_DATA {
                    microfips_core::ipv6_shim::icmpv6_echo_reply(
                        inner_payload,
                        &mut resp[app_offset..],
                    )
                } else {
                    None
                };
                let app_result = match shim_reply {
                    Some(len) => FspAppResult::Reply {
                        msg_type: microfips_core::fsp::FSP_MSG_DATA,
                        len,
                    },
                    None => {
                        let peer = PeerContext {
                            link_pubkey: self.link_pubkey,
                            src_addr: Some(NodeAddr(src_addr)),
                        };
                        self.app.on_fsp_message(
                            inner_msg_type,
                            inner_payload,
                            &mut resp[app_offset..],
                            &peer,
                        )
                    }
                };
                match app_result {
                    FspAppResult::None => HandleResult::None,
                    FspAppResult::Disconnect => HandleResult::Disconnect,
                    FspAppResult::Reply { msg_type, len } => {
                        let plaintext_len = microfips_core::fsp::fsp_prepend_inner_header(
                            0,
                            msg_type,
                            0x00,
                            &resp[app_offset..app_offset + len],
                            &mut self.app_buf,
                        );
                        if plaintext_len == 0 {
                            return HandleResult::None;
                        }
                        let send_ctr = self.fsp_session.next_send_counter();
                        let header = microfips_core::fsp::build_fsp_header(
                            send_ctr,
                            0x00,
                            (plaintext_len + microfips_core::noise::TAG_SIZE) as u16,
                        );
                        let ciphertext_offset = SESSION_DATAGRAM_BODY_SIZE + FSP_HEADER_SIZE;
                        let max_ciphertext = resp.len().saturating_sub(ciphertext_offset);
                        if max_ciphertext < plaintext_len + microfips_core::noise::TAG_SIZE {
                            return HandleResult::None;
                        }
                        let Ok(ciphertext_len) = noise::aead_encrypt(
                            &k_send,
                            send_ctr,
                            &header,
                            &self.app_buf[..plaintext_len],
                            &mut resp[ciphertext_offset
                                ..ciphertext_offset
                                    + plaintext_len
                                    + microfips_core::noise::TAG_SIZE],
                        ) else {
                            return HandleResult::None;
                        };
                        resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&reply_body);
                        resp[SESSION_DATAGRAM_BODY_SIZE..ciphertext_offset]
                            .copy_from_slice(&header);
                        HandleResult::SendDatagram(ciphertext_offset + ciphertext_len)
                    }
                }
            }
            _ => HandleResult::None,
        }
    }

    fn handle_initiator(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != wire::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        let target_addr = match &self.target_addr {
            Some(a) => *a,
            None => return HandleResult::None,
        };
        let my_addr = match self.my_addr() {
            Some(a) => a,
            None => return HandleResult::None,
        };
        let fsp = match &mut self.initiator {
            Some(f) => f,
            None => return HandleResult::None,
        };
        if payload.len() < SESSION_DATAGRAM_BODY_SIZE {
            return HandleResult::None;
        }
        let fsp_data = &payload[SESSION_DATAGRAM_BODY_SIZE..];
        if fsp_data.is_empty() {
            return HandleResult::None;
        }
        let fsp_phase = fsp_data[0] & 0x0F;

        match fsp.state() {
            FspInitiatorState::Idle => {}
            FspInitiatorState::AwaitingAck => {
                if fsp_phase == 0x02 {
                    if let Ok(()) = fsp.handle_ack(fsp_data) {
                        let mut msg3_buf = [0u8; 512];
                        if let Ok(msg3_len) = fsp.build_msg3(&self.fsp_epoch, &mut msg3_buf) {
                            let dg_body = microfips_core::fsp::build_session_datagram_body(
                                &my_addr,
                                &target_addr,
                            );
                            let dg_len = SESSION_DATAGRAM_BODY_SIZE + msg3_len;
                            resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                            resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + msg3_len]
                                .copy_from_slice(&msg3_buf[..msg3_len]);
                            self.fsp_timer =
                                Some(Instant::now() + Duration::from_secs(FSP_MSG3_TIMEOUT_SECS));
                            return HandleResult::SendDatagram(dg_len);
                        }
                    }
                }
            }
            FspInitiatorState::AwaitingEstablished => {
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
            }
            FspInitiatorState::Established => {
                if fsp_phase == 0x00 {
                    let Some((flags, counter, header, encrypted)) =
                        microfips_core::fsp::parse_fsp_encrypted_header(fsp_data)
                    else {
                        return HandleResult::None;
                    };
                    if flags & microfips_core::fsp::FLAG_UNENCRYPTED != 0 {
                        return HandleResult::None;
                    }
                    let (k_recv, _) = match fsp.session_keys() {
                        Some(keys) => keys,
                        None => return HandleResult::None,
                    };
                    let mut dec = [0u8; 512];
                    let Ok(dl) = noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut dec)
                    else {
                        return HandleResult::None;
                    };
                    let Some((_ts, _mt, _flags, inner_payload)) =
                        microfips_core::fsp::fsp_strip_inner_header(&dec[..dl])
                    else {
                        return HandleResult::None;
                    };
                    if inner_payload == b"PONG" && self.test_ping {
                        return HandleResult::Disconnect;
                    }
                }
            }
        }
        HandleResult::None
    }

    fn my_addr(&self) -> Option<[u8; 16]> {
        let pub_key = noise::ecdh_pubkey(&self.nsec).ok()?;
        let normalized = noise::parity_normalize(&pub_key);
        let x_only: [u8; 32] = normalized[1..].try_into().ok()?;
        Some(microfips_core::identity::NodeAddr::from_pubkey_x(&x_only).0)
    }

    fn send_ping(&mut self, resp: &mut [u8]) -> HandleResult {
        let target_addr = match &self.target_addr {
            Some(a) => *a,
            None => return HandleResult::None,
        };
        let my_addr = match self.my_addr() {
            Some(a) => a,
            None => return HandleResult::None,
        };
        let fsp = match &mut self.initiator {
            Some(f) => f,
            None => return HandleResult::None,
        };
        let dg_body = microfips_core::fsp::build_session_datagram_body(&my_addr, &target_addr);
        let (_k_recv, k_send) = match fsp.session_keys() {
            Some(k) => k,
            None => return HandleResult::None,
        };
        let send_ctr = fsp.next_send_counter();
        let ping = b"PING";
        let ts = 0u32;
        let mut fsp_packet = [0u8; 512];
        let fsp_total = match microfips_core::fsp::build_fsp_data_message(
            send_ctr,
            ts,
            ping,
            &k_send,
            &mut fsp_packet,
        ) {
            Ok(len) => len,
            Err(_) => return HandleResult::None,
        };
        let dg_len = SESSION_DATAGRAM_BODY_SIZE + fsp_total;
        resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
        resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + fsp_total]
            .copy_from_slice(&fsp_packet[..fsp_total]);
        self.fsp_timer = Some(Instant::now() + Duration::from_secs(10));
        HandleResult::SendDatagram(dg_len)
    }
}

impl<A: FspAppHandler, const APP_BUF: usize> NodeHandler for FspDualHandler<A, APP_BUF> {
    async fn on_event(&mut self, event: NodeEvent) {
        self.on_event_default(event);
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        let r = self.handle_responder(msg_type, payload, resp);
        let r = if r != HandleResult::None {
            r
        } else {
            self.handle_initiator(msg_type, payload, resp)
        };
        #[cfg(feature = "log")]
        if msg_type == wire::MSG_SESSION_DATAGRAM && payload.len() > SESSION_DATAGRAM_BODY_SIZE {
            let fsp_type = payload[SESSION_DATAGRAM_BODY_SIZE] & 0x0F;
            log::info!(
                "fsp: datagram in len={} fsp_type=0x{:02x} src={:02x}{:02x}..{:02x}{:02x} -> {:?}",
                payload.len(),
                fsp_type,
                payload[3],
                payload[4],
                payload[17],
                payload[18],
                r
            );
        }
        r
    }

    fn poll_at(&self) -> Option<Instant> {
        self.fsp_timer
    }

    fn on_tick(&mut self, resp: &mut [u8]) -> HandleResult {
        let target_addr = match &self.target_addr {
            Some(a) => *a,
            None => return HandleResult::None,
        };
        let my_addr = match self.my_addr() {
            Some(a) => a,
            None => return HandleResult::None,
        };
        let fsp = match &mut self.initiator {
            Some(f) => f,
            None => return HandleResult::None,
        };

        match fsp.state() {
            FspInitiatorState::Idle => {
                let dg_body =
                    microfips_core::fsp::build_session_datagram_body(&my_addr, &target_addr);
                let mut setup_buf = [0u8; 512];
                let setup_len = match fsp.build_setup(&my_addr, &target_addr, &mut setup_buf) {
                    Ok(l) => l,
                    Err(_) => return HandleResult::None,
                };
                let dg_len = SESSION_DATAGRAM_BODY_SIZE + setup_len;
                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + setup_len]
                    .copy_from_slice(&setup_buf[..setup_len]);
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::SendDatagram(dg_len)
            }
            FspInitiatorState::AwaitingAck => {
                fsp.reset();
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::None
            }
            FspInitiatorState::AwaitingEstablished => {
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::None
            }
            FspInitiatorState::Established => self.send_ping(resp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microfips_core::fsp::build_fsp_data_message;
    use microfips_core::fsp::build_session_datagram_body;
    use microfips_core::identity::NodeAddr;
    use microfips_core::identity::STM32_NSEC;
    use microfips_core::noise::ecdh_pubkey;
    use microfips_core::noise::parity_normalize;

    fn test_target_pub() -> [u8; 33] {
        ecdh_pubkey(&[0x22; 32]).unwrap()
    }

    struct CapturePeers {
        peers: [PeerContext; 4],
        count: usize,
    }

    impl CapturePeers {
        fn new() -> Self {
            Self {
                peers: [PeerContext {
                    link_pubkey: [0xff; 32],
                    src_addr: None,
                }; 4],
                count: 0,
            }
        }

        fn captured(&self) -> &[PeerContext] {
            &self.peers[..self.count.min(self.peers.len())]
        }
    }

    impl FspAppHandler for CapturePeers {
        fn on_fsp_message(
            &mut self,
            _msg_type: u8,
            _payload: &[u8],
            _response: &mut [u8],
            peer: &PeerContext,
        ) -> FspAppResult {
            if self.count < self.peers.len() {
                self.peers[self.count] = *peer;
            }
            self.count += 1;
            FspAppResult::None
        }
    }

    /// Drive a full FSP session (setup -> ack -> msg3 -> one data
    /// message) from a fresh initiator into `responder`, so its app
    /// handler observes exactly one PeerContext. Returns the
    /// initiator's NodeAddr.
    fn dance_one_data_message(responder: &mut FspDualHandler<CapturePeers, 256>) -> NodeAddr {
        let init_secret = [0x11u8; 32];
        let resp_secret = [0x22u8; 32];
        let init_pub = ecdh_pubkey(&init_secret).unwrap();
        let resp_pub = ecdh_pubkey(&resp_secret).unwrap();
        let init_xonly: [u8; 32] = parity_normalize(&init_pub)[1..].try_into().unwrap();
        let resp_xonly: [u8; 32] = parity_normalize(&resp_pub)[1..].try_into().unwrap();
        let init_addr = NodeAddr::from_pubkey_x(&init_xonly);
        let resp_addr = NodeAddr::from_pubkey_x(&resp_xonly);

        let mut initiator = FspInitiatorSession::new(&init_secret, &[0x44; 32], &resp_pub).unwrap();

        let mut setup = [0u8; 512];
        let setup_len = initiator
            .build_setup(init_addr.as_bytes(), resp_addr.as_bytes(), &mut setup)
            .unwrap();
        let mut setup_payload = [0u8; 512];
        setup_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&build_session_datagram_body(
            init_addr.as_bytes(),
            resp_addr.as_bytes(),
        ));
        setup_payload[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + setup_len]
            .copy_from_slice(&setup[..setup_len]);

        let mut buf = [0u8; 512];
        let ack_len = match responder.on_message(
            wire::MSG_SESSION_DATAGRAM,
            &setup_payload[..SESSION_DATAGRAM_BODY_SIZE + setup_len],
            &mut buf,
        ) {
            HandleResult::SendDatagram(len) => len,
            other => panic!("expected SessionAck, got {other:?}"),
        };
        initiator
            .handle_ack(&buf[SESSION_DATAGRAM_BODY_SIZE..ack_len])
            .unwrap();

        let mut msg3 = [0u8; 512];
        let msg3_len = initiator
            .build_msg3(&responder.fsp_epoch, &mut msg3)
            .unwrap();
        let mut msg3_payload = [0u8; 512];
        msg3_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&build_session_datagram_body(
            init_addr.as_bytes(),
            resp_addr.as_bytes(),
        ));
        msg3_payload[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + msg3_len]
            .copy_from_slice(&msg3[..msg3_len]);
        assert_eq!(
            responder.on_message(
                wire::MSG_SESSION_DATAGRAM,
                &msg3_payload[..SESSION_DATAGRAM_BODY_SIZE + msg3_len],
                &mut buf,
            ),
            HandleResult::None
        );
        assert_eq!(initiator.state(), FspInitiatorState::Established);

        let (_k_recv, k_send) = initiator.session_keys().unwrap();
        let mut fsp_packet = [0u8; 256];
        let fsp_len = build_fsp_data_message(0, 0, b"peer", &k_send, &mut fsp_packet).unwrap();
        let mut data_payload = [0u8; 512];
        data_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&build_session_datagram_body(
            init_addr.as_bytes(),
            resp_addr.as_bytes(),
        ));
        data_payload[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + fsp_len]
            .copy_from_slice(&fsp_packet[..fsp_len]);
        assert_eq!(
            responder.on_message(
                wire::MSG_SESSION_DATAGRAM,
                &data_payload[..SESSION_DATAGRAM_BODY_SIZE + fsp_len],
                &mut buf,
            ),
            HandleResult::None
        );
        init_addr
    }

    #[test]
    fn peer_context_carries_dual_target_link_pubkey_and_src_addr() {
        let init_pub = ecdh_pubkey(&[0x11; 32]).unwrap();
        let init_xonly: [u8; 32] = parity_normalize(&init_pub)[1..].try_into().unwrap();
        let expected_src = NodeAddr::from_pubkey_x(&init_xonly);

        let mut responder: FspDualHandler<CapturePeers, 256> = FspDualHandler::new_dual(
            [0x22; 32],
            [0x33; 32],
            [0x55; 32],
            &init_pub,
            [0x33; 16],
            [0x01, 0, 0, 0, 0, 0, 0, 0],
            CapturePeers::new(),
        );
        let src = dance_one_data_message(&mut responder);

        let captured = responder.app.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].link_pubkey, init_xonly);
        assert!(captured[0].link_pubkey_is_provisioned());
        assert_eq!(captured[0].src_addr, Some(src));
        assert_eq!(src, expected_src);
    }

    #[test]
    fn peer_context_sentinel_until_stamped_in_responder_mode() {
        let init_pub = ecdh_pubkey(&[0x11; 32]).unwrap();
        let init_xonly: [u8; 32] = parity_normalize(&init_pub)[1..].try_into().unwrap();

        let mut responder: FspDualHandler<CapturePeers, 256> = FspDualHandler::new_responder(
            [0x22; 32],
            [0x33; 32],
            [0x01, 0, 0, 0, 0, 0, 0, 0],
            CapturePeers::new(),
        );
        let src = dance_one_data_message(&mut responder);
        let captured = responder.app.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].link_pubkey, [0u8; 32]);
        assert!(!captured[0].link_pubkey_is_provisioned());
        assert_eq!(captured[0].src_addr, Some(src));

        // Stamp the pinned peer and verify the next observed message
        // carries it.
        responder.set_link_pubkey(init_xonly);
        dance_one_data_message(&mut responder);
        let captured = responder.app.captured();
        assert!(captured.len() >= 2);
        assert_eq!(captured[1].link_pubkey, init_xonly);
    }

    #[test]
    fn dual_handler_starts_timer_after_handshake() {
        let mut handler: FspDualHandler<_, 1024> = FspDualHandler::new_dual(
            STM32_NSEC,
            [0x11; 32],
            [0x22; 32],
            &test_target_pub(),
            [0x33; 16],
            [0x01, 0, 0, 0, 0, 0, 0, 0],
            NoopFspApp,
        );
        assert_eq!(handler.fsp_timer, None);
        handler.on_event_default(NodeEvent::HandshakeOk);
        assert!(handler.fsp_timer.is_some());
    }

    #[test]
    fn responder_handler_does_not_start_timer_after_handshake() {
        let mut handler: FspDualHandler<_, 1024> = FspDualHandler::new_responder(
            STM32_NSEC,
            [0x11; 32],
            [0x01, 0, 0, 0, 0, 0, 0, 0],
            NoopFspApp,
        );
        handler.on_event_default(NodeEvent::HandshakeOk);
        assert_eq!(handler.fsp_timer, None);
    }

    #[test]
    fn on_tick_from_idle_builds_session_setup() {
        let mut handler: FspDualHandler<_, 1024> = FspDualHandler::new_dual(
            STM32_NSEC,
            [0x11; 32],
            [0x22; 32],
            &test_target_pub(),
            [0x33; 16],
            [0x01, 0, 0, 0, 0, 0, 0, 0],
            NoopFspApp,
        );
        let mut resp = [0u8; 512];
        let result = handler.on_tick(&mut resp);
        match result {
            HandleResult::SendDatagram(len) => {
                assert!(len > SESSION_DATAGRAM_BODY_SIZE);
                assert_eq!(
                    handler.initiator.as_ref().unwrap().state(),
                    FspInitiatorState::AwaitingAck
                );
                assert!(handler.fsp_timer.is_some());
            }
            other => panic!("unexpected on_tick result: {:?}", other),
        }
    }
}
