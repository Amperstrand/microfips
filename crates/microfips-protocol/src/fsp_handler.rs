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
/// Responder session-drain window: a NEW initiator's SessionSetup is rejected
/// while the current session (or in-flight handshake) showed activity more
/// recently than this. XK/XX cannot identify the initiator at setup time
/// (its static only arrives in msg3), so without this guard two concurrent
/// initiators reset each other's session state on every retry — each setup
/// arriving mid-flight InvalidState-resets the other's handshake or kills the
/// other's established keys, and neither completes (bench: 2/5 success at 3s
/// spacing, 3/3 at 15s). Once the previous initiator goes quiet for this
/// window, its retry cadence has drained and the new setup is accepted.
const FSP_RESPONDER_DRAIN_SECS: u64 = 10;

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

/// Responder-side duplicate-setup recovery cache (#232): the last
/// accepted setup frame (FSP data bytes) and the full SessionAck
/// datagram answered for it. While that handshake is still
/// AwaitingMsg3, a byte-identical setup is the SAME initiator whose
/// ack was lost (the initiator's retry cache resends exact bytes) —
/// served by resending the cached ack. Mirrors the initiator's
/// `last_setup` resend cache above.
struct ResponderAckCache {
    setup: ([u8; 512], usize),
    ack: ([u8; SESSION_DATAGRAM_BODY_SIZE + 512], usize),
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
    /// Last responder-side session activity (setup accepted, msg3 completed,
    /// or a frame decrypted): drives the FSP_RESPONDER_DRAIN_SECS guard.
    /// Public so tests can backdate it; production code only writes it.
    pub session_activity: Option<Instant>,
    /// Responder drain window (default FSP_RESPONDER_DRAIN_SECS). Public for
    /// tests to shrink to milliseconds; production leaves it at the default.
    pub fsp_drain: Duration,
    pub test_ping: bool,
    pub app: A,
    app_buf: [u8; APP_BUF],
    /// Retry cache: the composed SessionSetup datagram from the last Idle
    /// send. The AwaitingAck retry RESENDS these identical bytes (the
    /// initiator's Noise state is consumed after the first send and cannot
    /// be rebuilt without fresh entropy; a byte-identical resend is also
    /// what the daemon's duplicate-msg1 path answers idempotently — the
    /// bbfa864 class). Without it the retry died permanently and silently.
    last_setup: Option<([u8; SESSION_DATAGRAM_BODY_SIZE + 512], usize)>,
    last_ack: Option<ResponderAckCache>,
    /// Src NodeAddr of the setup that created the current session — the
    /// responder's only pre-msg3 handle on "who is on the other side"
    /// besides the handshake bytes themselves (#232). A routing hint, not
    /// an identity claim: Noise proves the initiator at msg3.
    session_initiator: Option<[u8; 16]>,
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
            session_activity: None,
            fsp_drain: Duration::from_secs(FSP_RESPONDER_DRAIN_SECS),
            test_ping: false,
            app,
            app_buf: [0u8; APP_BUF],
            last_setup: None,
            last_ack: None,
            session_initiator: None,
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
            session_activity: None,
            fsp_drain: Duration::from_secs(FSP_RESPONDER_DRAIN_SECS),
            test_ping: false,
            app,
            app_buf: [0u8; APP_BUF],
            last_setup: None,
            last_ack: None,
            session_initiator: None,
        }
    }

    fn session_live(&self, now: Instant) -> bool {
        match self.session_activity {
            Some(last) => now.duration_since(last) < self.fsp_drain,
            None => false,
        }
    }

    /// The cached ack iff `fsp_data` is byte-identical to the setup that
    /// produced it — the same-initiator retransmission case (#232).
    /// Byte-identity is the only pre-msg3 initiator fingerprint available
    /// (XK/XX statics only arrive in msg3); anything byte-different is
    /// treated as a foreign initiator by the caller.
    fn cached_ack_for_duplicate(&self, fsp_data: &[u8]) -> Option<(&[u8], usize)> {
        let cache = self.last_ack.as_ref()?;
        let (setup_buf, setup_len) = &cache.setup;
        if fsp_data.len() != *setup_len || fsp_data != &setup_buf[..*setup_len] {
            return None;
        }
        let (ack_buf, ack_len) = &cache.ack;
        Some((&ack_buf[..*ack_len], *ack_len))
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
                self.session_activity = None;
            }
            NodeEvent::Error => {
                self.initiator = None;
                self.fsp_timer = None;
                self.session_activity = None;
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
                // Drain guard: the initiator is unidentifiable at setup time
                // (its static only arrives in msg3), so a setup arriving while
                // the current session or handshake was active inside the drain
                // window must NOT reset it — otherwise two concurrent
                // initiators tear each other down on every retry. Stay silent
                // instead; the new initiator's own retry cadence re-sends the
                // setup once the previous session has drained. Two same-
                // initiator exceptions apply (#232, both hardware-measured):
                if self.fsp_session.state() != FspSessionState::Idle
                    && self.session_live(Instant::now())
                {
                    // (1) A byte-identical setup while the handshake it
                    // created is still AwaitingMsg3 is the SAME initiator
                    // retransmitting because our SessionAck was lost — not a
                    // competing initiator. Resend the cached ack
                    // (idempotent, no state reset). Dropping it instead
                    // delayed recovery past the initiator's retry cadence
                    // (first retry at 8s lands inside the 10s window; only
                    // the ~16s drain-expired retry recovered), which cost
                    // rapid same-initiator probes their whole 28s budget
                    // (bench: 0/5 at 3s spacing).
                    if self.fsp_session.state() == FspSessionState::AwaitingMsg3 {
                        if let Some((ack_buf, ack_len)) = self.cached_ack_for_duplicate(fsp_data) {
                            resp[..ack_len].copy_from_slice(ack_buf);
                            self.session_activity = Some(Instant::now());
                            return HandleResult::SendDatagram(ack_len);
                        }
                    }
                    // (2) A setup whose src NodeAddr matches the
                    // initiator of the current session is the SAME node
                    // reconnecting with fresh entropy — its previous
                    // session was torn down without a wire teardown
                    // (daemon probes do exactly this: the probe closes its
                    // session unilaterally, and 3s later the next probe's
                    // fresh setup would otherwise die against the 10s
                    // window while the probe's session stage gives up at
                    // ~5.7s — hardware: alternating fail/ok, 2/5). Let it
                    // through to the reset+accept below. The src addr is a
                    // routing hint only: identity is still proven at msg3,
                    // and a foreign initiator (different src) keeps the
                    // silent drop, so the #224 concurrent-initiator
                    // protection is intact.
                    if self.session_initiator != Some(src_addr) {
                        return HandleResult::None;
                    }
                }
                if self.fsp_session.state() != FspSessionState::Idle {
                    self.fsp_session.reset();
                }
                let ack_len = match self.fsp_session.handle_setup(
                    &self.nsec,
                    &self.fsp_ephemeral,
                    &self.fsp_epoch,
                    fsp_data,
                    &mut resp[SESSION_DATAGRAM_BODY_SIZE..],
                ) {
                    Ok(len) => len,
                    Err(_) => return HandleResult::None,
                };
                self.session_activity = Some(Instant::now());
                self.session_initiator = Some(src_addr);
                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&reply_body);
                // Cache setup + ack so the same initiator's retransmission
                // can be answered idempotently while this handshake is
                // AwaitingMsg3 (#232). Overwritten on every accepted setup,
                // so the cache always describes the current handshake.
                if fsp_data.len() <= 512 {
                    let ack_total = SESSION_DATAGRAM_BODY_SIZE + ack_len;
                    let mut cache = ResponderAckCache {
                        setup: ([0u8; 512], fsp_data.len()),
                        ack: ([0u8; SESSION_DATAGRAM_BODY_SIZE + 512], ack_total),
                    };
                    cache.setup.0[..fsp_data.len()].copy_from_slice(fsp_data);
                    cache.ack.0[..ack_total].copy_from_slice(&resp[..ack_total]);
                    self.last_ack = Some(cache);
                }
                HandleResult::SendDatagram(SESSION_DATAGRAM_BODY_SIZE + ack_len)
            }
            0x03 => {
                if self.fsp_session.handle_msg3(fsp_data).is_err() {
                    return HandleResult::None;
                }
                self.session_activity = Some(Instant::now());
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
                self.session_activity = Some(Instant::now());
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
                    match fsp.handle_ack(fsp_data) {
                        Ok(()) => {
                            let mut msg3_buf = [0u8; 512];
                            if let Ok(msg3_len) = fsp.build_msg3(&self.fsp_epoch, &mut msg3_buf) {
                                let dg_body = microfips_core::fsp::build_session_datagram_body(
                                    &my_addr,
                                    &target_addr,
                                );
                                let dg_len = SESSION_DATAGRAM_BODY_SIZE + msg3_len;
                                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                                resp[SESSION_DATAGRAM_BODY_SIZE
                                    ..SESSION_DATAGRAM_BODY_SIZE + msg3_len]
                                    .copy_from_slice(&msg3_buf[..msg3_len]);
                                self.fsp_timer = Some(
                                    Instant::now() + Duration::from_secs(FSP_MSG3_TIMEOUT_SECS),
                                );
                                return HandleResult::SendDatagram(dg_len);
                            }
                        }
                        // Presence signature (AGENTS doctrine): a repeatedly
                        // rejected SessionAck is otherwise invisible — this
                        // line is what surfaces pin mismatches (#192/#203)
                        // and wire drift on the session layer.
                        Err(_e) => {
                            #[cfg(feature = "log")]
                            log::debug!("fsp: SessionAck rejected ({:?})", _e);
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
                let mut cached = ([0u8; SESSION_DATAGRAM_BODY_SIZE + 512], dg_len);
                cached.0[..dg_len].copy_from_slice(&resp[..dg_len]);
                self.last_setup = Some(cached);
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::SendDatagram(dg_len)
            }
            FspInitiatorState::AwaitingAck => {
                // Retry = resend the IDENTICAL setup (see last_setup). The
                // old reset()-then-rebuild path died permanently: reset
                // nulls the consumed Noise initiator, the Idle rebuild
                // then errored silently with no re-arm — one lost setup
                // killed the session machinery (2026-09-05 bench_xx flake).
                if let Some((buf, len)) = &self.last_setup {
                    let len = *len;
                    resp[..len].copy_from_slice(&buf[..len]);
                    self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                    HandleResult::SendDatagram(len)
                } else {
                    self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                    HandleResult::None
                }
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

    /// Build a fresh initiator's SessionSetup frame (XK msg1 + datagram body)
    /// for `init_secret`, addressed to the responder's derived address.
    fn build_setup_frame(init_secret: [u8; 32]) -> ([u8; 512], usize) {
        build_setup_frame_with_ephemeral(init_secret, [0x77; 32])
    }

    /// Same as [`build_setup_frame`], with an explicit initiator ephemeral —
    /// the reconnect tests use a fresh ephemeral to model the SAME initiator
    /// starting a NEW session (same identity/node addr, different handshake
    /// bytes), which is what a daemon probe sequence looks like to the
    /// responder.
    fn build_setup_frame_with_ephemeral(
        init_secret: [u8; 32],
        ephemeral: [u8; 32],
    ) -> ([u8; 512], usize) {
        let resp_pub = ecdh_pubkey(&[0x22; 32]).unwrap();
        let init_pub = ecdh_pubkey(&init_secret).unwrap();
        let init_xonly: [u8; 32] = parity_normalize(&init_pub)[1..].try_into().unwrap();
        let resp_xonly: [u8; 32] = parity_normalize(&resp_pub)[1..].try_into().unwrap();
        let init_addr = NodeAddr::from_pubkey_x(&init_xonly);
        let resp_addr = NodeAddr::from_pubkey_x(&resp_xonly);

        let mut initiator = FspInitiatorSession::new(&init_secret, &ephemeral, &resp_pub).unwrap();
        let mut setup = [0u8; 512];
        let setup_len = initiator
            .build_setup(init_addr.as_bytes(), resp_addr.as_bytes(), &mut setup)
            .unwrap();
        let mut payload = [0u8; 512];
        payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&build_session_datagram_body(
            init_addr.as_bytes(),
            resp_addr.as_bytes(),
        ));
        payload[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + setup_len]
            .copy_from_slice(&setup[..setup_len]);
        (payload, SESSION_DATAGRAM_BODY_SIZE + setup_len)
    }

    fn fresh_responder() -> FspDualHandler<CapturePeers, 256> {
        FspDualHandler::new_responder(
            [0x22; 32],
            [0x33; 32],
            [0x01, 0, 0, 0, 0, 0, 0, 0],
            CapturePeers::new(),
        )
    }

    /// Regression: a second initiator's SessionSetup arriving while the
    /// current session is active (inside the drain window) must be rejected
    /// WITHOUT destroying the live session — the pre-drain-guard code
    /// InvalidState-reset the established session on every such setup, so two
    /// concurrent initiators tore each other down on every retry (bench: 2/5
    /// success at 3s spacing).
    #[test]
    fn second_initiator_setup_rejected_while_session_active() {
        let mut responder = fresh_responder();
        // Keep the drain window open for the whole test.
        responder.fsp_drain = Duration::from_secs(3600);
        dance_one_data_message(&mut responder);
        assert_eq!(responder.fsp_session.state(), FspSessionState::Established);

        let (payload, len) = build_setup_frame([0x66; 32]);
        let mut buf = [0u8; 512];
        assert_eq!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload[..len], &mut buf),
            HandleResult::None,
            "fresh setup must be silently rejected while the session is live"
        );
        assert_eq!(
            responder.fsp_session.state(),
            FspSessionState::Established,
            "the live session must survive a rejected foreign setup"
        );

        // A third foreign setup is still rejected, and the app handler saw
        // nothing new (no foreign frame decrypted).
        let before = responder.app.count;
        let (payload2, len2) = build_setup_frame([0x77; 32]);
        assert_eq!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload2[..len2], &mut buf),
            HandleResult::None
        );
        assert_eq!(responder.app.count, before);
    }

    /// Once the drain window has passed with no activity, a new initiator's
    /// setup is accepted (the old code only managed this by accident, after
    /// the previous initiator's retries had exhausted).
    #[test]
    fn drained_session_accepts_new_initiator() {
        let mut responder = fresh_responder();
        responder.fsp_drain = Duration::from_secs(3600);
        dance_one_data_message(&mut responder);

        // Shrink the drain window instead of backdating an instant (the
        // host time driver starts near zero; large subtractions overflow).
        responder.fsp_drain = Duration::from_millis(1);

        let (payload, len) = build_setup_frame([0x66; 32]);
        let mut buf = [0u8; 512];
        assert!(
            matches!(
                responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload[..len], &mut buf),
                HandleResult::SendDatagram(_)
            ),
            "a setup after the drain window must be answered with a SessionAck"
        );
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);
    }

    /// A half-open handshake (setup accepted, msg3 never arrived) also holds
    /// the drain guard — a foreign setup must not steal it while fresh, but
    /// is accepted once it has drained.
    #[test]
    fn half_open_handshake_guards_then_drains() {
        let mut responder = fresh_responder();
        responder.fsp_drain = Duration::from_secs(3600);

        let (payload, len) = build_setup_frame([0x11; 32]);
        let mut buf = [0u8; 512];
        assert!(matches!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload[..len], &mut buf),
            HandleResult::SendDatagram(_)
        ));
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);

        let (foreign, flen) = build_setup_frame([0x66; 32]);
        assert_eq!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &foreign[..flen], &mut buf),
            HandleResult::None,
            "a live half-open handshake must not be stolen"
        );
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);

        responder.fsp_drain = Duration::from_millis(1);
        assert!(matches!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &foreign[..flen], &mut buf),
            HandleResult::SendDatagram(_)
        ));
    }

    /// #232: when the responder's SessionAck is lost, the SAME initiator
    /// retransmits its byte-identical SessionSetup (its own retry cache
    /// resends the exact bytes). Inside the drain window this used to be
    /// silently dropped — recovery only via the next drain-expired retry
    /// (~16s at an 8s retry cadence: the first retry at 8s lands inside
    /// the 10s window), which pushed rapid same-initiator probe sequences
    /// past their 28s budget (bench: 0/5 at 3s spacing). The duplicate
    /// must be answered by RESENDING the cached ack — idempotent, no
    /// state reset — so the initiator completes within one retry.
    #[test]
    fn duplicate_setup_inside_drain_resends_cached_ack() {
        let mut responder = fresh_responder();
        // Keep the drain window open for the whole test.
        responder.fsp_drain = Duration::from_secs(3600);

        // One live initiator, kept alive to finish the handshake after
        // the recovered ack (mirrors dance_one_data_message's setup half).
        let init_secret = [0x11u8; 32];
        let resp_pub = ecdh_pubkey(&[0x22; 32]).unwrap();
        let init_pub = ecdh_pubkey(&init_secret).unwrap();
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
        let frame_len = SESSION_DATAGRAM_BODY_SIZE + setup_len;

        // Setup #1: accepted, SessionAck produced — and lost on the way back.
        let mut buf = [0u8; 1024];
        let ack1 = match responder.on_message(
            wire::MSG_SESSION_DATAGRAM,
            &setup_payload[..frame_len],
            &mut buf,
        ) {
            HandleResult::SendDatagram(len) => buf[..len].to_vec(),
            other => panic!("expected SessionAck, got {other:?}"),
        };
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);

        // The same initiator retries the IDENTICAL bytes; the responder is
        // still AwaitingMsg3 inside the drain window.
        let ack2 = match responder.on_message(
            wire::MSG_SESSION_DATAGRAM,
            &setup_payload[..frame_len],
            &mut buf,
        ) {
            HandleResult::SendDatagram(len) => buf[..len].to_vec(),
            other => panic!(
                "duplicate setup inside the drain window must RESEND the cached ack, got {other:?}"
            ),
        };
        assert_eq!(ack1, ack2, "resent ack must be byte-identical (idempotent)");
        assert_eq!(
            responder.fsp_session.state(),
            FspSessionState::AwaitingMsg3,
            "duplicate must not reset the half-open handshake"
        );

        // Full recovery inside one drain window: the resent ack completes
        // the SAME initiator's handshake.
        initiator
            .handle_ack(&ack2[SESSION_DATAGRAM_BODY_SIZE..])
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
        assert_eq!(responder.fsp_session.state(), FspSessionState::Established);
        assert_eq!(initiator.state(), FspInitiatorState::Established);
    }

    /// #232 guard preservation: a FOREIGN setup (different initiator, so a
    /// byte-different frame) inside the drain window is still silently
    /// dropped while a cached ack exists — it must not receive the cached
    /// ack, must not disturb the in-flight handshake, and must not consume
    /// the cache.
    #[test]
    fn foreign_setup_inside_drain_still_rejected() {
        let mut responder = fresh_responder();
        responder.fsp_drain = Duration::from_secs(3600);

        let (payload, len) = build_setup_frame([0x11; 32]);
        let mut buf = [0u8; 1024];
        assert!(matches!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload[..len], &mut buf),
            HandleResult::SendDatagram(_)
        ));
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);

        let (foreign, flen) = build_setup_frame([0x66; 32]);
        assert_eq!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &foreign[..flen], &mut buf),
            HandleResult::None,
            "a foreign setup inside the drain window must still be dropped, not acked"
        );
        assert_eq!(
            responder.fsp_session.state(),
            FspSessionState::AwaitingMsg3,
            "the in-flight handshake must survive the foreign setup"
        );

        // The original initiator's retry is still served afterwards — the
        // foreign frame did not consume or invalidate the cached ack.
        assert!(matches!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload[..len], &mut buf),
            HandleResult::SendDatagram(_)
        ));
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);
    }

    /// #232 (probe path, hardware finding 2026-10-16): the SAME initiator
    /// starting a NEW session (fresh ephemeral, so byte-different setup, same
    /// src NodeAddr) while its OLD session is still Established inside the
    /// drain window must be ACCEPTED — reset + fresh handshake. This is what
    /// back-to-back daemon probes look like: each probe tears its session
    /// down daemon-side without a wire teardown, and the next probe's setup
    /// (3s later) otherwise dies against the 10s window while the probe's own
    /// session stage gives up at ~5.7s (measured 0/5 → alternating 2/5).
    #[test]
    fn same_initiator_reconnect_inside_drain_replaces_established_session() {
        let mut responder = fresh_responder();
        responder.fsp_drain = Duration::from_secs(3600);
        dance_one_data_message(&mut responder);
        assert_eq!(responder.fsp_session.state(), FspSessionState::Established);

        // The SAME initiator ([0x11] identity → same src NodeAddr) opens a
        // NEW session with a fresh ephemeral: different bytes, same identity.
        let (payload, len) = build_setup_frame_with_ephemeral([0x11; 32], [0x88; 32]);
        let mut buf = [0u8; 1024];
        assert!(
            matches!(
                responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload[..len], &mut buf),
                HandleResult::SendDatagram(_)
            ),
            "same-initiator reconnect inside the drain window must get a fresh SessionAck"
        );
        assert_eq!(
            responder.fsp_session.state(),
            FspSessionState::AwaitingMsg3,
            "the stale session must be replaced by the new handshake"
        );
    }

    /// The same-initiator reconnect also applies to a half-open handshake:
    /// if the initiator abandons an AwaitingMsg3 handshake (budget spent) and
    /// starts over with fresh entropy, the fresh setup replaces the stale
    /// half-open one instead of waiting out the drain window.
    #[test]
    fn same_initiator_fresh_setup_replaces_half_open() {
        let mut responder = fresh_responder();
        responder.fsp_drain = Duration::from_secs(3600);

        let (payload, len) = build_setup_frame([0x11; 32]);
        let mut buf = [0u8; 1024];
        assert!(matches!(
            responder.on_message(wire::MSG_SESSION_DATAGRAM, &payload[..len], &mut buf),
            HandleResult::SendDatagram(_)
        ));
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);

        let (fresh, flen) = build_setup_frame_with_ephemeral([0x11; 32], [0x99; 32]);
        assert!(
            matches!(
                responder.on_message(wire::MSG_SESSION_DATAGRAM, &fresh[..flen], &mut buf),
                HandleResult::SendDatagram(_)
            ),
            "same-initiator fresh setup must replace the stale half-open handshake"
        );
        assert_eq!(responder.fsp_session.state(), FspSessionState::AwaitingMsg3);
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
        // carries it. The second dance models a NEW session after the first
        // drained (the responder's drain guard would otherwise — correctly —
        // reject the setup while this session is still live).
        responder.set_link_pubkey(init_xonly);
        responder.session_activity = None;
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

    #[test]
    fn on_tick_awaiting_ack_resends_identical_setup() {
        // The retry arm used to reset() the initiator — nulling the
        // consumed Noise state — so the NEXT Idle arm errored silently
        // (InvalidState, no re-arm): one lost SessionSetup killed the
        // session machinery permanently (bench_xx flake 2026-09-05:
        // fsp_setup_sent=1, zero retries, nothing logged). The retry must
        // RESEND the identical setup bytes — the daemon's duplicate-msg1
        // path answers a byte-identical msg1 idempotently (bbfa864 class).
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
        let first = match handler.on_tick(&mut resp) {
            HandleResult::SendDatagram(len) => resp[..len].to_vec(),
            other => panic!("unexpected on_tick result: {:?}", other),
        };
        // No ack arrives; the retry tick fires:
        match handler.on_tick(&mut resp) {
            HandleResult::SendDatagram(len) => {
                assert_eq!(
                    &resp[..len],
                    &first[..],
                    "retry must resend byte-identical setup"
                );
            }
            other => panic!("retry on_tick must resend the setup, got {:?}", other),
        }
        // And it keeps retrying — not a one-shot:
        match handler.on_tick(&mut resp) {
            HandleResult::SendDatagram(len) => {
                assert_eq!(&resp[..len], &first[..], "third attempt must also resend")
            }
            other => panic!("third on_tick must resend, got {:?}", other),
        }
        assert!(
            handler.fsp_timer.is_some(),
            "timer must stay armed while retrying"
        );
        assert_eq!(
            handler.initiator.as_ref().unwrap().state(),
            FspInitiatorState::AwaitingAck,
            "resend must keep the state machine coherent for the ack"
        );
    }
}
