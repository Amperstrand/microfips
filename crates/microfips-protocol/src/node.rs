//! Ported from fips v0.4.0: `src/node/mod.rs`, `src/node/handlers/{dispatch,handshake,encrypted,session}.rs`, `src/node/{wire,session_wire}.rs`.
//!
//! ## Deviations from fips
//! - Combined 6+ upstream files into one for no_std simplicity.
//! - Custom transport/framing abstractions replace upstream's concrete-handle approach.
//! - Leaf-node-only: no routing, no spanning tree, no bloom filters.

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};
use microfips_core::wire;

use crate::error::ProtocolError;
use crate::framing;
use crate::peer_policy::{PeerPolicy, PeerPolicyTiming, PolicyVerdict};
use crate::transport::{CryptoRng, RngCore, Transport};

macro_rules! log_steady {
    ($($arg:tt)*) => {
        #[cfg(feature = "log")]
        log::info!($($arg)*);
    };
}

pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 10;
pub const DEFAULT_LINK_DEAD_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_RETRY_BASE_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_RETRY_MAX_BACKOFF_SECS: u64 = 300;
pub const DEFAULT_HANDSHAKE_RESEND_INTERVAL_MS: u64 = 3_000;
pub const DEFAULT_HANDSHAKE_RESEND_BACKOFF: u64 = 1;
pub const DEFAULT_HANDSHAKE_MAX_RESENDS: u32 = 10;
pub const DEFAULT_CONNECT_DELAY_MS: u64 = 500;
pub const MAX_COMPETING_MSG1: u32 = 3;

pub const RECV_BUF_SIZE: usize = 1500;
pub const MAX_FRAME_SIZE: usize = 2048;

/// Retain the drained epoch this long after its last authenticated use
/// (fips `node/handlers/rekey.rs:26`, peer-progress-aware).
const DRAIN_WINDOW_SECS: u64 = 10;

/// Suppress self-initiated rekey for this long after the peer initiated
/// one (dual-init protection; fips `rekey.rs:30`).
const REKEY_DAMPENING_SECS: u64 = 30;

/// In-flight self-initiated rekey: the initiator handshake state plus the
/// cached msg1 for the resend ladder (fips `set_rekey_state` analog).
struct RekeyInit {
    #[cfg(not(feature = "noise-xx"))]
    hs: microfips_core::noise::NoiseIkInitiator,
    #[cfg(feature = "noise-xx")]
    hs: microfips_core::noise::NoiseXxInitiator,
    our_index: wire::SessionIndex,
    msg1: [u8; 256],
    msg1_len: usize,
    resends: u32,
    next_resend_at: embassy_time::Instant,
}

/// One link-layer key epoch (fips `node/session/mod.rs` slots): `cur` is
/// active, `pend` holds a completed rekey handshake awaiting the peer's
/// cutover proof, `prev` retains the retired epoch for drain stragglers.
/// Each slot owns its send counter and replay window — counter spaces and
/// windows are per-epoch by construction.
struct EpochSlot {
    ks: [u8; 32],
    kr: [u8; 32],
    them: wire::SessionIndex,
    send_ctr: u64,
    k_bit: bool,
    replay: microfips_core::noise::ReplayWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeTiming {
    pub heartbeat_interval_secs: u64,
    pub link_dead_timeout_secs: u64,
    /// Self-initiated rekey trigger: seconds in a session before rotating
    /// keys (0 = never — the default; the daemon drives, we follow).
    pub rekey_after_secs: u64,
    /// Self-initiated rekey trigger: outbound messages before rotating
    /// (0 = never).
    pub rekey_after_messages: u64,
    pub retry_base_interval_secs: u64,
    pub retry_max_backoff_secs: u64,
    pub handshake_resend_interval_ms: u64,
    pub handshake_resend_backoff: u64,
    pub handshake_max_resends: u32,
    pub connect_delay_ms: u64,
}

impl Default for NodeTiming {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: DEFAULT_HEARTBEAT_INTERVAL_SECS,
            link_dead_timeout_secs: DEFAULT_LINK_DEAD_TIMEOUT_SECS,
            rekey_after_secs: 0,
            rekey_after_messages: 0,
            retry_base_interval_secs: DEFAULT_RETRY_BASE_INTERVAL_SECS,
            retry_max_backoff_secs: DEFAULT_RETRY_MAX_BACKOFF_SECS,
            handshake_resend_interval_ms: DEFAULT_HANDSHAKE_RESEND_INTERVAL_MS,
            handshake_resend_backoff: DEFAULT_HANDSHAKE_RESEND_BACKOFF,
            handshake_max_resends: DEFAULT_HANDSHAKE_MAX_RESENDS,
            connect_delay_ms: DEFAULT_CONNECT_DELAY_MS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Protocol state events emitted to the handler.
pub enum NodeEvent {
    /// Transport is ready (wait_ready completed).
    Connected,
    /// MSG1 (handshake initiation) has been sent.
    Msg1Sent,
    /// Handshake completed successfully, keys derived.
    HandshakeOk,
    /// A heartbeat was transmitted to the peer.
    HeartbeatSent,
    /// A heartbeat was received from the peer.
    HeartbeatRecv,
    /// Session ended after steady state.
    Disconnected,
    /// Handshake failed.
    Error,
}

/// Result from the handler's message callback.
#[derive(Debug, PartialEq)]
pub enum HandleResult {
    /// No response needed.
    None,
    /// Send a session datagram response of the given length (written into resp buffer).
    SendDatagram(usize),
    /// Request disconnect.
    Disconnect,
}

/// Callback interface for protocol events and application message handling.
pub trait NodeHandler {
    /// Called on protocol state transitions. Async to allow yielding or delays.
    fn on_event(&mut self, event: NodeEvent) -> impl core::future::Future<Output = ()>;

    /// Called when a decrypted established message is received (not heartbeat/disconnect).
    /// `msg_type` is the FIPS inner message type byte.
    /// `payload` is the decrypted payload after the 5-byte inner header.
    /// Write any response into `resp` and return `HandleResult::SendDatagram(len)`.
    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult;

    /// Return the earliest instant at which the handler needs to be woken.
    /// Return `None` if no timed actions are pending.
    fn poll_at(&self) -> Option<embassy_time::Instant> {
        None
    }

    /// Called when the timer fires and `poll_at()` was the earliest deadline.
    fn on_tick(&mut self, _resp: &mut [u8]) -> HandleResult {
        HandleResult::None
    }
}

/// No-op handler that ignores all events and messages.
pub struct NoopHandler;

impl NodeHandler for NoopHandler {
    async fn on_event(&mut self, _event: NodeEvent) {}
    fn on_message(&mut self, _msg_type: u8, _payload: &[u8], _resp: &mut [u8]) -> HandleResult {
        HandleResult::None
    }
}

#[cfg(feature = "benchmark")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ThroughputState {
    test_id: u32,
    frames_recv: u32,
    bytes_recv: u64,
    started_at: Option<Instant>,
    duration_secs: u8,
    active: bool,
}

pub struct Node<T: Transport, R: RngCore + CryptoRng> {
    transport: T,
    rng: R,
    timing: NodeTiming,
    policy: PeerPolicy,
    nsec: [u8; 32],
    peer_npub: [u8; 33],
    rbuf: [u8; MAX_FRAME_SIZE],
    rpos: usize,
    rlen: usize,
    resp_buf: [u8; 320],
    raw_framing: bool,
    epoch: u64,
    peer_sent_first: bool,
    /// Peer's FMP node profile from the XX negotiation payload
    /// (`None` until an XX handshake completes; always `None` on IK).
    #[cfg(feature = "noise-xx")]
    peer_profile: Option<wire::negotiation::NodeProfile>,
    /// FMP version agreed during the XX negotiation exchange.
    #[cfg(feature = "noise-xx")]
    fmp_version: Option<u8>,
    /// FMP node profile we advertise in negotiation. microfips is a leaf
    /// (single upstream peer, no tree/bloom/transit); tests and non-leaf
    /// deployments override via [`Node::set_node_profile`].
    #[cfg(feature = "noise-xx")]
    our_profile: wire::negotiation::NodeProfile,
    #[cfg(feature = "benchmark")]
    throughput: ThroughputState,
    #[cfg(feature = "mmp")]
    mmp: crate::mmp::MmpPeerState,
}

impl<T: Transport, R: RngCore + CryptoRng> Node<T, R> {
    async fn process_frame_action<H: NodeHandler>(
        &mut self,
        action: FrameAction,
        slot: &mut EpochSlot,
        handler: &mut H,
    ) -> Result<bool, ProtocolError> {
        match action {
            FrameAction::Continue => Ok(false),
            FrameAction::HeartbeatRecv => {
                self.policy.record_heartbeat();
                log_steady!("steady: heartbeat received from peer");
                handler.on_event(NodeEvent::HeartbeatRecv).await;
                Ok(false)
            }
            FrameAction::PeerDC { reason: _reason } => {
                log_steady!(
                    "steady: peer disconnect received (reason={}), exiting steady",
                    _reason
                );
                Ok(true)
            }
            FrameAction::SelfDC => {
                log_steady!("steady: self disconnect, exiting steady");
                self.send_disconnect(slot, wire::DISC_REASON_SHUTDOWN).await;
                Ok(true)
            }
            FrameAction::SendDatagram(len) => {
                self.policy.record_data_frame();
                log_steady!("steady: sending datagram {} bytes", len);
                self.send_session_datagram(slot, len).await;
                Ok(false)
            }
            FrameAction::SendLinkMessage { msg_type, len } => {
                self.policy.record_data_frame();
                log_steady!(
                    "steady: sending link msg type=0x{:02x} len={}",
                    msg_type,
                    len
                );
                self.send_link_message(slot, msg_type, len).await;
                Ok(false)
            }
        }
    }

    #[cfg(feature = "mmp")]
    fn maybe_handle_mmp_control(&mut self, frame: &DecryptedFrame<'_>) -> Option<FrameAction> {
        match frame.msg_type {
            wire::MSG_SENDER_REPORT => {
                if let Some(_sr) = microfips_core::mmp::SenderReport::decode(frame.payload) {
                    let now = embassy_time::Instant::now();
                    if self.mmp.receiver.should_send_report(now) {
                        if let Some(rr) = self.mmp.receiver.build_report(now) {
                            let encoded = rr.encode();
                            let body_len = encoded.len();
                            self.resp_buf[..body_len].copy_from_slice(&encoded);
                            return Some(FrameAction::SendLinkMessage {
                                msg_type: wire::MSG_RECEIVER_REPORT,
                                len: body_len,
                            });
                        }
                    }
                }
                Some(FrameAction::Continue)
            }
            wire::MSG_RECEIVER_REPORT => {
                if let Some(rr) = microfips_core::mmp::ReceiverReport::decode(frame.payload) {
                    let now = embassy_time::Instant::now();
                    let our_ts = now.as_millis() as u32;
                    let _first_rtt = self.mmp.metrics.process_receiver_report(&rr, our_ts, now);
                    if let Some(srtt_ms) = self.mmp.metrics.srtt_ms() {
                        let srtt_us = (srtt_ms * 1000.0) as i64;
                        self.mmp.sender.update_report_interval_from_srtt(srtt_us);
                        self.mmp.receiver.update_report_interval_from_srtt(srtt_us);
                    }
                    let our_recv = self.mmp.receiver.cumulative_packets_recv();
                    let peer_highest = self.mmp.receiver.highest_counter();
                    self.mmp
                        .metrics
                        .update_reverse_delivery(our_recv, peer_highest);
                }
                Some(FrameAction::Continue)
            }
            _ => None,
        }
    }

    pub fn new(transport: T, rng: R, nsec: [u8; 32], peer_npub: [u8; 33]) -> Self {
        Self::with_timing(transport, rng, nsec, peer_npub, NodeTiming::default())
    }

    pub fn with_timing(
        transport: T,
        rng: R,
        nsec: [u8; 32],
        peer_npub: [u8; 33],
        timing: NodeTiming,
    ) -> Self {
        Self {
            transport,
            rng,
            timing,
            policy: PeerPolicy::with_timing(PeerPolicyTiming {
                retry_base_interval_secs: timing.retry_base_interval_secs,
                retry_max_backoff_secs: timing.retry_max_backoff_secs,
                frame_rate_window_ms: crate::peer_policy::DEFAULT_FRAME_RATE_WINDOW_MS,
                link_dead_timeout_secs: timing.link_dead_timeout_secs,
            }),
            nsec,
            peer_npub,
            rbuf: [0u8; MAX_FRAME_SIZE],
            rpos: 0,
            rlen: 0,
            resp_buf: [0u8; 320],
            raw_framing: false,
            epoch: 0,
            peer_sent_first: false,
            #[cfg(feature = "noise-xx")]
            peer_profile: None,
            #[cfg(feature = "noise-xx")]
            fmp_version: None,
            #[cfg(feature = "noise-xx")]
            our_profile: microfips_core::wire::negotiation::NodeProfile::Leaf,
            #[cfg(feature = "benchmark")]
            throughput: ThroughputState::default(),
            #[cfg(feature = "mmp")]
            mmp: crate::mmp::MmpPeerState::default(),
        }
    }

    /// Enable or disable raw FMP framing mode.
    ///
    /// When enabled, frames are sent and received without the 2-byte LE length
    /// prefix. Frame boundaries are determined from the 4-byte FMP common
    /// prefix instead, matching the wire format used by FIPS's TCP transport.
    /// Use this when connecting directly to a FIPS node over TCP without a
    /// bridge or proxy.
    pub fn set_raw_framing(&mut self, raw: bool) {
        self.raw_framing = raw;
    }

    /// Hint that the peer already sent MSG1 as the first frame (e.g. FIPS probe
    /// auto-connect sends MSG1 immediately after pubkey exchange on BLE L2CAP).
    /// When set, handshake() skips sending its own MSG1 and enters the responder
    /// path directly, avoiding cross-connection deadlock.
    pub fn set_peer_sent_first(&mut self, sent: bool) {
        self.peer_sent_first = sent;
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Peer's FMP node profile learned from the XX negotiation payload
    /// (`None` until an XX handshake completes; always `None` on IK).
    #[cfg(feature = "noise-xx")]
    pub fn peer_node_profile(&self) -> Option<wire::negotiation::NodeProfile> {
        self.peer_profile
    }

    /// FMP version agreed during the XX negotiation exchange.
    #[cfg(feature = "noise-xx")]
    pub fn fmp_agreed_version(&self) -> Option<u8> {
        self.fmp_version
    }

    /// Override the FMP node profile advertised in XX negotiation
    /// (default `Leaf`). Leaf+leaf links are rejected by the pairing rule —
    /// tests that peer two `Node`s must declare `Full` on one side.
    #[cfg(feature = "noise-xx")]
    pub fn set_node_profile(&mut self, profile: wire::negotiation::NodeProfile) {
        self.our_profile = profile;
    }

    fn generate_valid_eph(&mut self) -> [u8; 32] {
        use microfips_core::noise;

        loop {
            let mut eph = [0u8; 32];
            self.rng.fill_bytes(&mut eph);
            if noise::ecdh_pubkey(&eph).is_ok() {
                return eph;
            }
        }
    }

    fn allocate_session_index(&mut self) -> wire::SessionIndex {
        loop {
            let idx = self.rng.next_u32();
            if idx != 0 {
                return wire::SessionIndex::new(idx);
            }
        }
    }

    fn advance_epoch(&mut self) -> [u8; microfips_core::noise::EPOCH_SIZE] {
        self.epoch = self.epoch.wrapping_add(1);
        let mut epoch = [0u8; microfips_core::noise::EPOCH_SIZE];
        let epoch_le = self.epoch.to_le_bytes();
        let copy_len = epoch.len().min(epoch_le.len());
        epoch[..copy_len].copy_from_slice(&epoch_le[..copy_len]);
        epoch
    }

    pub async fn run<H: NodeHandler>(&mut self, handler: &mut H) -> ! {
        loop {
            match self.policy.check_reconnect(Instant::now()) {
                PolicyVerdict::Allow => {}
                PolicyVerdict::Backoff(delay) => {
                    log_steady!("policy: reconnect backoff {}ms", delay.as_millis());
                    Timer::after(delay).await;
                }
                PolicyVerdict::Reject => {
                    log_steady!("policy: rejected: reconnect");
                    Timer::after(Duration::from_secs(self.timing.retry_base_interval_secs)).await;
                    continue;
                }
            }
            self.policy.record_connect_attempt(Instant::now());
            let _ = self.session(handler).await;
        }
    }

    async fn session<H: NodeHandler>(&mut self, handler: &mut H) -> Result<(), ProtocolError> {
        self.transport
            .wait_ready()
            .await
            .map_err(|_| ProtocolError::Disconnected)?;
        let epoch = self.advance_epoch();
        Timer::after(Duration::from_millis(self.timing.connect_delay_ms)).await;
        handler.on_event(NodeEvent::Connected).await;

        self.rpos = 0;
        self.rlen = 0;
        #[cfg(feature = "benchmark")]
        {
            self.throughput = ThroughputState::default();
        }

        match self.handshake(epoch, handler).await {
            Ok((mut ks, mut kr, them)) => {
                self.rpos = 0;
                self.rlen = 0;
                self.policy.record_handshake_ok(Instant::now());
                log_steady!("session: handshake ok, entering steady");
                handler.on_event(NodeEvent::HandshakeOk).await;
                let result = self.steady(epoch, &ks, &kr, them, handler).await;
                // Wipe the session keys at steady exit (deviation F8, #182).
                use microfips_core::noise::Zeroize;
                ks.zeroize();
                kr.zeroize();
                self.policy.reset_session();
                log_steady!("session: steady exited, result={:?}", result.is_ok());
                handler.on_event(NodeEvent::Disconnected).await;
                result
            }
            Err(e) => {
                self.policy.record_handshake_failure(Instant::now());
                self.policy.reset_session();
                log_steady!("session: handshake failed: {:?}", e);
                handler.on_event(NodeEvent::Error).await;
                Err(e)
            }
        }
    }

    async fn handshake<H: NodeHandler>(
        &mut self,
        epoch: [u8; microfips_core::noise::EPOCH_SIZE],
        handler: &mut H,
    ) -> Result<([u8; 32], [u8; 32], wire::SessionIndex), ProtocolError> {
        #[cfg(feature = "noise-xx")]
        {
            self.handshake_xx(epoch, handler).await
        }
        #[cfg(not(feature = "noise-xx"))]
        {
            self.handshake_ik(epoch, handler).await
        }
    }

    /// Validate the peer's decrypted FMP negotiation payload against our
    /// advertised profile and version range, recording the agreed version
    /// and peer profile (FIPS next `decide_fmp_negotiation` + `agree_version`).
    #[cfg(feature = "noise-xx")]
    fn apply_fmp_negotiation(&mut self, neg_bytes: &[u8]) -> Result<(), ProtocolError> {
        use microfips_core::wire::negotiation::{self, NegotiationHeader, NodeProfile};

        let ours = NegotiationHeader {
            version_min: microfips_core::wire::FMP_VERSION,
            version_max: microfips_core::wire::FMP_VERSION,
            features: negotiation::fmp_features(self.our_profile),
        };
        let theirs = NegotiationHeader::parse(neg_bytes).map_err(|_e| {
            #[cfg(feature = "log")]
            log::warn!("fmp negotiation: bad payload: {}", _e);
            ProtocolError::InvalidMessage
        })?;
        let version = ours.agree_version(&theirs).map_err(|_| {
            #[cfg(feature = "log")]
            log::warn!(
                "fmp negotiation: no version overlap (our {}..{}, their {}..{})",
                ours.version_min,
                ours.version_max,
                theirs.version_min,
                theirs.version_max
            );
            ProtocolError::InvalidMessage
        })?;
        let their_profile = match theirs.node_profile() {
            Some(p) => p,
            None => {
                #[cfg(feature = "log")]
                log::warn!(
                    "fmp negotiation: unknown profile bits {:b}",
                    theirs.features & negotiation::FMP_FEAT_PROFILE_MASK
                );
                return Err(ProtocolError::InvalidMessage);
            }
        };
        if !NodeProfile::valid_pairing(self.our_profile, their_profile) {
            #[cfg(feature = "log")]
            log::warn!(
                "fmp negotiation: invalid pairing {}+{}",
                self.our_profile,
                their_profile
            );
            return Err(ProtocolError::InvalidMessage);
        }
        self.fmp_version = Some(version);
        self.peer_profile = Some(their_profile);
        #[cfg(feature = "log")]
        log::info!(
            "fmp negotiation: agreed version {}, peer profile {}",
            version,
            their_profile
        );
        Ok(())
    }

    #[cfg(feature = "noise-xx")]
    async fn handshake_xx<H: NodeHandler>(
        &mut self,
        epoch: [u8; microfips_core::noise::EPOCH_SIZE],
        handler: &mut H,
    ) -> Result<([u8; 32], [u8; 32], wire::SessionIndex), ProtocolError> {
        use microfips_core::identity::NodeAddr;
        use microfips_core::noise;
        use microfips_core::wire;

        let my_pub = noise::ecdh_pubkey(&self.nsec)?;
        let my_x_only: [u8; 32] = my_pub[1..33].try_into().unwrap();
        let my_addr = NodeAddr::from_pubkey_x(&my_x_only);
        let peer_x_only: [u8; 32] = self.peer_npub[1..33].try_into().unwrap();
        let peer_addr = NodeAddr::from_pubkey_x(&peer_x_only);

        let initiator_eph = self.generate_valid_eph();
        let (mut noise_st, _e_pub) = noise::NoiseXxInitiator::new(&initiator_eph, &self.nsec)?;

        let mut n1 = [0u8; 256];
        let n1len = noise_st.write_message1(&mut n1)?;

        let our_index = self.allocate_session_index();
        let mut f1 = [0u8; 256];
        let f1len = wire::build_msg1(our_index, &n1[..n1len], &mut f1)
            .ok_or(ProtocolError::InvalidFrame)?;

        if !self.peer_sent_first {
            self.send_frame(&f1[..f1len]).await?;
            handler.on_event(NodeEvent::Msg1Sent).await;
        } else {
            #[cfg(feature = "log")]
            log::info!("peer sent MSG1 first, entering responder path");
        }

        let mut mb = [0u8; MAX_FRAME_SIZE];
        let mut resend_count: u32 = 0;
        loop {
            let recv_timeout_ms = self.current_handshake_resend_timeout_ms(resend_count);
            match self.recv_frame(&mut mb, recv_timeout_ms).await {
                Ok(ml) => {
                    resend_count = 0;
                    let m = wire::parse_message(&mb[..ml]).ok_or(ProtocolError::InvalidMessage)?;
                    match m {
                        wire::FmpMessage::Msg2 {
                            sender_idx,
                            noise_payload,
                            ..
                        } => {
                            let mut st = noise_st;
                            let (base2, neg2) = wire::negotiation::split_msg2_noise(noise_payload);
                            #[cfg(feature = "log")]
                            log::debug!(
                                "xx init: msg2 noise={}B negotiation-extra={}B",
                                noise_payload.len(),
                                neg2.map(|e| e.len()).unwrap_or(0)
                            );
                            let (_resp_pub, _resp_epoch) = st
                                .read_message2(base2)
                                .map_err(|_| ProtocolError::DecryptFailed)?;
                            if let Some(encrypted) = neg2 {
                                let mut plain = [0u8; wire::negotiation::NEGOTIATION_MAX_SIZE];
                                let n = st
                                    .decrypt_payload(encrypted, &mut plain)
                                    .map_err(|_| ProtocolError::DecryptFailed)?;
                                self.apply_fmp_negotiation(&plain[..n])?;
                            }

                            let mut n3 = [0u8; noise::XX_HANDSHAKE_MSG3_SIZE
                                + wire::negotiation::NEGOTIATION_MAX_SIZE
                                + noise::TAG_SIZE];
                            let n3len = st
                                .write_message3(&my_pub, &epoch, &mut n3)
                                .map_err(|_| ProtocolError::DecryptFailed)?;
                            let mut neg = [0u8; wire::negotiation::NEGOTIATION_MAX_SIZE];
                            let neglen = wire::negotiation::encode_payload(
                                &mut neg,
                                wire::FMP_VERSION,
                                wire::FMP_VERSION,
                                wire::negotiation::fmp_features(self.our_profile),
                                None,
                            )
                            .ok_or(ProtocolError::InvalidFrame)?;
                            let neg_enc_len = st
                                .encrypt_payload(&neg[..neglen], &mut n3[n3len..])
                                .map_err(|_| ProtocolError::DecryptFailed)?;
                            let mut f3 = [0u8; 512];
                            let f3len = wire::build_msg3(
                                our_index,
                                sender_idx,
                                &n3[..n3len + neg_enc_len],
                                &mut f3,
                            )
                            .ok_or(ProtocolError::InvalidFrame)?;
                            self.send_frame(&f3[..f3len]).await?;

                            // finalize() returns (c1, c2) = (init→resp, resp→init)
                            let (c1, c2) = st.finalize();
                            return Ok((c1, c2, sender_idx));
                        }
                        wire::FmpMessage::Msg1 {
                            sender_idx: peer_sender_idx,
                            noise_payload,
                        } => {
                            if my_addr.as_bytes() == peer_addr.as_bytes() {
                                #[cfg(feature = "log")]
                                log::warn!("handshake: self-connection detected, aborting");
                                return Err(ProtocolError::InvalidMessage);
                            }

                            // XX tie-breaking: if we also sent MSG1, yield when our
                            // address is lower. (Identity cannot be verified from
                            // XX MSG1 — it's ephemeral-only. Verification happens
                            // after MSG3 reveals the initiator's static key.)
                            if !self.peer_sent_first && my_addr.as_bytes() < peer_addr.as_bytes() {
                                continue;
                            }

                            let mut responder = noise::NoiseXxResponder::new(&self.nsec)
                                .map_err(|_| ProtocolError::InvalidMessage)?;
                            responder
                                .read_message1(noise_payload)
                                .map_err(|_| ProtocolError::InvalidMessage)?;

                            let mut resp_eph = self.generate_valid_eph();
                            while resp_eph == initiator_eph {
                                resp_eph = self.generate_valid_eph();
                            }

                            let mut msg2_noise = [0u8; noise::XX_HANDSHAKE_MSG2_SIZE
                                + wire::negotiation::NEGOTIATION_MAX_SIZE
                                + noise::TAG_SIZE];
                            let msg2_noise_len = responder
                                .write_message2(&resp_eph, &epoch, &mut msg2_noise)
                                .map_err(|_| ProtocolError::DecryptFailed)?;
                            let mut neg = [0u8; wire::negotiation::NEGOTIATION_MAX_SIZE];
                            let neglen = wire::negotiation::encode_payload(
                                &mut neg,
                                wire::FMP_VERSION,
                                wire::FMP_VERSION,
                                wire::negotiation::fmp_features(self.our_profile),
                                None,
                            )
                            .ok_or(ProtocolError::InvalidMessage)?;
                            let neg_enc_len = responder
                                .encrypt_payload(&neg[..neglen], &mut msg2_noise[msg2_noise_len..])
                                .map_err(|_| ProtocolError::DecryptFailed)?;
                            let msg2_total_len = msg2_noise_len + neg_enc_len;

                            let resp_index = self.allocate_session_index();
                            let mut msg2_buf = [0u8; 512];
                            let msg2_len = wire::build_msg2(
                                resp_index,
                                peer_sender_idx,
                                &msg2_noise[..msg2_total_len],
                                &mut msg2_buf,
                            )
                            .ok_or(ProtocolError::InvalidMessage)?;
                            self.send_frame(&msg2_buf[..msg2_len]).await?;

                            let mut msg3_resend_count: u32 = 0;
                            loop {
                                let msg3_timeout_ms =
                                    self.current_handshake_resend_timeout_ms(msg3_resend_count);
                                match self.recv_frame(&mut mb, msg3_timeout_ms).await {
                                    Ok(ml3) => {
                                        let m3 = wire::parse_message(&mb[..ml3])
                                            .ok_or(ProtocolError::InvalidMessage)?;
                                        match m3 {
                                            wire::FmpMessage::Msg3 {
                                                noise_payload: np3, ..
                                            } => {
                                                let (base3, neg3) =
                                                    wire::negotiation::split_msg3_noise(np3);
                                                let (init_pub, _init_epoch) = responder
                                                    .read_message3(base3)
                                                    .map_err(|_| ProtocolError::InvalidMessage)?;
                                                if let Some(encrypted) = neg3 {
                                                    let mut plain = [0u8;
                                                        wire::negotiation::NEGOTIATION_MAX_SIZE];
                                                    let n = responder
                                                        .decrypt_payload(encrypted, &mut plain)
                                                        .map_err(|_| {
                                                            ProtocolError::InvalidMessage
                                                        })?;
                                                    self.apply_fmp_negotiation(&plain[..n])?;
                                                }

                                                // Verify identity NOW — XX reveals
                                                // initiator's static key in MSG3.
                                                // Compare x-only bytes (1..33) because
                                                // the compressed prefix may differ.
                                                if init_pub[1..33] != self.peer_npub[1..33] {
                                                    #[cfg(feature = "log")]
                                                    log::warn!("handshake: MSG3 identity mismatch");
                                                    return Err(ProtocolError::InvalidMessage);
                                                }

                                                // Responder keys are reversed:
                                                // c1 = init→resp (our recv),
                                                // c2 = resp→init (our send)
                                                let (c1, c2) = responder.finalize();
                                                return Ok((c2, c1, peer_sender_idx));
                                            }
                                            _ => {
                                                #[cfg(feature = "log")]
                                                log::warn!(
                                                    "handshake: expected MSG3, ignoring other frame"
                                                );
                                                continue;
                                            }
                                        }
                                    }
                                    Err(ProtocolError::Timeout) => {
                                        msg3_resend_count += 1;
                                        if msg3_resend_count > self.timing.handshake_max_resends {
                                            return Err(ProtocolError::Timeout);
                                        }
                                        self.send_frame(&msg2_buf[..msg2_len]).await?;
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                        }
                        _ => continue,
                    }
                }
                Err(ProtocolError::Timeout) => {
                    resend_count += 1;
                    if resend_count > self.timing.handshake_max_resends {
                        return Err(ProtocolError::Timeout);
                    }
                    if !self.peer_sent_first {
                        self.send_frame(&f1[..f1len]).await?;
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(not(feature = "noise-xx"))]
    async fn handshake_ik<H: NodeHandler>(
        &mut self,
        epoch: [u8; microfips_core::noise::EPOCH_SIZE],
        handler: &mut H,
    ) -> Result<([u8; 32], [u8; 32], wire::SessionIndex), ProtocolError> {
        use microfips_core::identity::NodeAddr;
        use microfips_core::noise;
        use microfips_core::wire;

        let my_pub = noise::ecdh_pubkey(&self.nsec)?;
        let my_x_only: [u8; 32] = my_pub[1..33].try_into().unwrap();
        let my_addr = NodeAddr::from_pubkey_x(&my_x_only);
        let peer_x_only: [u8; 32] = self.peer_npub[1..33].try_into().unwrap();
        let peer_addr = NodeAddr::from_pubkey_x(&peer_x_only);

        let initiator_eph = self.generate_valid_eph();
        let (mut noise_st, _e_pub) =
            noise::NoiseIkInitiator::new(&initiator_eph, &self.nsec, &self.peer_npub)?;

        let mut n1 = [0u8; 256];
        let n1len = noise_st.write_message1(&my_pub, &epoch, &mut n1)?;

        let our_index = self.allocate_session_index();
        let mut f1 = [0u8; 256];
        let f1len = wire::build_msg1(our_index, &n1[..n1len], &mut f1)
            .ok_or(ProtocolError::InvalidFrame)?;

        if !self.peer_sent_first {
            self.send_frame(&f1[..f1len]).await?;
            handler.on_event(NodeEvent::Msg1Sent).await;
        } else {
            #[cfg(feature = "log")]
            log::info!("peer sent MSG1 first, entering IK responder path");
        }

        let mut mb = [0u8; MAX_FRAME_SIZE];
        let mut resend_count: u32 = 0;
        loop {
            let recv_timeout_ms = self.current_handshake_resend_timeout_ms(resend_count);
            match self.recv_frame(&mut mb, recv_timeout_ms).await {
                Ok(ml) => {
                    resend_count = 0;
                    let m = wire::parse_message(&mb[..ml]).ok_or(ProtocolError::InvalidMessage)?;
                    match m {
                        wire::FmpMessage::Msg2 {
                            sender_idx,
                            noise_payload,
                            ..
                        } => {
                            let _resp_epoch = noise_st
                                .read_message2(noise_payload)
                                .map_err(|_| ProtocolError::DecryptFailed)?;

                            let (c1, c2) = noise_st.finalize();
                            return Ok((c1, c2, sender_idx));
                        }
                        wire::FmpMessage::Msg1 {
                            sender_idx: peer_sender_idx,
                            noise_payload,
                        } => {
                            if my_addr.as_bytes() == peer_addr.as_bytes() {
                                #[cfg(feature = "log")]
                                log::warn!("handshake: self-connection detected, aborting");
                                return Err(ProtocolError::InvalidMessage);
                            }

                            if !self.peer_sent_first && my_addr.as_bytes() < peer_addr.as_bytes() {
                                continue;
                            }

                            let e_init_pub: &[u8; noise::PUBKEY_SIZE] = noise_payload
                                [..noise::PUBKEY_SIZE]
                                .try_into()
                                .map_err(|_| ProtocolError::InvalidMessage)?;

                            let mut responder =
                                noise::NoiseIkResponder::new(&self.nsec, e_init_pub)
                                    .map_err(|_| ProtocolError::InvalidMessage)?;

                            let (init_pub, _init_epoch) = responder
                                .read_message1(&noise_payload[noise::PUBKEY_SIZE..])
                                .map_err(|_| ProtocolError::InvalidMessage)?;

                            if init_pub[1..33] != self.peer_npub[1..33] {
                                #[cfg(feature = "log")]
                                log::warn!("handshake: IK MSG1 identity mismatch");
                                return Err(ProtocolError::InvalidMessage);
                            }

                            let mut resp_eph = self.generate_valid_eph();
                            while resp_eph == initiator_eph {
                                resp_eph = self.generate_valid_eph();
                            }

                            let mut msg2_noise = [0u8; 128];
                            let msg2_noise_len = responder
                                .write_message2(&resp_eph, &epoch, &mut msg2_noise)
                                .map_err(|_| ProtocolError::DecryptFailed)?;

                            let resp_index = self.allocate_session_index();
                            let mut msg2_buf = [0u8; 256];
                            let msg2_len = wire::build_msg2(
                                resp_index,
                                peer_sender_idx,
                                &msg2_noise[..msg2_noise_len],
                                &mut msg2_buf,
                            )
                            .ok_or(ProtocolError::InvalidMessage)?;
                            self.send_frame(&msg2_buf[..msg2_len]).await?;

                            let (c1, c2) = responder.finalize();
                            return Ok((c2, c1, peer_sender_idx));
                        }
                        _ => continue,
                    }
                }
                Err(ProtocolError::Timeout) => {
                    resend_count += 1;
                    if resend_count > self.timing.handshake_max_resends {
                        return Err(ProtocolError::Timeout);
                    }
                    if !self.peer_sent_first {
                        self.send_frame(&f1[..f1len]).await?;
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn steady<H: NodeHandler>(
        &mut self,
        epoch: [u8; microfips_core::noise::EPOCH_SIZE],
        ks: &[u8; 32],
        kr: &[u8; 32],
        them: wire::SessionIndex,
        handler: &mut H,
    ) -> Result<(), ProtocolError> {
        log_steady!(
            "steady: entered, next_hb in {}s",
            self.timing.heartbeat_interval_secs
        );
        let mut next_hb = embassy_time::Instant::now() + Duration::from_secs(1);
        let mut next_sr = embassy_time::Instant::now()
            + Duration::from_secs(self.timing.heartbeat_interval_secs / 2);
        #[allow(unused_mut, unused_variables)]
        let mut sr_start_ctr: u64 = 0;
        #[allow(unused_mut, unused_variables)]
        let mut sr_start_ts: u32 = embassy_time::Instant::now().as_millis() as u32;
        let mut dec_buf = [0u8; MAX_FRAME_SIZE];
        // Key-epoch slots: rekey rotates these in place (fips trial-decrypt
        // cascade). `cur` is active; `pend` holds a completed rekey answer
        // awaiting the peer's cutover proof; `prev` drains old-epoch
        // stragglers for DRAIN_WINDOW_SECS past their last authenticated use.
        let mut cur = EpochSlot {
            ks: *ks,
            kr: *kr,
            them,
            send_ctr: 0,
            k_bit: false,
            replay: microfips_core::noise::ReplayWindow::new(),
        };
        let mut pend: Option<EpochSlot> = None;
        let mut prev: Option<EpochSlot> = None;
        let mut prev_drain_base = embassy_time::Instant::now();
        let mut session_started = embassy_time::Instant::now();
        let mut rekey_init: Option<RekeyInit> = None;
        // True while `pend` was armed by OUR initiation (timer-cutover is
        // the initiator's trigger; responder-armed pend waits for proof).
        let mut pend_self = false;
        let mut last_peer_rekey_at: Option<embassy_time::Instant> = None;
        // Idempotent rekey answering: the initiator resends the SAME msg1
        // bytes while its msg2 is in flight; a duplicate must draw a resend
        // of the SAME msg2 (a fresh ephemeral would derive different keys —
        // the 2026-09-01 soak blip).
        let mut last_rekey_msg1: Option<([u8; 128], usize)> = None;
        let mut last_rekey_msg2: Option<([u8; 256], usize)> = None;
        // Mid-flight XX rekey responder: (state, our msg2 index, their msg1 index).
        #[cfg(feature = "noise-xx")]
        let mut rekey_hs: Option<(
            microfips_core::noise::NoiseXxResponder,
            wire::SessionIndex,
            wire::SessionIndex,
        )> = None;
        // Refreshed on every authenticated frame. On transports where sends
        // keep succeeding after the peer is gone (e.g. ESP-NOW MAC-level
        // ACKs from a relay), RX silence is the only death signal.
        let mut last_rx = embassy_time::Instant::now();

        loop {
            let idle_secs = embassy_time::Instant::now()
                .saturating_duration_since(last_rx)
                .as_secs();
            if idle_secs > self.timing.link_dead_timeout_secs {
                log_steady!("steady: link dead, {}s without valid frames", idle_secs);
                self.send_disconnect(&mut cur, wire::DISC_REASON_TRANSPORT_FAILURE)
                    .await;
                return Err(ProtocolError::Timeout);
            }

            let mut rx = [0u8; RECV_BUF_SIZE];
            let rx_fut = self.transport.recv(&mut rx);
            let tick = handler.poll_at();
            let base_deadline = next_hb.min(next_sr);
            let deadline = tick.unwrap_or(base_deadline).min(base_deadline);
            let hb_fut = Timer::at(deadline);

            match select(rx_fut, hb_fut).await {
                Either::First(Ok(n)) => {
                    log_steady!("steady: recv returned {} bytes", n);
                    if self.rlen + n > self.rbuf.len() {
                        self.rlen = 0;
                        self.rpos = 0;
                        continue;
                    }
                    self.rbuf[self.rlen..self.rlen + n].copy_from_slice(&rx[..n]);
                    self.rlen += n;

                    'frames: while self.rpos < self.rlen {
                        let extracted = if self.raw_framing {
                            extract_raw_frame(&self.rbuf, self.rpos, self.rlen)
                        } else {
                            extract_length_prefixed_frame(&self.rbuf, self.rpos, self.rlen)
                        };
                        let (frame_data, new_pos) = match extracted {
                            Some(v) => v,
                            None => break,
                        };

                        if frame_data.is_empty() {
                            self.rpos = new_pos;
                            continue;
                        }

                        self.rpos = new_pos;
                        if self.policy.check_frame_rate(Instant::now()) == PolicyVerdict::Reject {
                            log_steady!("policy: rejected: frame rate");
                            continue;
                        }

                        // Route by FMP phase: Msg1 mid-session is rekey
                        // maintenance traffic (fips handlers/handshake.rs
                        // `is_established_link_msg1`); established frames run
                        // the epoch cascade.
                        match wire::parse_message(frame_data) {
                            Some(wire::FmpMessage::Msg1 {
                                sender_idx,
                                noise_payload,
                            }) => {
                                // Copy off the rbuf borrow before &mut self.
                                let mut np = [0u8; 128];
                                let np_len = noise_payload.len().min(np.len());
                                np[..np_len].copy_from_slice(&noise_payload[..np_len]);
                                let mut msg1_wire = [0u8; 128];
                                let wire_len = frame_data.len().min(msg1_wire.len());
                                msg1_wire[..wire_len].copy_from_slice(&frame_data[..wire_len]);
                                let is_dup = last_rekey_msg1.is_some_and(|(buf, len)| {
                                    len == wire_len && buf[..len] == msg1_wire[..len]
                                });

                                if is_dup {
                                    if let Some((buf, len)) = last_rekey_msg2 {
                                        log_steady!("steady: duplicate rekey msg1, resending msg2");
                                        let _ = self.send_frame(&buf[..len]).await;
                                    }
                                } else {
                                    log_steady!("steady: rekey msg1 received, answering");
                                    #[cfg(not(feature = "noise-xx"))]
                                    if let Some((slot, msg2, msg2_len)) = self
                                        .answer_rekey_msg1_ik(
                                            sender_idx,
                                            &np[..np_len],
                                            epoch,
                                            cur.k_bit,
                                        )
                                        .await
                                    {
                                        let _ = self.send_frame(&msg2[..msg2_len]).await;
                                        pend = Some(slot);
                                        last_rekey_msg1 = Some((msg1_wire, wire_len));
                                        last_rekey_msg2 = Some((msg2, msg2_len));
                                    }
                                    #[cfg(feature = "noise-xx")]
                                    if let Some((responder, resp_index, msg2, msg2_len)) =
                                        self.begin_rekey_xx(sender_idx, &np[..np_len], epoch).await
                                    {
                                        let _ = self.send_frame(&msg2[..msg2_len]).await;
                                        rekey_hs = Some((responder, resp_index, sender_idx));
                                        last_rekey_msg1 = Some((msg1_wire, wire_len));
                                        last_rekey_msg2 = Some((msg2, msg2_len));
                                    }
                                }
                                // Peer-initiated rekey observed: dampen our
                                // own initiation window (dual-init guard).
                                last_peer_rekey_at = Some(embassy_time::Instant::now());
                                self.policy.record_good_frame();
                                last_rx = embassy_time::Instant::now();
                                continue;
                            }
                            #[cfg(feature = "noise-xx")]
                            Some(wire::FmpMessage::Msg3 { noise_payload, .. })
                                if rekey_hs.is_some() =>
                            {
                                let (mut responder, _resp_index, their_idx) =
                                    rekey_hs.take().expect("checked above");
                                // XX identity is only provable at msg3.
                                if let Ok((init_pub, _init_epoch)) =
                                    responder.read_message3(noise_payload)
                                {
                                    if init_pub[1..33] == self.peer_npub[1..33] {
                                        let (c1, c2) = responder.finalize();
                                        pend = Some(EpochSlot {
                                            ks: c2,
                                            kr: c1,
                                            them: their_idx,
                                            send_ctr: 0,
                                            k_bit: !cur.k_bit,
                                            replay: microfips_core::noise::ReplayWindow::new(),
                                        });
                                        log_steady!("steady: rekey complete, pending epoch armed");
                                    } else {
                                        log_steady!(
                                            "steady: rekey msg3 identity mismatch, discarded"
                                        );
                                    }
                                } else {
                                    log_steady!("steady: rekey msg3 parse failed, discarded");
                                }
                                self.policy.record_good_frame();
                                last_rx = embassy_time::Instant::now();
                                continue;
                            }
                            Some(wire::FmpMessage::Msg2 {
                                sender_idx,
                                receiver_idx,
                                noise_payload,
                            }) if rekey_init.is_some() => {
                                let mut ri = rekey_init.take().expect("guarded");
                                if receiver_idx != ri.our_index {
                                    // Not ours (stale/foreign msg2): keep waiting.
                                    rekey_init = Some(ri);
                                    self.policy.record_good_frame();
                                    last_rx = embassy_time::Instant::now();
                                    continue;
                                }
                                let mut np2 = [0u8; 128];
                                let np2_len = noise_payload.len().min(np2.len());
                                np2[..np2_len].copy_from_slice(&noise_payload[..np2_len]);

                                #[cfg(not(feature = "noise-xx"))]
                                let completed = match ri.hs.read_message2(&np2[..np2_len]) {
                                    Ok(_) => {
                                        let (c1, c2) = ri.hs.finalize();
                                        Some((c1, c2))
                                    }
                                    Err(_) => None,
                                };
                                #[cfg(feature = "noise-xx")]
                                let completed = if ri.hs.read_message2(&np2[..np2_len]).is_err() {
                                    None
                                } else {
                                    match microfips_core::noise::ecdh_pubkey(&self.nsec) {
                                        Ok(my_pub) => {
                                            let mut n3 = [0u8; 128];
                                            match ri.hs.write_message3(&my_pub, &epoch, &mut n3) {
                                                Ok(n3len) => {
                                                    let mut msg3 = [0u8; 256];
                                                    match wire::build_msg3(
                                                        ri.our_index,
                                                        sender_idx,
                                                        &n3[..n3len],
                                                        &mut msg3,
                                                    ) {
                                                        Some(msg3_len) => {
                                                            if self
                                                                .send_frame(&msg3[..msg3_len])
                                                                .await
                                                                .is_err()
                                                            {
                                                                None
                                                            } else {
                                                                let (c1, c2) = ri.hs.finalize();
                                                                Some((c1, c2))
                                                            }
                                                        }
                                                        None => None,
                                                    }
                                                }
                                                Err(_) => None,
                                            }
                                        }
                                        Err(_) => None,
                                    }
                                };

                                if let Some((c1, c2)) = completed {
                                    pend = Some(EpochSlot {
                                        ks: c1,
                                        kr: c2,
                                        them: sender_idx,
                                        send_ctr: 0,
                                        k_bit: !cur.k_bit,
                                        replay: microfips_core::noise::ReplayWindow::new(),
                                    });
                                    pend_self = true;
                                    log_steady!(
                                        "steady: rekey complete (self-initiated), pending armed"
                                    );
                                } else {
                                    log_steady!("steady: rekey msg2 failed to parse, abandoning");
                                }
                                self.policy.record_good_frame();
                                last_rx = embassy_time::Instant::now();
                                continue;
                            }
                            _ => {}
                        }

                        // Established frame: trial-decrypt across live epochs
                        // (fips `fsp_trial_decrypt`). The received K-bit is an
                        // ordering hint only; a pending-slot success IS the
                        // cutover proof.
                        let recv_k = wire::EncryptedHeader::parse(frame_data)
                            .is_some_and(|e| e.header_bytes[1] & wire::FLAG_KEY_EPOCH != 0);
                        let pend_first = recv_k != cur.k_bit && pend.is_some();

                        let mut from_pend = false;
                        let mut from_prev = false;
                        let frame = 'winner: {
                            if !pend_first {
                                if let Some(f) = decrypt_established_frame(
                                    &cur.kr,
                                    frame_data,
                                    &mut dec_buf,
                                    &mut cur.replay,
                                ) {
                                    break 'winner f;
                                }
                            }
                            if let Some(slot) = pend.as_mut() {
                                if let Some(f) = decrypt_established_frame(
                                    &slot.kr,
                                    frame_data,
                                    &mut dec_buf,
                                    &mut slot.replay,
                                ) {
                                    from_pend = true;
                                    break 'winner f;
                                }
                            }
                            if pend_first {
                                if let Some(f) = decrypt_established_frame(
                                    &cur.kr,
                                    frame_data,
                                    &mut dec_buf,
                                    &mut cur.replay,
                                ) {
                                    break 'winner f;
                                }
                            }
                            if let Some(slot) = prev.as_mut() {
                                if let Some(f) = decrypt_established_frame(
                                    &slot.kr,
                                    frame_data,
                                    &mut dec_buf,
                                    &mut slot.replay,
                                ) {
                                    from_prev = true;
                                    break 'winner f;
                                }
                            }
                            self.policy.record_bad_frame();
                            if self.policy.check_bad_frame_limit() == PolicyVerdict::Reject
                                || self.policy.check_total_bad_frame_limit()
                                    == PolicyVerdict::Reject
                            {
                                log_steady!("policy: rejected: bad frame limit");
                                self.send_disconnect(
                                    &mut cur,
                                    wire::DISC_REASON_SECURITY_VIOLATION,
                                )
                                .await;
                                return Err(ProtocolError::Disconnected);
                            }
                            continue 'frames;
                        };
                        self.policy.record_good_frame();
                        last_rx = embassy_time::Instant::now();

                        if from_pend {
                            // Authenticated decrypt against pending = the
                            // peer cut over (fips `handle_peer_kbit_flip`).
                            let new_cur = pend.take().expect("from_pend implies pend");
                            prev = Some(core::mem::replace(&mut cur, new_cur));
                            prev_drain_base = embassy_time::Instant::now();
                            session_started = embassy_time::Instant::now();
                            #[cfg(feature = "mmp")]
                            self.mmp.reset_for_rekey(Instant::now());
                            log_steady!("steady: rekey cutover complete, K-bit flipped");
                        } else if from_prev {
                            // Peer still sealing in the old epoch: hold it.
                            prev_drain_base = embassy_time::Instant::now();
                        }

                        #[cfg(feature = "mmp")]
                        self.mmp.receiver.record_recv(
                            frame.counter,
                            frame.sender_timestamp,
                            frame.frame_bytes,
                            false,
                            embassy_time::Instant::now(),
                        );

                        #[cfg(feature = "mmp")]
                        if let Some(action) = self.maybe_handle_mmp_control(&frame) {
                            if self.process_frame_action(action, &mut cur, handler).await? {
                                return Ok(());
                            }
                            continue;
                        }

                        let result = {
                            #[cfg(feature = "benchmark")]
                            {
                                dispatch_link_message(
                                    &frame,
                                    &mut self.throughput,
                                    handler,
                                    &mut self.resp_buf,
                                )
                            }
                            #[cfg(not(feature = "benchmark"))]
                            {
                                dispatch_link_message(&frame, &mut (), handler, &mut self.resp_buf)
                            }
                        };
                        if self.process_frame_action(result, &mut cur, handler).await? {
                            return Ok(());
                        }
                    }
                    if self.rpos >= self.rlen {
                        self.rpos = 0;
                        self.rlen = 0;
                    }
                    let now = embassy_time::Instant::now();
                    if now >= next_hb {
                        log_steady!(
                            "steady: sending heartbeat (recv branch, ctr={})",
                            cur.send_ctr
                        );
                        next_hb = self.send_heartbeat(&mut cur).await;
                        handler.on_event(NodeEvent::HeartbeatSent).await;
                        #[cfg(feature = "mmp")]
                        self.mmp.snapshot_stats();
                    }
                    #[cfg(feature = "mmp")]
                    if now >= next_sr {
                        if let Some(sr) = self.mmp.sender.build_report(now) {
                            log_steady!("steady: sending sender report (recv branch)");
                            next_sr = now + self.mmp.sender.report_interval();
                            let encoded = sr.encode();
                            let body_len = encoded.len();
                            self.resp_buf[..body_len].copy_from_slice(&encoded);
                            self.send_link_message(&mut cur, wire::MSG_SENDER_REPORT, body_len)
                                .await;
                        } else {
                            next_sr = now + self.mmp.sender.report_interval();
                        }
                    }
                    #[cfg(not(feature = "mmp"))]
                    if now >= next_sr {
                        log_steady!("steady: sending sender report (recv branch)");
                        next_sr = now + Duration::from_secs(self.timing.heartbeat_interval_secs);
                        let sr_end_ts = now.as_millis() as u32;
                        let mut sr = [0u8; microfips_core::mmp::report::SENDER_REPORT_BODY_SIZE];
                        sr[3..11].copy_from_slice(&sr_start_ctr.to_le_bytes());
                        sr[11..19].copy_from_slice(&cur.send_ctr.to_le_bytes());
                        sr[19..23].copy_from_slice(&sr_start_ts.to_le_bytes());
                        sr[23..27].copy_from_slice(&sr_end_ts.to_le_bytes());
                        self.resp_buf[..microfips_core::mmp::report::SENDER_REPORT_BODY_SIZE]
                            .copy_from_slice(&sr);
                        self.send_link_message(
                            &mut cur,
                            wire::MSG_SENDER_REPORT,
                            microfips_core::mmp::report::SENDER_REPORT_BODY_SIZE,
                        )
                        .await;
                        sr_start_ctr = cur.send_ctr;
                        sr_start_ts = sr_end_ts;
                    }
                    if let Some(t) = tick {
                        #[allow(clippy::collapsible_if)]
                        if now >= t {
                            if let HandleResult::SendDatagram(len) =
                                handler.on_tick(&mut self.resp_buf)
                            {
                                self.send_session_datagram(&mut cur, len).await;
                            }
                        }
                    }
                }
                Either::First(Err(e)) => {
                    log_steady!("steady: recv error, disconnecting: {:?}", e);
                    let _ = e;
                    self.send_disconnect(&mut cur, wire::DISC_REASON_TRANSPORT_FAILURE)
                        .await;
                    return Err(ProtocolError::Disconnected);
                }
                Either::Second(()) => {
                    let now = embassy_time::Instant::now();
                    // Initiator cutover: pend armed by OUR rekey promotes on
                    // the next tick-send (fips "first send after completion");
                    // responder-armed pend still waits for the decrypt proof.
                    if pend_self && pend.is_some() {
                        let new_cur = pend.take().expect("checked");
                        prev = Some(core::mem::replace(&mut cur, new_cur));
                        prev_drain_base = now;
                        // Each epoch ages independently (fips resets
                        // session_start at promote — otherwise the trigger
                        // stays armed and re-initiates every tick).
                        session_started = now;
                        #[cfg(feature = "mmp")]
                        self.mmp.reset_for_rekey(Instant::now());
                        pend_self = false;
                        log_steady!(
                            "steady: rekey cutover complete (self-initiated), K-bit flipped"
                        );
                    }
                    // Self-initiated rekey trigger (0 = off). Dampened for
                    // REKEY_DAMPENING_SECS after the peer initiated one.
                    if rekey_init.is_none()
                        && pend.is_none()
                        && !matches!(last_peer_rekey_at, Some(t) if now
                            .saturating_duration_since(t)
                            .as_secs()
                            < REKEY_DAMPENING_SECS)
                        && ((self.timing.rekey_after_secs > 0
                            && now.saturating_duration_since(session_started).as_secs()
                                >= self.timing.rekey_after_secs)
                            || (self.timing.rekey_after_messages > 0
                                && cur.send_ctr >= self.timing.rekey_after_messages))
                    {
                        if let Some(ri) = self.initiate_rekey(epoch).await {
                            rekey_init = Some(ri);
                        }
                    }
                    // Resend ladder / abandon (same cadence as the initial
                    // handshake, fips `resend_pending_rekeys`).
                    if let Some(ri) = rekey_init.as_mut() {
                        if now >= ri.next_resend_at {
                            if ri.resends >= self.timing.handshake_max_resends {
                                log_steady!("steady: rekey msg1 unconfirmed, abandoning cycle");
                                rekey_init = None;
                            } else {
                                let _ = self.send_frame(&ri.msg1[..ri.msg1_len]).await;
                                ri.resends += 1;
                                let delay = self.current_handshake_resend_timeout_ms(ri.resends);
                                ri.next_resend_at = now + Duration::from_millis(delay as u64);
                            }
                        }
                    }
                    // Drain sweeper: retire the previous epoch once the peer
                    // has been silent on it for a full window (fips peer-
                    // progress-aware drain).
                    if prev.is_some()
                        && now.saturating_duration_since(prev_drain_base).as_secs()
                            > DRAIN_WINDOW_SECS
                    {
                        if let Some(mut retired) = prev.take() {
                            use microfips_core::noise::Zeroize;
                            retired.ks.zeroize();
                            retired.kr.zeroize();
                            log_steady!("steady: drain complete, previous epoch keys zeroized");
                        }
                    }
                    if now >= next_hb {
                        log_steady!(
                            "steady: sending heartbeat (timer branch, ctr={})",
                            cur.send_ctr
                        );
                        next_hb = self.send_heartbeat(&mut cur).await;
                        handler.on_event(NodeEvent::HeartbeatSent).await;
                        if self.policy.check_silent_peer(Instant::now()) == PolicyVerdict::Reject {
                            log_steady!("policy: rejected: silent peer");
                            self.send_disconnect(&mut cur, wire::DISC_REASON_RESOURCE_EXHAUSTION)
                                .await;
                            return Err(ProtocolError::Disconnected);
                        }
                        #[cfg(feature = "mmp")]
                        self.mmp.snapshot_stats();
                    }
                    #[cfg(feature = "mmp")]
                    if now >= next_sr {
                        if let Some(sr) = self.mmp.sender.build_report(now) {
                            log_steady!("steady: sending sender report (timer branch)");
                            next_sr = now + self.mmp.sender.report_interval();
                            let encoded = sr.encode();
                            let body_len = encoded.len();
                            self.resp_buf[..body_len].copy_from_slice(&encoded);
                            self.send_link_message(&mut cur, wire::MSG_SENDER_REPORT, body_len)
                                .await;
                        } else {
                            next_sr = now + self.mmp.sender.report_interval();
                        }
                    }
                    #[cfg(not(feature = "mmp"))]
                    if now >= next_sr {
                        next_sr = now + Duration::from_secs(self.timing.heartbeat_interval_secs);
                        let sr_end_ts = now.as_millis() as u32;
                        let mut sr = [0u8; microfips_core::mmp::report::SENDER_REPORT_BODY_SIZE];
                        sr[3..11].copy_from_slice(&sr_start_ctr.to_le_bytes());
                        sr[11..19].copy_from_slice(&cur.send_ctr.to_le_bytes());
                        sr[19..23].copy_from_slice(&sr_start_ts.to_le_bytes());
                        sr[23..27].copy_from_slice(&sr_end_ts.to_le_bytes());
                        self.resp_buf[..microfips_core::mmp::report::SENDER_REPORT_BODY_SIZE]
                            .copy_from_slice(&sr);
                        self.send_link_message(
                            &mut cur,
                            wire::MSG_SENDER_REPORT,
                            microfips_core::mmp::report::SENDER_REPORT_BODY_SIZE,
                        )
                        .await;
                        sr_start_ctr = cur.send_ctr;
                        sr_start_ts = sr_end_ts;
                    }
                    if let Some(t) = tick {
                        #[allow(clippy::collapsible_if)]
                        if now >= t {
                            if let HandleResult::SendDatagram(len) =
                                handler.on_tick(&mut self.resp_buf)
                            {
                                self.send_session_datagram(&mut cur, len).await;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Encrypt and send a session datagram via FMP established frame.
    /// FIPS: mod.rs:1578-1663 send_encrypted_link_message_with_ce() —
    /// prepend_inner_header(timestamp, plaintext) → build_established_header →
    /// encrypt_with_aad(header as AAD) → transport.send().
    async fn send_session_datagram(&mut self, slot: &mut EpochSlot, len: usize) {
        use microfips_core::wire;
        let c = slot.send_ctr;
        slot.send_ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let msg_end = 1 + len;
        let mut msg_buf = [0u8; 512];
        msg_buf[0] = wire::MSG_SESSION_DATAGRAM;
        msg_buf[1..msg_end].copy_from_slice(&self.resp_buf[..len]);
        let mut inner_buf = [0u8; 512];
        let inner_len = match wire::prepend_inner_header(ts, &msg_buf[..msg_end], &mut inner_buf) {
            Some(l) => l,
            None => {
                #[cfg(feature = "log")]
                log::warn!("send_session_datagram: prepend_inner_header failed");
                return;
            }
        };
        let flags = if slot.k_bit {
            wire::FLAG_KEY_EPOCH
        } else {
            0x00
        };
        let fl = wire::encrypt_and_assemble(
            slot.them,
            c,
            flags,
            &inner_buf[..inner_len],
            &slot.ks,
            &mut out,
        );
        if let Some(fl) = fl {
            log_steady!(
                "steady: sending session datagram type=0x{:02x} len={} frame={}B",
                wire::MSG_SESSION_DATAGRAM,
                len,
                fl
            );
            if let Err(_e) = self.send_frame(&out[..fl]).await {
                #[cfg(feature = "log")]
                log::warn!("send failed: {:?}", _e);
            }
            #[cfg(feature = "mmp")]
            self.mmp.sender.record_sent(c, ts, fl);
            // App-level send on the direct (non-FrameAction) path — feed
            // the silent-peer policy here, or a heartbeat-only-looking but
            // healthy link gets torn down at link_dead_timeout (bench-found
            // vs the next-line XX daemon, #193).
            self.policy.record_data_frame();
        }
    }

    async fn send_link_message(&mut self, slot: &mut EpochSlot, msg_type: u8, len: usize) {
        use microfips_core::wire;
        let c = slot.send_ctr;
        slot.send_ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let msg_end = 1 + len;
        let mut msg_buf = [0u8; 512];
        msg_buf[0] = msg_type;
        msg_buf[1..msg_end].copy_from_slice(&self.resp_buf[..len]);
        let mut inner_buf = [0u8; 512];
        let inner_len = match wire::prepend_inner_header(ts, &msg_buf[..msg_end], &mut inner_buf) {
            Some(l) => l,
            None => {
                #[cfg(feature = "log")]
                log::warn!("send_link_message: prepend_inner_header failed");
                return;
            }
        };
        let flags = if slot.k_bit {
            wire::FLAG_KEY_EPOCH
        } else {
            0x00
        };
        let fl = wire::encrypt_and_assemble(
            slot.them,
            c,
            flags,
            &inner_buf[..inner_len],
            &slot.ks,
            &mut out,
        );
        if let Some(fl) = fl {
            if let Err(_e) = self.send_frame(&out[..fl]).await {
                #[cfg(feature = "log")]
                log::warn!("send failed: {:?}", _e);
            }
            #[cfg(feature = "mmp")]
            self.mmp.sender.record_sent(c, ts, fl);
            self.policy.record_data_frame();
        }
    }

    /// Encrypt and send a heartbeat via FMP established frame.
    /// FIPS: Same send path as send_session_datagram, with MSG_HEARTBEAT (0x51) and empty payload.
    /// FIPS: dispatch.rs:54 traces "Received heartbeat" on rx.
    async fn send_heartbeat(&mut self, slot: &mut EpochSlot) -> embassy_time::Instant {
        use microfips_core::wire;

        let c = slot.send_ctr;
        slot.send_ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let mut inner_buf = [0u8; 32];
        let inner_len = match wire::prepend_inner_header(ts, &[wire::MSG_HEARTBEAT], &mut inner_buf)
        {
            Some(l) => l,
            None => return self.next_heartbeat_deadline(),
        };
        let flags = if slot.k_bit {
            wire::FLAG_KEY_EPOCH
        } else {
            0x00
        };
        let fl = wire::encrypt_and_assemble(
            slot.them,
            c,
            flags,
            &inner_buf[..inner_len],
            &slot.ks,
            &mut out,
        );

        if let Some(fl) = fl {
            if let Err(_e) = self.send_frame(&out[..fl]).await {
                #[cfg(feature = "log")]
                log::warn!("send failed: {:?}", _e);
            }
            #[cfg(feature = "mmp")]
            self.mmp.sender.record_sent(c, ts, fl);
        }

        self.next_heartbeat_deadline()
    }

    fn next_heartbeat_deadline(&self) -> embassy_time::Instant {
        embassy_time::Instant::now() + Duration::from_secs(self.timing.heartbeat_interval_secs)
    }

    fn current_handshake_resend_timeout_ms(&self, resend_count: u32) -> u32 {
        let base = self.timing.handshake_resend_interval_ms;
        if resend_count == 0 {
            return base.min(u32::MAX as u64) as u32;
        }

        let factor = self.timing.handshake_resend_backoff.max(1);
        let mut scaled = base;
        for _ in 0..resend_count.min(15) {
            scaled = scaled.saturating_mul(factor);
        }

        scaled.min(u32::MAX as u64) as u32
    }

    async fn send_disconnect(&mut self, slot: &mut EpochSlot, reason: u8) {
        let c = slot.send_ctr;
        slot.send_ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let mut inner_buf = [0u8; 32];
        let inner_len =
            match wire::prepend_inner_header(ts, &[wire::MSG_DISCONNECT, reason], &mut inner_buf) {
                Some(l) => l,
                None => {
                    #[cfg(feature = "log")]
                    log::warn!("send_disconnect: prepend_inner_header failed");
                    return;
                }
            };
        let flags = if slot.k_bit {
            wire::FLAG_KEY_EPOCH
        } else {
            0x00
        };
        let fl = wire::encrypt_and_assemble(
            slot.them,
            c,
            flags,
            &inner_buf[..inner_len],
            &slot.ks,
            &mut out,
        );
        if let Some(fl) = fl {
            if let Err(_e) = self.send_frame(&out[..fl]).await {
                #[cfg(feature = "log")]
                log::warn!("send failed: {:?}", _e);
            }
            #[cfg(feature = "mmp")]
            self.mmp.sender.record_sent(c, ts, fl);
        }
    }

    /// Initiate a rekey over the established link: fresh initiator
    /// handshake with the long-term key and the session epoch, msg1 with a
    /// fresh session index (fips `initiate_rekey`). The caller owns the
    /// resend ladder via the returned cached msg1.
    async fn initiate_rekey(
        &mut self,
        _epoch: [u8; microfips_core::noise::EPOCH_SIZE],
    ) -> Option<RekeyInit> {
        use microfips_core::noise;

        #[cfg(not(feature = "noise-xx"))]
        let my_pub = noise::ecdh_pubkey(&self.nsec).ok()?;
        let eph = self.generate_valid_eph();
        #[cfg(not(feature = "noise-xx"))]
        let (mut hs, _) = noise::NoiseIkInitiator::new(&eph, &self.nsec, &self.peer_npub).ok()?;
        #[cfg(feature = "noise-xx")]
        let (mut hs, _) = noise::NoiseXxInitiator::new(&eph, &self.nsec).ok()?;

        let mut n1 = [0u8; 256];
        #[cfg(not(feature = "noise-xx"))]
        let n1len = hs.write_message1(&my_pub, &_epoch, &mut n1).ok()?;
        #[cfg(feature = "noise-xx")]
        let n1len = hs.write_message1(&mut n1).ok()?;

        let our_index = self.allocate_session_index();
        let mut msg1 = [0u8; 256];
        let msg1_len = wire::build_msg1(our_index, &n1[..n1len], &mut msg1)?;
        self.send_frame(&msg1[..msg1_len]).await.ok()?;
        log_steady!("steady: rekey initiated, msg1 sent");

        Some(RekeyInit {
            hs,
            our_index,
            msg1,
            msg1_len,
            resends: 0,
            next_resend_at: embassy_time::Instant::now()
                + Duration::from_millis(self.timing.handshake_resend_interval_ms),
        })
    }

    /// Build the answer to an inbound rekey msg1 (IK) on the established
    /// link: fresh responder handshake, identity-checked against the pinned
    /// peer key, msg2 with a fresh session index. Returns the pending epoch
    /// plus the msg2 frame bytes — the caller sends and caches them so a
    /// resent msg1 draws a byte-identical msg2.
    #[cfg(not(feature = "noise-xx"))]
    async fn answer_rekey_msg1_ik(
        &mut self,
        peer_sender_idx: wire::SessionIndex,
        noise_payload: &[u8],
        epoch: [u8; microfips_core::noise::EPOCH_SIZE],
        cur_k_bit: bool,
    ) -> Option<(EpochSlot, [u8; 256], usize)> {
        use microfips_core::noise::{NoiseIkResponder, PUBKEY_SIZE};

        if noise_payload.len() < PUBKEY_SIZE {
            return None;
        }
        let e_init_pub: [u8; PUBKEY_SIZE] = noise_payload[..PUBKEY_SIZE].try_into().ok()?;
        let mut responder = NoiseIkResponder::new(&self.nsec, &e_init_pub).ok()?;
        let (init_pub, _parsed_epoch) = responder
            .read_message1(&noise_payload[PUBKEY_SIZE..])
            .ok()?;
        if init_pub[1..33] != self.peer_npub[1..33] {
            log_steady!("steady: rekey msg1 identity mismatch, discarded");
            return None;
        }

        let resp_eph = self.generate_valid_eph();
        let mut msg2_noise = [0u8; 128];
        let noise_len = responder
            .write_message2(&resp_eph, &epoch, &mut msg2_noise)
            .ok()?;

        let resp_index = self.allocate_session_index();
        let mut msg2_buf = [0u8; 256];
        let msg2_len = wire::build_msg2(
            resp_index,
            peer_sender_idx,
            &msg2_noise[..noise_len],
            &mut msg2_buf,
        )?;

        let (c1, c2) = responder.finalize();
        Some((
            EpochSlot {
                ks: c2,
                kr: c1,
                them: peer_sender_idx,
                send_ctr: 0,
                k_bit: !cur_k_bit,
                replay: microfips_core::noise::ReplayWindow::new(),
            },
            msg2_buf,
            msg2_len,
        ))
    }

    /// Build the first half of an inbound XX rekey answer on the established
    /// link: msg1 read, msg2 built (caller sends + caches it); the responder
    /// state is held until the peer's msg3 completes it.
    #[cfg(feature = "noise-xx")]
    async fn begin_rekey_xx(
        &mut self,
        peer_sender_idx: wire::SessionIndex,
        noise_payload: &[u8],
        epoch: [u8; microfips_core::noise::EPOCH_SIZE],
    ) -> Option<(
        microfips_core::noise::NoiseXxResponder,
        wire::SessionIndex,
        [u8; 256],
        usize,
    )> {
        use microfips_core::noise::{NoiseXxResponder, XX_HANDSHAKE_MSG1_SIZE};

        if noise_payload.len() != XX_HANDSHAKE_MSG1_SIZE {
            return None;
        }
        let mut responder = NoiseXxResponder::new(&self.nsec).ok()?;
        responder.read_message1(noise_payload).ok()?;

        let resp_eph = self.generate_valid_eph();
        let mut msg2_noise = [0u8; 128];
        let noise_len = responder
            .write_message2(&resp_eph, &epoch, &mut msg2_noise)
            .ok()?;

        let resp_index = self.allocate_session_index();
        let mut msg2_buf = [0u8; 256];
        let msg2_len = wire::build_msg2(
            resp_index,
            peer_sender_idx,
            &msg2_noise[..noise_len],
            &mut msg2_buf,
        )?;
        Some((responder, resp_index, msg2_buf, msg2_len))
    }

    async fn send_frame(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        if !self.raw_framing {
            let hdr = (payload.len() as u16).to_le_bytes();
            self.transport
                .send(&hdr)
                .await
                .map_err(|_| ProtocolError::Disconnected)?;
        }
        self.transport
            .send(payload)
            .await
            .map_err(|_| ProtocolError::Disconnected)
    }

    async fn recv_frame(
        &mut self,
        out: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, ProtocolError> {
        if self.raw_framing {
            self.recv_frame_raw(out, timeout_ms).await
        } else {
            self.recv_frame_length_prefixed(out, timeout_ms).await
        }
    }

    async fn recv_frame_length_prefixed(
        &mut self,
        out: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, ProtocolError> {
        loop {
            if let Some((frame, new_pos)) =
                extract_length_prefixed_frame(&self.rbuf, self.rpos, self.rlen)
            {
                self.rpos = new_pos;
                if self.rpos >= self.rlen {
                    self.rpos = 0;
                    self.rlen = 0;
                }
                if frame.is_empty() {
                    // Invalid length — skip and keep reading
                    continue;
                }
                let l = frame.len().min(out.len());
                out[..l].copy_from_slice(&frame[..l]);
                return Ok(l);
            }

            framing::compact(&mut self.rbuf, &mut self.rpos, &mut self.rlen);
            let mut rx = [0u8; RECV_BUF_SIZE];
            match select(
                self.transport.recv(&mut rx),
                Timer::after(Duration::from_millis(timeout_ms as u64)),
            )
            .await
            {
                Either::First(Ok(n)) => {
                    if self.rlen + n > self.rbuf.len() {
                        self.rlen = 0;
                        self.rpos = 0;
                        continue;
                    }
                    self.rbuf[self.rlen..self.rlen + n].copy_from_slice(&rx[..n]);
                    self.rlen += n;
                }
                Either::First(Err(_)) => {
                    return Err(ProtocolError::Disconnected);
                }
                Either::Second(()) => return Err(ProtocolError::Timeout),
            }
        }
    }

    async fn recv_frame_raw(
        &mut self,
        out: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, ProtocolError> {
        loop {
            if let Some((frame, new_pos)) = extract_raw_frame(&self.rbuf, self.rpos, self.rlen) {
                let l = frame.len().min(out.len());
                out[..l].copy_from_slice(&frame[..l]);
                self.rpos = new_pos;
                if self.rpos >= self.rlen {
                    self.rpos = 0;
                    self.rlen = 0;
                }
                return Ok(l);
            }

            framing::compact(&mut self.rbuf, &mut self.rpos, &mut self.rlen);
            let mut rx = [0u8; RECV_BUF_SIZE];
            match select(
                self.transport.recv(&mut rx),
                Timer::after(Duration::from_millis(timeout_ms as u64)),
            )
            .await
            {
                Either::First(Ok(n)) => {
                    if self.rlen + n > self.rbuf.len() {
                        self.rlen = 0;
                        self.rpos = 0;
                        continue;
                    }
                    self.rbuf[self.rlen..self.rlen + n].copy_from_slice(&rx[..n]);
                    self.rlen += n;
                }
                Either::First(Err(_)) => {
                    return Err(ProtocolError::Disconnected);
                }
                Either::Second(()) => return Err(ProtocolError::Timeout),
            }
        }
    }
}

#[derive(Debug, PartialEq)]
struct DecryptedFrame<'a> {
    counter: u64,
    sender_timestamp: u32,
    msg_type: u8,
    payload: &'a [u8],
    frame_bytes: usize,
}

/// Decrypt a single FMP established frame.
/// FIPS: handlers/encrypted.rs:23-171 handle_encrypted_frame() → AEAD decrypt with
/// 16-byte header as AAD → strip_inner_header → dispatch_link_message.
///
/// Replay protection (fips `noise/replay.rs` semantics): the counter is
/// checked against the window BEFORE the expensive AEAD decrypt and only
/// accepted AFTER it succeeds, so garbage cannot exhaust the window.
fn decrypt_established_frame<'a>(
    kr: &[u8; 32],
    data: &[u8],
    dec_buf: &'a mut [u8; MAX_FRAME_SIZE],
    replay: &mut microfips_core::noise::ReplayWindow,
) -> Option<DecryptedFrame<'a>> {
    use microfips_core::wire;

    let m = match wire::parse_message(data) {
        Some(m) => m,
        None => {
            #[cfg(feature = "log")]
            log::warn!("handle_frame: parse_message failed ({}B)", data.len());
            return None;
        }
    };

    let wire::FmpMessage::Established { .. } = m else {
        #[cfg(feature = "std")]
        if matches!(
            m,
            wire::FmpMessage::Msg1 { .. }
                | wire::FmpMessage::Msg2 { .. }
                | wire::FmpMessage::Msg3 { .. }
        ) {
            log::warn!("discarding handshake frame in established state");
        }
        return None;
    };

    let enc = wire::EncryptedHeader::parse(data)?;
    #[cfg(feature = "log")]
    log::debug!(
        "FMP established: counter={} enc_len={}",
        enc.counter,
        data.len() - wire::ESTABLISHED_HEADER_SIZE
    );
    if !replay.check(enc.counter) {
        #[cfg(feature = "log")]
        log::warn!("FMP replay rejected: counter={}", enc.counter);
        return None;
    }
    let dl = match microfips_core::noise::aead_decrypt(
        kr,
        enc.counter,
        &enc.header_bytes,
        &data[wire::ESTABLISHED_HEADER_SIZE..],
        dec_buf,
    ) {
        Ok(l) => l,
        Err(_err) => {
            #[cfg(feature = "std")]
            log::debug!(
                "FMP decrypt failed: counter={} hdr={:02x?} err={:?}",
                enc.counter,
                &enc.header_bytes[..16.min(enc.header_bytes.len())],
                _err
            );
            return None;
        }
    };
    replay.accept(enc.counter);

    let (sender_timestamp, inner_rest) = wire::strip_inner_header(&dec_buf[..dl])?;
    let (&msg_type, payload) = inner_rest.split_first()?;
    #[cfg(feature = "log")]
    log::debug!(
        "FMP frame: msg_type=0x{:02x} payload_len={}",
        msg_type,
        payload.len()
    );

    Some(DecryptedFrame {
        counter: enc.counter,
        sender_timestamp,
        msg_type,
        payload,
        frame_bytes: data.len(),
    })
}

fn build_receiver_report_response(payload: &[u8], resp: &mut [u8]) -> FrameAction {
    use microfips_core::wire;

    if payload.len() >= 27 && resp.len() >= microfips_core::mmp::report::RECEIVER_REPORT_BODY_SIZE {
        let end_ctr = u64::from_le_bytes(payload[11..19].try_into().unwrap_or(0u64.to_le_bytes()));
        let end_ts = u32::from_le_bytes(payload[23..27].try_into().unwrap_or(0u32.to_le_bytes()));
        resp[..microfips_core::mmp::report::RECEIVER_REPORT_BODY_SIZE]
            .copy_from_slice(&[0u8; microfips_core::mmp::report::RECEIVER_REPORT_BODY_SIZE]);
        resp[3..11].copy_from_slice(&end_ctr.to_le_bytes());
        resp[27..31].copy_from_slice(&end_ts.to_le_bytes());
        FrameAction::SendLinkMessage {
            msg_type: wire::MSG_RECEIVER_REPORT,
            len: microfips_core::mmp::report::RECEIVER_REPORT_BODY_SIZE,
        }
    } else {
        FrameAction::Continue
    }
}

#[cfg(feature = "benchmark")]
fn handle_throughput_request(frame: &DecryptedFrame<'_>, throughput: &mut ThroughputState) {
    if let Some((test_id, direction, duration_secs, _frame_size, _rate_bps)) =
        wire::parse_throughput_request(frame.payload)
    {
        if direction == 0 {
            *throughput = ThroughputState {
                test_id,
                frames_recv: 0,
                bytes_recv: 0,
                started_at: Some(Instant::now()),
                duration_secs,
                active: true,
            };
        }
    }
}

#[cfg(feature = "benchmark")]
fn handle_throughput_stream(
    frame: &DecryptedFrame<'_>,
    throughput: &mut ThroughputState,
    resp: &mut [u8],
) -> FrameAction {
    use microfips_core::wire;

    if !throughput.active {
        return FrameAction::Continue;
    }

    let Some((test_id, _sequence)) = wire::parse_throughput_stream(frame.payload) else {
        return FrameAction::Continue;
    };

    if test_id != throughput.test_id {
        return FrameAction::Continue;
    }

    throughput.frames_recv = throughput.frames_recv.saturating_add(1);
    throughput.bytes_recv = throughput
        .bytes_recv
        .saturating_add(frame.payload.len() as u64);

    let elapsed_us = match throughput.started_at {
        Some(t) => Instant::now().as_micros().saturating_sub(t.as_micros()),
        None => return FrameAction::Continue,
    };
    let target_duration_us = u64::from(throughput.duration_secs) * 1_000_000;
    if elapsed_us < target_duration_us {
        return FrameAction::Continue;
    }

    let report = *throughput;
    throughput.active = false;
    let achieved_bps = report
        .bytes_recv
        .saturating_mul(8)
        .saturating_mul(1_000_000)
        .checked_div(elapsed_us)
        .unwrap_or(0);

    if let Some(resp_len) = wire::build_throughput_report(
        report.test_id,
        0,
        report.frames_recv,
        report.bytes_recv,
        elapsed_us,
        achieved_bps,
        resp,
    ) {
        FrameAction::SendLinkMessage {
            msg_type: wire::MSG_THROUGHPUT_REPORT,
            len: resp_len,
        }
    } else {
        FrameAction::Continue
    }
}

#[cfg(feature = "benchmark")]
fn dispatch_link_message<H: NodeHandler>(
    frame: &DecryptedFrame<'_>,
    throughput: &mut ThroughputState,
    handler: &mut H,
    resp: &mut [u8],
) -> FrameAction {
    use microfips_core::wire;

    match frame.msg_type {
        wire::MSG_HEARTBEAT => FrameAction::HeartbeatRecv,
        wire::MSG_DISCONNECT => {
            let reason = frame
                .payload
                .first()
                .copied()
                .unwrap_or(wire::DISC_REASON_OTHER);
            FrameAction::PeerDC { reason }
        }
        wire::MSG_SENDER_REPORT => build_receiver_report_response(frame.payload, resp),
        wire::MSG_RECEIVER_REPORT => FrameAction::Continue,
        wire::MSG_ECHO_REQUEST => {
            if let Some((send_ts, seq, payload)) = wire::parse_echo_request(frame.payload) {
                let now_us = Instant::now().as_micros();
                if let Some(resp_len) =
                    wire::build_echo_response(send_ts, now_us, seq, payload, resp)
                {
                    FrameAction::SendLinkMessage {
                        msg_type: wire::MSG_ECHO_RESPONSE,
                        len: resp_len,
                    }
                } else {
                    FrameAction::Continue
                }
            } else {
                FrameAction::Continue
            }
        }
        wire::MSG_THROUGHPUT_REQUEST => {
            handle_throughput_request(frame, throughput);
            FrameAction::Continue
        }
        wire::MSG_THROUGHPUT_STREAM => handle_throughput_stream(frame, throughput, resp),
        _ => match handler.on_message(frame.msg_type, frame.payload, resp) {
            HandleResult::None => FrameAction::Continue,
            HandleResult::SendDatagram(len) => FrameAction::SendDatagram(len),
            HandleResult::Disconnect => FrameAction::SelfDC,
        },
    }
}

#[cfg(not(feature = "benchmark"))]
fn dispatch_link_message<H: NodeHandler>(
    frame: &DecryptedFrame<'_>,
    _throughput: &mut (),
    handler: &mut H,
    resp: &mut [u8],
) -> FrameAction {
    use microfips_core::wire;

    match frame.msg_type {
        wire::MSG_HEARTBEAT => FrameAction::HeartbeatRecv,
        wire::MSG_DISCONNECT => {
            let reason = frame
                .payload
                .first()
                .copied()
                .unwrap_or(wire::DISC_REASON_OTHER);
            FrameAction::PeerDC { reason }
        }
        wire::MSG_SENDER_REPORT => build_receiver_report_response(frame.payload, resp),
        wire::MSG_RECEIVER_REPORT => FrameAction::Continue,
        wire::MSG_ECHO_REQUEST => {
            if let Some((send_ts, seq, payload)) = wire::parse_echo_request(frame.payload) {
                let now_us = Instant::now().as_micros();
                if let Some(resp_len) =
                    wire::build_echo_response(send_ts, now_us, seq, payload, resp)
                {
                    FrameAction::SendLinkMessage {
                        msg_type: wire::MSG_ECHO_RESPONSE,
                        len: resp_len,
                    }
                } else {
                    FrameAction::Continue
                }
            } else {
                FrameAction::Continue
            }
        }
        wire::MSG_THROUGHPUT_REQUEST | wire::MSG_THROUGHPUT_STREAM => FrameAction::Continue,
        _ => match handler.on_message(frame.msg_type, frame.payload, resp) {
            HandleResult::None => FrameAction::Continue,
            HandleResult::SendDatagram(len) => FrameAction::SendDatagram(len),
            HandleResult::Disconnect => FrameAction::SelfDC,
        },
    }
}

#[derive(Debug, PartialEq)]
enum FrameAction {
    Continue,
    HeartbeatRecv,
    PeerDC { reason: u8 },
    SelfDC,
    SendDatagram(usize),
    SendLinkMessage { msg_type: u8, len: usize },
}

/// Determine the total wire size of a raw FMP frame from its 4-byte common prefix.
///
/// For MSG1, uses the fixed wire size (41B on XX / 122B on IK — never
/// carries a negotiation extra). For MSG2/MSG3, derives the total from the
/// prefix `payload_len` field, which both microfips and FIPS write as the
/// true post-prefix size including any appended negotiation payload — the
/// fixed `MSGx_WIRE_SIZE` constants cover only the base Noise message and
/// would silently truncate the negotiation extra (raw-UDP desync of the
/// AEAD counter → the peer's msg3 decrypt fails).
/// For established frames, returns `None` — the caller must use the full
/// available buffer as one frame (UDP datagram boundary).
///
/// Returns `None` if fewer than 4 bytes are available, the prefix is invalid,
/// or the computed total exceeds [`framing::MAX_FRAME`].
///
/// **Why not use `payload_len` for established frames?** FIPS writes the inner
/// plaintext length in `payload_len` (N1 deviation), not the post-prefix wire
/// size. Since we also write a different value (post-prefix wire size including
/// AEAD tag), the field is unreliable for determining frame boundaries across
/// implementations. Raw UDP framing relies on datagram boundaries instead.
fn fmp_raw_frame_size(data: &[u8]) -> Option<usize> {
    use microfips_core::wire;

    let prefix = wire::CommonPrefix::parse(data)?;
    match prefix.phase {
        wire::PHASE_MSG1 => {
            let total = wire::MSG1_WIRE_SIZE;
            if data.len() < total {
                None
            } else {
                Some(total)
            }
        }
        wire::PHASE_MSG2 => handshake_frame_size(data, &prefix, wire::MSG2_WIRE_SIZE),
        wire::PHASE_MSG3 => handshake_frame_size(data, &prefix, wire::MSG3_WIRE_SIZE),
        _ => None,
    }
}

/// Total wire size of a negotiation-capable handshake frame (msg2/msg3):
/// `COMMON_PREFIX_SIZE + payload_len`, validated against the base size and
/// the transport frame cap.
fn handshake_frame_size(
    data: &[u8],
    prefix: &wire::CommonPrefix,
    base_wire_size: usize,
) -> Option<usize> {
    use microfips_core::wire;

    let total = wire::COMMON_PREFIX_SIZE + prefix.payload_len as usize;
    if total < base_wire_size || total > data.len() || total > framing::MAX_FRAME {
        return None;
    }
    Some(total)
}

/// Extract one complete length-prefixed frame from `buf[pos..len]`.
///
/// Returns `(frame_slice, new_pos)` where `frame_slice` is the payload
/// (without the 2-byte header) and `new_pos` is the buffer position after
/// the frame. Returns `None` if a complete frame is not yet available.
fn extract_length_prefixed_frame(buf: &[u8], pos: usize, len: usize) -> Option<(&[u8], usize)> {
    let avail = len - pos;
    if avail < 2 {
        return None;
    }
    let ml = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
    if ml == 0 || ml > framing::MAX_FRAME {
        // Invalid length — skip the 2-byte header to avoid deadlock
        let skip = core::cmp::min(2, avail);
        return Some((&buf[pos..pos], pos + skip));
    }
    if avail - 2 < ml {
        return None;
    }
    let s = pos + 2;
    let e = s + ml;
    Some((&buf[s..e], e))
}

/// Extract one complete raw FMP frame from `buf[pos..len]`.
///
/// Returns `(frame_slice, new_pos)` where `frame_slice` is the full FMP frame
/// (including the 4-byte common prefix) and `new_pos` is the buffer position
/// after the frame. Returns `None` if a complete frame is not yet available.
///
/// For MSG1/MSG2, uses exact wire sizes. For established frames (where
/// `payload_len` is unreliable across implementations), treats the entire
/// available buffer as one frame — this is correct for raw UDP transport
/// where each datagram is exactly one FMP frame.
fn extract_raw_frame(buf: &[u8], pos: usize, len: usize) -> Option<(&[u8], usize)> {
    use microfips_core::wire;

    let avail = len - pos;
    if avail < wire::COMMON_PREFIX_SIZE {
        return None;
    }
    match fmp_raw_frame_size(&buf[pos..len]) {
        Some(total) => {
            if avail < total {
                return None;
            }
            let e = pos + total;
            Some((&buf[pos..e], e))
        }
        None => {
            let prefix = wire::CommonPrefix::parse(&buf[pos..len])?;
            match prefix.phase {
                wire::PHASE_ESTABLISHED => {
                    if avail < wire::ESTABLISHED_HEADER_SIZE + microfips_core::noise::TAG_SIZE {
                        return None;
                    }
                    let e = pos + avail;
                    Some((&buf[pos..e], e))
                }
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_harness::{
        build_test_frame, decrypt_test_frame, distinct_secret_pair, node_addr_from_secret,
        random_secret, recv_test_frame, send_test_frame, ScriptedPeer, TestRng,
    };
    use crate::test_helpers::block_on;
    use crate::transport::Transport;
    use std::boxed::Box;
    use std::vec;

    fn fresh_inner() -> &'static crate::transport::mock::MockTransportInner {
        Box::leak(Box::new(crate::transport::mock::MockTransportInner::new()))
    }

    #[test]
    fn test_send_frame_works() {
        let inner = fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner);

        block_on(async {
            let mut node = Node::new(transport, TestRng::new(&[0u8; 32]), [0u8; 32], [0u8; 33]);
            node.send_frame(b"hello").await.unwrap();

            let tx = inner.tx.lock().unwrap();
            let expected: std::vec::Vec<u8> = {
                let mut v = (5u16).to_le_bytes().to_vec();
                v.extend_from_slice(b"hello");
                v
            };
            assert_eq!(*tx, expected);
        });
    }

    #[test]
    fn test_node_new_uses_fips_aligned_default_timing() {
        let inner = fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner);

        let node = Node::new(transport, TestRng::new(&[0u8; 32]), [0u8; 32], [0u8; 33]);

        assert_eq!(node.timing, NodeTiming::default());
    }

    #[test]
    fn test_node_with_timing_overrides_defaults() {
        let inner = fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner);
        let timing = NodeTiming {
            heartbeat_interval_secs: 7,
            link_dead_timeout_secs: 9,
            retry_base_interval_secs: 2,
            retry_max_backoff_secs: 11,
            handshake_resend_interval_ms: 250,
            handshake_resend_backoff: 3,
            handshake_max_resends: 4,
            connect_delay_ms: 42,
            rekey_after_secs: 0,
            rekey_after_messages: 0,
        };

        let node = Node::with_timing(
            transport,
            TestRng::new(&[0u8; 32]),
            [0u8; 32],
            [0u8; 33],
            timing,
        );

        assert_eq!(node.timing, timing);
        assert_eq!(node.current_handshake_resend_timeout_ms(0), 250);
        assert_eq!(node.current_handshake_resend_timeout_ms(1), 750);
        assert_eq!(node.current_handshake_resend_timeout_ms(2), 2_250);
    }

    #[test]
    fn test_recv_frame_from_buffer() {
        let inner = fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner);

        block_on(async {
            let mut node = Node::new(transport, TestRng::new(&[0u8; 32]), [0u8; 32], [0u8; 33]);

            let frame: std::vec::Vec<u8> = {
                let mut v = (3u16).to_le_bytes().to_vec();
                v.extend_from_slice(b"abc");
                v
            };
            inner.rx.lock().unwrap().extend_from_slice(&frame);

            let mut out = [0u8; 256];
            let n = node.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 3);
            assert_eq!(&out[..3], b"abc");
        });
    }

    struct NoopTestHandler;
    impl NodeHandler for NoopTestHandler {
        async fn on_event(&mut self, _event: NodeEvent) {}
        fn on_message(&mut self, _msg_type: u8, _payload: &[u8], _resp: &mut [u8]) -> HandleResult {
            HandleResult::None
        }
    }

    #[derive(Default)]
    struct RecordingHandler {
        events: std::vec::Vec<NodeEvent>,
    }

    impl NodeHandler for RecordingHandler {
        async fn on_event(&mut self, event: NodeEvent) {
            self.events.push(event);
        }

        fn on_message(&mut self, _msg_type: u8, _payload: &[u8], _resp: &mut [u8]) -> HandleResult {
            HandleResult::None
        }
    }

    #[cfg(feature = "benchmark")]
    fn dispatch_test_frame<H: NodeHandler>(
        key: &[u8; 32],
        frame: &[u8],
        throughput: &mut ThroughputState,
        handler: &mut H,
        resp: &mut [u8],
    ) -> FrameAction {
        let mut dec_buf = [0u8; MAX_FRAME_SIZE];
        let Some(frame) = decrypt_established_frame(
            key,
            frame,
            &mut dec_buf,
            &mut microfips_core::noise::ReplayWindow::new(),
        ) else {
            return FrameAction::Continue;
        };
        dispatch_link_message(&frame, throughput, handler, resp)
    }

    #[cfg(not(feature = "benchmark"))]
    fn dispatch_test_frame<H: NodeHandler>(
        key: &[u8; 32],
        frame: &[u8],
        _throughput: &mut (),
        handler: &mut H,
        resp: &mut [u8],
    ) -> FrameAction {
        let mut dec_buf = [0u8; MAX_FRAME_SIZE];
        let Some(frame) = decrypt_established_frame(
            key,
            frame,
            &mut dec_buf,
            &mut microfips_core::noise::ReplayWindow::new(),
        ) else {
            return FrameAction::Continue;
        };
        dispatch_link_message(&frame, _throughput, handler, resp)
    }

    #[test]
    fn test_handle_frame_heartbeat() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 12345;
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            0,
            wire::MSG_HEARTBEAT,
            ts,
            &[],
            &key,
        );

        let mut resp = [0u8; 256];
        let result = {
            #[cfg(feature = "benchmark")]
            {
                dispatch_test_frame(
                    &key,
                    &frame,
                    &mut ThroughputState::default(),
                    &mut NoopTestHandler,
                    &mut resp,
                )
            }
            #[cfg(not(feature = "benchmark"))]
            {
                dispatch_test_frame(&key, &frame, &mut (), &mut NoopTestHandler, &mut resp)
            }
        };
        assert_eq!(result, FrameAction::HeartbeatRecv);
    }

    #[test]
    fn test_handle_frame_disconnect() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 54321;
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            1,
            wire::MSG_DISCONNECT,
            ts,
            &[],
            &key,
        );

        let mut resp = [0u8; 256];
        let result = {
            #[cfg(feature = "benchmark")]
            {
                dispatch_test_frame(
                    &key,
                    &frame,
                    &mut ThroughputState::default(),
                    &mut NoopTestHandler,
                    &mut resp,
                )
            }
            #[cfg(not(feature = "benchmark"))]
            {
                dispatch_test_frame(&key, &frame, &mut (), &mut NoopTestHandler, &mut resp)
            }
        };
        assert_eq!(
            result,
            FrameAction::PeerDC {
                reason: wire::DISC_REASON_OTHER
            }
        );
    }

    #[test]
    fn test_handle_frame_unknown_type_skipped() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 99999;
        let frame = build_test_frame(wire::SessionIndex::new(0), 2, 0x05, ts, b"unknown", &key);

        let mut resp = [0u8; 256];
        let result = {
            #[cfg(feature = "benchmark")]
            {
                dispatch_test_frame(
                    &key,
                    &frame,
                    &mut ThroughputState::default(),
                    &mut NoopTestHandler,
                    &mut resp,
                )
            }
            #[cfg(not(feature = "benchmark"))]
            {
                dispatch_test_frame(&key, &frame, &mut (), &mut NoopTestHandler, &mut resp)
            }
        };
        assert_eq!(result, FrameAction::Continue);
    }

    #[test]
    fn test_handle_frame_wrong_key_skipped() {
        use microfips_core::wire;

        let key_a: [u8; 32] = [0x42; 32];
        let key_b: [u8; 32] = [0x99; 32];
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            0,
            wire::MSG_HEARTBEAT,
            100,
            &[],
            &key_a,
        );

        let mut dec_buf = [0u8; MAX_FRAME_SIZE];
        assert!(decrypt_established_frame(
            &key_b,
            &frame,
            &mut dec_buf,
            &mut microfips_core::noise::ReplayWindow::new()
        )
        .is_none());
    }

    #[test]
    fn test_handle_frame_garbage_skipped() {
        let key: [u8; 32] = [0x42; 32];
        assert!(decrypt_established_frame(
            &key,
            &[],
            &mut [0u8; MAX_FRAME_SIZE],
            &mut microfips_core::noise::ReplayWindow::new()
        )
        .is_none());
        assert!(decrypt_established_frame(
            &key,
            &[0x00],
            &mut [0u8; MAX_FRAME_SIZE],
            &mut microfips_core::noise::ReplayWindow::new()
        )
        .is_none());
        assert!(decrypt_established_frame(
            &key,
            &[0xFF; 4],
            &mut [0u8; MAX_FRAME_SIZE],
            &mut microfips_core::noise::ReplayWindow::new()
        )
        .is_none());
    }

    #[test]
    fn test_handle_frame_datagram_response() {
        use microfips_core::wire;

        struct DatagramHandler;
        impl NodeHandler for DatagramHandler {
            async fn on_event(&mut self, _event: NodeEvent) {}
            fn on_message(
                &mut self,
                msg_type: u8,
                payload: &[u8],
                resp: &mut [u8],
            ) -> HandleResult {
                if msg_type == wire::MSG_SESSION_DATAGRAM && payload == b"ping" {
                    let response = b"pong";
                    resp[..response.len()].copy_from_slice(response);
                    HandleResult::SendDatagram(response.len())
                } else {
                    HandleResult::None
                }
            }
        }

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 77777;
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            5,
            wire::MSG_SESSION_DATAGRAM,
            ts,
            b"ping",
            &key,
        );

        let mut resp = [0u8; 256];
        let result = {
            #[cfg(feature = "benchmark")]
            {
                dispatch_test_frame(
                    &key,
                    &frame,
                    &mut ThroughputState::default(),
                    &mut DatagramHandler,
                    &mut resp,
                )
            }
            #[cfg(not(feature = "benchmark"))]
            {
                dispatch_test_frame(&key, &frame, &mut (), &mut DatagramHandler, &mut resp)
            }
        };
        assert_eq!(result, FrameAction::SendDatagram(4));
        assert_eq!(&resp[..4], b"pong");
    }

    #[test]
    fn test_handle_frame_echo_request() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let send_ts = 0x0102_0304_0506_0708u64;
        let seq = 0x1122_3344u32;
        let payload = b"echo-payload";
        let mut echo_request = [0u8; wire::ECHO_REQUEST_MIN_SIZE + wire::ECHO_MAX_PAYLOAD];
        echo_request[0..8].copy_from_slice(&send_ts.to_le_bytes());
        echo_request[8..12].copy_from_slice(&seq.to_le_bytes());
        echo_request[12..12 + payload.len()].copy_from_slice(payload);
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            8,
            wire::MSG_ECHO_REQUEST,
            321,
            &echo_request[..12 + payload.len()],
            &key,
        );

        let mut resp = [0u8; 256];
        let result = {
            #[cfg(feature = "benchmark")]
            {
                dispatch_test_frame(
                    &key,
                    &frame,
                    &mut ThroughputState::default(),
                    &mut NoopTestHandler,
                    &mut resp,
                )
            }
            #[cfg(not(feature = "benchmark"))]
            {
                dispatch_test_frame(&key, &frame, &mut (), &mut NoopTestHandler, &mut resp)
            }
        };

        assert_eq!(
            result,
            FrameAction::SendLinkMessage {
                msg_type: wire::MSG_ECHO_RESPONSE,
                len: wire::ECHO_RESPONSE_MIN_SIZE + payload.len(),
            }
        );
    }

    #[test]
    fn test_handle_frame_receiver_report_skipped() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            9,
            wire::MSG_RECEIVER_REPORT,
            654,
            &[0u8; 10],
            &key,
        );

        let mut resp = [0u8; 256];
        let result = {
            #[cfg(feature = "benchmark")]
            {
                dispatch_test_frame(
                    &key,
                    &frame,
                    &mut ThroughputState::default(),
                    &mut NoopTestHandler,
                    &mut resp,
                )
            }
            #[cfg(not(feature = "benchmark"))]
            {
                dispatch_test_frame(&key, &frame, &mut (), &mut NoopTestHandler, &mut resp)
            }
        };

        assert_eq!(result, FrameAction::Continue);
    }

    #[test]
    fn test_handle_frame_self_disconnect() {
        use microfips_core::wire;

        struct DisconnectHandler;

        impl NodeHandler for DisconnectHandler {
            async fn on_event(&mut self, _event: NodeEvent) {}

            fn on_message(
                &mut self,
                msg_type: u8,
                _payload: &[u8],
                _resp: &mut [u8],
            ) -> HandleResult {
                if msg_type == 0xAA {
                    HandleResult::Disconnect
                } else {
                    HandleResult::None
                }
            }
        }

        let key: [u8; 32] = [0x42; 32];
        let frame = build_test_frame(wire::SessionIndex::new(0), 10, 0xAA, 987, b"bye", &key);

        let mut resp = [0u8; 256];
        let result = {
            #[cfg(feature = "benchmark")]
            {
                dispatch_test_frame(
                    &key,
                    &frame,
                    &mut ThroughputState::default(),
                    &mut DisconnectHandler,
                    &mut resp,
                )
            }
            #[cfg(not(feature = "benchmark"))]
            {
                dispatch_test_frame(&key, &frame, &mut (), &mut DisconnectHandler, &mut resp)
            }
        };

        assert_eq!(result, FrameAction::SelfDC);
    }

    #[test]
    fn test_decrypt_frame_field_validation() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let counter = 0x0102_0304_0506_0708u64;
        let timestamp = 0x1122_3344u32;
        let msg_type = wire::MSG_SESSION_DATAGRAM;
        let payload = b"field-check";
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            counter,
            msg_type,
            timestamp,
            payload,
            &key,
        );

        let mut dec_buf = [0u8; MAX_FRAME_SIZE];
        let decrypted = decrypt_established_frame(
            &key,
            &frame,
            &mut dec_buf,
            &mut microfips_core::noise::ReplayWindow::new(),
        )
        .unwrap();

        assert_eq!(decrypted.counter, counter);
        assert_eq!(decrypted.sender_timestamp, timestamp);
        assert_eq!(decrypted.msg_type, msg_type);
        assert_eq!(decrypted.payload, payload);
        assert_eq!(decrypted.frame_bytes, frame.len());
    }

    #[test]
    #[cfg(feature = "benchmark")]
    fn test_handle_frame_throughput_request_activates_state() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let body = [
            0x78, 0x56, 0x34, 0x12, 0x00, 0x01, 0x00, 0x04, 0x00, 0x65, 0xcd, 0x1d,
        ];
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            6,
            wire::MSG_THROUGHPUT_REQUEST,
            123,
            &body,
            &key,
        );

        let mut throughput = ThroughputState::default();
        let mut resp = [0u8; 256];
        let result = dispatch_test_frame(
            &key,
            &frame,
            &mut throughput,
            &mut NoopTestHandler,
            &mut resp,
        );
        assert_eq!(result, FrameAction::Continue);
        assert!(throughput.active);
        assert_eq!(throughput.test_id, 0x12345678);
        assert_eq!(throughput.duration_secs, 1);
    }

    #[test]
    #[cfg(feature = "benchmark")]
    fn test_handle_frame_throughput_stream_sends_report() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let payload = [
            0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        let frame = build_test_frame(
            wire::SessionIndex::new(0),
            7,
            wire::MSG_THROUGHPUT_STREAM,
            456,
            &payload,
            &key,
        );

        let mut throughput = ThroughputState {
            test_id: 0x12345678,
            frames_recv: 0,
            bytes_recv: 0,
            started_at: Some(Instant::now()),
            duration_secs: 0,
            active: true,
        };
        let mut resp = [0u8; 256];
        let result = dispatch_test_frame(
            &key,
            &frame,
            &mut throughput,
            &mut NoopTestHandler,
            &mut resp,
        );
        assert!(matches!(
            result,
            FrameAction::SendLinkMessage {
                msg_type: wire::MSG_THROUGHPUT_REPORT,
                len: wire::THROUGHPUT_REPORT_SIZE,
            }
        ));
        assert!(!throughput.active);
        assert_eq!(
            u32::from_le_bytes(resp[0..4].try_into().unwrap()),
            0x12345678
        );
        assert_eq!(u32::from_le_bytes(resp[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(resp[8..12].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(resp[12..20].try_into().unwrap()),
            payload.len() as u64
        );
    }

    // NOTE: test_handshake_with_mock_responder requires refactoring handshake()
    // into separate build_msg1/process_msg2 methods, or a mock transport
    // that doesn't echo send->rx. Post-merge TODO.

    #[cfg(not(feature = "noise-xx"))]
    fn build_msg1_frame(
        initiator_secret: &[u8; 32],
        responder_pub: &[u8; 33],
        eph: &[u8; 32],
        sender_idx: u32,
        epoch: u64,
    ) -> (std::vec::Vec<u8>, microfips_core::noise::NoiseIkInitiator) {
        use microfips_core::noise::{self, NoiseIkInitiator};
        use microfips_core::wire;

        let initiator_pub = noise::ecdh_pubkey(initiator_secret).unwrap();
        let (mut initiator, _e_pub) =
            NoiseIkInitiator::new(eph, initiator_secret, responder_pub).unwrap();
        let mut epoch_bytes = [0u8; noise::EPOCH_SIZE];
        epoch_bytes[..8].copy_from_slice(&epoch.to_le_bytes());

        let mut msg1_noise = [0u8; 256];
        let msg1_noise_len = initiator
            .write_message1(&initiator_pub, &epoch_bytes, &mut msg1_noise)
            .unwrap();

        let mut msg1_buf = [0u8; 256];
        let msg1_len = wire::build_msg1(
            wire::SessionIndex::new(sender_idx),
            &msg1_noise[..msg1_noise_len],
            &mut msg1_buf,
        )
        .unwrap();
        (msg1_buf[..msg1_len].to_vec(), initiator)
    }

    /// XX msg1 carries the ephemeral only — no responder key or epoch.
    #[cfg(feature = "noise-xx")]
    fn build_msg1_frame(
        initiator_secret: &[u8; 32],
        _responder_pub: &[u8; 33],
        eph: &[u8; 32],
        sender_idx: u32,
        _epoch: u64,
    ) -> (std::vec::Vec<u8>, microfips_core::noise::NoiseXxInitiator) {
        use microfips_core::noise::NoiseXxInitiator;
        use microfips_core::wire;

        let (mut initiator, _e_pub) = NoiseXxInitiator::new(eph, initiator_secret).unwrap();

        let mut msg1_noise = [0u8; 256];
        let msg1_noise_len = initiator.write_message1(&mut msg1_noise).unwrap();

        let mut msg1_buf = [0u8; 256];
        let msg1_len = wire::build_msg1(
            wire::SessionIndex::new(sender_idx),
            &msg1_noise[..msg1_noise_len],
            &mut msg1_buf,
        )
        .unwrap();
        (msg1_buf[..msg1_len].to_vec(), initiator)
    }

    #[test]
    fn test_advance_epoch_starts_at_one_and_uses_little_endian() {
        let inner = fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner);
        let mut node = Node::new(transport, TestRng::new(&[]), [0u8; 32], [0u8; 33]);

        assert_eq!(node.advance_epoch(), 1u64.to_le_bytes());
        assert_eq!(node.epoch, 1);
        node.epoch = 0x0102_0304_0506_0707;
        assert_eq!(node.advance_epoch(), 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(node.epoch, 0x0102_0304_0506_0708);
    }

    #[test]
    fn test_advance_epoch_wraps() {
        let inner = fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner);
        let mut node = Node::new(transport, TestRng::new(&[]), [0u8; 32], [0u8; 33]);

        node.epoch = u64::MAX;
        assert_eq!(node.advance_epoch(), 0u64.to_le_bytes());
        assert_eq!(node.epoch, 0);
    }

    #[test]
    fn test_handshake_with_responder() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;
        use microfips_core::wire;

        // Use fresh random keys to prove the handshake works with any valid keypair.
        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, mut resp_transport) = channel_pair();

        block_on(async move {
            let responder = async {
                let mut hdr = [0u8; 2];
                let mut total = 0;
                while total < 2 {
                    total += resp_transport.recv(&mut hdr[total..]).await.unwrap();
                }
                let msg1_len = u16::from_le_bytes(hdr) as usize;
                let mut buf = [0u8; 256];
                total = 0;
                while total < msg1_len {
                    total += resp_transport.recv(&mut buf[total..]).await.unwrap();
                }

                let msg = wire::parse_message(&buf[..msg1_len]).unwrap();
                let noise_payload = match msg {
                    wire::FmpMessage::Msg1 { noise_payload, .. } => noise_payload,
                    _ => panic!("expected Msg1"),
                };

                #[cfg(not(feature = "noise-xx"))]
                {
                    use microfips_core::noise::{NoiseIkResponder, PUBKEY_SIZE};

                    let ei_pub: [u8; PUBKEY_SIZE] =
                        noise_payload[..PUBKEY_SIZE].try_into().unwrap();
                    let mut resp = NoiseIkResponder::new(&responder_secret, &ei_pub)
                        .expect("IK responder init failed");
                    let (_init_pub, epoch) = resp
                        .read_message1(&noise_payload[PUBKEY_SIZE..])
                        .expect("read_message1 failed");

                    let resp_eph = random_secret();
                    let mut msg2_noise = [0u8; 128];
                    let msg2_noise_len = resp
                        .write_message2(&resp_eph, &epoch, &mut msg2_noise)
                        .expect("write_message2 failed");

                    let mut msg2_buf = [0u8; 256];
                    let msg2_len = wire::build_msg2(
                        wire::SessionIndex::new(1),
                        wire::SessionIndex::new(0),
                        &msg2_noise[..msg2_noise_len],
                        &mut msg2_buf,
                    )
                    .unwrap();

                    let frame_hdr = (msg2_len as u16).to_le_bytes();
                    resp_transport.send(&frame_hdr).await.unwrap();
                    resp_transport.send(&msg2_buf[..msg2_len]).await.unwrap();
                }

                #[cfg(feature = "noise-xx")]
                {
                    use microfips_core::noise::NoiseXxResponder;
                    use microfips_core::wire::negotiation;

                    let mut resp =
                        NoiseXxResponder::new(&responder_secret).expect("XX responder init failed");
                    resp.read_message1(noise_payload)
                        .expect("read_message1 failed");

                    let resp_eph = random_secret();
                    let mut msg2_noise = [0u8; microfips_core::noise::XX_HANDSHAKE_MSG2_SIZE
                        + negotiation::NEGOTIATION_MAX_SIZE
                        + microfips_core::noise::TAG_SIZE];
                    let msg2_noise_len = resp
                        .write_message2(&resp_eph, &1u64.to_le_bytes(), &mut msg2_noise)
                        .expect("write_message2 failed");
                    // Daemon stand-in: Full-profile negotiation block.
                    let mut neg = [0u8; negotiation::NEGOTIATION_MAX_SIZE];
                    let neglen = negotiation::encode_payload(
                        &mut neg,
                        wire::FMP_VERSION,
                        wire::FMP_VERSION,
                        negotiation::fmp_features(negotiation::NodeProfile::Full),
                        None,
                    )
                    .unwrap();
                    let neg_enc_len = resp
                        .encrypt_payload(&neg[..neglen], &mut msg2_noise[msg2_noise_len..])
                        .expect("encrypt_payload failed");

                    let mut msg2_buf = [0u8; 512];
                    let msg2_len = wire::build_msg2(
                        wire::SessionIndex::new(1),
                        wire::SessionIndex::new(0),
                        &msg2_noise[..msg2_noise_len + neg_enc_len],
                        &mut msg2_buf,
                    )
                    .unwrap();

                    let frame_hdr = (msg2_len as u16).to_le_bytes();
                    resp_transport.send(&frame_hdr).await.unwrap();
                    resp_transport.send(&msg2_buf[..msg2_len]).await.unwrap();

                    let mut hdr3 = [0u8; 2];
                    let mut total3 = 0;
                    while total3 < 2 {
                        total3 += resp_transport.recv(&mut hdr3[total3..]).await.unwrap();
                    }
                    let msg3_len = u16::from_le_bytes(hdr3) as usize;
                    let mut buf3 = [0u8; 256];
                    total3 = 0;
                    while total3 < msg3_len {
                        total3 += resp_transport.recv(&mut buf3[total3..]).await.unwrap();
                    }
                    let msg3 = wire::parse_message(&buf3[..msg3_len]).unwrap();
                    match msg3 {
                        wire::FmpMessage::Msg3 { noise_payload, .. } => {
                            let (base3, neg3) = negotiation::split_msg3_noise(noise_payload);
                            resp.read_message3(base3).expect("read_message3 failed");
                            let encrypted = neg3.expect("node msg3 carries negotiation");
                            let mut plain = [0u8; negotiation::NEGOTIATION_MAX_SIZE];
                            let n = resp
                                .decrypt_payload(encrypted, &mut plain)
                                .expect("decrypt_payload failed");
                            let header =
                                negotiation::NegotiationHeader::parse(&plain[..n]).unwrap();
                            assert_eq!(header.node_profile(), Some(negotiation::NodeProfile::Leaf));
                            assert_eq!(negotiation::rekey_of(&plain[..n]), Ok(None));
                        }
                        _ => panic!("expected Msg3"),
                    }
                }
            };

            let initiator = async move {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                let result = node.handshake(epoch, &mut handler).await;
                assert!(result.is_ok(), "handshake should succeed");
                #[cfg(feature = "noise-xx")]
                {
                    use microfips_core::wire::negotiation::NodeProfile;
                    assert_eq!(node.peer_node_profile(), Some(NodeProfile::Full));
                    assert_eq!(node.fmp_agreed_version(), Some(1));
                }
                let (ks, kr, them) = result.unwrap();
                assert_eq!(
                    them,
                    wire::SessionIndex::new(1),
                    "responder sender_idx should be 1"
                );
                assert_eq!(ks.len(), 32);
                assert_eq!(kr.len(), 32);
            };

            join(responder, initiator).await;
        });
    }

    #[test]
    fn test_handshake_msg1_wire_size() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;
        use microfips_core::wire;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, mut resp_transport) = channel_pair();

        block_on(async move {
            let responder = async move {
                let mut hdr = [0u8; 2];
                let mut total = 0;
                while total < 2 {
                    total += resp_transport.recv(&mut hdr[total..]).await.unwrap();
                }
                let msg1_len = u16::from_le_bytes(hdr) as usize;
                assert_eq!(
                    msg1_len,
                    wire::MSG1_WIRE_SIZE,
                    "MSG1 should be 114 bytes on wire"
                );
                let mut buf = [0u8; 256];
                total = 0;
                while total < msg1_len {
                    total += resp_transport.recv(&mut buf[total..]).await.unwrap();
                }
                let msg = wire::parse_message(&buf[..msg1_len]).unwrap();
                match msg {
                    wire::FmpMessage::Msg1 {
                        sender_idx,
                        noise_payload,
                        ..
                    } => {
                        assert_ne!(
                            sender_idx,
                            wire::SessionIndex::new(0),
                            "initiator sender_idx should be random non-zero"
                        );
                        assert_eq!(noise_payload.len(), wire::HANDSHAKE_MSG1_SIZE);
                    }
                    _ => panic!("expected Msg1"),
                }
            };

            let initiator = async move {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                let _ = node.handshake(epoch, &mut handler).await;
            };

            join(responder, initiator).await;
        });
    }

    #[test]
    fn test_handshake_timeout_on_no_response() {
        use crate::transport::channel::pair as channel_pair;

        let (init_transport, _resp_transport) = channel_pair();

        block_on(async move {
            let secret = random_secret();
            let mut node = Node::new(init_transport, TestRng::from_os_rng(), secret, [0x02; 33]);
            let mut handler = NoopTestHandler;
            let epoch = node.advance_epoch();
            let result = node.handshake(epoch, &mut handler).await;
            assert_eq!(result, Err(ProtocolError::Timeout));
        });
    }

    #[test]
    fn test_session_emits_connected_then_error_on_handshake_timeout() {
        use crate::transport::channel::pair as channel_pair;

        let (init_transport, _resp_transport) = channel_pair();

        block_on(async move {
            let secret = random_secret();
            let mut node = Node::new(init_transport, TestRng::from_os_rng(), secret, [0x02; 33]);
            let mut handler = RecordingHandler::default();
            let result = node.session(&mut handler).await;
            assert_eq!(result, Err(ProtocolError::Timeout));
            assert_eq!(
                handler.events,
                vec![NodeEvent::Connected, NodeEvent::Msg1Sent, NodeEvent::Error]
            );
        });
    }

    #[test]
    fn test_session_emits_disconnected_after_transport_close() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;
        use microfips_core::wire;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, mut resp_transport) = channel_pair();

        block_on(async move {
            let responder = async {
                let mut hdr = [0u8; 2];
                let mut total = 0;
                while total < 2 {
                    total += resp_transport.recv(&mut hdr[total..]).await.unwrap();
                }
                let msg1_len = u16::from_le_bytes(hdr) as usize;
                let mut buf = [0u8; 256];
                total = 0;
                while total < msg1_len {
                    total += resp_transport.recv(&mut buf[total..]).await.unwrap();
                }

                let msg = wire::parse_message(&buf[..msg1_len]).unwrap();
                let noise_payload = match msg {
                    wire::FmpMessage::Msg1 { noise_payload, .. } => noise_payload,
                    _ => panic!("expected Msg1"),
                };

                #[cfg(not(feature = "noise-xx"))]
                {
                    use microfips_core::noise::{NoiseIkResponder, PUBKEY_SIZE};

                    let ei_pub: [u8; PUBKEY_SIZE] =
                        noise_payload[..PUBKEY_SIZE].try_into().unwrap();
                    let mut resp = NoiseIkResponder::new(&responder_secret, &ei_pub).unwrap();
                    let (_init_pub, epoch) =
                        resp.read_message1(&noise_payload[PUBKEY_SIZE..]).unwrap();
                    assert_eq!(epoch, 1u64.to_le_bytes());

                    let resp_eph = random_secret();
                    let mut msg2_noise = [0u8; 128];
                    let msg2_noise_len = resp
                        .write_message2(&resp_eph, &epoch, &mut msg2_noise)
                        .unwrap();

                    let mut msg2_buf = [0u8; 256];
                    let msg2_len = wire::build_msg2(
                        wire::SessionIndex::new(1),
                        wire::SessionIndex::new(0),
                        &msg2_noise[..msg2_noise_len],
                        &mut msg2_buf,
                    )
                    .unwrap();
                    let frame_hdr = (msg2_len as u16).to_le_bytes();
                    resp_transport.send(&frame_hdr).await.unwrap();
                    resp_transport.send(&msg2_buf[..msg2_len]).await.unwrap();

                    let _ = resp.finalize();
                    resp_transport.close();
                }

                #[cfg(feature = "noise-xx")]
                {
                    use microfips_core::noise::NoiseXxResponder;
                    use microfips_core::wire::negotiation;

                    let mut resp = NoiseXxResponder::new(&responder_secret).unwrap();
                    resp.read_message1(noise_payload).unwrap();

                    let resp_eph = random_secret();
                    let mut msg2_noise = [0u8; microfips_core::noise::XX_HANDSHAKE_MSG2_SIZE
                        + negotiation::NEGOTIATION_MAX_SIZE
                        + microfips_core::noise::TAG_SIZE];
                    let msg2_noise_len = resp
                        .write_message2(&resp_eph, &1u64.to_le_bytes(), &mut msg2_noise)
                        .unwrap();
                    // Daemon stand-in: Full-profile negotiation block.
                    let mut neg = [0u8; negotiation::NEGOTIATION_MAX_SIZE];
                    let neglen = negotiation::encode_payload(
                        &mut neg,
                        wire::FMP_VERSION,
                        wire::FMP_VERSION,
                        negotiation::fmp_features(negotiation::NodeProfile::Full),
                        None,
                    )
                    .unwrap();
                    let neg_enc_len = resp
                        .encrypt_payload(&neg[..neglen], &mut msg2_noise[msg2_noise_len..])
                        .unwrap();

                    let mut msg2_buf = [0u8; 512];
                    let msg2_len = wire::build_msg2(
                        wire::SessionIndex::new(1),
                        wire::SessionIndex::new(0),
                        &msg2_noise[..msg2_noise_len + neg_enc_len],
                        &mut msg2_buf,
                    )
                    .unwrap();
                    let frame_hdr = (msg2_len as u16).to_le_bytes();
                    resp_transport.send(&frame_hdr).await.unwrap();
                    resp_transport.send(&msg2_buf[..msg2_len]).await.unwrap();

                    let mut hdr3 = [0u8; 2];
                    let mut total3 = 0;
                    while total3 < 2 {
                        total3 += resp_transport.recv(&mut hdr3[total3..]).await.unwrap();
                    }
                    let msg3_len = u16::from_le_bytes(hdr3) as usize;
                    let mut buf3 = [0u8; 256];
                    total3 = 0;
                    while total3 < msg3_len {
                        total3 += resp_transport.recv(&mut buf3[total3..]).await.unwrap();
                    }
                    let msg3 = wire::parse_message(&buf3[..msg3_len]).unwrap();
                    match msg3 {
                        wire::FmpMessage::Msg3 { noise_payload, .. } => {
                            let (base3, _) = negotiation::split_msg3_noise(noise_payload);
                            let (init_pub, init_epoch) = resp.read_message3(base3).unwrap();
                            assert_eq!(init_pub, ecdh_pubkey(&initiator_secret).unwrap());
                            assert_eq!(init_epoch, 1u64.to_le_bytes());
                        }
                        _ => panic!("expected Msg3"),
                    }

                    let _ = resp.finalize();
                    resp_transport.close();
                }
            };

            let initiator = async move {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Err(ProtocolError::Disconnected));
                assert_eq!(
                    handler.events,
                    vec![
                        NodeEvent::Connected,
                        NodeEvent::Msg1Sent,
                        NodeEvent::HandshakeOk,
                        NodeEvent::Disconnected
                    ]
                );
            };

            join(responder, initiator).await;
        });
    }

    #[test]
    fn test_peer_policy_integration_backoff_on_handshake_failure() {
        use crate::peer_policy::RECONNECT_BACKOFF_BASE_MS;
        use crate::transport::channel::pair as channel_pair;

        let (transport, mut peer) = channel_pair();
        peer.close();
        let secret = random_secret();
        let peer_secret = random_secret();
        let peer_pub = microfips_core::noise::ecdh_pubkey(&peer_secret).unwrap();

        block_on(async move {
            let mut node = Node::new(transport, TestRng::from_os_rng(), secret, peer_pub);
            let mut handler = RecordingHandler::default();

            let r1 = node.session(&mut handler).await;
            assert!(r1.is_err());
            assert!(handler.events.contains(&NodeEvent::Connected));
            assert!(handler.events.contains(&NodeEvent::Error));

            let backoff_secs = (RECONNECT_BACKOFF_BASE_MS / 1000) + 1;
            Timer::after(Duration::from_secs(backoff_secs)).await;

            let policy_verdict = node.policy.check_reconnect(Instant::now());
            match policy_verdict {
                PolicyVerdict::Allow => {}
                other => panic!(
                    "expected Allow after {}s backoff, got {:?}",
                    backoff_secs, other
                ),
            }
        });
    }

    #[test]
    fn test_peer_policy_integration_survives_frame_flood() {
        use crate::peer_policy::FRAME_RATE_WINDOW_MS;
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;

        let (transport, mut peer) = channel_pair();
        let key = [0x42; 32];
        let them = wire::SessionIndex::new(7);

        block_on(async move {
            let peer_task = async move {
                for counter in 0..110u64 {
                    let frame =
                        build_test_frame(them, counter, wire::MSG_HEARTBEAT, 1000, &[], &key);
                    send_test_frame(&mut peer, &frame).await;
                }

                Timer::after(Duration::from_millis(FRAME_RATE_WINDOW_MS + 50)).await;

                let hb = build_test_frame(them, 200, wire::MSG_HEARTBEAT, 2000, &[], &key);
                send_test_frame(&mut peer, &hb).await;

                let disconnect =
                    build_test_frame(them, 201, wire::MSG_DISCONNECT, 3000, &[0x00], &key);
                send_test_frame(&mut peer, &disconnect).await;
            };

            let node_task = async move {
                let mut node = Node::new(
                    transport,
                    TestRng::from_os_rng(),
                    random_secret(),
                    microfips_core::noise::ecdh_pubkey(&random_secret()).unwrap(),
                );
                let mut handler = NoopTestHandler;
                let result = node
                    .steady(1u64.to_le_bytes(), &key, &key, them, &mut handler)
                    .await;
                assert_eq!(result, Ok(()));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    #[ignore] // Requires real-time wait for heartbeat timer; see peer_policy unit tests instead
    fn test_peer_policy_integration_detects_silent_peer() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;

        let (transport, mut peer) = channel_pair();
        let key = [0x24; 32];
        let them = wire::SessionIndex::new(9);

        block_on(async move {
            let peer_task = async move {
                let hb = build_test_frame(them, 0, wire::MSG_HEARTBEAT, 1000, &[], &key);
                send_test_frame(&mut peer, &hb).await;

                let sent_hb = recv_test_frame(&mut peer).await;
                let (msg_type, payload) = decrypt_test_frame(&key, &sent_hb);
                assert_eq!(msg_type, wire::MSG_HEARTBEAT);
                assert!(payload.is_empty());

                let sent_disc = recv_test_frame(&mut peer).await;
                let (msg_type, payload) = decrypt_test_frame(&key, &sent_disc);
                assert_eq!(msg_type, wire::MSG_DISCONNECT);
                assert_eq!(payload, [wire::DISC_REASON_RESOURCE_EXHAUSTION]);
            };

            let node_task = async move {
                let mut node = Node::new(
                    transport,
                    TestRng::from_os_rng(),
                    random_secret(),
                    microfips_core::noise::ecdh_pubkey(&random_secret()).unwrap(),
                );
                node.policy.record_handshake_ok(Instant::now());
                node.policy.force_past_session_start();
                let mut handler = RecordingHandler::default();
                let result = node
                    .steady(1u64.to_le_bytes(), &key, &key, them, &mut handler)
                    .await;
                assert_eq!(result, Err(ProtocolError::Disconnected));
                assert!(handler.events.contains(&NodeEvent::HeartbeatRecv));
                assert!(handler.events.contains(&NodeEvent::HeartbeatSent));
            };

            join(peer_task, node_task).await;
        });
    }

    /// Bench-found (#193, 2026-09-02): against a next-line XX daemon the
    /// hardware session churned every ~link_dead_timeout with `policy:
    /// rejected: silent peer` although heartbeats flowed BOTH ways. Root
    /// cause: the policy's data-frame counter is only fed through
    /// FrameAction dispatch, while the steady loop's timer-branch MMP
    /// SenderReports (and direct session-datagram sends) bypass it — a
    /// peer that heartbeats but exchanges no FSP/replies starves the
    /// counter and we tear down a healthy link. A listening leaf against
    /// an idle daemon is exactly that shape. Fix under test: app-level
    /// sends must count at the send functions, not at the dispatcher.
    #[test]
    fn test_steady_survives_silent_peer_timeout_when_reports_flow() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;

        let (transport, mut peer) = channel_pair();
        let key = [0x24; 32];
        let them = wire::SessionIndex::new(9);

        // Fast clock: link_dead 2s, heartbeat 1s, MMP reports at the 200ms
        // cold-start cadence (never tuned — the peer sends no ReceiverReports,
        // mirroring the next-daemon interop gap).
        let timing = NodeTiming {
            heartbeat_interval_secs: 1,
            link_dead_timeout_secs: 2,
            ..NodeTiming::default()
        };

        block_on(async move {
            let peer_task = async move {
                let started = Instant::now();
                let mut last_hb: Option<Instant> = None;
                let mut reports_seen = 0u32;
                let mut node_disconnects = 0u32;
                let mut peer_hb_ctr: u64 = 5000;
                loop {
                    // The node emits ~5 frames/s (heartbeat + SenderReports),
                    // so this blocking recv returns promptly; each arrival is
                    // our chance to answer with a peer heartbeat.
                    let frame = recv_test_frame(&mut peer).await;
                    let (msg_type, _payload) = decrypt_test_frame(&key, &frame);
                    match msg_type {
                        wire::MSG_SENDER_REPORT => reports_seen += 1,
                        // The node tore the link down itself (the bug under
                        // test): nothing more will arrive — fail fast.
                        wire::MSG_DISCONNECT => {
                            node_disconnects += 1;
                            return (reports_seen, node_disconnects);
                        }
                        _ => {}
                    }
                    let send_hb_due = last_hb
                        .map(|t| t.elapsed() >= Duration::from_millis(300))
                        .unwrap_or(true);
                    if send_hb_due {
                        let hb = build_test_frame(
                            them,
                            peer_hb_ctr,
                            wire::MSG_HEARTBEAT,
                            1000,
                            &[],
                            &key,
                        );
                        send_test_frame(&mut peer, &hb).await;
                        peer_hb_ctr += 1;
                        last_hb = Some(Instant::now());
                    }
                    // Survive 2x the link_dead timeout + margin, then the
                    // peer ends the session cleanly.
                    if started.elapsed() >= Duration::from_secs(6) {
                        let disc = build_test_frame(
                            them,
                            peer_hb_ctr,
                            wire::MSG_DISCONNECT,
                            2000,
                            &[wire::DISC_REASON_SHUTDOWN],
                            &key,
                        );
                        send_test_frame(&mut peer, &disc).await;
                        return (reports_seen, node_disconnects);
                    }
                }
            };

            let node_task = async move {
                let mut node = Node::with_timing(
                    transport,
                    TestRng::from_os_rng(),
                    random_secret(),
                    microfips_core::noise::ecdh_pubkey(&random_secret()).unwrap(),
                    timing,
                );
                node.policy.record_handshake_ok(Instant::now());
                let mut handler = RecordingHandler::default();
                let result = node
                    .steady(1u64.to_le_bytes(), &key, &key, them, &mut handler)
                    .await;
                (result, handler.events)
            };

            let ((reports_seen, node_disconnects), (result, _events)) =
                join(peer_task, node_task).await;

            // The link survived past 2x link_dead: steady exited only via the
            // peer's clean disconnect, with zero self-initiated disconnects.
            assert_eq!(result, Ok(()));
            assert_eq!(node_disconnects, 0, "node tore down a live link");
            // And the channel that should have kept it alive was active.
            assert!(reports_seen >= 1, "no MMP SenderReports observed");
        });
    }

    #[cfg(not(feature = "noise-xx"))]
    #[test]
    fn test_tiebreaker_simultaneous_handshake_ik() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let (secret_a, secret_b) = distinct_secret_pair();
        let pub_a = ecdh_pubkey(&secret_a).unwrap();
        let pub_b = ecdh_pubkey(&secret_b).unwrap();
        let addr_a = node_addr_from_secret(&secret_a);
        let addr_b = node_addr_from_secret(&secret_b);

        let (transport_a, transport_b) = channel_pair();

        block_on(async move {
            let node_a = async move {
                let mut node = Node::new(transport_a, TestRng::from_os_rng(), secret_a, pub_b);
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                node.handshake(epoch, &mut handler).await.unwrap()
            };

            let node_b = async move {
                let mut node = Node::new(transport_b, TestRng::from_os_rng(), secret_b, pub_a);
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                node.handshake(epoch, &mut handler).await.unwrap()
            };

            let (result_a, result_b) = join(node_a, node_b).await;
            assert_eq!(result_a.0, result_b.1);
            assert_eq!(result_a.1, result_b.0);

            let (winner, loser) = if addr_a.as_bytes() < addr_b.as_bytes() {
                (result_a, result_b)
            } else {
                (result_b, result_a)
            };
            assert_eq!(winner.0, loser.1);
            assert_eq!(winner.1, loser.0);
        });
    }

    #[test]
    fn test_tiebreaker_simultaneous_handshake() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let (secret_a, secret_b) = distinct_secret_pair();
        let pub_a = ecdh_pubkey(&secret_a).unwrap();
        let pub_b = ecdh_pubkey(&secret_b).unwrap();
        let addr_a = node_addr_from_secret(&secret_a);
        let addr_b = node_addr_from_secret(&secret_b);

        let (transport_a, transport_b) = channel_pair();

        block_on(async move {
            let node_a = async move {
                let mut node = Node::new(transport_a, TestRng::from_os_rng(), secret_a, pub_b);
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                node.handshake(epoch, &mut handler).await.unwrap()
            };

            let node_b = async move {
                let mut node = Node::new(transport_b, TestRng::from_os_rng(), secret_b, pub_a);
                // Two leaves cannot pair — stand one side up as Full.
                #[cfg(feature = "noise-xx")]
                node.set_node_profile(microfips_core::wire::negotiation::NodeProfile::Full);
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                node.handshake(epoch, &mut handler).await.unwrap()
            };

            let (result_a, result_b) = join(node_a, node_b).await;
            assert_eq!(result_a.0, result_b.1);
            assert_eq!(result_a.1, result_b.0);

            let (winner, loser) = if addr_a.as_bytes() < addr_b.as_bytes() {
                (result_a, result_b)
            } else {
                (result_b, result_a)
            };
            assert_eq!(winner.0, loser.1);
            assert_eq!(winner.1, loser.0);
        });
    }

    #[test]
    fn test_tiebreaker_winner_ignores_msg1() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;
        use microfips_core::wire;

        let (a, b) = distinct_secret_pair();
        let (local_secret, remote_secret) =
            if node_addr_from_secret(&a).as_bytes() < node_addr_from_secret(&b).as_bytes() {
                (a, b)
            } else {
                (b, a)
            };
        let local_pub = ecdh_pubkey(&local_secret).unwrap();
        let remote_pub = ecdh_pubkey(&remote_secret).unwrap();

        let (local_transport, mut remote_transport) = channel_pair();

        block_on(async move {
            let remote = async move {
                let competing_eph = random_secret();
                let (competing_msg1, _) =
                    build_msg1_frame(&remote_secret, &local_pub, &competing_eph, 7, 1);
                send_test_frame(&mut remote_transport, &competing_msg1).await;

                let local_msg1 = recv_test_frame(&mut remote_transport).await;
                let msg = wire::parse_message(&local_msg1).unwrap();
                let (local_sender_idx, noise_payload) = match msg {
                    wire::FmpMessage::Msg1 {
                        sender_idx,
                        noise_payload,
                    } => (sender_idx, noise_payload),
                    _ => panic!("expected Msg1"),
                };

                #[cfg(not(feature = "noise-xx"))]
                {
                    use microfips_core::noise::{NoiseIkResponder, PUBKEY_SIZE};

                    let ei_pub: [u8; PUBKEY_SIZE] =
                        noise_payload[..PUBKEY_SIZE].try_into().unwrap();
                    let mut responder = NoiseIkResponder::new(&remote_secret, &ei_pub).unwrap();
                    let (_initiator_pub, epoch) = responder
                        .read_message1(&noise_payload[PUBKEY_SIZE..])
                        .unwrap();

                    let mut msg2_noise = [0u8; 128];
                    let msg2_noise_len = responder
                        .write_message2(&random_secret(), &epoch, &mut msg2_noise)
                        .unwrap();

                    let mut msg2_buf = [0u8; 256];
                    let msg2_len = wire::build_msg2(
                        wire::SessionIndex::new(11),
                        local_sender_idx,
                        &msg2_noise[..msg2_noise_len],
                        &mut msg2_buf,
                    )
                    .unwrap();
                    send_test_frame(&mut remote_transport, &msg2_buf[..msg2_len]).await;
                }

                #[cfg(feature = "noise-xx")]
                {
                    use microfips_core::noise::NoiseXxResponder;

                    let mut responder = NoiseXxResponder::new(&remote_secret).unwrap();
                    responder.read_message1(noise_payload).unwrap();

                    let mut msg2_noise = [0u8; 128];
                    let msg2_noise_len = responder
                        .write_message2(&random_secret(), &1u64.to_le_bytes(), &mut msg2_noise)
                        .unwrap();

                    let mut msg2_buf = [0u8; 256];
                    let msg2_len = wire::build_msg2(
                        wire::SessionIndex::new(11),
                        local_sender_idx,
                        &msg2_noise[..msg2_noise_len],
                        &mut msg2_buf,
                    )
                    .unwrap();
                    send_test_frame(&mut remote_transport, &msg2_buf[..msg2_len]).await;
                }
            };

            let local = async move {
                let mut node = Node::new(
                    local_transport,
                    TestRng::from_os_rng(),
                    local_secret,
                    remote_pub,
                );
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                let result = node.handshake(epoch, &mut handler).await.unwrap();
                assert_eq!(result.2, wire::SessionIndex::new(11));
            };

            join(remote, local).await;
        });
    }

    #[test]
    fn test_tiebreaker_loser_becomes_responder() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;
        use microfips_core::wire;

        let (a, b) = distinct_secret_pair();
        let (remote_secret, local_secret) =
            if node_addr_from_secret(&a).as_bytes() < node_addr_from_secret(&b).as_bytes() {
                (a, b)
            } else {
                (b, a)
            };
        let local_pub = ecdh_pubkey(&local_secret).unwrap();
        let remote_pub = ecdh_pubkey(&remote_secret).unwrap();

        let (local_transport, mut remote_transport) = channel_pair();

        block_on(async move {
            let remote = async move {
                let remote_sender_idx = 7;
                let remote_eph = random_secret();
                let (msg1_frame, mut initiator) = build_msg1_frame(
                    &remote_secret,
                    &local_pub,
                    &remote_eph,
                    remote_sender_idx,
                    1,
                );
                send_test_frame(&mut remote_transport, &msg1_frame).await;

                loop {
                    let frame = recv_test_frame(&mut remote_transport).await;
                    let msg = wire::parse_message(&frame).unwrap();
                    match msg {
                        wire::FmpMessage::Msg1 { .. } => continue,
                        wire::FmpMessage::Msg2 {
                            sender_idx,
                            receiver_idx,
                            noise_payload,
                        } => {
                            assert!(sender_idx.as_u32() != 0, "sender_idx should be non-zero");
                            assert_eq!(receiver_idx, wire::SessionIndex::new(remote_sender_idx));
                            #[cfg(not(feature = "noise-xx"))]
                            initiator.read_message2(noise_payload).unwrap();
                            #[cfg(feature = "noise-xx")]
                            {
                                use microfips_core::wire::negotiation;
                                let (base2, neg2) = negotiation::split_msg2_noise(noise_payload);
                                initiator.read_message2(base2).unwrap();
                                let mut plain = [0u8; negotiation::NEGOTIATION_MAX_SIZE];
                                let n = initiator
                                    .decrypt_payload(
                                        neg2.expect("node msg2 carries negotiation"),
                                        &mut plain,
                                    )
                                    .unwrap();
                                assert_eq!(
                                    negotiation::NegotiationHeader::parse(&plain[..n])
                                        .unwrap()
                                        .node_profile(),
                                    Some(negotiation::NodeProfile::Leaf)
                                );
                            }
                            #[cfg(feature = "noise-xx")]
                            {
                                let mut msg3_noise = [0u8; 128];
                                let msg3_noise_len = initiator
                                    .write_message3(
                                        &remote_pub,
                                        &1u64.to_le_bytes(),
                                        &mut msg3_noise,
                                    )
                                    .unwrap();
                                let mut msg3_buf = [0u8; 256];
                                let msg3_len = wire::build_msg3(
                                    wire::SessionIndex::new(remote_sender_idx),
                                    sender_idx,
                                    &msg3_noise[..msg3_noise_len],
                                    &mut msg3_buf,
                                )
                                .unwrap();
                                send_test_frame(&mut remote_transport, &msg3_buf[..msg3_len]).await;
                            }
                            return initiator.finalize();
                        }
                        _ => panic!("expected Msg2"),
                    }
                }
            };

            let local = async move {
                let mut node = Node::new(
                    local_transport,
                    TestRng::from_os_rng(),
                    local_secret,
                    remote_pub,
                );
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                node.handshake(epoch, &mut handler).await.unwrap()
            };

            let ((remote_ks, remote_kr), local_result) = join(remote, local).await;
            assert_eq!(local_result.2, wire::SessionIndex::new(7));
            assert_eq!(local_result.0, remote_kr);
            assert_eq!(local_result.1, remote_ks);
        });
    }

    #[test]
    fn test_tiebreaker_counter_abort() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let (a, b) = distinct_secret_pair();
        let (local_secret, remote_secret) =
            if node_addr_from_secret(&a).as_bytes() < node_addr_from_secret(&b).as_bytes() {
                (a, b)
            } else {
                (b, a)
            };
        let local_pub = ecdh_pubkey(&local_secret).unwrap();
        let remote_pub = ecdh_pubkey(&remote_secret).unwrap();

        let (local_transport, mut remote_transport) = channel_pair();

        block_on(async move {
            let remote = async move {
                for sender_idx in 0..=MAX_COMPETING_MSG1 {
                    let competing_eph = random_secret();
                    let (msg1_frame, _) =
                        build_msg1_frame(&remote_secret, &local_pub, &competing_eph, sender_idx, 1);
                    send_test_frame(&mut remote_transport, &msg1_frame).await;
                }
            };

            let local = async move {
                let timing = NodeTiming {
                    handshake_resend_interval_ms: 50,
                    handshake_resend_backoff: 1,
                    handshake_max_resends: 2,
                    ..NodeTiming::default()
                };
                let mut node = Node::with_timing(
                    local_transport,
                    TestRng::from_os_rng(),
                    local_secret,
                    remote_pub,
                    timing,
                );
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                let result = node.handshake(epoch, &mut handler).await;
                assert_eq!(result, Err(ProtocolError::Timeout));
            };

            join(remote, local).await;
        });
    }

    // --- Tests for fmp_raw_frame_size ---

    #[test]
    fn test_fmp_raw_frame_size_valid_msg1() {
        use microfips_core::wire;
        let mut data = [0u8; wire::MSG1_WIRE_SIZE];
        data[..4].copy_from_slice(&wire::build_prefix(wire::PHASE_MSG1, 0x00, 110));
        assert_eq!(fmp_raw_frame_size(&data), Some(wire::MSG1_WIRE_SIZE));
    }

    #[test]
    fn test_fmp_raw_frame_size_valid_msg2() {
        use microfips_core::wire;
        let mut data = [0u8; wire::MSG2_WIRE_SIZE];
        let payload_len = (wire::IDX_SIZE * 2 + wire::HANDSHAKE_MSG2_SIZE) as u16;
        data[..4].copy_from_slice(&wire::build_prefix(wire::PHASE_MSG2, 0x00, payload_len));
        assert_eq!(fmp_raw_frame_size(&data), Some(wire::MSG2_WIRE_SIZE));
    }

    #[test]
    fn test_fmp_raw_frame_size_established_returns_none() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_ESTABLISHED, 0x00, 84);
        assert_eq!(fmp_raw_frame_size(&prefix), None);
    }

    #[cfg(feature = "noise-xx")]
    #[test]
    fn test_fmp_raw_frame_size_msg2_with_negotiation_extra() {
        use microfips_core::wire;
        // Regression (raw-UDP truncation, found against FIPS next): a msg2
        // carrying a 26B negotiation extra must extract in full — the fixed
        // MSG2_WIRE_SIZE constant silently dropped the extra, desyncing the
        // AEAD counter so the peer's msg3 decrypt failed.
        let base_noise = [0u8; wire::HANDSHAKE_MSG2_SIZE];
        let extra = [0xA5u8; 26];
        let total_noise_len = base_noise.len() + extra.len();
        let mut data = [0u8; 256];
        let prefix = wire::build_prefix(
            wire::PHASE_MSG2,
            0x00,
            (wire::IDX_SIZE * 2 + total_noise_len) as u16,
        );
        data[..4].copy_from_slice(&prefix);
        data[12..12 + base_noise.len()].copy_from_slice(&base_noise);
        data[12 + base_noise.len()..12 + total_noise_len].copy_from_slice(&extra);

        let expected = wire::COMMON_PREFIX_SIZE + wire::IDX_SIZE * 2 + total_noise_len;
        assert_eq!(fmp_raw_frame_size(&data[..expected]), Some(expected));
    }

    #[cfg(feature = "noise-xx")]
    #[test]
    fn test_fmp_raw_frame_size_msg3_with_negotiation_extra() {
        use microfips_core::wire;
        let base_noise = [0u8; wire::HANDSHAKE_MSG3_SIZE];
        let extra = [0x5Au8; 26];
        let total_noise_len = base_noise.len() + extra.len();
        let mut data = [0u8; 256];
        let prefix = wire::build_prefix(
            wire::PHASE_MSG3,
            0x00,
            (wire::IDX_SIZE * 2 + total_noise_len) as u16,
        );
        data[..4].copy_from_slice(&prefix);
        data[12..12 + base_noise.len()].copy_from_slice(&base_noise);
        data[12 + base_noise.len()..12 + total_noise_len].copy_from_slice(&extra);

        let expected = wire::COMMON_PREFIX_SIZE + wire::IDX_SIZE * 2 + total_noise_len;
        assert_eq!(fmp_raw_frame_size(&data[..expected]), Some(expected));
    }

    #[test]
    fn test_fmp_raw_frame_size_msg2_short_payload_len_rejected() {
        use microfips_core::wire;
        // payload_len smaller than the base msg2 (8 idx + base noise) is bogus.
        let mut data = [0u8; wire::MSG2_WIRE_SIZE];
        data[..4].copy_from_slice(&wire::build_prefix(wire::PHASE_MSG2, 0x00, 4));
        assert_eq!(fmp_raw_frame_size(&data), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_msg2_payload_len_beyond_buffer_rejected() {
        use microfips_core::wire;
        let mut data = [0u8; wire::MSG2_WIRE_SIZE];
        data[..4].copy_from_slice(&wire::build_prefix(wire::PHASE_MSG2, 0x00, 4096));
        assert_eq!(fmp_raw_frame_size(&data), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_truncated_prefix() {
        assert_eq!(fmp_raw_frame_size(&[0x01, 0x00, 0x6e]), None);
        assert_eq!(fmp_raw_frame_size(&[]), None);
        assert_eq!(fmp_raw_frame_size(&[0x00]), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_zero_payload_non_established() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_MSG1, 0x00, 0);
        assert_eq!(fmp_raw_frame_size(&prefix), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_zero_payload_established() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_ESTABLISHED, 0x00, 0);
        assert_eq!(fmp_raw_frame_size(&prefix), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_bad_version() {
        let data = [0x50, 0x00, 0x00, 0x00];
        assert_eq!(fmp_raw_frame_size(&data), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_msg1_needs_full_data() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_MSG1, 0x00, 110);
        assert_eq!(fmp_raw_frame_size(&prefix), None);
    }

    // --- Tests for extract_length_prefixed_frame ---

    #[test]
    fn test_extract_length_prefixed_complete() {
        let mut buf = [0u8; 16];
        let payload = b"hello";
        buf[..2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        buf[2..2 + payload.len()].copy_from_slice(payload);
        let (frame, pos) = extract_length_prefixed_frame(&buf, 0, 7).unwrap();
        assert_eq!(frame, payload);
        assert_eq!(pos, 7);
    }

    #[test]
    fn test_extract_length_prefixed_incomplete() {
        let buf = [0x05, 0x00, 0x68, 0x65];
        assert_eq!(extract_length_prefixed_frame(&buf, 0, 4), None);
    }

    #[test]
    fn test_extract_length_prefixed_zero_length() {
        let buf = [0x00, 0x00, 0xFF, 0xFF];
        let (frame, pos) = extract_length_prefixed_frame(&buf, 0, 4).unwrap();
        assert!(frame.is_empty());
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_extract_length_prefixed_exceeds_max() {
        let buf = [
            (framing::MAX_FRAME as u16 + 1).to_le_bytes()[0],
            (framing::MAX_FRAME as u16 + 1).to_le_bytes()[1],
            0x00,
        ];
        let (frame, pos) = extract_length_prefixed_frame(&buf, 0, 3).unwrap();
        assert!(frame.is_empty());
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_extract_length_prefixed_empty_buffer() {
        assert_eq!(extract_length_prefixed_frame(&[], 0, 0), None);
        assert_eq!(extract_length_prefixed_frame(&[0x05], 0, 1), None);
    }

    #[test]
    fn test_extract_length_prefixed_multiple_frames() {
        let mut buf = [0u8; 20];
        buf[0..2].copy_from_slice(&3u16.to_le_bytes());
        buf[2..5].copy_from_slice(b"abc");
        buf[5..7].copy_from_slice(&2u16.to_le_bytes());
        buf[7..9].copy_from_slice(b"xy");
        let (frame, pos) = extract_length_prefixed_frame(&buf, 0, 9).unwrap();
        assert_eq!(frame, b"abc");
        assert_eq!(pos, 5);
        let (frame2, pos2) = extract_length_prefixed_frame(&buf, pos, 9).unwrap();
        assert_eq!(frame2, b"xy");
        assert_eq!(pos2, 9);
    }

    // --- Tests for extract_raw_frame ---

    #[test]
    fn test_extract_raw_frame_established_uses_full_buffer() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_ESTABLISHED, 0x00, 10);
        let mut buf = [0u8; 64];
        buf[..4].copy_from_slice(&prefix);
        buf[4..].fill(0xAA);
        let (frame, pos) = extract_raw_frame(&buf, 0, 64).unwrap();
        assert_eq!(frame.len(), 64);
        assert_eq!(frame[..4], prefix);
        assert_eq!(pos, 64);
    }

    #[test]
    fn test_extract_raw_frame_established_too_short() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_ESTABLISHED, 0x00, 10);
        let mut buf = [0u8; 20];
        buf[..4].copy_from_slice(&prefix);
        buf[4..].fill(0xAA);
        assert_eq!(extract_raw_frame(&buf, 0, 20), None);
    }

    #[test]
    fn test_extract_raw_frame_truncated_prefix() {
        let buf = [0x00, 0x00, 0x34];
        assert_eq!(extract_raw_frame(&buf, 0, 3), None);
    }

    #[test]
    fn test_extract_raw_frame_empty_buffer() {
        assert_eq!(extract_raw_frame(&[], 0, 0), None);
    }

    #[test]
    fn test_extract_raw_frame_msg2_mid_buffer() {
        use microfips_core::wire;
        // MSG2 payload = 2 session indices + noise payload (IK: 65, XX: 114).
        let payload_len = (wire::MSG2_WIRE_SIZE - wire::COMMON_PREFIX_SIZE) as u16;
        let prefix = wire::build_prefix(wire::PHASE_MSG2, 0x00, payload_len);
        let mut buf = [0u8; 128];
        buf[10..14].copy_from_slice(&prefix);
        buf[14..14 + payload_len as usize].fill(0xCC);
        let end = 14 + payload_len as usize;
        let (frame, pos) = extract_raw_frame(&buf, 10, end).unwrap();
        assert_eq!(frame.len(), wire::MSG2_WIRE_SIZE);
        assert_eq!(frame[..4], prefix);
        assert_eq!(pos, end);
    }

    #[test]
    fn test_extract_raw_frame_msg2_needs_full_data() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_MSG2, 0x00, 65);
        let mut buf = [0u8; 32];
        buf[..4].copy_from_slice(&prefix);
        buf[4..].fill(0xCC);
        assert_eq!(extract_raw_frame(&buf, 0, 32), None);
    }

    #[test]
    fn test_xonly_peer_comparison_accepts_odd_parity() {
        // Same x-coordinate, different prefix byte (even vs odd y-parity)
        let mut peer_pub_even = [0u8; 33];
        peer_pub_even[0] = 0x02;
        peer_pub_even[1..33].copy_from_slice(&[0xABu8; 32]);

        let mut initiator_pub_odd = [0u8; 33];
        initiator_pub_odd[0] = 0x03; // different prefix
        initiator_pub_odd[1..33].copy_from_slice(&[0xABu8; 32]); // same x-coord

        // x-only comparison should match
        assert_eq!(
            initiator_pub_odd[1..33],
            peer_pub_even[1..33],
            "x-only comparison failed: same x-coord should match regardless of prefix"
        );

        // Full comparison would wrongly fail
        assert_ne!(
            initiator_pub_odd, peer_pub_even,
            "full comparison correctly differs when prefix differs"
        );
    }

    // --- ScriptedPeer tests ---

    #[test]
    fn test_scripted_peer_full_session_handshake_heartbeat_disconnect() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                Timer::after(Duration::from_millis(50)).await;
                peer.send_heartbeat().await;
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let (ks, kr, them) = node
                    .handshake(1u64.to_le_bytes(), &mut handler)
                    .await
                    .unwrap();
                node.rpos = 0;
                node.rlen = 0;
                let result = node
                    .steady(1u64.to_le_bytes(), &ks, &kr, them, &mut handler)
                    .await;
                assert_eq!(result, Ok(()));
                assert!(handler.events.contains(&NodeEvent::HeartbeatRecv));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_scripted_peer_corrupted_msg2_causes_handshake_failure() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                let _ = peer.recv_raw_frame().await;
                peer.send_corrupted_msg2().await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert!(result.is_err());
                assert!(handler.events.contains(&NodeEvent::Error));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_scripted_peer_silent_disconnect() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                peer.send_heartbeat().await;
                peer.close();
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Err(ProtocolError::Disconnected));
                assert!(handler.events.contains(&NodeEvent::HandshakeOk));
                assert!(handler.events.contains(&NodeEvent::Disconnected));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_scripted_peer_rx_silence_ends_session() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::select::{select, Either};
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            // The peer completes the handshake, sends one heartbeat, then
            // goes silent WITHOUT closing the transport: the node's sends
            // keep succeeding, only RX stops (the ESP-NOW failure mode).
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                peer.send_heartbeat().await;
                loop {
                    let _ = peer.recv_raw_frame().await;
                }
            };

            let node_task = async {
                let mut node = Node::with_timing(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                    NodeTiming {
                        heartbeat_interval_secs: 1,
                        link_dead_timeout_secs: 1,
                        ..NodeTiming::default()
                    },
                );
                let mut handler = RecordingHandler::default();
                let (ks, kr, them) = node
                    .handshake(1u64.to_le_bytes(), &mut handler)
                    .await
                    .unwrap();
                node.rpos = 0;
                node.rlen = 0;
                let result = node
                    .steady(1u64.to_le_bytes(), &ks, &kr, them, &mut handler)
                    .await;
                assert_eq!(result, Err(ProtocolError::Timeout));
            };

            match select(core::pin::pin!(peer_task), core::pin::pin!(node_task)).await {
                Either::First(_) => panic!("silent peer task must not finish"),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn test_scripted_peer_garbage_frame_ignored_in_steady() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                Timer::after(Duration::from_millis(50)).await;
                peer.send_garbage().await;
                peer.send_heartbeat().await;
                peer.send_disconnect(wire::DISC_REASON_OTHER).await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                node.policy.record_handshake_ok(Instant::now());
                node.policy.force_past_session_start();
                let mut handler = RecordingHandler::default();

                let (ks, kr, them) = node
                    .handshake(1u64.to_le_bytes(), &mut handler)
                    .await
                    .unwrap();
                node.rpos = 0;
                node.rlen = 0;

                let result = node
                    .steady(1u64.to_le_bytes(), &ks, &kr, them, &mut handler)
                    .await;
                assert_eq!(result, Ok(()));
                assert!(handler.events.contains(&NodeEvent::HeartbeatRecv));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_scripted_peer_datagram_exchange() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        struct PingHandler;
        impl NodeHandler for PingHandler {
            async fn on_event(&mut self, _event: NodeEvent) {}
            fn on_message(
                &mut self,
                msg_type: u8,
                payload: &[u8],
                resp: &mut [u8],
            ) -> HandleResult {
                if msg_type == wire::MSG_SESSION_DATAGRAM && payload == b"ping" {
                    resp[..4].copy_from_slice(b"pong");
                    HandleResult::SendDatagram(4)
                } else {
                    HandleResult::None
                }
            }
        }

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                Timer::after(Duration::from_millis(50)).await;
                peer.send_heartbeat().await;
                peer.send_datagram(b"ping").await;
                let (msg_type, payload) = peer.recv_decrypted_frame().await;
                assert_eq!(msg_type, wire::MSG_SESSION_DATAGRAM);
                assert_eq!(payload, b"pong");
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = PingHandler;
                let result = node.session(&mut handler).await;
                assert_eq!(result, Ok(()));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_scripted_peer_no_response_causes_handshake_timeout() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                let _ = peer.recv_raw_frame().await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = NoopTestHandler;
                let epoch = node.advance_epoch();
                let result = node.handshake(epoch, &mut handler).await;
                assert_eq!(result, Err(ProtocolError::Timeout));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_scripted_peer_multiple_heartbeats_before_disconnect() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                Timer::after(Duration::from_millis(50)).await;
                for _ in 0..5 {
                    peer.send_heartbeat().await;
                }
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Ok(()));

                let hb_recv_count = handler
                    .events
                    .iter()
                    .filter(|e| **e == NodeEvent::HeartbeatRecv)
                    .count();
                assert!(
                    hb_recv_count >= 5,
                    "expected at least 5 HeartbeatRecv, got {}",
                    hb_recv_count
                );
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_replayed_established_frame_is_dropped() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                let them = peer.complete_handshake().await;
                Timer::after(Duration::from_millis(50)).await;

                // One heartbeat frame, delivered twice byte-for-byte: the
                // second copy is a replay and must be dropped (#181).
                let ks = peer.ks.unwrap();
                let frame = build_test_frame(
                    them,
                    0,
                    wire::MSG_HEARTBEAT,
                    embassy_time::Instant::now().as_millis() as u32,
                    &[],
                    &ks,
                );
                peer.send_raw_frame(&frame).await;
                peer.send_raw_frame(&frame).await;

                // The disconnect must use a fresh counter, or it would be a
                // replay of counter 0 itself.
                peer.send_ctr = 1;
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Ok(()), "session must end via disconnect, not error");

                let hb_recv_count = handler
                    .events
                    .iter()
                    .filter(|e| **e == NodeEvent::HeartbeatRecv)
                    .count();
                assert_eq!(
                    hb_recv_count, 1,
                    "replayed heartbeat must be dropped exactly once received"
                );
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_rekey_msg1_resend_is_idempotent() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let node_pub = ecdh_pubkey(&initiator_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                Timer::after(Duration::from_millis(50)).await;

                // The daemon resends the SAME msg1 bytes when its msg2 is in
                // flight; both copies must draw the same answer.
                let rekey_eph = random_secret();
                let rekey_idx: u32 = 0x7E57_0002;
                let (msg1_frame, mut rekey_init) =
                    build_msg1_frame(&responder_secret, &node_pub, &rekey_eph, rekey_idx, 1);
                peer.send_raw_frame(&msg1_frame).await;
                Timer::after(Duration::from_millis(50)).await;
                peer.send_raw_frame(&msg1_frame).await;

                let msg2_a =
                    embassy_time::with_timeout(Duration::from_millis(3000), peer.recv_raw_frame())
                        .await
                        .expect("first msg2");
                let msg2_b =
                    embassy_time::with_timeout(Duration::from_millis(3000), peer.recv_raw_frame())
                        .await
                        .expect("second msg2 (resend answer)");
                assert_eq!(
                    msg2_a, msg2_b,
                    "duplicate msg1 must draw byte-identical msg2 resends"
                );

                let msg = wire::parse_message(&msg2_a).unwrap();
                let (node_new_idx, np2) = match msg {
                    wire::FmpMessage::Msg2 {
                        sender_idx,
                        noise_payload,
                        ..
                    } => (sender_idx, noise_payload),
                    _ => panic!("expected Msg2"),
                };
                rekey_init.read_message2(np2).unwrap();

                #[cfg(feature = "noise-xx")]
                {
                    let n3 = {
                        let mut buf = [0u8; 128];
                        let len = rekey_init
                            .write_message3(&responder_pub, &1u64.to_le_bytes(), &mut buf)
                            .unwrap();
                        buf[..len].to_vec()
                    };
                    let mut msg3_frame = [0u8; 256];
                    let msg3_len = wire::build_msg3(
                        wire::SessionIndex::new(rekey_idx),
                        node_new_idx,
                        &n3,
                        &mut msg3_frame,
                    )
                    .unwrap();
                    peer.send_raw_frame(&msg3_frame[..msg3_len]).await;
                }

                let (c1, c2) = rekey_init.finalize();
                let hb = crate::test_harness::build_test_frame_flags(
                    node_new_idx,
                    0,
                    wire::MSG_HEARTBEAT,
                    embassy_time::Instant::now().as_millis() as u32,
                    &[],
                    &c1,
                    wire::FLAG_KEY_EPOCH,
                );
                peer.send_raw_frame(&hb).await;
                Timer::after(Duration::from_millis(50)).await;

                peer.ks = Some(c1);
                peer.kr = Some(c2);
                peer.peer_sender_idx = Some(node_new_idx);
                peer.send_ctr = 1;
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Ok(()));
                assert!(handler.events.contains(&NodeEvent::HeartbeatRecv));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_node_initiates_rekey_and_peer_follows_cutover() {
        use crate::test_harness::{build_test_frame_flags, success_timing};
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let node_pub = ecdh_pubkey(&initiator_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;

                // The node's rekey timer fires: its next outbound frame must
                // be a rekey Msg1, not an old-epoch heartbeat.
                let frame =
                    embassy_time::with_timeout(Duration::from_millis(5000), peer.recv_raw_frame())
                        .await
                        .expect("node never initiated rekey");
                let msg = wire::parse_message(&frame).unwrap();
                let (node_new_idx, np1) = match msg {
                    wire::FmpMessage::Msg1 {
                        sender_idx,
                        noise_payload,
                    } => (sender_idx, noise_payload),
                    _ => panic!("expected rekey Msg1 from node, got {:?}", msg),
                };

                // Peer answers as the rekey responder.
                let resp_idx = wire::SessionIndex::new(0xBEEF_0001);
                #[cfg(not(feature = "noise-xx"))]
                let (peer_ks, peer_kr) = {
                    use microfips_core::noise::{NoiseIkResponder, PUBKEY_SIZE};
                    let ei_pub: [u8; PUBKEY_SIZE] = np1[..PUBKEY_SIZE].try_into().unwrap();
                    let mut resp = NoiseIkResponder::new(&responder_secret, &ei_pub).unwrap();
                    let (init_pub, _e) = resp.read_message1(&np1[PUBKEY_SIZE..]).unwrap();
                    assert_eq!(
                        init_pub[1..33],
                        node_pub[1..33],
                        "rekey initiator must be the pinned peer"
                    );
                    let mut n2 = [0u8; 128];
                    let l = resp
                        .write_message2(&random_secret(), &1u64.to_le_bytes(), &mut n2)
                        .unwrap();
                    let mut buf = [0u8; 256];
                    let bl = wire::build_msg2(resp_idx, node_new_idx, &n2[..l], &mut buf).unwrap();
                    peer.send_raw_frame(&buf[..bl]).await;
                    let (c1, c2) = resp.finalize();
                    (c2, c1)
                };
                #[cfg(feature = "noise-xx")]
                let (peer_ks, peer_kr) = {
                    use microfips_core::noise::NoiseXxResponder;
                    let mut resp = NoiseXxResponder::new(&responder_secret).unwrap();
                    resp.read_message1(np1).unwrap();
                    let mut n2 = [0u8; 128];
                    let l = resp
                        .write_message2(&random_secret(), &1u64.to_le_bytes(), &mut n2)
                        .unwrap();
                    let mut buf = [0u8; 256];
                    let bl = wire::build_msg2(resp_idx, node_new_idx, &n2[..l], &mut buf).unwrap();
                    peer.send_raw_frame(&buf[..bl]).await;

                    // Old-epoch stragglers may interleave before msg3.
                    let mut np3 = None;
                    for _ in 0..6 {
                        let f = embassy_time::with_timeout(
                            Duration::from_millis(5000),
                            peer.recv_raw_frame(),
                        )
                        .await
                        .expect("node went silent before msg3");
                        if let Some(wire::FmpMessage::Msg3 { noise_payload, .. }) =
                            wire::parse_message(&f)
                        {
                            np3 = Some(noise_payload.to_vec());
                            break;
                        }
                    }
                    let np3 = np3.expect("node never sent msg3");
                    let (init_pub, _e) = resp.read_message3(np3.as_slice()).unwrap();
                    assert_eq!(init_pub[1..33], node_pub[1..33]);
                    let (c1, c2) = resp.finalize();
                    (c2, c1)
                };

                // Initiator cutover: the node's first send after msg2 may be
                // an old-epoch straggler (heartbeat in the same tick as the
                // initiation — the drain window exists for exactly this);
                // skip those until a NEW-epoch K-bit frame arrives.
                fn try_decrypt(key: &[u8; 32], frame: &[u8]) -> Option<(u8, std::vec::Vec<u8>)> {
                    let enc = wire::EncryptedHeader::parse(frame)?;
                    let mut dec = [0u8; MAX_FRAME_SIZE];
                    let dl = microfips_core::noise::aead_decrypt(
                        key,
                        enc.counter,
                        &enc.header_bytes,
                        &frame[wire::ESTABLISHED_HEADER_SIZE..],
                        &mut dec,
                    )
                    .ok()?;
                    let (_, inner) = wire::strip_inner_header(&dec[..dl])?;
                    Some((inner[0], inner[1..].to_vec()))
                }

                let old_kr = peer.kr.expect("initial epoch keys");
                let mut got_new_epoch = false;
                for _ in 0..6 {
                    let hb_frame = embassy_time::with_timeout(
                        Duration::from_millis(5000),
                        peer.recv_raw_frame(),
                    )
                    .await
                    .expect("node went silent after rekey");
                    if let Some((_msg_type, _)) = try_decrypt(&peer_kr, &hb_frame) {
                        // Any authenticated new-epoch frame proves the cutover
                        // (heartbeat or MMP report — both seal post-promote).
                        let enc = wire::EncryptedHeader::parse(&hb_frame).unwrap();
                        assert_ne!(
                            enc.header_bytes[1] & wire::FLAG_KEY_EPOCH,
                            0,
                            "post-cutover frames must carry the K-bit"
                        );
                        got_new_epoch = true;
                        break;
                    }
                    // Straggler: must still authenticate in the old epoch.
                    assert!(
                        try_decrypt(&old_kr, &hb_frame).is_some(),
                        "frame authenticated in neither epoch"
                    );
                }
                assert!(got_new_epoch, "node never cut over to the new epoch");

                // Peer follows the cutover and ends the session on the new epoch.
                let ts = embassy_time::Instant::now().as_millis() as u32;
                let hb = build_test_frame_flags(
                    node_new_idx,
                    0,
                    wire::MSG_HEARTBEAT,
                    ts,
                    &[],
                    &peer_ks,
                    wire::FLAG_KEY_EPOCH,
                );
                peer.send_raw_frame(&hb).await;
                Timer::after(Duration::from_millis(100)).await;
                peer.ks = Some(peer_ks);
                peer.kr = Some(peer_kr);
                peer.peer_sender_idx = Some(node_new_idx);
                peer.send_ctr = 1;
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::with_timing(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                    NodeTiming {
                        rekey_after_secs: 1,
                        heartbeat_interval_secs: 1,
                        link_dead_timeout_secs: 8,
                        ..success_timing()
                    },
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Ok(()));
                assert!(handler.events.contains(&NodeEvent::HeartbeatRecv));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_rekey_dampening_suppresses_dual_init() {
        use crate::test_harness::build_test_frame_flags;
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let node_pub = ecdh_pubkey(&initiator_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                Timer::after(Duration::from_millis(300)).await;

                // Peer initiates first; the node's own timer fires inside the
                // 30s dampening window and must stay silent (no Msg1 of its own).
                let rekey_eph = random_secret();
                let rekey_idx: u32 = 0x7E57_0003;
                let (msg1_frame, mut rekey_init) =
                    build_msg1_frame(&responder_secret, &node_pub, &rekey_eph, rekey_idx, 1);
                peer.send_raw_frame(&msg1_frame).await;

                let msg2 =
                    embassy_time::with_timeout(Duration::from_millis(3000), peer.recv_raw_frame())
                        .await
                        .expect("node did not answer the rekey msg1");
                let msg = wire::parse_message(&msg2).unwrap();
                let (node_new_idx, np2) = match msg {
                    wire::FmpMessage::Msg2 {
                        sender_idx,
                        noise_payload,
                        ..
                    } => (sender_idx, noise_payload),
                    _ => panic!("expected Msg2"),
                };
                rekey_init.read_message2(np2).unwrap();

                #[cfg(feature = "noise-xx")]
                {
                    let n3 = {
                        let mut buf = [0u8; 128];
                        let len = rekey_init
                            .write_message3(&responder_pub, &1u64.to_le_bytes(), &mut buf)
                            .unwrap();
                        buf[..len].to_vec()
                    };
                    let mut f = [0u8; 256];
                    let fl = wire::build_msg3(
                        wire::SessionIndex::new(rekey_idx),
                        node_new_idx,
                        &n3,
                        &mut f,
                    )
                    .unwrap();
                    peer.send_raw_frame(&f[..fl]).await;
                }

                let (c1, c2) = rekey_init.finalize();
                let peer_ks = c1;
                let peer_kr = c2;

                // Dampening window: collect the node's frames for ~3s. The
                // node's own rekey timer (1s) fires inside this window —
                // none of these frames may be a Msg1.
                let mut saw_msg1 = 0;
                for _ in 0..3 {
                    if let Ok(f) = embassy_time::with_timeout(
                        Duration::from_millis(1000),
                        peer.recv_raw_frame(),
                    )
                    .await
                    {
                        if let Some(wire::FmpMessage::Msg1 { .. }) = wire::parse_message(&f) {
                            saw_msg1 += 1;
                        }
                    }
                }
                assert_eq!(
                    saw_msg1, 0,
                    "node must not dual-initiate inside the dampening window"
                );

                // Cutover proof ends the window behavior; clean shutdown after.
                let ts = embassy_time::Instant::now().as_millis() as u32;
                let hb = build_test_frame_flags(
                    node_new_idx,
                    0,
                    wire::MSG_HEARTBEAT,
                    ts,
                    &[],
                    &peer_ks,
                    wire::FLAG_KEY_EPOCH,
                );
                peer.send_raw_frame(&hb).await;
                Timer::after(Duration::from_millis(200)).await;
                peer.ks = Some(peer_ks);
                peer.kr = Some(peer_kr);
                peer.peer_sender_idx = Some(node_new_idx);
                peer.send_ctr = 1;
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::with_timing(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                    NodeTiming {
                        rekey_after_secs: 1,
                        heartbeat_interval_secs: 1,
                        link_dead_timeout_secs: 8,
                        ..crate::test_harness::success_timing()
                    },
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Ok(()));
                assert!(handler.events.contains(&NodeEvent::HeartbeatRecv));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_steady_answers_peer_rekey_and_follows_cutover() {
        use crate::test_harness::build_test_frame_flags;
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::noise::ecdh_pubkey;

        let initiator_secret = random_secret();
        let responder_secret = random_secret();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let node_pub = ecdh_pubkey(&initiator_secret).unwrap();

        let (init_transport, peer_transport) = channel_pair();

        block_on(async move {
            let peer_task = async {
                let mut peer = ScriptedPeer::new(peer_transport, responder_secret);
                peer.complete_handshake().await;
                Timer::after(Duration::from_millis(50)).await;

                // Rekey: the peer initiates with a fresh ephemeral + fresh
                // sender index, exactly like the daemon does every 120s.
                let rekey_eph = random_secret();
                let rekey_idx: u32 = 0x7E57_0001;
                let (msg1_frame, mut rekey_init) =
                    build_msg1_frame(&responder_secret, &node_pub, &rekey_eph, rekey_idx, 1);
                peer.send_raw_frame(&msg1_frame).await;

                let msg2 =
                    embassy_time::with_timeout(Duration::from_millis(3000), peer.recv_raw_frame())
                        .await
                        .expect("node did not answer the rekey msg1 with msg2");
                let msg = wire::parse_message(&msg2).unwrap();
                let (node_new_idx, np2) = match msg {
                    wire::FmpMessage::Msg2 {
                        sender_idx,
                        receiver_idx,
                        noise_payload,
                    } => {
                        assert_eq!(receiver_idx, wire::SessionIndex::new(rekey_idx));
                        (sender_idx, noise_payload)
                    }
                    _ => panic!("expected Msg2"),
                };
                rekey_init.read_message2(np2).unwrap();

                #[cfg(feature = "noise-xx")]
                {
                    let n3 = {
                        let mut buf = [0u8; 128];
                        let len = rekey_init
                            .write_message3(&responder_pub, &1u64.to_le_bytes(), &mut buf)
                            .unwrap();
                        buf[..len].to_vec()
                    };
                    let mut msg3_frame = [0u8; 256];
                    let msg3_len = wire::build_msg3(
                        wire::SessionIndex::new(rekey_idx),
                        node_new_idx,
                        &n3,
                        &mut msg3_frame,
                    )
                    .unwrap();
                    peer.send_raw_frame(&msg3_frame[..msg3_len]).await;
                }

                let (c1, c2) = rekey_init.finalize();
                // Peer is the rekey initiator: sends with c1, receives with c2.
                let peer_ks = c1;
                let _peer_kr = c2;
                let ts = embassy_time::Instant::now().as_millis() as u32;

                // Peer has cut over: first frame sealed in the NEW epoch,
                // K-bit set. The node's pending-decrypt promotes it.
                let hb1 = build_test_frame_flags(
                    node_new_idx,
                    0,
                    wire::MSG_HEARTBEAT,
                    ts,
                    &[],
                    &peer_ks,
                    wire::FLAG_KEY_EPOCH,
                );
                peer.send_raw_frame(&hb1).await;
                Timer::after(Duration::from_millis(50)).await;

                let hb2 = build_test_frame_flags(
                    node_new_idx,
                    1,
                    wire::MSG_HEARTBEAT,
                    ts,
                    &[],
                    &peer_ks,
                    wire::FLAG_KEY_EPOCH,
                );
                peer.send_raw_frame(&hb2).await;

                // An old-epoch straggler: sealed with the initial epoch keys
                // and their counter space — must still decrypt (drain slot).
                let old_ks = peer.ks.unwrap();
                let old_them = peer.peer_sender_idx.unwrap();
                let stray = build_test_frame_flags(
                    old_them,
                    5,
                    wire::MSG_HEARTBEAT,
                    ts,
                    &[],
                    &old_ks,
                    0x00,
                );
                peer.send_raw_frame(&stray).await;

                peer.ks = Some(peer_ks);
                peer.kr = Some(_peer_kr);
                peer.peer_sender_idx = Some(node_new_idx);
                peer.send_ctr = 2;
                peer.send_disconnect(wire::DISC_REASON_SHUTDOWN).await;
            };

            let node_task = async {
                let mut node = Node::new(
                    init_transport,
                    TestRng::from_os_rng(),
                    initiator_secret,
                    responder_pub,
                );
                let mut handler = RecordingHandler::default();
                let result = node.session(&mut handler).await;
                assert_eq!(result, Ok(()), "session must end via clean disconnect");

                let hb_recv = handler
                    .events
                    .iter()
                    .filter(|e| **e == NodeEvent::HeartbeatRecv)
                    .count();
                assert!(
                    hb_recv >= 3,
                    "expected 2 new-epoch + 1 old-epoch-straggler heartbeats, got {}",
                    hb_recv
                );
            };

            join(peer_task, node_task).await;
        });
    }
}
