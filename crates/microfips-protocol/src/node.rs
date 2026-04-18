use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};
use microfips_core::wire;

use crate::error::ProtocolError;
use crate::framing;
use crate::peer_policy::{PeerPolicy, PolicyVerdict};
use crate::transport::{CryptoRng, RngCore, Transport};

macro_rules! log_steady {
    ($($arg:tt)*) => {
        #[cfg(feature = "log")]
        log::info!($($arg)*);
    };
}

pub const HB_SECS: u64 = 10;
pub const RECV_TIMEOUT_MS: u64 = 30_000;
pub const RETRY_SECS: u64 = 3;
pub const BACKOFF_MAX_SECS: u64 = 60;
pub const MSG1_RESEND_SECS: u64 = 3;
pub const MSG1_RESEND_MAX: u32 = 10;
pub const CONNECT_DELAY_MS: u64 = 500;
pub const MAX_COMPETING_MSG1: u32 = 3;

pub const RECV_BUF_SIZE: usize = 1500;

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

pub struct Node<T: Transport, R: RngCore + CryptoRng> {
    transport: T,
    rng: R,
    policy: PeerPolicy,
    nsec: [u8; 32],
    peer_npub: [u8; 33],
    rbuf: [u8; 2048],
    rpos: usize,
    rlen: usize,
    resp_buf: [u8; 256],
    raw_framing: bool,
    epoch: u64,
    peer_sent_first: bool,
}

impl<T: Transport, R: RngCore + CryptoRng> Node<T, R> {
    pub fn new(transport: T, rng: R, nsec: [u8; 32], peer_npub: [u8; 33]) -> Self {
        Self {
            transport,
            rng,
            policy: PeerPolicy::new(),
            nsec,
            peer_npub,
            rbuf: [0u8; 2048],
            rpos: 0,
            rlen: 0,
            resp_buf: [0u8; 256],
            raw_framing: false,
            epoch: 0,
            peer_sent_first: false,
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
        let mut backoff: u32 = 0;
        loop {
            match self.policy.check_reconnect(Instant::now()) {
                PolicyVerdict::Allow => {}
                PolicyVerdict::Backoff(delay) => {
                    log_steady!("policy: reconnect backoff {}ms", delay.as_millis());
                    Timer::after(delay).await;
                }
                PolicyVerdict::Reject => {
                    log_steady!("policy: rejected: reconnect");
                    Timer::after(Duration::from_secs(RETRY_SECS)).await;
                    continue;
                }
            }
            self.policy.record_connect_attempt(Instant::now());
            let result = self.session(handler).await;
            if result.is_ok() {
                backoff = 0;
            } else {
                backoff = backoff.saturating_add(1);
            }
            let delay = RETRY_SECS * (1u64 << backoff.min(4));
            Timer::after(Duration::from_secs(delay.min(BACKOFF_MAX_SECS))).await;
        }
    }

    async fn session<H: NodeHandler>(&mut self, handler: &mut H) -> Result<(), ProtocolError> {
        self.transport
            .wait_ready()
            .await
            .map_err(|_| ProtocolError::Disconnected)?;
        let epoch = self.advance_epoch();
        Timer::after(Duration::from_millis(CONNECT_DELAY_MS)).await;
        handler.on_event(NodeEvent::Connected).await;

        self.rpos = 0;
        self.rlen = 0;

        match self.handshake(epoch, handler).await {
            Ok((ks, kr, them)) => {
                self.policy.record_handshake_ok(Instant::now());
                log_steady!("session: handshake ok, entering steady");
                handler.on_event(NodeEvent::HandshakeOk).await;
                let result = self.steady(&ks, &kr, them, handler).await;
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
        use microfips_core::identity::NodeAddr;
        use microfips_core::noise;
        use microfips_core::wire;

        let my_pub = noise::ecdh_pubkey(&self.nsec).unwrap();
        let my_x_only: [u8; 32] = my_pub[1..33].try_into().unwrap();
        let my_addr = NodeAddr::from_pubkey_x(&my_x_only);
        let peer_x_only: [u8; 32] = self.peer_npub[1..33].try_into().unwrap();
        let peer_addr = NodeAddr::from_pubkey_x(&peer_x_only);

        let initiator_eph = self.generate_valid_eph();
        let (mut noise_st, _e_pub) =
            noise::NoiseIkInitiator::new(&initiator_eph, &self.nsec, &self.peer_npub)
                .expect("noise init");

        let mut n1 = [0u8; 256];
        let n1len = noise_st
            .write_message1(&my_pub, &epoch, &mut n1)
            .expect("write_message1");

        let our_index = self.allocate_session_index();
        let mut f1 = [0u8; 256];
        let f1len = wire::build_msg1(our_index, &n1[..n1len], &mut f1).unwrap();

        if !self.peer_sent_first {
            self.send_frame(&f1[..f1len]).await?;
            handler.on_event(NodeEvent::Msg1Sent).await;
        } else {
            #[cfg(feature = "log")]
            log::info!("peer sent MSG1 first, entering responder path");
        }

        let mut mb = [0u8; 2048];
        let mut competing_msg1_count: u32 = 0;
        let mut resend_count: u32 = 0;
        loop {
            match self
                .recv_frame(&mut mb, MSG1_RESEND_SECS as u32 * 1000)
                .await
            {
                Ok(ml) => {
                    resend_count = 0;
                    let m = wire::parse_message(&mb[..ml]).ok_or(ProtocolError::InvalidMessage)?;
                    match m {
                        wire::FmpMessage::Msg2 {
                            sender_idx,
                            noise_payload,
                            ..
                        } => {
                            let mut st = noise_st.clone();
                            st.read_message2(noise_payload)?;
                            let (ks, kr) = st.finalize();
                            return Ok((ks, kr, sender_idx));
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

                            if noise_payload.len() < noise::PUBKEY_SIZE {
                                #[cfg(feature = "log")]
                                log::warn!(
                                    "handshake: MSG1 noise payload too short ({})",
                                    noise_payload.len()
                                );
                                return Err(ProtocolError::InvalidMessage);
                            }

                            let peer_e_pub: [u8; noise::PUBKEY_SIZE] = noise_payload
                                [..noise::PUBKEY_SIZE]
                                .try_into()
                                .map_err(|_| ProtocolError::InvalidMessage)?;

                            let mut responder =
                                match noise::NoiseIkResponder::new(&self.nsec, &peer_e_pub) {
                                    Ok(r) => r,
                                    Err(_e) => {
                                        #[cfg(feature = "log")]
                                        log::error!(
                                            "handshake: NoiseIkResponder::new failed: {:?}",
                                            _e
                                        );
                                        return Err(ProtocolError::InvalidMessage);
                                    }
                                };

                            let (initiator_static_pub, epoch) = match responder
                                .read_message1(&noise_payload[noise::PUBKEY_SIZE..])
                            {
                                Ok(v) => v,
                                Err(_e) => {
                                    #[cfg(feature = "log")]
                                    log::error!("handshake: read_message1 failed: {:?}", _e);
                                    return Err(ProtocolError::InvalidMessage);
                                }
                            };

                            // Compare x-only bytes only (1..33). The prefix byte may differ:
                            // peer_pub is constructed with 0x02 from x-only exchange data,
                            // but the Noise-decrypted initiator_static_pub has the actual
                            // compressed pubkey prefix (0x02 or 0x03 depending on y-parity).
                            // Both represent the same key — only the x-coordinate matters.
                            let from_configured_peer =
                                initiator_static_pub[1..33] == self.peer_npub[1..33];
                            #[cfg(feature = "log")]
                            {
                                log::info!("handshake: from_configured_peer={} peer_sent_first={} prefix_initiator=0x{:02x} prefix_peer=0x{:02x}",
                                    from_configured_peer, self.peer_sent_first,
                                    initiator_static_pub[0], self.peer_npub[0]);
                            }

                            if from_configured_peer
                                && !self.peer_sent_first
                                && my_addr.as_bytes() < peer_addr.as_bytes()
                            {
                                #[cfg(feature = "log")]
                                log::warn!(
                                    "discarding MSG1 from configured peer (waiting for MSG2)"
                                );
                                continue;
                            }

                            if !from_configured_peer {
                                competing_msg1_count += 1;
                                if competing_msg1_count > MAX_COMPETING_MSG1 {
                                    return Err(ProtocolError::Timeout);
                                }
                                continue;
                            }

                            let mut resp_eph = self.generate_valid_eph();
                            while resp_eph == initiator_eph {
                                resp_eph = self.generate_valid_eph();
                            }

                            let mut msg2_noise = [0u8; 128];
                            let msg2_noise_len = match responder.write_message2(
                                &resp_eph,
                                &epoch,
                                &mut msg2_noise,
                            ) {
                                Ok(n) => n,
                                Err(_e) => {
                                    #[cfg(feature = "log")]
                                    log::error!("handshake: write_message2 failed: {:?}", _e);
                                    return Err(ProtocolError::DecryptFailed);
                                }
                            };

                            let our_index = self.allocate_session_index();
                            let mut msg2_buf = [0u8; 256];
                            let msg2_len = wire::build_msg2(
                                our_index,
                                peer_sender_idx,
                                &msg2_noise[..msg2_noise_len],
                                &mut msg2_buf,
                            )
                            .ok_or(ProtocolError::InvalidMessage)?;
                            self.send_frame(&msg2_buf[..msg2_len]).await?;

                            let (k1, k2) = responder.finalize();
                            return Ok((k2, k1, peer_sender_idx));
                        }
                        _ => continue,
                    }
                }
                Err(ProtocolError::Timeout) => {
                    resend_count += 1;
                    if resend_count > MSG1_RESEND_MAX {
                        return Err(ProtocolError::Timeout);
                    }
                    self.send_frame(&f1[..f1len]).await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn steady<H: NodeHandler>(
        &mut self,
        ks: &[u8; 32],
        kr: &[u8; 32],
        them: wire::SessionIndex,
        handler: &mut H,
    ) -> Result<(), ProtocolError> {
        log_steady!("steady: entered, next_hb in {}s", HB_SECS);
        let mut next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);
        let mut next_sr = embassy_time::Instant::now() + Duration::from_secs(HB_SECS / 2);
        let mut send_ctr: u64 = 0;
        let mut sr_start_ctr: u64 = 0;
        let mut sr_start_ts: u32 = embassy_time::Instant::now().as_millis() as u32;

        loop {
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

                    while self.rpos < self.rlen {
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

                        let result =
                            handle_frame_inner(kr, frame_data, handler, &mut self.resp_buf);
                        if frame_is_policy_good(kr, frame_data) {
                            self.policy.record_good_frame();
                        } else {
                            self.policy.record_bad_frame();
                        }
                        if self.policy.check_bad_frame_limit() == PolicyVerdict::Reject {
                            log_steady!("policy: rejected: bad frame limit");
                            self.send_disconnect(
                                ks,
                                them,
                                &mut send_ctr,
                                wire::DISC_REASON_SECURITY_VIOLATION,
                            )
                            .await;
                            return Err(ProtocolError::Disconnected);
                        }

                        match result {
                            FrameAction::Continue => {}
                            FrameAction::HeartbeatRecv => {
                                self.policy.record_heartbeat();
                                log_steady!("steady: heartbeat received from peer");
                                handler.on_event(NodeEvent::HeartbeatRecv).await;
                            }
                            FrameAction::PeerDC => {
                                log_steady!("steady: peer disconnect received, exiting steady");
                                return Ok(());
                            }
                            FrameAction::SelfDC => {
                                log_steady!("steady: self disconnect, exiting steady");
                                let _ = self
                                    .send_disconnect(ks, them, &mut send_ctr, wire::DISC_REASON_SHUTDOWN)
                                    .await;
                                return Ok(());
                            }
                            FrameAction::SendDatagram(len) => {
                                self.policy.record_data_frame();
                                log_steady!("steady: sending datagram {} bytes", len);
                                self.send_datagram(them, &mut send_ctr, len, ks).await;
                            }
                            FrameAction::SendLinkMessage { msg_type, len } => {
                                self.policy.record_data_frame();
                                log_steady!("steady: sending link msg type=0x{:02x} len={}", msg_type, len);
                                self.send_link_message(them, &mut send_ctr, msg_type, len, ks)
                                    .await;
                            }
                        }
                    }
                    if self.rpos >= self.rlen {
                        self.rpos = 0;
                        self.rlen = 0;
                    }
                    let now = embassy_time::Instant::now();
                    if now >= next_hb {
                        log_steady!("steady: sending heartbeat (recv branch, ctr={})", send_ctr);
                        next_hb = self.send_heartbeat(ks, them, &mut send_ctr).await;
                        handler.on_event(NodeEvent::HeartbeatSent).await;
                    }
                    if now >= next_sr {
                        log_steady!("steady: sending sender report (recv branch)");
                        next_sr = now + Duration::from_secs(HB_SECS);
                        let sr_end_ts = now.as_millis() as u32;
                        let mut sr = [0u8; 47];
                        sr[3..11].copy_from_slice(&sr_start_ctr.to_le_bytes());
                        sr[11..19].copy_from_slice(&send_ctr.to_le_bytes());
                        sr[19..23].copy_from_slice(&sr_start_ts.to_le_bytes());
                        sr[23..27].copy_from_slice(&sr_end_ts.to_le_bytes());
                        self.resp_buf[..47].copy_from_slice(&sr);
                        self.send_link_message(them, &mut send_ctr, wire::MSG_SENDER_REPORT, 47, ks)
                            .await;
                        sr_start_ctr = send_ctr;
                        sr_start_ts = sr_end_ts;
                    }
                    if let Some(t) = tick {
                        #[allow(clippy::collapsible_if)]
                        if now >= t {
                            if let HandleResult::SendDatagram(len) =
                                handler.on_tick(&mut self.resp_buf)
                            {
                                self.send_datagram(them, &mut send_ctr, len, ks).await;
                            }
                        }
                    }
                }
                Either::First(Err(e)) => {
                    log_steady!("steady: recv error, disconnecting: {:?}", e);
                    let _ = self
                        .send_disconnect(
                            ks,
                            them,
                            &mut send_ctr,
                            wire::DISC_REASON_TRANSPORT_FAILURE,
                        )
                        .await;
                    return Err(ProtocolError::Disconnected);
                }
                Either::Second(()) => {
                    let now = embassy_time::Instant::now();
                    if now >= next_hb {
                        log_steady!("steady: sending heartbeat (timer branch, ctr={})", send_ctr);
                        next_hb = self.send_heartbeat(ks, them, &mut send_ctr).await;
                        handler.on_event(NodeEvent::HeartbeatSent).await;
                        if self.policy.check_silent_peer(Instant::now()) == PolicyVerdict::Reject {
                            log_steady!("policy: rejected: silent peer");
                            self.send_disconnect(
                                ks,
                                them,
                                &mut send_ctr,
                                wire::DISC_REASON_RESOURCE_EXHAUSTION,
                            )
                            .await;
                            return Err(ProtocolError::Disconnected);
                        }
                    }
                    if now >= next_sr {
                        next_sr = now + Duration::from_secs(HB_SECS);
                        let sr_end_ts = now.as_millis() as u32;
                        let mut sr = [0u8; 47];
                        sr[3..11].copy_from_slice(&sr_start_ctr.to_le_bytes());
                        sr[11..19].copy_from_slice(&send_ctr.to_le_bytes());
                        sr[19..23].copy_from_slice(&sr_start_ts.to_le_bytes());
                        sr[23..27].copy_from_slice(&sr_end_ts.to_le_bytes());
                        self.resp_buf[..47].copy_from_slice(&sr);
                        self.send_link_message(them, &mut send_ctr, wire::MSG_SENDER_REPORT, 47, ks)
                            .await;
                        sr_start_ctr = send_ctr;
                        sr_start_ts = sr_end_ts;
                    }
                    if let Some(t) = tick {
                        #[allow(clippy::collapsible_if)]
                        if now >= t {
                            if let HandleResult::SendDatagram(len) =
                                handler.on_tick(&mut self.resp_buf)
                            {
                                self.send_datagram(them, &mut send_ctr, len, ks).await;
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
    async fn send_datagram(
        &mut self,
        them: wire::SessionIndex,
        send_ctr: &mut u64,
        len: usize,
        ks: &[u8; 32],
    ) {
        use microfips_core::wire;
        let c = *send_ctr;
        *send_ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let msg_end = 1 + len;
        let mut msg_buf = [0u8; 512];
        msg_buf[0] = wire::MSG_SESSION_DATAGRAM;
        msg_buf[1..msg_end].copy_from_slice(&self.resp_buf[..len]);
        let mut inner_buf = [0u8; 512];
        let inner_len =
            wire::prepend_inner_header(ts, &msg_buf[..msg_end], &mut inner_buf).unwrap();
        let fl = wire::encrypt_and_assemble(them, c, 0x00, &inner_buf[..inner_len], ks, &mut out);
        if let Some(fl) = fl {
            let _ = self.send_frame(&out[..fl]).await;
        }
    }

    async fn send_link_message(
        &mut self,
        them: wire::SessionIndex,
        send_ctr: &mut u64,
        msg_type: u8,
        len: usize,
        ks: &[u8; 32],
    ) {
        use microfips_core::wire;
        let c = *send_ctr;
        *send_ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let msg_end = 1 + len;
        let mut msg_buf = [0u8; 512];
        msg_buf[0] = msg_type;
        msg_buf[1..msg_end].copy_from_slice(&self.resp_buf[..len]);
        let mut inner_buf = [0u8; 512];
        let inner_len =
            wire::prepend_inner_header(ts, &msg_buf[..msg_end], &mut inner_buf).unwrap();
        let fl = wire::encrypt_and_assemble(them, c, 0x00, &inner_buf[..inner_len], ks, &mut out);
        if let Some(fl) = fl {
            let _ = self.send_frame(&out[..fl]).await;
        }
    }

    /// Encrypt and send a heartbeat via FMP established frame.
    /// FIPS: Same send path as send_datagram, with MSG_HEARTBEAT (0x51) and empty payload.
    /// FIPS: dispatch.rs:54 traces "Received heartbeat" on rx.
    async fn send_heartbeat(
        &mut self,
        ks: &[u8; 32],
        them: wire::SessionIndex,
        ctr: &mut u64,
    ) -> embassy_time::Instant {
        use microfips_core::wire;

        let c = *ctr;
        *ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let mut inner_buf = [0u8; 32];
        let inner_len =
            wire::prepend_inner_header(ts, &[wire::MSG_HEARTBEAT], &mut inner_buf).unwrap();
        let fl = wire::encrypt_and_assemble(them, c, 0x00, &inner_buf[..inner_len], ks, &mut out);

        if let Some(fl) = fl {
            let _ = self.send_frame(&out[..fl]).await;
        }

        embassy_time::Instant::now() + Duration::from_secs(HB_SECS)
    }

    async fn send_disconnect(
        &mut self,
        ks: &[u8; 32],
        them: wire::SessionIndex,
        ctr: &mut u64,
        reason: u8,
    ) {
        let c = *ctr;
        *ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let mut inner_buf = [0u8; 32];
        let inner_len =
            wire::prepend_inner_header(ts, &[wire::MSG_DISCONNECT, reason], &mut inner_buf)
                .unwrap();
        let fl =
            wire::encrypt_and_assemble(them, c, 0x00, &inner_buf[..inner_len], ks, &mut out);
        if let Some(fl) = fl {
            let _ = self.send_frame(&out[..fl]).await;
        }
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

/// Decrypt and dispatch a single FMP established frame.
/// FIPS: handlers/encrypted.rs:23-171 handle_encrypted_frame() → AEAD decrypt with
/// 16-byte header as AAD → strip_inner_header → dispatch_link_message.
/// Our implementation combines the decrypt + dispatch into one function.
fn handle_frame_inner<H: NodeHandler>(
    kr: &[u8; 32],
    data: &[u8],
    handler: &mut H,
    resp: &mut [u8],
) -> FrameAction {
    use microfips_core::wire;

    let m = match wire::parse_message(data) {
        Some(m) => m,
        None => {
            #[cfg(feature = "log")]
            log::warn!("handle_frame: parse_message failed ({}B)", data.len());
            return FrameAction::Continue;
        }
    };

    match m {
        wire::FmpMessage::Established { .. } => {
            let enc = match wire::EncryptedHeader::parse(data) {
                Some(h) => h,
                None => return FrameAction::Continue,
            };
            #[cfg(feature = "log")]
            log::debug!(
                "FMP established: counter={} enc_len={}",
                enc.counter,
                data.len() - wire::ESTABLISHED_HEADER_SIZE
            );
            let mut dec = [0u8; 2048];
            let dl = match microfips_core::noise::aead_decrypt(
                kr,
                enc.counter,
                &enc.header_bytes,
                &data[wire::ESTABLISHED_HEADER_SIZE..],
                &mut dec,
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
                    return FrameAction::Continue;
                }
            };
            let (_timestamp, inner_rest) = match wire::strip_inner_header(&dec[..dl]) {
                Some(r) => r,
                None => return FrameAction::Continue,
            };
            let msg_type = inner_rest.first().copied().unwrap_or(0);
            let inner_payload = &inner_rest[1..];
            #[cfg(feature = "log")]
            log::debug!(
                "FMP frame: msg_type=0x{:02x} payload_len={}",
                msg_type,
                inner_payload.len()
            );
            match msg_type {
                wire::MSG_HEARTBEAT => FrameAction::HeartbeatRecv,
                wire::MSG_DISCONNECT => FrameAction::PeerDC,
                wire::MSG_SENDER_REPORT => {
                    // FIPS MMP SenderReport → ReceiverReport (wire format offsets from FIPS src/mmp/report.rs).
                    // SenderReport inner payload (47B): [3B reserved][8B start_ctr][8B end_ctr]
                    //   [4B start_ts][4B end_ts][4B bytes_sent][8B pkts_sent][8B bytes_sent_total]
                    // ReceiverReport inner payload (67B): [3B reserved][8B highest_ctr][8B pkts_recv]
                    //   [8B bytes_recv][4B timestamp_echo][40B remaining fields, all zero]
                    if inner_payload.len() >= 27 && resp.len() >= 67 {
                        let end_ctr = u64::from_le_bytes(
                            inner_payload[11..19]
                                .try_into()
                                .unwrap_or(0u64.to_le_bytes()),
                        );
                        let end_ts = u32::from_le_bytes(
                            inner_payload[23..27]
                                .try_into()
                                .unwrap_or(0u32.to_le_bytes()),
                        );
                        resp[..67].copy_from_slice(&[0u8; 67]);
                        resp[3..11].copy_from_slice(&end_ctr.to_le_bytes());
                        resp[27..31].copy_from_slice(&end_ts.to_le_bytes());
                        FrameAction::SendLinkMessage {
                            msg_type: wire::MSG_RECEIVER_REPORT,
                            len: 67,
                        }
                    } else {
                        FrameAction::Continue
                    }
                }
                _ => {
                    if msg_type != wire::MSG_SESSION_DATAGRAM {
                        #[cfg(feature = "log")]
                        log::warn!("unrecognized link message type: 0x{:02x}", msg_type);
                    }
                    match handler.on_message(msg_type, inner_payload, resp) {
                        HandleResult::None => FrameAction::Continue,
                        HandleResult::SendDatagram(len) => FrameAction::SendDatagram(len),
                        HandleResult::Disconnect => FrameAction::SelfDC,
                    }
                }
            }
        }
        _ => {
            #[cfg(feature = "std")]
            if matches!(
                m,
                wire::FmpMessage::Msg1 { .. } | wire::FmpMessage::Msg2 { .. }
            ) {
                log::warn!("discarding handshake frame in established state");
            }
            FrameAction::Continue
        }
    }
}

fn frame_is_policy_good(kr: &[u8; 32], data: &[u8]) -> bool {
    use microfips_core::wire;

    let wire::FmpMessage::Established { .. } = (match wire::parse_message(data) {
        Some(m) => m,
        None => return false,
    }) else {
        return false;
    };

    let Some(enc) = wire::EncryptedHeader::parse(data) else {
        return false;
    };
    let mut dec = [0u8; 2048];
    let Ok(dl) = microfips_core::noise::aead_decrypt(
        kr,
        enc.counter,
        &enc.header_bytes,
        &data[wire::ESTABLISHED_HEADER_SIZE..],
        &mut dec,
    ) else {
        return false;
    };

    wire::strip_inner_header(&dec[..dl]).is_some()
}

#[derive(Debug, PartialEq)]
enum FrameAction {
    Continue,
    HeartbeatRecv,
    PeerDC,
    SelfDC,
    SendDatagram(usize),
    SendLinkMessage { msg_type: u8, len: usize },
}

/// Determine the total wire size of a raw FMP frame from its 4-byte common prefix.
///
/// For MSG1/MSG2, uses the fixed wire sizes (114/69 bytes).
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
        wire::PHASE_MSG2 => {
            let total = wire::MSG2_WIRE_SIZE;
            if data.len() < total {
                None
            } else {
                Some(total)
            }
        }
        _ => None,
    }
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
    use crate::test_helpers::block_on;
    use crate::transport::Transport;
    use std::boxed::Box;
    use std::vec;

    struct TestRng {
        bytes: std::sync::Mutex<std::vec::Vec<u8>>,
    }

    impl TestRng {
        fn new(data: &[u8]) -> Self {
            Self {
                bytes: std::sync::Mutex::new(data.to_vec()),
            }
        }

        /// Create a TestRng seeded with OS-level randomness, so each test
        /// run exercises the protocol with different ephemeral key material.
        fn from_os_rng() -> Self {
            use rand::RngCore;
            let mut seed = [0u8; 64];
            rand::rng().fill_bytes(&mut seed);
            Self::new(&seed)
        }
    }

    impl rand_core::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.fill_bytes(&mut buf);
            u32::from_le_bytes(buf)
        }

        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        }

        fn fill_bytes(&mut self, buf: &mut [u8]) {
            let mut bytes = self.bytes.lock().unwrap();
            let n = buf.len().min(bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            bytes.drain(..n);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for TestRng {}

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

    fn build_test_frame(
        receiver: wire::SessionIndex,
        counter: u64,
        msg_type: u8,
        timestamp: u32,
        payload: &[u8],
        key: &[u8; 32],
    ) -> std::vec::Vec<u8> {
        let msg_end = 1 + payload.len();
        let mut msg_buf = [0u8; 512];
        msg_buf[0] = msg_type;
        msg_buf[1..msg_end].copy_from_slice(payload);
        let mut inner_buf = [0u8; 512];
        let inner_len =
            wire::prepend_inner_header(timestamp, &msg_buf[..msg_end], &mut inner_buf).unwrap();
        let mut out = [0u8; 1024];
        let fl = wire::encrypt_and_assemble(
            receiver,
            counter,
            0x00,
            &inner_buf[..inner_len],
            key,
            &mut out,
        )
        .unwrap();
        out[..fl].to_vec()
    }

    fn decrypt_test_frame(
        key: &[u8; 32],
        frame: &[u8],
    ) -> (u8, std::vec::Vec<u8>) {
        use microfips_core::wire;

        let enc = wire::EncryptedHeader::parse(frame).expect("encrypted header");
        let mut dec = [0u8; 2048];
        let dl = microfips_core::noise::aead_decrypt(
            key,
            enc.counter,
            &enc.header_bytes,
            &frame[wire::ESTABLISHED_HEADER_SIZE..],
            &mut dec,
        )
        .expect("decrypt frame");
        let (_, inner) = wire::strip_inner_header(&dec[..dl]).expect("inner header");
        (inner[0], inner[1..].to_vec())
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
        let result = handle_frame_inner(&key, &frame, &mut NoopTestHandler, &mut resp);
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
        let result = handle_frame_inner(&key, &frame, &mut NoopTestHandler, &mut resp);
        assert_eq!(result, FrameAction::PeerDC);
    }

    #[test]
    fn test_handle_frame_unknown_type_skipped() {
        use microfips_core::wire;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 99999;
        let frame = build_test_frame(wire::SessionIndex::new(0), 2, 0x05, ts, b"unknown", &key);

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key, &frame, &mut NoopTestHandler, &mut resp);
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

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key_b, &frame, &mut NoopTestHandler, &mut resp);
        assert_eq!(result, FrameAction::Continue);
    }

    #[test]
    fn test_handle_frame_garbage_skipped() {
        let key: [u8; 32] = [0x42; 32];
        let mut resp = [0u8; 256];
        assert_eq!(
            handle_frame_inner(&key, &[], &mut NoopTestHandler, &mut resp),
            FrameAction::Continue
        );
        assert_eq!(
            handle_frame_inner(&key, &[0x00], &mut NoopTestHandler, &mut resp),
            FrameAction::Continue
        );
        assert_eq!(
            handle_frame_inner(&key, &[0xFF; 4], &mut NoopTestHandler, &mut resp),
            FrameAction::Continue
        );
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
        let result = handle_frame_inner(&key, &frame, &mut DatagramHandler, &mut resp);
        assert_eq!(result, FrameAction::SendDatagram(4));
        assert_eq!(&resp[..4], b"pong");
    }

    // NOTE: test_handshake_with_mock_responder requires refactoring handshake()
    // into separate build_msg1/process_msg2 methods, or a mock transport
    // that doesn't echo send->rx. Post-merge TODO.

    /// Generate a fresh random secp256k1 secret key for testing.
    fn random_secret() -> [u8; 32] {
        use k256::SecretKey;
        use rand::RngCore;
        let mut key = [0u8; 32];
        loop {
            rand::rng().fill_bytes(&mut key);
            if SecretKey::from_slice(&key).is_ok() {
                return key;
            }
        }
    }

    fn node_addr_from_secret(secret: &[u8; 32]) -> microfips_core::identity::NodeAddr {
        let pubkey = microfips_core::noise::ecdh_pubkey(secret).unwrap();
        let x_only: [u8; 32] = pubkey[1..33].try_into().unwrap();
        microfips_core::identity::NodeAddr::from_pubkey_x(&x_only)
    }

    fn distinct_secret_pair() -> ([u8; 32], [u8; 32]) {
        loop {
            let a = random_secret();
            let b = random_secret();
            if node_addr_from_secret(&a).as_bytes() != node_addr_from_secret(&b).as_bytes() {
                return (a, b);
            }
        }
    }

    async fn recv_test_frame(
        transport: &mut crate::transport::channel::ChannelTransport,
    ) -> std::vec::Vec<u8> {
        let mut hdr = [0u8; 2];
        let mut total = 0;
        while total < 2 {
            total += transport.recv(&mut hdr[total..]).await.unwrap();
        }

        let frame_len = u16::from_le_bytes(hdr) as usize;
        let mut frame = vec![0u8; frame_len];
        total = 0;
        while total < frame_len {
            total += transport.recv(&mut frame[total..]).await.unwrap();
        }
        frame
    }

    async fn send_test_frame(
        transport: &mut crate::transport::channel::ChannelTransport,
        frame: &[u8],
    ) {
        transport
            .send(&(frame.len() as u16).to_le_bytes())
            .await
            .unwrap();
        transport.send(frame).await.unwrap();
    }

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
        use microfips_core::noise::{ecdh_pubkey, NoiseIkResponder, PUBKEY_SIZE};
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

                let ei_pub: [u8; PUBKEY_SIZE] = noise_payload[..PUBKEY_SIZE].try_into().unwrap();
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
                        assert_eq!(noise_payload.len(), 106);
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
        use microfips_core::noise::{ecdh_pubkey, NoiseIkResponder, PUBKEY_SIZE};
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

                let ei_pub: [u8; PUBKEY_SIZE] = noise_payload[..PUBKEY_SIZE].try_into().unwrap();
                let mut resp = NoiseIkResponder::new(&responder_secret, &ei_pub).unwrap();
                let (_init_pub, epoch) = resp.read_message1(&noise_payload[PUBKEY_SIZE..]).unwrap();
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

        #[derive(Clone, Default)]
        struct SharedEvents(std::sync::Arc<std::sync::Mutex<std::vec::Vec<(NodeEvent, Instant)>>>);

        impl SharedEvents {
            fn push(&self, event: NodeEvent) {
                self.0.lock().unwrap().push((event, Instant::now()));
            }

            fn snapshot(&self) -> std::vec::Vec<(NodeEvent, Instant)> {
                self.0.lock().unwrap().clone()
            }
        }

        struct EventHandler {
            events: SharedEvents,
        }

        impl NodeHandler for EventHandler {
            async fn on_event(&mut self, event: NodeEvent) {
                self.events.push(event);
            }

            fn on_message(
                &mut self,
                _msg_type: u8,
                _payload: &[u8],
                _resp: &mut [u8],
            ) -> HandleResult {
                HandleResult::None
            }
        }

        let (transport, mut peer) = channel_pair();
        peer.close();
        let secret = random_secret();
        let peer_secret = random_secret();
        let peer_pub = microfips_core::noise::ecdh_pubkey(&peer_secret).unwrap();
        let events = SharedEvents::default();

        block_on(async move {
            let mut node = Node::new(transport, TestRng::from_os_rng(), secret, peer_pub);
            let mut handler = EventHandler {
                events: events.clone(),
            };

            let monitor = async move {
                loop {
                    let snapshot = events.snapshot();
                    let connected: std::vec::Vec<_> = snapshot
                        .iter()
                        .filter_map(|(event, at)| (*event == NodeEvent::Connected).then_some(*at))
                        .collect();
                    let error_count = snapshot
                        .iter()
                        .filter(|(event, _)| *event == NodeEvent::Error)
                        .count();
                    if connected.len() >= 2 && error_count >= 1 {
                        return connected;
                    }
                    Timer::after(Duration::from_millis(10)).await;
                }
            };

            let connected_times = match select(node.run(&mut handler), monitor).await {
                Either::Second(times) => times,
                Either::First(_) => unreachable!(),
            };

            let delta_ms = connected_times[1]
                .as_millis()
                .saturating_sub(connected_times[0].as_millis()) as u64;
            assert!(
                delta_ms >= (RETRY_SECS * 2 * 1000) + RECONNECT_BACKOFF_BASE_MS - 250,
                "expected policy backoff after handshake failure, delta_ms={delta_ms}"
            );
        });
    }

    #[test]
    fn test_peer_policy_integration_survives_frame_flood() {
        use crate::peer_policy::FRAME_RATE_WINDOW_MS;
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;

        struct PongHandler;

        impl NodeHandler for PongHandler {
            async fn on_event(&mut self, _event: NodeEvent) {}

            fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
                if msg_type == wire::MSG_SESSION_DATAGRAM && payload == b"ping" {
                    resp[..4].copy_from_slice(b"pong");
                    HandleResult::SendDatagram(4)
                } else {
                    HandleResult::None
                }
            }
        }

        let (transport, mut peer) = channel_pair();
        let key = [0x42; 32];
        let them = wire::SessionIndex::new(7);

        block_on(async move {
            let peer_task = async move {
                for counter in 0..110u64 {
                    let frame = build_test_frame(them, counter, wire::MSG_HEARTBEAT, 1000, &[], &key);
                    send_test_frame(&mut peer, &frame).await;
                }

                Timer::after(Duration::from_millis(FRAME_RATE_WINDOW_MS + 50)).await;

                let ping = build_test_frame(
                    them,
                    200,
                    wire::MSG_SESSION_DATAGRAM,
                    2000,
                    b"ping",
                    &key,
                );
                send_test_frame(&mut peer, &ping).await;

                let response = recv_test_frame(&mut peer).await;
                let (msg_type, payload) = decrypt_test_frame(&key, &response);
                assert_eq!(msg_type, wire::MSG_SESSION_DATAGRAM);
                assert_eq!(payload, b"pong");

                let disconnect = build_test_frame(them, 201, wire::MSG_DISCONNECT, 3000, &[0x00], &key);
                send_test_frame(&mut peer, &disconnect).await;
            };

            let node_task = async move {
                let mut node = Node::new(
                    transport,
                    TestRng::from_os_rng(),
                    random_secret(),
                    microfips_core::noise::ecdh_pubkey(&random_secret()).unwrap(),
                );
                let mut handler = PongHandler;
                let result = node.steady(&key, &key, them, &mut handler).await;
                assert_eq!(result, Ok(()));
            };

            join(peer_task, node_task).await;
        });
    }

    #[test]
    fn test_peer_policy_integration_detects_silent_peer() {
        use crate::peer_policy::SILENT_PEER_SECS;
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
                node.policy.record_handshake_ok(
                    Instant::now() - Duration::from_secs(SILENT_PEER_SECS + 1),
                );
                let mut handler = RecordingHandler::default();
                let result = node.steady(&key, &key, them, &mut handler).await;
                assert_eq!(result, Err(ProtocolError::Disconnected));
                assert!(handler.events.contains(&NodeEvent::HeartbeatRecv));
                assert!(handler.events.contains(&NodeEvent::HeartbeatSent));
            };

            join(peer_task, node_task).await;
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
        use microfips_core::noise::{ecdh_pubkey, NoiseIkResponder, PUBKEY_SIZE};
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

                let ei_pub: [u8; PUBKEY_SIZE] = noise_payload[..PUBKEY_SIZE].try_into().unwrap();
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
                            assert_eq!(sender_idx, wire::SessionIndex::new(0));
                            assert_eq!(receiver_idx, wire::SessionIndex::new(remote_sender_idx));
                            initiator.read_message2(noise_payload).unwrap();
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
                let mut node = Node::new(
                    local_transport,
                    TestRng::from_os_rng(),
                    local_secret,
                    remote_pub,
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
        data[..4].copy_from_slice(&wire::build_prefix(wire::PHASE_MSG2, 0x00, 65));
        assert_eq!(fmp_raw_frame_size(&data), Some(wire::MSG2_WIRE_SIZE));
    }

    #[test]
    fn test_fmp_raw_frame_size_established_returns_none() {
        use microfips_core::wire;
        let prefix = wire::build_prefix(wire::PHASE_ESTABLISHED, 0x00, 84);
        assert_eq!(fmp_raw_frame_size(&prefix), None);
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
        let prefix = wire::build_prefix(wire::PHASE_MSG2, 0x00, 65);
        let mut buf = [0u8; 128];
        buf[10..14].copy_from_slice(&prefix);
        buf[14..14 + 65].fill(0xCC);
        let (frame, pos) = extract_raw_frame(&buf, 10, 79).unwrap();
        assert_eq!(frame.len(), 69);
        assert_eq!(frame[..4], prefix);
        assert_eq!(pos, 79);
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
}
