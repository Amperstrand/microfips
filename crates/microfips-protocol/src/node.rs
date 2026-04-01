use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use crate::error::ProtocolError;
use crate::framing;
use crate::transport::{CryptoRng, RngCore, Transport};

pub const HB_SECS: u64 = 10;
pub const RECV_TIMEOUT_MS: u64 = 30_000;
pub const RETRY_SECS: u64 = 3;
pub const CONNECT_DELAY_MS: u64 = 500;

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
    secret: [u8; 32],
    peer_pub: [u8; 33],
    rbuf: [u8; 2048],
    rpos: usize,
    rlen: usize,
    resp_buf: [u8; 256],
    raw_framing: bool,
}

impl<T: Transport, R: RngCore + CryptoRng> Node<T, R> {
    pub fn new(transport: T, rng: R, secret: [u8; 32], peer_pub: [u8; 33]) -> Self {
        Self {
            transport,
            rng,
            secret,
            peer_pub,
            rbuf: [0u8; 2048],
            rpos: 0,
            rlen: 0,
            resp_buf: [0u8; 256],
            raw_framing: false,
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

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub async fn run<H: NodeHandler>(&mut self, handler: &mut H) -> ! {
        loop {
            let _ = self.session(handler).await;
            Timer::after(Duration::from_secs(RETRY_SECS)).await;
        }
    }

    async fn session<H: NodeHandler>(&mut self, handler: &mut H) -> Result<(), ProtocolError> {
        self.transport
            .wait_ready()
            .await
            .map_err(|_| ProtocolError::Disconnected)?;
        Timer::after(Duration::from_millis(CONNECT_DELAY_MS)).await;
        handler.on_event(NodeEvent::Connected).await;

        self.rpos = 0;
        self.rlen = 0;

        match self.handshake(handler).await {
            Ok((ks, kr, them)) => {
                handler.on_event(NodeEvent::HandshakeOk).await;
                let result = self.steady(&ks, &kr, them, handler).await;
                handler.on_event(NodeEvent::Disconnected).await;
                result
            }
            Err(e) => {
                handler.on_event(NodeEvent::Error).await;
                Err(e)
            }
        }
    }

    async fn handshake<H: NodeHandler>(
        &mut self,
        handler: &mut H,
    ) -> Result<([u8; 32], [u8; 32], u32), ProtocolError> {
        use microfips_core::fmp;
        use microfips_core::noise;

        let my_pub = noise::ecdh_pubkey(&self.secret).unwrap();

        let mut eph = [0u8; 32];
        self.rng.fill_bytes(&mut eph);
        let (mut noise_st, _e_pub) =
            noise::NoiseIkInitiator::new(&eph, &self.secret, &self.peer_pub).expect("noise init");

        let epoch: [u8; noise::EPOCH_SIZE] = [0x01, 0, 0, 0, 0, 0, 0, 0];

        let mut n1 = [0u8; 256];
        let n1len = noise_st
            .write_message1(&my_pub, &epoch, &mut n1)
            .expect("write_message1");

        let mut f1 = [0u8; 256];
        let f1len = fmp::build_msg1(0, &n1[..n1len], &mut f1).unwrap();

        self.send_frame(&f1[..f1len]).await?;
        handler.on_event(NodeEvent::Msg1Sent).await;

        let mut mb = [0u8; 2048];
        loop {
            let ml = self.recv_frame(&mut mb, RECV_TIMEOUT_MS as u32).await?;
            let m = fmp::parse_message(&mb[..ml]).ok_or(ProtocolError::InvalidMessage)?;
            match m {
                fmp::FmpMessage::Msg2 {
                    sender_idx,
                    noise_payload,
                    ..
                } => {
                    let mut st = noise_st.clone();
                    st.read_message2(noise_payload)?;
                    let (ks, kr) = st.finalize();
                    return Ok((ks, kr, sender_idx));
                }
                _ => continue,
            }
        }
    }

    async fn steady<H: NodeHandler>(
        &mut self,
        ks: &[u8; 32],
        kr: &[u8; 32],
        them: u32,
        handler: &mut H,
    ) -> Result<(), ProtocolError> {
        let mut next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);
        let mut send_ctr: u64 = 0;

        loop {
            let mut rx = [0u8; 256];
            let rx_fut = self.transport.recv(&mut rx);
            let tick = handler.poll_at();
            let deadline = tick.unwrap_or(next_hb).min(next_hb);
            let hb_fut = Timer::at(deadline);

            match select(rx_fut, hb_fut).await {
                Either::First(Ok(n)) => {
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

                        let result =
                            handle_frame_inner(kr, frame_data, handler, &mut self.resp_buf);
                        self.rpos = new_pos;

                        match result {
                            FrameAction::Continue => {}
                            FrameAction::HeartbeatRecv => {
                                handler.on_event(NodeEvent::HeartbeatRecv).await;
                            }
                            FrameAction::PeerDC => return Ok(()),
                            FrameAction::SendDatagram(len) => {
                                self.send_datagram(them, &mut send_ctr, len, ks).await;
                            }
                        }
                    }
                    if self.rpos >= self.rlen {
                        self.rpos = 0;
                        self.rlen = 0;
                    }
                    let now = embassy_time::Instant::now();
                    if now >= next_hb {
                        next_hb = self.send_heartbeat(ks, them, &mut send_ctr).await;
                        handler.on_event(NodeEvent::HeartbeatSent).await;
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
                Either::First(Err(_)) => {
                    return Err(ProtocolError::Disconnected);
                }
                Either::Second(()) => {
                    let now = embassy_time::Instant::now();
                    if now >= next_hb {
                        next_hb = self.send_heartbeat(ks, them, &mut send_ctr).await;
                        handler.on_event(NodeEvent::HeartbeatSent).await;
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
    async fn send_datagram(&mut self, them: u32, send_ctr: &mut u64, len: usize, ks: &[u8; 32]) {
        use microfips_core::fmp;
        let c = *send_ctr;
        *send_ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let fl = fmp::build_established(
            them,
            c,
            fmp::MSG_SESSION_DATAGRAM,
            ts,
            &self.resp_buf[..len],
            ks,
            &mut out,
        );
        if let Some(fl) = fl {
            let _ = self.send_frame(&out[..fl]).await;
        }
    }

    /// Send a heartbeat via FMP established frame.
    /// FIPS: Same send path as send_datagram, with MSG_HEARTBEAT (0x51) and empty payload.
    /// FIPS: dispatch.rs:54 traces "Received heartbeat" on rx.
    async fn send_heartbeat(
        &mut self,
        ks: &[u8; 32],
        them: u32,
        ctr: &mut u64,
    ) -> embassy_time::Instant {
        use microfips_core::fmp;

        let c = *ctr;
        *ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let fl = fmp::build_established(them, c, fmp::MSG_HEARTBEAT, ts, &[], ks, &mut out);

        if let Some(fl) = fl {
            let _ = self.send_frame(&out[..fl]).await;
        }

        embassy_time::Instant::now() + Duration::from_secs(HB_SECS)
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
            let mut rx = [0u8; 256];
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
            let mut rx = [0u8; 256];
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
    use microfips_core::fmp;

    let m = match fmp::parse_message(data) {
        Some(m) => m,
        None => return FrameAction::Continue,
    };

    match m {
        fmp::FmpMessage::Established {
            counter, encrypted, ..
        } => {
            #[cfg(feature = "std")]
            log::debug!(
                "FMP established: counter={} enc_len={}",
                counter,
                encrypted.len()
            );
            let hdr = &data[..fmp::ESTABLISHED_HEADER_SIZE];
            let mut dec = [0u8; 2048];
            let dl =
                match microfips_core::noise::aead_decrypt(kr, counter, hdr, encrypted, &mut dec) {
                    Ok(l) => l,
                    Err(_err) => {
                        #[cfg(feature = "std")]
                        log::debug!(
                            "FMP decrypt failed: counter={} hdr={:02x?} err={:?}",
                            counter,
                            &hdr[..16.min(hdr.len())],
                            _err
                        );
                        return FrameAction::Continue;
                    }
                };
            if dl < fmp::INNER_HEADER_SIZE {
                return FrameAction::Continue;
            }
            let msg_type = dec[4];
            #[cfg(feature = "std")]
            log::debug!(
                "FMP frame: msg_type=0x{:02x} payload_len={}",
                msg_type,
                dl - 5
            );
            match msg_type {
                fmp::MSG_HEARTBEAT => FrameAction::HeartbeatRecv,
                fmp::MSG_DISCONNECT => FrameAction::PeerDC,
                _ => {
                    let payload = &dec[fmp::INNER_HEADER_SIZE..dl];
                    match handler.on_message(msg_type, payload, resp) {
                        HandleResult::None => FrameAction::Continue,
                        HandleResult::SendDatagram(len) => FrameAction::SendDatagram(len),
                        HandleResult::Disconnect => FrameAction::PeerDC,
                    }
                }
            }
        }
        _ => FrameAction::Continue,
    }
}

#[derive(Debug, PartialEq)]
enum FrameAction {
    Continue,
    HeartbeatRecv,
    PeerDC,
    SendDatagram(usize),
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
    use microfips_core::fmp;

    let (phase, _flags, _payload_len) = fmp::parse_prefix(data)?;

    match phase {
        fmp::PHASE_MSG1 => {
            let total = fmp::MSG1_WIRE_SIZE;
            if data.len() < total {
                None
            } else {
                Some(total)
            }
        }
        fmp::PHASE_MSG2 => {
            let total = fmp::MSG2_WIRE_SIZE;
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
    use microfips_core::fmp;

    let avail = len - pos;
    if avail < fmp::COMMON_PREFIX_SIZE {
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
            let (phase, _flags, _pl) = fmp::parse_prefix(&buf[pos..len])?;
            match phase {
                fmp::PHASE_ESTABLISHED => {
                    if avail < fmp::ESTABLISHED_HEADER_SIZE + microfips_core::noise::TAG_SIZE {
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
    use std::sync::LazyLock;
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

    fn inner() -> &'static crate::transport::mock::MockTransportInner {
        static INNER: LazyLock<crate::transport::mock::MockTransportInner> =
            LazyLock::new(crate::transport::mock::MockTransportInner::new);
        &INNER
    }

    fn fresh_inner() -> &'static crate::transport::mock::MockTransportInner {
        let r = inner();
        r.reset();
        r
    }

    #[test]
    fn test_send_frame_works() {
        let transport = crate::transport::mock::MockTransport::new(fresh_inner());

        block_on(async {
            let mut node = Node::new(transport, TestRng::new(&[0u8; 32]), [0u8; 32], [0u8; 33]);
            node.send_frame(b"hello").await.unwrap();

            let tx = inner().tx.lock().unwrap();
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
        fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner());

        block_on(async {
            let mut node = Node::new(transport, TestRng::new(&[0u8; 32]), [0u8; 32], [0u8; 33]);

            let frame: std::vec::Vec<u8> = {
                let mut v = (3u16).to_le_bytes().to_vec();
                v.extend_from_slice(b"abc");
                v
            };
            inner().rx.lock().unwrap().extend_from_slice(&frame);

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

    #[test]
    fn test_handle_frame_heartbeat() {
        use microfips_core::fmp;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 12345;
        let mut out = [0u8; 256];
        let fl = fmp::build_established(0, 0, fmp::MSG_HEARTBEAT, ts, &[], &key, &mut out).unwrap();

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key, &out[..fl], &mut NoopTestHandler, &mut resp);
        assert_eq!(result, FrameAction::HeartbeatRecv);
    }

    #[test]
    fn test_handle_frame_disconnect() {
        use microfips_core::fmp;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 54321;
        let mut out = [0u8; 256];
        let fl =
            fmp::build_established(0, 1, fmp::MSG_DISCONNECT, ts, &[], &key, &mut out).unwrap();

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key, &out[..fl], &mut NoopTestHandler, &mut resp);
        assert_eq!(result, FrameAction::PeerDC);
    }

    #[test]
    fn test_handle_frame_unknown_type_skipped() {
        use microfips_core::fmp;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 99999;
        let mut out = [0u8; 256];
        let fl = fmp::build_established(0, 2, 0x05, ts, b"unknown", &key, &mut out).unwrap();

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key, &out[..fl], &mut NoopTestHandler, &mut resp);
        assert_eq!(result, FrameAction::Continue);
    }

    #[test]
    fn test_handle_frame_wrong_key_skipped() {
        use microfips_core::fmp;

        let key_a: [u8; 32] = [0x42; 32];
        let key_b: [u8; 32] = [0x99; 32];
        let mut out = [0u8; 256];
        let fl =
            fmp::build_established(0, 0, fmp::MSG_HEARTBEAT, 100, &[], &key_a, &mut out).unwrap();

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key_b, &out[..fl], &mut NoopTestHandler, &mut resp);
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
        use microfips_core::fmp;

        struct DatagramHandler;
        impl NodeHandler for DatagramHandler {
            async fn on_event(&mut self, _event: NodeEvent) {}
            fn on_message(
                &mut self,
                msg_type: u8,
                payload: &[u8],
                resp: &mut [u8],
            ) -> HandleResult {
                if msg_type == fmp::MSG_SESSION_DATAGRAM && payload == b"ping" {
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
        let mut out = [0u8; 256];
        let fl =
            fmp::build_established(0, 5, fmp::MSG_SESSION_DATAGRAM, ts, b"ping", &key, &mut out)
                .unwrap();

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key, &out[..fl], &mut DatagramHandler, &mut resp);
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

    #[test]
    fn test_handshake_with_responder() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::fmp;
        use microfips_core::noise::{ecdh_pubkey, NoiseIkResponder, PUBKEY_SIZE};

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

                let msg = fmp::parse_message(&buf[..msg1_len]).unwrap();
                let noise_payload = match msg {
                    fmp::FmpMessage::Msg1 { noise_payload, .. } => noise_payload,
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
                let msg2_len =
                    fmp::build_msg2(1, 0, &msg2_noise[..msg2_noise_len], &mut msg2_buf).unwrap();

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
                let result = node.handshake(&mut handler).await;
                assert!(result.is_ok(), "handshake should succeed");
                let (ks, kr, them) = result.unwrap();
                assert_eq!(them, 1, "responder sender_idx should be 1");
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
        use microfips_core::fmp;
        use microfips_core::noise::ecdh_pubkey;

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
                    fmp::MSG1_WIRE_SIZE,
                    "MSG1 should be 114 bytes on wire"
                );
                let mut buf = [0u8; 256];
                total = 0;
                while total < msg1_len {
                    total += resp_transport.recv(&mut buf[total..]).await.unwrap();
                }
                let msg = fmp::parse_message(&buf[..msg1_len]).unwrap();
                match msg {
                    fmp::FmpMessage::Msg1 {
                        sender_idx,
                        noise_payload,
                        ..
                    } => {
                        assert_eq!(sender_idx, 0, "initiator sender_idx should be 0");
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
                let _ = node.handshake(&mut handler).await;
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
            let result = node.handshake(&mut handler).await;
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
        use microfips_core::fmp;
        use microfips_core::noise::{ecdh_pubkey, NoiseIkResponder, PUBKEY_SIZE};

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

                let msg = fmp::parse_message(&buf[..msg1_len]).unwrap();
                let noise_payload = match msg {
                    fmp::FmpMessage::Msg1 { noise_payload, .. } => noise_payload,
                    _ => panic!("expected Msg1"),
                };

                let ei_pub: [u8; PUBKEY_SIZE] = noise_payload[..PUBKEY_SIZE].try_into().unwrap();
                let mut resp = NoiseIkResponder::new(&responder_secret, &ei_pub).unwrap();
                let (_init_pub, epoch) = resp.read_message1(&noise_payload[PUBKEY_SIZE..]).unwrap();

                let resp_eph = random_secret();
                let mut msg2_noise = [0u8; 128];
                let msg2_noise_len = resp
                    .write_message2(&resp_eph, &epoch, &mut msg2_noise)
                    .unwrap();

                let mut msg2_buf = [0u8; 256];
                let msg2_len =
                    fmp::build_msg2(1, 0, &msg2_noise[..msg2_noise_len], &mut msg2_buf).unwrap();
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

    // --- Tests for fmp_raw_frame_size ---

    #[test]
    fn test_fmp_raw_frame_size_valid_msg1() {
        use microfips_core::fmp;
        let mut data = [0u8; fmp::MSG1_WIRE_SIZE];
        data[..4].copy_from_slice(&fmp::build_prefix(fmp::PHASE_MSG1, 0x00, 110));
        assert_eq!(fmp_raw_frame_size(&data), Some(fmp::MSG1_WIRE_SIZE));
    }

    #[test]
    fn test_fmp_raw_frame_size_valid_msg2() {
        use microfips_core::fmp;
        let mut data = [0u8; fmp::MSG2_WIRE_SIZE];
        data[..4].copy_from_slice(&fmp::build_prefix(fmp::PHASE_MSG2, 0x00, 65));
        assert_eq!(fmp_raw_frame_size(&data), Some(fmp::MSG2_WIRE_SIZE));
    }

    #[test]
    fn test_fmp_raw_frame_size_established_returns_none() {
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_ESTABLISHED, 0x00, 84);
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
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_MSG1, 0x00, 0);
        assert_eq!(fmp_raw_frame_size(&prefix), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_zero_payload_established() {
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_ESTABLISHED, 0x00, 0);
        assert_eq!(fmp_raw_frame_size(&prefix), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_bad_version() {
        let data = [0x50, 0x00, 0x00, 0x00];
        assert_eq!(fmp_raw_frame_size(&data), None);
    }

    #[test]
    fn test_fmp_raw_frame_size_msg1_needs_full_data() {
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_MSG1, 0x00, 110);
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
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_ESTABLISHED, 0x00, 10);
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
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_ESTABLISHED, 0x00, 10);
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
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_MSG2, 0x00, 65);
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
        use microfips_core::fmp;
        let prefix = fmp::build_prefix(fmp::PHASE_MSG2, 0x00, 65);
        let mut buf = [0u8; 32];
        buf[..4].copy_from_slice(&prefix);
        buf[4..].fill(0xCC);
        assert_eq!(extract_raw_frame(&buf, 0, 32), None);
    }
}
