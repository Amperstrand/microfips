use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};

use crate::error::ProtocolError;
use crate::framing;
use crate::transport::{CryptoRng, Transport};

pub const HB_SECS: u64 = 10;
pub const RECV_TIMEOUT_MS: u64 = 30_000;
pub const RETRY_SECS: u64 = 3;
pub const CONNECT_DELAY_MS: u64 = 500;

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
}

/// No-op handler that ignores all events and messages.
pub struct NoopHandler;

impl NodeHandler for NoopHandler {
    async fn on_event(&mut self, _event: NodeEvent) {}

    fn on_message(&mut self, _msg_type: u8, _payload: &[u8], _resp: &mut [u8]) -> HandleResult {
        HandleResult::None
    }
}

pub struct Node<T: Transport, R: CryptoRng> {
    transport: T,
    rng: R,
    secret: [u8; 32],
    peer_pub: [u8; 33],
    rbuf: [u8; 2048],
    rpos: usize,
    rlen: usize,
    resp_buf: [u8; 256],
}

impl<T: Transport, R: CryptoRng> Node<T, R> {
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
        }
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
        let f1len = fmp::build_msg1(0, &n1[..n1len], &mut f1);

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
                    st.read_message2(noise_payload)
                        .map_err(|_| ProtocolError::DecryptFailed)?;
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
            let hb_fut = Timer::at(next_hb);

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
                        if self.rlen - self.rpos < 2 {
                            break;
                        }
                        let ml =
                            u16::from_le_bytes([self.rbuf[self.rpos], self.rbuf[self.rpos + 1]])
                                as usize;
                        if ml == 0 || ml > framing::MAX_FRAME {
                            self.rpos = self.rlen;
                            break;
                        }
                        if self.rlen - self.rpos - 2 < ml {
                            break;
                        }
                        let s = self.rpos + 2;
                        let e = s + ml;

                        let result =
                            handle_frame_inner(kr, &self.rbuf[s..e], handler, &mut self.resp_buf);
                        self.rpos = e;

                        match result {
                            FrameAction::Continue => {}
                            FrameAction::HeartbeatRecv => {
                                handler.on_event(NodeEvent::HeartbeatRecv).await;
                            }
                            FrameAction::PeerDC => return Ok(()),
                            FrameAction::SendDatagram(len) => {
                                use microfips_core::fmp;
                                let c = send_ctr;
                                send_ctr += 1;
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
                                let _ = self.send_frame(&out[..fl]).await;
                            }
                        }
                    }
                    if self.rpos >= self.rlen {
                        self.rpos = 0;
                        self.rlen = 0;
                    }
                    if embassy_time::Instant::now() >= next_hb {
                        next_hb = self.send_heartbeat(ks, them, &mut send_ctr).await;
                        handler.on_event(NodeEvent::HeartbeatSent).await;
                    }
                }
                Either::First(Err(_)) => {
                    return Err(ProtocolError::Disconnected);
                }
                Either::Second(()) => {
                    next_hb = self.send_heartbeat(ks, them, &mut send_ctr).await;
                    handler.on_event(NodeEvent::HeartbeatSent).await;
                }
            }
        }
    }

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

        let _ = self.send_frame(&out[..fl]).await;

        embassy_time::Instant::now() + Duration::from_secs(HB_SECS)
    }

    async fn send_frame(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        let hdr = (payload.len() as u16).to_le_bytes();
        self.transport
            .send(&hdr)
            .await
            .map_err(|_| ProtocolError::Disconnected)?;
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
        loop {
            let need_more = if self.rpos < self.rlen {
                if self.rlen - self.rpos < 2 {
                    true
                } else {
                    let ml = u16::from_le_bytes([self.rbuf[self.rpos], self.rbuf[self.rpos + 1]])
                        as usize;
                    if ml == 0 || ml > framing::MAX_FRAME {
                        self.rpos = self.rlen;
                        true
                    } else if self.rlen - self.rpos - 2 < ml {
                        true
                    } else {
                        let s = self.rpos + 2;
                        let e = s + ml;
                        let l = ml.min(out.len());
                        out[..l].copy_from_slice(&self.rbuf[s..s + l]);
                        self.rpos = e;
                        if self.rpos >= self.rlen {
                            self.rpos = 0;
                            self.rlen = 0;
                        }
                        return Ok(l);
                    }
                }
            } else {
                true
            };

            if need_more {
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
}

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
            let hdr = &data[..fmp::ESTABLISHED_HEADER_SIZE];
            let mut dec = [0u8; 2048];
            let dl =
                match microfips_core::noise::aead_decrypt(kr, counter, hdr, encrypted, &mut dec) {
                    Ok(l) => l,
                    Err(_) => return FrameAction::Continue,
                };
            if dl < fmp::INNER_HEADER_SIZE {
                return FrameAction::Continue;
            }
            let msg_type = dec[4];
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

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_executor::Executor;
    use std::sync::LazyLock;

    fn block_on<F: std::future::Future + Send + 'static>(f: F) -> F::Output
    where
        F::Output: Send + 'static,
    {
        use embassy_executor::task;
        use std::boxed::Box;
        use std::sync::{Arc, Mutex};

        let executor: &'static mut Executor = Box::leak(Box::new(Executor::new()));

        let result: Arc<Mutex<Option<F::Output>>> = Arc::new(Mutex::new(None));
        let result_clone = result.clone();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_clone = done.clone();
        let boxed: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
            Box::pin(async move {
                let output = f.await;
                *result_clone.lock().unwrap() = Some(output);
                done_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            });

        #[task(pool_size = 64)]
        async fn run_boxed(fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
            fut.await
        }

        let done_check = done.clone();

        executor.run_until(
            |spawner| {
                spawner.spawn(run_boxed(boxed).unwrap());
            },
            move || done_check.load(std::sync::atomic::Ordering::Relaxed),
        );

        result.lock().unwrap().take().unwrap()
    }

    struct TestRng {
        bytes: std::sync::Mutex<std::vec::Vec<u8>>,
    }

    impl TestRng {
        fn new(data: &[u8]) -> Self {
            Self {
                bytes: std::sync::Mutex::new(data.to_vec()),
            }
        }
    }

    impl CryptoRng for TestRng {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            let mut bytes = self.bytes.lock().unwrap();
            let n = buf.len().min(bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            bytes.drain(..n);
        }
    }

    fn inner() -> &'static crate::transport::mock::MockTransportInner {
        static INNER: LazyLock<crate::transport::mock::MockTransportInner> =
            LazyLock::new(crate::transport::mock::MockTransportInner::new);
        &*INNER
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

    #[test]
    fn test_handle_frame_heartbeat() {
        use microfips_core::fmp;

        let key: [u8; 32] = [0x42; 32];
        let ts: u32 = 12345;
        let mut out = [0u8; 256];
        let fl = fmp::build_established(0, 0, fmp::MSG_HEARTBEAT, ts, &[], &key, &mut out);

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
        let fl = fmp::build_established(0, 1, fmp::MSG_DISCONNECT, ts, &[], &key, &mut out);

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
        let fl = fmp::build_established(0, 2, 0x05, ts, b"unknown", &key, &mut out);

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
        let fl = fmp::build_established(0, 0, fmp::MSG_HEARTBEAT, 100, &[], &key_a, &mut out);

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
            fmp::build_established(0, 5, fmp::MSG_SESSION_DATAGRAM, ts, b"ping", &key, &mut out);

        let mut resp = [0u8; 256];
        let result = handle_frame_inner(&key, &out[..fl], &mut DatagramHandler, &mut resp);
        assert_eq!(result, FrameAction::SendDatagram(4));
        assert_eq!(&resp[..4], b"pong");
    }

    // NOTE: test_handshake_with_mock_responder requires refactoring handshake()
    // into separate build_msg1/process_msg2 methods, or a mock transport
    // that doesn't echo send->rx. Post-merge TODO.

    #[test]
    fn test_handshake_with_responder() {
        use crate::transport::channel::pair as channel_pair;
        use embassy_futures::join::join;
        use microfips_core::fmp;
        use microfips_core::noise::{NoiseIkResponder, PUBKEY_SIZE, ecdh_pubkey};

        let initiator_secret: [u8; 32] = [0x11; 32];
        let responder_secret: [u8; 32] = [0x22; 32];
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
                let mut resp = NoiseIkResponder::new(&responder_secret, &ei_pub);
                let (_init_pub, epoch) = resp.read_message1(&noise_payload[PUBKEY_SIZE..]);

                let resp_eph: [u8; 32] = [0x33; 32];
                let mut msg2_noise = [0u8; 128];
                let msg2_noise_len = resp.write_message2(&resp_eph, &epoch, &mut msg2_noise);

                let mut msg2_buf = [0u8; 256];
                let msg2_len = fmp::build_msg2(1, 0, &msg2_noise[..msg2_noise_len], &mut msg2_buf);

                let frame_hdr = (msg2_len as u16).to_le_bytes();
                resp_transport.send(&frame_hdr).await.unwrap();
                resp_transport.send(&msg2_buf[..msg2_len]).await.unwrap();
            };

            let initiator = async move {
                let mut node = Node::new(
                    init_transport,
                    TestRng::new(&[0x01; 32]),
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

        let initiator_secret: [u8; 32] = [0x11; 32];
        let responder_secret: [u8; 32] = [0x22; 32];
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
                    TestRng::new(&[0x01; 32]),
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
            let mut node = Node::new(
                init_transport,
                TestRng::new(&[0x01; 32]),
                [0x11; 32],
                [0x02; 33],
            );
            let mut handler = NoopTestHandler;
            let result = node.handshake(&mut handler).await;
            assert_eq!(result, Err(ProtocolError::Timeout));
        });
    }
}
