use std::boxed::Box;
use std::collections::VecDeque;
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use embassy_time::{Duration, Timer};

use crate::error::ProtocolError;

/// Matcher function type for ExpectSend steps.
type SendMatcher = Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

/// A single step in a scripted sequence.
pub enum Step {
    /// Expect send() to be called with data matching this pattern.
    /// `matcher` receives the sent data and returns Ok(()) if acceptable,
    /// or Err(description) if unexpected.
    ExpectSend(SendMatcher),
    /// Provide data on the next recv() call.
    Recv(Vec<u8>),
    /// Delay before the next recv() returns (simulates network latency).
    DelayMs(u64),
    /// Close the transport — recv() returns Disconnected error.
    Close,
}

/// A transport that follows a pre-programmed script of send/recv steps.
/// Steps are consumed in order. If the script runs out, recv() blocks forever.
pub struct ScriptedTransport {
    steps: VecDeque<Step>,
    sent_data: Vec<Vec<u8>>,
}

impl ScriptedTransport {
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
            sent_data: Vec::new(),
        }
    }

    pub fn recv_bytes(data: &[u8]) -> Self {
        Self::new(vec![Step::Recv(data.to_vec())])
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn sent_data(&self) -> &[Vec<u8>] {
        &self.sent_data
    }

    pub fn into_sent_data(self) -> Vec<Vec<u8>> {
        self.sent_data
    }
}

impl super::Transport for ScriptedTransport {
    type Error = ProtocolError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.sent_data.push(data.to_vec());

        if let Some(Step::ExpectSend(_)) = self.steps.front() {
            let Some(Step::ExpectSend(matcher)) = self.steps.pop_front() else {
                unreachable!();
            };
            matcher(data).map_err(|_| ProtocolError::InvalidMessage)?;
        }

        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            match self.steps.pop_front() {
                Some(Step::Recv(mut data)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        let rest = data.split_off(n);
                        self.steps.push_front(Step::Recv(rest));
                    }
                    return Ok(n);
                }
                Some(Step::DelayMs(ms)) => Timer::after(Duration::from_millis(ms)).await,
                Some(Step::Close) => return Err(ProtocolError::Disconnected),
                Some(step @ Step::ExpectSend(_)) => {
                    self.steps.push_front(step);
                    Timer::after(Duration::from_millis(1)).await;
                }
                None => Timer::after(Duration::from_millis(1)).await,
            }
        }
    }
}

/// High-level builder for scripted protocol scenarios.
#[derive(Default)]
pub struct ScriptedPeer {
    steps: Vec<Step>,
}

impl ScriptedPeer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn expect_send<F>(mut self, matcher: F) -> Self
    where
        F: Fn(&[u8]) -> Result<(), String> + Send + Sync + 'static,
    {
        self.steps.push(Step::ExpectSend(Box::new(matcher)));
        self
    }

    pub fn expect_send_bytes(self, expected: &[u8]) -> Self {
        let expected = expected.to_vec();
        self.expect_send(move |actual| {
            if actual == expected.as_slice() {
                Ok(())
            } else {
                Err(format!(
                    "unexpected send: expected {:?}, got {:?}",
                    expected, actual
                ))
            }
        })
    }

    pub fn expect_frame_send(self, payload: &[u8]) -> Self {
        let header = (payload.len() as u16).to_le_bytes();
        self.expect_send_bytes(&header).expect_send_bytes(payload)
    }

    pub fn recv(mut self, data: &[u8]) -> Self {
        self.steps.push(Step::Recv(data.to_vec()));
        self
    }

    pub fn recv_frame(self, payload: &[u8]) -> Self {
        let mut framed = (payload.len() as u16).to_le_bytes().to_vec();
        framed.extend_from_slice(payload);
        self.recv(&framed)
    }

    pub fn delay_ms(mut self, ms: u64) -> Self {
        self.steps.push(Step::DelayMs(ms));
        self
    }

    pub fn close(mut self) -> Self {
        self.steps.push(Step::Close);
        self
    }

    pub fn build(self) -> ScriptedTransport {
        ScriptedTransport::new(self.steps)
    }
}

#[cfg(test)]
mod tests {
    use super::{ScriptedPeer, ScriptedTransport, Step};
    use crate::error::ProtocolError;
    use crate::node::{HandleResult, Node, NodeEvent, NodeHandler, NodeTiming};
    use crate::test_helpers::block_on;
    use crate::transport::{CryptoRng, RngCore, Transport};
    use embassy_futures::select::{select, Either};
    use embassy_time::{Duration, Timer};
    use microfips_core::noise::{ecdh_pubkey, NoiseIkInitiator, NoiseIkResponder, PUBKEY_SIZE};
    use microfips_core::wire;
    use rand::RngCore as _;
    use rand::SeedableRng;
    use std::boxed::Box;
    use std::sync::{Arc, Mutex};
    use std::time::Instant as StdInstant;
    use std::vec;
    use std::vec::Vec;

    struct TestRng {
        inner: rand::rngs::StdRng,
    }

    impl TestRng {
        fn new(seed: [u8; 32]) -> Self {
            Self {
                inner: rand::rngs::StdRng::from_seed(seed),
            }
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.inner.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.inner.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.inner.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    #[derive(Clone, Default)]
    struct RecordingHandler {
        events: Arc<Mutex<Vec<NodeEvent>>>,
    }

    impl RecordingHandler {
        fn new() -> Self {
            Self::default()
        }

        #[allow(dead_code)]
        fn events(&self) -> Vec<NodeEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    impl NodeHandler for RecordingHandler {
        async fn on_event(&mut self, event: NodeEvent) {
            self.events.lock().unwrap().push(event);
        }

        fn on_message(&mut self, _msg_type: u8, _payload: &[u8], _resp: &mut [u8]) -> HandleResult {
            HandleResult::None
        }
    }

    struct HandshakeFixture {
        msg1: Vec<u8>,
        msg2: Vec<u8>,
        initiator_ks: [u8; 32],
        initiator_kr: [u8; 32],
        responder_sender_idx: wire::SessionIndex,
    }

    fn deterministic_secret(last: u8) -> [u8; 32] {
        let mut secret = [0u8; 32];
        secret[31] = last;
        secret
    }

    fn generate_valid_eph<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
        loop {
            let mut eph = [0u8; 32];
            rng.fill_bytes(&mut eph);
            if ecdh_pubkey(&eph).is_ok() {
                return eph;
            }
        }
    }

    fn allocate_session_index<R: RngCore>(rng: &mut R) -> wire::SessionIndex {
        loop {
            let idx = rng.next_u32();
            if idx != 0 {
                return wire::SessionIndex::new(idx);
            }
        }
    }

    fn build_handshake_fixture(
        seed: [u8; 32],
        initiator_secret: [u8; 32],
        responder_secret: [u8; 32],
        epoch: [u8; 8],
    ) -> HandshakeFixture {
        let initiator_pub = ecdh_pubkey(&initiator_secret).unwrap();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let mut rng = TestRng::new(seed);

        let initiator_eph = generate_valid_eph(&mut rng);
        let (mut initiator, _) =
            NoiseIkInitiator::new(&initiator_eph, &initiator_secret, &responder_pub).unwrap();

        let mut msg1_noise = [0u8; 256];
        let msg1_noise_len = initiator
            .write_message1(&initiator_pub, &epoch, &mut msg1_noise)
            .unwrap();

        let initiator_sender_idx = allocate_session_index(&mut rng);
        let mut msg1 = [0u8; 256];
        let msg1_len = wire::build_msg1(
            initiator_sender_idx,
            &msg1_noise[..msg1_noise_len],
            &mut msg1,
        )
        .unwrap();

        let wire::FmpMessage::Msg1 { noise_payload, .. } =
            wire::parse_message(&msg1[..msg1_len]).unwrap()
        else {
            unreachable!();
        };

        let ei_pub: [u8; PUBKEY_SIZE] = noise_payload[..PUBKEY_SIZE].try_into().unwrap();
        let mut responder = NoiseIkResponder::new(&responder_secret, &ei_pub).unwrap();
        let (_init_pub, parsed_epoch) = responder
            .read_message1(&noise_payload[PUBKEY_SIZE..])
            .unwrap();
        assert_eq!(parsed_epoch, epoch);

        let responder_eph = generate_valid_eph(&mut rng);
        let mut msg2_noise = [0u8; 128];
        let msg2_noise_len = responder
            .write_message2(&responder_eph, &epoch, &mut msg2_noise)
            .unwrap();

        let responder_sender_idx = wire::SessionIndex::new(0xCAFE_0001);
        let mut msg2 = [0u8; 256];
        let msg2_len = wire::build_msg2(
            responder_sender_idx,
            initiator_sender_idx,
            &msg2_noise[..msg2_noise_len],
            &mut msg2,
        )
        .unwrap();

        let mut verify_initiator = initiator.clone();
        verify_initiator
            .read_message2(&msg2_noise[..msg2_noise_len])
            .unwrap();
        let (initiator_ks, initiator_kr) = verify_initiator.finalize();
        let (responder_kr, responder_ks) = responder.finalize();
        assert_eq!(initiator_ks, responder_kr);
        assert_eq!(initiator_kr, responder_ks);

        HandshakeFixture {
            msg1: msg1[..msg1_len].to_vec(),
            msg2: msg2[..msg2_len].to_vec(),
            initiator_ks,
            initiator_kr,
            responder_sender_idx,
        }
    }

    fn build_established_frame(
        sender_idx: wire::SessionIndex,
        counter: u64,
        msg_type: u8,
        payload: &[u8],
        key: &[u8; 32],
    ) -> Vec<u8> {
        let timestamp = embassy_time::Instant::now().as_millis() as u32;
        let mut inner = [0u8; 256];
        let mut out = [0u8; 256];
        let mut msg = vec![msg_type];
        msg.extend_from_slice(payload);
        let inner_len = wire::prepend_inner_header(timestamp, &msg, &mut inner).unwrap();
        let out_len = wire::encrypt_and_assemble(
            sender_idx,
            counter,
            0x00,
            &inner[..inner_len],
            key,
            &mut out,
        )
        .unwrap();
        out[..out_len].to_vec()
    }

    fn success_timing() -> NodeTiming {
        NodeTiming {
            heartbeat_interval_secs: 1,
            link_dead_timeout_secs: 5,
            retry_base_interval_secs: 60,
            retry_max_backoff_secs: 60,
            handshake_resend_interval_ms: 10,
            handshake_resend_backoff: 1,
            handshake_max_resends: 1,
            connect_delay_ms: 0,
        }
    }

    fn timeout_timing() -> NodeTiming {
        NodeTiming {
            handshake_resend_interval_ms: 5,
            handshake_resend_backoff: 1,
            handshake_max_resends: 1,
            connect_delay_ms: 0,
            ..success_timing()
        }
    }

    async fn wait_for_events<F>(events: Arc<Mutex<Vec<NodeEvent>>>, predicate: F)
    where
        F: Fn(&[NodeEvent]) -> bool,
    {
        loop {
            if predicate(&events.lock().unwrap()) {
                return;
            }
            Timer::after(Duration::from_millis(1)).await;
        }
    }

    #[test]
    fn test_scripted_recv_returns_data() {
        let mut transport = ScriptedTransport::recv_bytes(&[1, 2, 3]);

        block_on(async move {
            let mut buf = [0u8; 8];
            let n = transport.recv(&mut buf).await.unwrap();
            assert_eq!(n, 3);
            assert_eq!(&buf[..n], &[1, 2, 3]);
        });
    }

    #[test]
    fn test_scripted_send_captures_data() {
        let mut transport = ScriptedTransport::empty();

        block_on(async move {
            transport.send(&[9, 8, 7]).await.unwrap();
            assert_eq!(transport.sent_data(), &[vec![9, 8, 7]]);
        });
    }

    #[test]
    fn test_scripted_close_returns_error() {
        let mut transport = ScriptedTransport::new(vec![Step::Close]);

        block_on(async move {
            let mut buf = [0u8; 8];
            assert_eq!(
                transport.recv(&mut buf).await,
                Err(ProtocolError::Disconnected)
            );
        });
    }

    #[test]
    fn test_scripted_multiple_steps() {
        let mut transport = ScriptedTransport::new(vec![
            Step::Recv(vec![1, 2]),
            Step::ExpectSend(Box::new(|data| {
                if data == [3, 4] {
                    Ok(())
                } else {
                    Err("unexpected send".into())
                }
            })),
            Step::Recv(vec![5, 6]),
        ]);

        block_on(async move {
            let mut buf = [0u8; 8];
            let n1 = transport.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n1], &[1, 2]);
            transport.send(&[3, 4]).await.unwrap();
            let n2 = transport.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n2], &[5, 6]);
            assert_eq!(transport.sent_data(), &[vec![3, 4]]);
        });
    }

    #[test]
    fn test_scripted_delay() {
        let mut transport = ScriptedTransport::new(vec![Step::DelayMs(10), Step::Recv(vec![0xAA])]);

        block_on(async move {
            let started = StdInstant::now();
            let mut buf = [0u8; 4];
            let n = transport.recv(&mut buf).await.unwrap();
            assert_eq!(n, 1);
            assert_eq!(buf[0], 0xAA);
            assert!(started.elapsed() >= std::time::Duration::from_millis(10));
        });
    }

    #[test]
    fn test_scripted_peer_successful_handshake() {
        let initiator_secret = deterministic_secret(1);
        let responder_secret = deterministic_secret(2);
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let seed = [0x11; 32];
        let fixture =
            build_handshake_fixture(seed, initiator_secret, responder_secret, 1u64.to_le_bytes());

        let transport = ScriptedPeer::new()
            .expect_frame_send(&fixture.msg1)
            .recv_frame(&fixture.msg2)
            .close()
            .build();

        let mut node = Node::with_timing(
            transport,
            TestRng::new(seed),
            initiator_secret,
            responder_pub,
            success_timing(),
        );
        let mut handler = RecordingHandler::new();
        let events = handler.events.clone();

        block_on(async move {
            let outcome = select(
                node.run(&mut handler),
                wait_for_events(events.clone(), |seen| {
                    seen.contains(&NodeEvent::HandshakeOk)
                        && seen.contains(&NodeEvent::Disconnected)
                }),
            )
            .await;
            assert!(matches!(outcome, Either::Second(())));

            let seen = events.lock().unwrap().clone();
            assert!(seen.contains(&NodeEvent::Connected));
            assert!(seen.contains(&NodeEvent::Msg1Sent));
            assert!(seen.contains(&NodeEvent::HandshakeOk));
            assert!(seen.contains(&NodeEvent::Disconnected));
        });
    }

    #[test]
    fn test_scripted_peer_heartbeat_exchange() {
        let initiator_secret = deterministic_secret(3);
        let responder_secret = deterministic_secret(4);
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let seed = [0x22; 32];
        let fixture =
            build_handshake_fixture(seed, initiator_secret, responder_secret, 1u64.to_le_bytes());
        let peer_heartbeat = build_established_frame(
            fixture.responder_sender_idx,
            0,
            wire::MSG_HEARTBEAT,
            &[],
            &fixture.initiator_kr,
        );
        let node_heartbeat = build_established_frame(
            fixture.responder_sender_idx,
            0,
            wire::MSG_HEARTBEAT,
            &[],
            &fixture.initiator_ks,
        );

        let transport = ScriptedPeer::new()
            .expect_frame_send(&fixture.msg1)
            .recv_frame(&fixture.msg2)
            .recv_frame(&peer_heartbeat)
            .expect_frame_send(&node_heartbeat)
            .close()
            .build();

        let mut node = Node::with_timing(
            transport,
            TestRng::new(seed),
            initiator_secret,
            responder_pub,
            success_timing(),
        );
        let mut handler = RecordingHandler::new();
        let events = handler.events.clone();

        block_on(async move {
            let outcome = select(
                node.run(&mut handler),
                wait_for_events(events.clone(), |seen| {
                    seen.contains(&NodeEvent::HandshakeOk)
                        && seen.contains(&NodeEvent::HeartbeatRecv)
                        && seen.contains(&NodeEvent::HeartbeatSent)
                }),
            )
            .await;
            assert!(matches!(outcome, Either::Second(())));

            let seen = events.lock().unwrap().clone();
            assert!(seen.contains(&NodeEvent::HeartbeatRecv));
            assert!(seen.contains(&NodeEvent::HeartbeatSent));
        });
    }

    #[test]
    fn test_scripted_peer_timeout_handling() {
        let initiator_secret = deterministic_secret(5);
        let responder_secret = deterministic_secret(6);
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let seed = [0x33; 32];
        let fixture =
            build_handshake_fixture(seed, initiator_secret, responder_secret, 1u64.to_le_bytes());

        let transport = ScriptedPeer::new()
            .expect_frame_send(&fixture.msg1)
            .expect_frame_send(&fixture.msg1)
            .build();

        let mut node = Node::with_timing(
            transport,
            TestRng::new(seed),
            initiator_secret,
            responder_pub,
            timeout_timing(),
        );
        let mut handler = RecordingHandler::new();
        let events = handler.events.clone();

        block_on(async move {
            let outcome = select(
                node.run(&mut handler),
                wait_for_events(events.clone(), |seen| seen.contains(&NodeEvent::Error)),
            )
            .await;
            assert!(matches!(outcome, Either::Second(())));

            let seen = events.lock().unwrap().clone();
            assert!(seen.contains(&NodeEvent::Connected));
            assert!(seen.contains(&NodeEvent::Msg1Sent));
            assert!(seen.contains(&NodeEvent::Error));
        });
    }
}
