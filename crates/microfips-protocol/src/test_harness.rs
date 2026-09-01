//! Shared test harness for the protocol suite (#186): one `TestRng`, one
//! `HandshakeFixture` (IK/XX cfg-switched), one channel-based `ScriptedPeer`,
//! and the frame builders they share. Consolidated from node.rs's tests module
//! and transport/scripted.rs so protocol scenarios — including future rekey
//! scenarios (#183) — are written exactly once.
//!
//! Naming note: `transport::scripted::ScriptedPeer` (the step-list *builder*)
//! is a different transport-mechanics tool; the one here drives a real `Node`
//! over a channel pair.

use crate::node::MAX_FRAME_SIZE;
use crate::node::{HandleResult, NodeEvent, NodeHandler, NodeTiming};
use crate::transport::{CryptoRng, RngCore, Transport};
use microfips_core::noise::ecdh_pubkey;
use microfips_core::wire;
use rand::SeedableRng;

use std::sync::{Arc, Mutex};
use std::vec::Vec;

use embassy_time::{Duration, Timer};

pub struct TestRng {
    inner: Mutex<rand::rngs::StdRng>,
}

impl TestRng {
    pub fn new(data: &[u8]) -> Self {
        let mut seed = [0u8; 32];
        let copy_len = data.len().min(seed.len());
        seed[..copy_len].copy_from_slice(&data[..copy_len]);
        Self {
            inner: Mutex::new(rand::rngs::StdRng::from_seed(seed)),
        }
    }

    pub fn from_os_rng() -> Self {
        Self {
            inner: Mutex::new(rand::rngs::StdRng::from_os_rng()),
        }
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        use rand::RngCore;
        self.inner.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        use rand::RngCore;
        self.inner.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        use rand::RngCore;
        self.inner.lock().unwrap().fill_bytes(buf)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

#[derive(Clone, Default)]
pub struct RecordingHandler {
    pub events: Arc<Mutex<Vec<NodeEvent>>>,
}

impl RecordingHandler {
    pub fn new() -> Self {
        Self::default()
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

pub fn deterministic_secret(last: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[31] = last;
    secret
}

pub fn generate_valid_eph<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    loop {
        let mut eph = [0u8; 32];
        rng.fill_bytes(&mut eph);
        if ecdh_pubkey(&eph).is_ok() {
            return eph;
        }
    }
}

pub fn allocate_session_index<R: RngCore>(rng: &mut R) -> wire::SessionIndex {
    loop {
        let idx = rng.next_u32();
        if idx != 0 {
            return wire::SessionIndex::new(idx);
        }
    }
}

pub struct HandshakeFixture {
    pub msg1: Vec<u8>,
    pub msg2: Vec<u8>,
    #[cfg(feature = "noise-xx")]
    pub msg3: Vec<u8>,
    pub initiator_ks: [u8; 32],
    pub initiator_kr: [u8; 32],
    pub responder_sender_idx: wire::SessionIndex,
}

#[cfg(not(feature = "noise-xx"))]
pub fn build_handshake_fixture(
    seed: [u8; 32],
    initiator_secret: [u8; 32],
    responder_secret: [u8; 32],
    epoch: [u8; 8],
) -> HandshakeFixture {
    use microfips_core::noise::{NoiseIkInitiator, NoiseIkResponder, PUBKEY_SIZE};

    let initiator_pub = ecdh_pubkey(&initiator_secret).unwrap();
    let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
    let mut rng = TestRng::new(&seed);

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

/// XX variant: mirrors the Node's `handshake_xx` RNG draw order (ephemeral,
/// then sender index) so `msg1` matches the Node byte-for-byte, and derives
/// the `msg3` the Node sends after `msg2`. Do not reorder the draws in
/// `handshake_xx` without mirroring here — the coupling is deliberate and
/// only surfaces as mysteriously failing fixture tests.
#[cfg(feature = "noise-xx")]
pub fn build_handshake_fixture(
    seed: [u8; 32],
    initiator_secret: [u8; 32],
    responder_secret: [u8; 32],
    epoch: [u8; 8],
) -> HandshakeFixture {
    use microfips_core::noise::{NoiseXxInitiator, NoiseXxResponder};

    let initiator_pub = ecdh_pubkey(&initiator_secret).unwrap();
    let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
    let mut rng = TestRng::new(&seed);

    let initiator_eph = generate_valid_eph(&mut rng);
    let (mut initiator, _) = NoiseXxInitiator::new(&initiator_eph, &initiator_secret).unwrap();

    let mut msg1_noise = [0u8; 256];
    let msg1_noise_len = initiator.write_message1(&mut msg1_noise).unwrap();

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

    let mut responder = NoiseXxResponder::new(&responder_secret).unwrap();
    responder.read_message1(noise_payload).unwrap();

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

    // Same handshake state + static pub + epoch ⇒ byte-identical msg3.
    let mut verify_initiator = initiator;
    let (resp_pub, parsed_epoch) = verify_initiator
        .read_message2(&msg2_noise[..msg2_noise_len])
        .unwrap();
    assert_eq!(parsed_epoch, epoch);
    assert_eq!(resp_pub, responder_pub);

    let mut msg3_noise = [0u8; 128];
    let msg3_noise_len = verify_initiator
        .write_message3(&initiator_pub, &epoch, &mut msg3_noise)
        .unwrap();
    let mut msg3 = [0u8; 256];
    let msg3_len = wire::build_msg3(
        initiator_sender_idx,
        responder_sender_idx,
        &msg3_noise[..msg3_noise_len],
        &mut msg3,
    )
    .unwrap();

    responder
        .read_message3(&msg3_noise[..msg3_noise_len])
        .unwrap();

    let (initiator_ks, initiator_kr) = verify_initiator.finalize();
    let (responder_kr, responder_ks) = responder.finalize();
    assert_eq!(initiator_ks, responder_kr);
    assert_eq!(initiator_kr, responder_ks);

    HandshakeFixture {
        msg1: msg1[..msg1_len].to_vec(),
        msg2: msg2[..msg2_len].to_vec(),
        msg3: msg3[..msg3_len].to_vec(),
        initiator_ks,
        initiator_kr,
        responder_sender_idx,
    }
}

pub fn build_established_frame(
    sender_idx: wire::SessionIndex,
    counter: u64,
    msg_type: u8,
    payload: &[u8],
    key: &[u8; 32],
) -> Vec<u8> {
    let timestamp = embassy_time::Instant::now().as_millis() as u32;
    let mut inner = [0u8; 256];
    let mut out = [0u8; 256];
    let mut msg = std::vec![msg_type];
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

pub fn success_timing() -> NodeTiming {
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

pub fn timeout_timing() -> NodeTiming {
    NodeTiming {
        handshake_resend_interval_ms: 5,
        handshake_resend_backoff: 1,
        handshake_max_resends: 1,
        connect_delay_ms: 0,
        ..success_timing()
    }
}

pub async fn wait_for_events<F>(events: Arc<Mutex<Vec<NodeEvent>>>, predicate: F)
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

pub fn build_test_frame(
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

pub fn decrypt_test_frame(key: &[u8; 32], frame: &[u8]) -> (u8, std::vec::Vec<u8>) {
    use microfips_core::wire;

    let enc = wire::EncryptedHeader::parse(frame).expect("encrypted header");
    let mut dec = [0u8; MAX_FRAME_SIZE];
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

/// Generate a fresh random secp256k1 secret key for testing.
pub fn random_secret() -> [u8; 32] {
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

pub fn node_addr_from_secret(secret: &[u8; 32]) -> microfips_core::identity::NodeAddr {
    let pubkey = microfips_core::noise::ecdh_pubkey(secret).unwrap();
    let x_only: [u8; 32] = pubkey[1..33].try_into().unwrap();
    microfips_core::identity::NodeAddr::from_pubkey_x(&x_only)
}

pub fn distinct_secret_pair() -> ([u8; 32], [u8; 32]) {
    loop {
        let a = random_secret();
        let b = random_secret();
        if node_addr_from_secret(&a).as_bytes() != node_addr_from_secret(&b).as_bytes() {
            return (a, b);
        }
    }
}

pub async fn recv_test_frame(
    transport: &mut crate::transport::channel::ChannelTransport,
) -> std::vec::Vec<u8> {
    let mut hdr = [0u8; 2];
    let mut total = 0;
    while total < 2 {
        total += transport.recv(&mut hdr[total..]).await.unwrap();
    }

    let frame_len = u16::from_le_bytes(hdr) as usize;
    let mut frame = std::vec![0u8; frame_len];
    total = 0;
    while total < frame_len {
        total += transport.recv(&mut frame[total..]).await.unwrap();
    }
    frame
}

pub async fn send_test_frame(
    transport: &mut crate::transport::channel::ChannelTransport,
    frame: &[u8],
) {
    transport
        .send(&(frame.len() as u16).to_le_bytes())
        .await
        .unwrap();
    transport.send(frame).await.unwrap();
}

/// Channel-based scripted peer: completes a real handshake against a `Node`,
/// then feeds it established frames. Field access is intentionally public —
/// scenarios inspect `ks`/`send_ctr` to craft replays and fresh counters.
pub struct ScriptedPeer {
    pub transport: crate::transport::channel::ChannelTransport,
    pub secret: [u8; 32],
    pub peer_sender_idx: Option<wire::SessionIndex>,
    pub epoch: Option<[u8; 8]>,
    pub ks: Option<[u8; 32]>,
    pub kr: Option<[u8; 32]>,
    pub send_ctr: u64,
}

impl ScriptedPeer {
    pub fn new(transport: crate::transport::channel::ChannelTransport, secret: [u8; 32]) -> Self {
        Self {
            transport,
            secret,
            peer_sender_idx: None,
            epoch: None,
            ks: None,
            kr: None,
            send_ctr: 0,
        }
    }

    pub async fn recv_raw_frame(&mut self) -> std::vec::Vec<u8> {
        recv_test_frame(&mut self.transport).await
    }

    pub async fn send_raw_frame(&mut self, frame: &[u8]) {
        send_test_frame(&mut self.transport, frame).await
    }

    pub async fn complete_handshake(&mut self) -> wire::SessionIndex {
        #[cfg(feature = "noise-xx")]
        {
            self.complete_handshake_xx().await
        }
        #[cfg(not(feature = "noise-xx"))]
        {
            self.complete_handshake_ik().await
        }
    }

    #[cfg(not(feature = "noise-xx"))]
    async fn complete_handshake_ik(&mut self) -> wire::SessionIndex {
        use microfips_core::noise::{NoiseIkResponder, PUBKEY_SIZE};

        let frame = self.recv_raw_frame().await;
        let msg = wire::parse_message(&frame).expect("expected valid FMP message");
        let (peer_sender_idx, noise_payload) = match msg {
            wire::FmpMessage::Msg1 {
                sender_idx,
                noise_payload,
            } => (sender_idx, noise_payload),
            _ => panic!("expected Msg1, got {:?}", msg),
        };

        assert!(
            noise_payload.len() >= PUBKEY_SIZE,
            "MSG1 noise payload too short"
        );

        let ei_pub: [u8; PUBKEY_SIZE] = noise_payload[..PUBKEY_SIZE].try_into().unwrap();
        let mut responder =
            NoiseIkResponder::new(&self.secret, &ei_pub).expect("responder init failed");
        let (_init_pub, epoch) = responder
            .read_message1(&noise_payload[PUBKEY_SIZE..])
            .expect("read_message1 failed");

        let resp_eph = random_secret();
        let mut msg2_noise = [0u8; 128];
        let msg2_noise_len = responder
            .write_message2(&resp_eph, &epoch, &mut msg2_noise)
            .expect("write_message2 failed");

        let our_index = wire::SessionIndex::new(0xCAFE_0001);
        let mut msg2_buf = [0u8; 256];
        let msg2_len = wire::build_msg2(
            our_index,
            peer_sender_idx,
            &msg2_noise[..msg2_noise_len],
            &mut msg2_buf,
        )
        .unwrap();

        self.send_raw_frame(&msg2_buf[..msg2_len]).await;

        let (k1, k2) = responder.finalize();
        self.ks = Some(k2);
        self.kr = Some(k1);
        self.peer_sender_idx = Some(peer_sender_idx);
        self.epoch = Some(epoch);

        peer_sender_idx
    }

    #[cfg(feature = "noise-xx")]
    async fn complete_handshake_xx(&mut self) -> wire::SessionIndex {
        use microfips_core::noise::{NoiseXxResponder, XX_HANDSHAKE_MSG1_SIZE};

        let frame = self.recv_raw_frame().await;
        let msg = wire::parse_message(&frame).expect("expected valid FMP message");
        let (peer_sender_idx, noise_payload) = match msg {
            wire::FmpMessage::Msg1 {
                sender_idx,
                noise_payload,
            } => (sender_idx, noise_payload),
            _ => panic!("expected Msg1, got {:?}", msg),
        };

        assert_eq!(
            noise_payload.len(),
            XX_HANDSHAKE_MSG1_SIZE,
            "XX MSG1 noise payload must be 33B"
        );

        let mut responder = NoiseXxResponder::new(&self.secret).expect("responder init failed");
        responder
            .read_message1(noise_payload)
            .expect("read_message1 failed");

        let resp_eph = random_secret();
        let epoch = 1u64.to_le_bytes();
        let mut msg2_noise = [0u8; 128];
        let msg2_noise_len = responder
            .write_message2(&resp_eph, &epoch, &mut msg2_noise)
            .expect("write_message2 failed");

        let our_index = wire::SessionIndex::new(0xCAFE_0001);
        let mut msg2_buf = [0u8; 256];
        let msg2_len = wire::build_msg2(
            our_index,
            peer_sender_idx,
            &msg2_noise[..msg2_noise_len],
            &mut msg2_buf,
        )
        .unwrap();

        self.send_raw_frame(&msg2_buf[..msg2_len]).await;

        let frame3 = self.recv_raw_frame().await;
        let msg3 = wire::parse_message(&frame3).expect("expected valid FMP MSG3");
        match msg3 {
            wire::FmpMessage::Msg3 { noise_payload, .. } => {
                responder
                    .read_message3(noise_payload)
                    .expect("read_message3 failed");
            }
            _ => panic!("expected Msg3, got {:?}", msg3),
        }

        let (k1, k2) = responder.finalize();
        self.ks = Some(k2);
        self.kr = Some(k1);
        self.peer_sender_idx = Some(peer_sender_idx);
        self.epoch = Some(epoch);

        peer_sender_idx
    }

    pub async fn send_corrupted_msg2(&mut self) {
        use microfips_core::wire;
        let mut noise_payload = [0u8; 80];
        {
            use rand::RngCore;
            rand::rng().fill_bytes(&mut noise_payload);
        }
        let mut msg2_buf = [0u8; 256];
        let msg2_len = wire::build_msg2(
            wire::SessionIndex::new(1),
            wire::SessionIndex::new(1),
            &noise_payload,
            &mut msg2_buf,
        )
        .unwrap();
        self.send_raw_frame(&msg2_buf[..msg2_len]).await;
    }

    pub async fn send_heartbeat(&mut self) {
        let ks = self.ks.unwrap();
        let them = self.peer_sender_idx.unwrap();
        let frame = build_test_frame(
            them,
            self.send_ctr,
            wire::MSG_HEARTBEAT,
            embassy_time::Instant::now().as_millis() as u32,
            &[],
            &ks,
        );
        self.send_ctr += 1;
        self.send_raw_frame(&frame).await;
    }

    pub async fn send_disconnect(&mut self, reason: u8) {
        let ks = self.ks.unwrap();
        let them = self.peer_sender_idx.unwrap();
        let frame = build_test_frame(
            them,
            self.send_ctr,
            wire::MSG_DISCONNECT,
            embassy_time::Instant::now().as_millis() as u32,
            &[reason],
            &ks,
        );
        self.send_ctr += 1;
        self.send_raw_frame(&frame).await;
    }

    pub async fn send_datagram(&mut self, payload: &[u8]) {
        let ks = self.ks.unwrap();
        let them = self.peer_sender_idx.unwrap();
        let frame = build_test_frame(
            them,
            self.send_ctr,
            wire::MSG_SESSION_DATAGRAM,
            embassy_time::Instant::now().as_millis() as u32,
            payload,
            &ks,
        );
        self.send_ctr += 1;
        self.send_raw_frame(&frame).await;
    }

    pub async fn send_garbage(&mut self) {
        let payload: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut frame = (payload.len() as u16).to_le_bytes().to_vec();
        frame.extend_from_slice(payload);
        self.send_raw_frame(&frame).await;
    }

    pub fn close(&mut self) {
        self.transport.close();
    }

    pub async fn recv_decrypted_frame(&mut self) -> (u8, std::vec::Vec<u8>) {
        let frame = self.recv_raw_frame().await;
        let kr = self.kr.unwrap();
        decrypt_test_frame(&kr, &frame)
    }
}
