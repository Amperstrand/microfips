use microfips_core::fmp;
use microfips_core::fsp::{
    self, FSP_HEADER_SIZE, FSP_MSG_DATA, FspInitiatorSession, FspSession, HTTP_RESPONSE,
    SESSION_DATAGRAM_BODY_SIZE, build_fsp_encrypted, build_fsp_header, build_session_datagram_body,
    build_session_msg3, build_session_setup, fsp_prepend_inner_header, handle_fsp_datagram,
    parse_session_ack,
};
use microfips_core::identity::{DEFAULT_SECRET, NodeAddr};
use microfips_core::noise::{
    NoiseIkInitiator, NoiseIkResponder, NoiseXkInitiator, PUBKEY_SIZE, TAG_SIZE, aead_decrypt,
    aead_encrypt, ecdh_pubkey, parity_normalize,
};
use rand::RngCore;

const INIT_SECRET: [u8; 32] = DEFAULT_SECRET;
const RESP_SECRET: [u8; 32] = [0x22; 32];

fn gen_key() -> [u8; 32] {
    use k256::SecretKey;
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    loop {
        rng.fill_bytes(&mut key);
        if SecretKey::from_slice(&key).is_ok() {
            return key;
        }
    }
}

fn init_pub() -> [u8; PUBKEY_SIZE] {
    ecdh_pubkey(&INIT_SECRET).unwrap()
}

fn resp_pub() -> [u8; PUBKEY_SIZE] {
    ecdh_pubkey(&RESP_SECRET).unwrap()
}

fn init_addr() -> NodeAddr {
    let pub_key = init_pub();
    let normalized = parity_normalize(&pub_key);
    let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
    NodeAddr::from_pubkey_x(&x_only)
}

fn resp_addr() -> NodeAddr {
    let pub_key = resp_pub();
    let normalized = parity_normalize(&pub_key);
    let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
    NodeAddr::from_pubkey_x(&x_only)
}

fn session_datagram_body(src: &NodeAddr, dst: &NodeAddr) -> [u8; SESSION_DATAGRAM_BODY_SIZE] {
    let mut body = [0u8; SESSION_DATAGRAM_BODY_SIZE];
    body[0] = 64;
    body[1..3].copy_from_slice(&1400u16.to_le_bytes());
    body[3..19].copy_from_slice(src.as_bytes());
    body[19..35].copy_from_slice(dst.as_bytes());
    body
}

fn build_fmp_established_datagram(
    receiver_idx: u32,
    counter: u64,
    timestamp: u32,
    payload: &[u8],
    key: &[u8; 32],
    out: &mut [u8],
) -> Option<usize> {
    fmp::build_established(
        receiver_idx,
        counter,
        fmp::MSG_SESSION_DATAGRAM,
        timestamp,
        payload,
        key,
        out,
    )
}

fn decrypt_fmp_established(data: &[u8], key: &[u8; 32]) -> Option<(u64, u8, Vec<u8>)> {
    let msg = fmp::parse_message(data)?;
    match msg {
        fmp::FmpMessage::Established {
            counter, encrypted, ..
        } => {
            let hdr = &data[..fmp::ESTABLISHED_HEADER_SIZE];
            let mut dec = [0u8; 2048];
            let dl = aead_decrypt(key, counter, hdr, encrypted, &mut dec).ok()?;
            if dl < fmp::INNER_HEADER_SIZE {
                return None;
            }
            let msg_type = dec[4];
            let payload = dec[fmp::INNER_HEADER_SIZE..dl].to_vec();
            Some((counter, msg_type, payload))
        }
        _ => None,
    }
}

fn do_ik_handshake() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let init_eph: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let resp_eph: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF,
    ];
    let epoch = [0x01, 0, 0, 0, 0, 0, 0, 0];

    let init_pub = init_pub();
    let resp_pub = resp_pub();

    let (mut initiator, _) = NoiseIkInitiator::new(&init_eph, &INIT_SECRET, &resp_pub).unwrap();

    let mut msg1 = [0u8; 128];
    let msg1_len = initiator
        .write_message1(&init_pub, &epoch, &mut msg1)
        .unwrap();
    assert_eq!(msg1_len, fmp::HANDSHAKE_MSG1_SIZE);

    let e_init: [u8; PUBKEY_SIZE] = msg1[..PUBKEY_SIZE].try_into().unwrap();
    let mut responder = NoiseIkResponder::new(&RESP_SECRET, &e_init).unwrap();
    let (recv_pub, recv_epoch) = responder
        .read_message1(&msg1[PUBKEY_SIZE..msg1_len])
        .unwrap();
    assert_eq!(recv_pub, init_pub);
    assert_eq!(recv_epoch, epoch);

    let mut msg2_noise = [0u8; 128];
    let msg2_len = responder
        .write_message2(&resp_eph, &epoch, &mut msg2_noise)
        .unwrap();
    assert_eq!(msg2_len, fmp::HANDSHAKE_MSG2_SIZE);

    initiator.read_message2(&msg2_noise[..msg2_len]).unwrap();

    let (init_k1, init_k2) = initiator.finalize();
    let (resp_k1, resp_k2) = responder.finalize();

    let init_k_send = init_k1;
    let init_k_recv = init_k2;
    let resp_k_send = resp_k2;
    let resp_k_recv = resp_k1;

    assert_eq!(
        init_k_send, resp_k_recv,
        "IK: initiator k_send == responder k_recv"
    );
    assert_eq!(
        init_k_recv, resp_k_send,
        "IK: initiator k_recv == responder k_send"
    );

    (init_k_send, init_k_recv, resp_k_send, resp_k_recv)
}

#[test]
fn test_session_datagram_body_format() {
    let src = resp_addr();
    let dst = init_addr();
    let body = session_datagram_body(&src, &dst);

    assert_eq!(body[0], 64, "TTL should be 64");
    let mtu = u16::from_le_bytes([body[1], body[2]]);
    assert_eq!(mtu, 1400, "MTU should be 1400");
    assert_eq!(&body[3..19], src.as_bytes(), "src addr at bytes 3-18");
    assert_eq!(&body[19..35], dst.as_bytes(), "dst addr at bytes 19-34");
    assert_eq!(body.len(), SESSION_DATAGRAM_BODY_SIZE);
}

#[test]
fn test_fsp_full_handshake_over_fmp() {
    let fsp_resp_secret = gen_key();
    let fsp_resp_eph = gen_key();
    let fsp_init_secret = gen_key();
    let fsp_init_eph: [u8; 32] = [0x01; 32];
    let fsp_resp_pub = ecdh_pubkey(&fsp_resp_secret).unwrap();
    let fsp_init_pub = ecdh_pubkey(&fsp_init_secret).unwrap();

    let fsp_resp_epoch: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
    let fsp_init_epoch: [u8; 8] = [0x02, 0, 0, 0, 0, 0, 0, 0];

    let (mut xk_init, xk_init_pub_check) =
        NoiseXkInitiator::new(&fsp_init_eph, &fsp_init_secret, &fsp_resp_pub).unwrap();
    assert_eq!(xk_init_pub_check, ecdh_pubkey(&fsp_init_eph).unwrap());

    let mut xk_msg1 = [0u8; 64];
    let msg1_len = xk_init.write_message1(&mut xk_msg1).unwrap();

    let responder_addr = {
        let normalized = parity_normalize(&fsp_resp_pub);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        NodeAddr::from_pubkey_x(&x_only)
    };
    let initiator_addr = {
        let normalized = parity_normalize(&fsp_init_pub);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        NodeAddr::from_pubkey_x(&x_only)
    };

    let mut setup_buf = [0u8; 512];
    let setup_len = build_session_setup(
        0x03,
        &[responder_addr.0],
        &[initiator_addr.0],
        &xk_msg1[..msg1_len],
        &mut setup_buf,
    )
    .unwrap();

    let mut fsp_session = FspSession::new();
    let mut ack_buf = [0u8; 512];
    let ack_len = fsp_session
        .handle_setup(
            &fsp_resp_secret,
            &fsp_resp_eph,
            &fsp_resp_epoch,
            &setup_buf[..setup_len],
            &mut ack_buf,
        )
        .unwrap();
    assert!(ack_len > 0);
    assert_eq!(fsp_session.state(), fsp::FspSessionState::AwaitingMsg3);
    assert_eq!(fsp_session.session_keys(), None);

    let mut ack_stored = [0u8; 512];
    ack_stored[..ack_len].copy_from_slice(&ack_buf[..ack_len]);
    let xk_msg2_payload = parse_session_ack(&ack_stored[..ack_len]).unwrap();
    assert_eq!(xk_msg2_payload.len(), fsp::XK_HANDSHAKE_MSG2_SIZE);

    let received_epoch = xk_init.read_message2(xk_msg2_payload).unwrap();
    assert_eq!(received_epoch, fsp_resp_epoch);

    let mut xk_msg3_noise = [0u8; 128];
    let xk_msg3_len = xk_init
        .write_message3(&fsp_init_pub, &fsp_init_epoch, &mut xk_msg3_noise)
        .unwrap();
    assert_eq!(xk_msg3_len, fsp::XK_HANDSHAKE_MSG3_SIZE);

    let mut msg3_buf = [0u8; 512];
    let msg3_fsp_len = build_session_msg3(&xk_msg3_noise[..xk_msg3_len], &mut msg3_buf).unwrap();

    fsp_session.handle_msg3(&msg3_buf[..msg3_fsp_len]).unwrap();
    assert_eq!(fsp_session.state(), fsp::FspSessionState::Established);
    let (k_recv, k_send) = fsp_session.session_keys().unwrap();
    assert_ne!(k_recv, [0u8; 32]);
    assert_ne!(k_send, [0u8; 32]);
    assert_eq!(fsp_session.initiator_pub(), Some(fsp_init_pub));

    let (k_send_i, k_recv_i) = xk_init.finalize();
    assert_eq!(k_recv, k_send_i, "session k_recv == initiator k_send");
    assert_eq!(k_send, k_recv_i, "session k_send == initiator k_recv");

    let http_request = b"GET / HTTP/1.1\r\nHost: microfips-stm32\r\n\r\n";
    let mut plaintext = [0u8; 512];
    let inner = fsp_prepend_inner_header(2000, FSP_MSG_DATA, 0x00, http_request, &mut plaintext);
    let header = build_fsp_header(0, 0x00, (inner + TAG_SIZE) as u16);
    let mut ciphertext = vec![0u8; inner + TAG_SIZE];
    aead_encrypt(&k_send_i, 0, &header, &plaintext[..inner], &mut ciphertext).unwrap();
    let mut fsp_enc_packet = vec![0u8; FSP_HEADER_SIZE + ciphertext.len()];
    build_fsp_encrypted(&header, &ciphertext, &mut fsp_enc_packet);

    let body = session_datagram_body(&initiator_addr, &responder_addr);
    let mut http_payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + fsp_enc_packet.len()];
    http_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&body);
    http_payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&fsp_enc_packet);

    let mut http_buf = [0u8; 512];
    let http_response_len = match handle_fsp_datagram(
        &mut fsp_session,
        &fsp_resp_secret,
        &fsp_resp_eph,
        &fsp_resp_epoch,
        &http_payload,
        &mut http_buf,
    )
    .unwrap()
    {
        fsp::FspHandlerResult::SendDatagram(len) => len,
        other => panic!(
            "Step 3 (HTTP GET): Expected SendDatagram with HTTP response, got {:?}",
            other
        ),
    };
    assert!(
        http_response_len > SESSION_DATAGRAM_BODY_SIZE,
        "response must include SessionDatagram body"
    );
    let reply_dg = &http_buf[..http_response_len];
    assert_eq!(
        &reply_dg[3..19],
        responder_addr.as_bytes(),
        "reply src should be original dst"
    );
    assert_eq!(
        &reply_dg[19..35],
        initiator_addr.as_bytes(),
        "reply dst should be original src"
    );
    let fsp_reply = &reply_dg[SESSION_DATAGRAM_BODY_SIZE..];
    assert_eq!(
        fsp_reply[0] & 0x0F,
        0x00,
        "reply should be phase ESTABLISHED (encrypted)"
    );
    let reply_hdr: [u8; FSP_HEADER_SIZE] = fsp_reply[..FSP_HEADER_SIZE].try_into().unwrap();
    let ct = &fsp_reply[FSP_HEADER_SIZE..];
    let mut dec = [0u8; 512];
    let dl = aead_decrypt(&k_recv_i, 1, &reply_hdr, ct, &mut dec).unwrap();
    let (ts, mt, ifl, inner) = fsp::fsp_strip_inner_header(&dec[..dl]).unwrap();
    assert_eq!(mt, FSP_MSG_DATA);
    assert_eq!(inner, HTTP_RESPONSE);
}

#[test]
fn test_fsp_setup_over_fmp_roundtrip() {
    let (_init_k_send, init_k_recv, resp_k_send, _resp_k_recv) = do_ik_handshake();

    let resp_addr = resp_addr();
    let init_addr = init_addr();
    let dg_body = session_datagram_body(&resp_addr, &init_addr);

    let xk_resp_eph: [u8; 32] = [0xCC; 32];
    let init_pub = init_pub();
    let (mut xk_init, _) = NoiseXkInitiator::new(&xk_resp_eph, &RESP_SECRET, &init_pub).unwrap();

    let mut xk_msg1 = [0u8; 64];
    let xk_msg1_len = xk_init.write_message1(&mut xk_msg1).unwrap();
    assert_eq!(xk_msg1_len, fsp::XK_HANDSHAKE_MSG1_SIZE);

    let mut setup_buf = [0u8; 512];
    let src_coords = [*resp_addr.as_bytes()];
    let dst_coords = [*init_addr.as_bytes()];
    let setup_len = build_session_setup(
        0x03,
        &src_coords,
        &dst_coords,
        &xk_msg1[..xk_msg1_len],
        &mut setup_buf,
    )
    .unwrap();

    let mut dg_payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + setup_len];
    dg_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    dg_payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&setup_buf[..setup_len]);

    let mut fmp_out = [0u8; 1024];
    let fmp_len =
        build_fmp_established_datagram(0, 0, 1000, &dg_payload, &resp_k_send, &mut fmp_out)
            .unwrap();
    assert!(fmp_len > 0);

    let (ctr, msg_type, payload) =
        decrypt_fmp_established(&fmp_out[..fmp_len], &init_k_recv).unwrap();
    assert_eq!(ctr, 0);
    assert_eq!(msg_type, fmp::MSG_SESSION_DATAGRAM);
    assert_eq!(payload.len(), dg_payload.len());

    let mut fsp_session = FspSession::new();
    let init_fsp_eph: [u8; 32] = [0xDD; 32];
    let init_fsp_epoch: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
    let mut resp_buf = [0u8; 512];
    let result = handle_fsp_datagram(
        &mut fsp_session,
        &INIT_SECRET,
        &init_fsp_eph,
        &init_fsp_epoch,
        &payload,
        &mut resp_buf,
    );
    match result {
        Ok(fsp::FspHandlerResult::SendDatagram(ack_len)) => {
            assert!(ack_len > 0, "SessionAck must have nonzero length");
            assert_eq!(fsp_session.state(), fsp::FspSessionState::AwaitingMsg3);
        }
        other => panic!("Expected SendDatagram, got {:?}", other),
    }
}

#[test]
fn test_build_session_datagram_body_matches_manual() {
    let src = resp_addr();
    let dst = init_addr();
    let body = build_session_datagram_body(src.as_bytes(), dst.as_bytes());
    let manual = session_datagram_body(&src, &dst);
    assert_eq!(body, manual);
    assert_eq!(body.len(), SESSION_DATAGRAM_BODY_SIZE);
    assert_eq!(body[0], 64);
    let mtu = u16::from_le_bytes([body[1], body[2]]);
    assert_eq!(mtu, 1400);
    assert_eq!(&body[3..19], src.as_bytes());
    assert_eq!(&body[19..35], dst.as_bytes());
}

#[test]
fn test_fsp_initiator_session_flow() {
    let fsp_init_secret = gen_key();
    let fsp_init_eph: [u8; 32] = [0xBB; 32];
    let fsp_resp_secret = gen_key();
    let fsp_resp_pub = ecdh_pubkey(&fsp_resp_secret).unwrap();

    let initiator_addr = {
        let pub_key = ecdh_pubkey(&fsp_init_secret).unwrap();
        let normalized = parity_normalize(&pub_key);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        NodeAddr::from_pubkey_x(&x_only)
    };
    let responder_addr = {
        let normalized = parity_normalize(&fsp_resp_pub);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        NodeAddr::from_pubkey_x(&x_only)
    };

    let mut init_session =
        FspInitiatorSession::new(&fsp_init_secret, &fsp_init_eph, &fsp_resp_pub).unwrap();
    assert_eq!(init_session.state(), fsp::FspInitiatorState::Idle);
    assert_eq!(init_session.session_keys(), None);

    let mut setup_buf = [0u8; 512];
    let setup_len = init_session
        .build_setup(
            initiator_addr.as_bytes(),
            responder_addr.as_bytes(),
            &mut setup_buf,
        )
        .unwrap();
    assert!(setup_len > 0);
    assert_eq!(init_session.state(), fsp::FspInitiatorState::AwaitingAck);

    let fsp_resp_eph = gen_key();
    let fsp_resp_epoch: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
    let mut fsp_session = FspSession::new();
    let mut ack_buf = [0u8; 512];
    let ack_len = fsp_session
        .handle_setup(
            &fsp_resp_secret,
            &fsp_resp_eph,
            &fsp_resp_epoch,
            &setup_buf[..setup_len],
            &mut ack_buf,
        )
        .unwrap();

    let mut ack_stored = [0u8; 512];
    ack_stored[..ack_len].copy_from_slice(&ack_buf[..ack_len]);

    init_session.handle_ack(&ack_stored[..ack_len]).unwrap();
    assert_eq!(
        init_session.state(),
        fsp::FspInitiatorState::AwaitingEstablished
    );

    let fsp_init_epoch: [u8; 8] = [0x02, 0, 0, 0, 0, 0, 0, 0];
    let mut msg3_buf = [0u8; 512];
    let msg3_len = init_session
        .build_msg3(&fsp_init_epoch, &mut msg3_buf)
        .unwrap();
    assert!(msg3_len > 0);
    assert_eq!(init_session.state(), fsp::FspInitiatorState::Established);

    fsp_session.handle_msg3(&msg3_buf[..msg3_len]).unwrap();
    assert_eq!(fsp_session.state(), fsp::FspSessionState::Established);

    let (init_k_recv, init_k_send) = init_session.session_keys().unwrap();
    let (resp_k_recv, resp_k_send) = fsp_session.session_keys().unwrap();
    assert_eq!(
        init_k_send, resp_k_recv,
        "initiator k_send == responder k_recv"
    );
    assert_eq!(
        init_k_recv, resp_k_send,
        "initiator k_recv == responder k_send"
    );
}

#[test]
fn test_ping_pong_roundtrip() {
    let fsp_init_secret = gen_key();
    let fsp_init_eph: [u8; 32] = [0xBB; 32];
    let fsp_resp_secret = gen_key();
    let fsp_resp_eph = gen_key();
    let fsp_resp_pub = ecdh_pubkey(&fsp_resp_secret).unwrap();
    let fsp_resp_epoch: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
    let fsp_init_epoch: [u8; 8] = [0x02, 0, 0, 0, 0, 0, 0, 0];

    let initiator_addr = {
        let pub_key = ecdh_pubkey(&fsp_init_secret).unwrap();
        let normalized = parity_normalize(&pub_key);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        NodeAddr::from_pubkey_x(&x_only)
    };
    let responder_addr = {
        let normalized = parity_normalize(&fsp_resp_pub);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        NodeAddr::from_pubkey_x(&x_only)
    };

    let dg_body = build_session_datagram_body(initiator_addr.as_bytes(), responder_addr.as_bytes());

    let mut init_session =
        FspInitiatorSession::new(&fsp_init_secret, &fsp_init_eph, &fsp_resp_pub).unwrap();

    let mut setup_buf = [0u8; 512];
    let setup_len = init_session
        .build_setup(
            initiator_addr.as_bytes(),
            responder_addr.as_bytes(),
            &mut setup_buf,
        )
        .unwrap();

    let mut fsp_session = FspSession::new();
    let mut ack_buf = [0u8; 512];
    let ack_len = fsp_session
        .handle_setup(
            &fsp_resp_secret,
            &fsp_resp_eph,
            &fsp_resp_epoch,
            &setup_buf[..setup_len],
            &mut ack_buf,
        )
        .unwrap();

    let mut ack_stored = [0u8; 512];
    ack_stored[..ack_len].copy_from_slice(&ack_buf[..ack_len]);
    init_session.handle_ack(&ack_stored[..ack_len]).unwrap();

    let mut msg3_buf = [0u8; 512];
    let msg3_len = init_session
        .build_msg3(&fsp_init_epoch, &mut msg3_buf)
        .unwrap();
    fsp_session.handle_msg3(&msg3_buf[..msg3_len]).unwrap();

    let (init_k_recv, init_k_send) = init_session.session_keys().unwrap();

    let ping_payload = b"PING";
    let mut plaintext = [0u8; 512];
    let inner = fsp_prepend_inner_header(3000, FSP_MSG_DATA, 0x00, ping_payload, &mut plaintext);
    let header = build_fsp_header(0, 0x00, (inner + TAG_SIZE) as u16);
    let mut ciphertext = vec![0u8; inner + TAG_SIZE];
    aead_encrypt(
        &init_k_send,
        0,
        &header,
        &plaintext[..inner],
        &mut ciphertext,
    )
    .unwrap();
    let mut fsp_enc_packet = vec![0u8; FSP_HEADER_SIZE + ciphertext.len()];
    build_fsp_encrypted(&header, &ciphertext, &mut fsp_enc_packet);

    let mut ping_dg = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + fsp_enc_packet.len()];
    ping_dg[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    ping_dg[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&fsp_enc_packet);

    let mut pong_buf = [0u8; 512];
    let pong_len = match handle_fsp_datagram(
        &mut fsp_session,
        &fsp_resp_secret,
        &fsp_resp_eph,
        &fsp_resp_epoch,
        &ping_dg,
        &mut pong_buf,
    )
    .unwrap()
    {
        fsp::FspHandlerResult::SendDatagram(len) => len,
        other => panic!("Expected SendDatagram(PONG), got {:?}", other),
    };
    assert!(
        pong_len > SESSION_DATAGRAM_BODY_SIZE,
        "PONG must include SessionDatagram body"
    );
    let reply_dg = &pong_buf[..pong_len];
    assert_eq!(
        &reply_dg[3..19],
        responder_addr.as_bytes(),
        "reply src should be original dst"
    );
    assert_eq!(
        &reply_dg[19..35],
        initiator_addr.as_bytes(),
        "reply dst should be original src"
    );
    let fsp_reply = &reply_dg[SESSION_DATAGRAM_BODY_SIZE..];
    assert_eq!(fsp_reply[0] & 0x0F, 0x00, "PONG reply should be encrypted");
    let reply_hdr: [u8; FSP_HEADER_SIZE] = fsp_reply[..FSP_HEADER_SIZE].try_into().unwrap();
    let ct = &fsp_reply[FSP_HEADER_SIZE..];
    let mut dec = [0u8; 512];
    let dl = aead_decrypt(&init_k_recv, 1, &reply_hdr, ct, &mut dec).unwrap();
    let (_ts, mt, _ifl, inner) = fsp::fsp_strip_inner_header(&dec[..dl]).unwrap();
    assert_eq!(mt, FSP_MSG_DATA);
    assert_eq!(inner, b"PONG");
}
