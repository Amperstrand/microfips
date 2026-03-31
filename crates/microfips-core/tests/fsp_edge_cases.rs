use microfips_core::fsp::{
    self, build_fsp_encrypted, build_fsp_header, build_session_datagram_body, build_session_msg3,
    build_session_setup, fsp_prepend_inner_header, handle_fsp_datagram, parse_session_ack,
    FspInitiatorSession, FspSession, FSP_HEADER_SIZE, FSP_MSG_DATA, SESSION_DATAGRAM_BODY_SIZE,
};
use microfips_core::noise::{
    aead_decrypt, aead_encrypt, ecdh_pubkey, parity_normalize, NoiseXkInitiator, PUBKEY_SIZE,
    TAG_SIZE,
};

const INIT_SECRET: [u8; 32] = {
    let mut k = [0u8; 32];
    k[31] = 4;
    k
};

const RESP_SECRET: [u8; 32] = {
    let mut k = [0u8; 32];
    k[31] = 3;
    k
};

const INIT_EPH: [u8; 32] = [0x01; 32];
const RESP_EPH: [u8; 32] = [0xCC; 32];

const EPOCH_R: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
const EPOCH_I: [u8; 8] = [0x02, 0, 0, 0, 0, 0, 0, 0];

fn make_addr(val: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = val;
    a
}

fn init_pub() -> [u8; PUBKEY_SIZE] {
    ecdh_pubkey(&INIT_SECRET).unwrap()
}

fn resp_pub() -> [u8; PUBKEY_SIZE] {
    ecdh_pubkey(&RESP_SECRET).unwrap()
}

fn addr_from_pub(pub_key: &[u8; PUBKEY_SIZE]) -> [u8; 16] {
    use microfips_core::identity::NodeAddr;
    let normalized = parity_normalize(pub_key);
    let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
    NodeAddr::from_pubkey_x(&x_only).0
}

fn do_fsp_handshake() -> (FspInitiatorSession, FspSession, [u8; 16], [u8; 16]) {
    let resp_pub = resp_pub();
    let init_pub = init_pub();
    let initiator_addr = addr_from_pub(&init_pub);
    let responder_addr = addr_from_pub(&resp_pub);

    let mut init_session = FspInitiatorSession::new(&INIT_SECRET, &INIT_EPH, &resp_pub).unwrap();

    let mut setup_buf = [0u8; 512];
    let setup_len = init_session
        .build_setup(&initiator_addr, &responder_addr, &mut setup_buf)
        .unwrap();

    let mut resp_session = FspSession::new();
    let mut ack_buf = [0u8; 512];
    let ack_len = resp_session
        .handle_setup(
            &RESP_SECRET,
            &RESP_EPH,
            &EPOCH_R,
            &setup_buf[..setup_len],
            &mut ack_buf,
        )
        .unwrap();

    let mut ack_stored = [0u8; 512];
    ack_stored[..ack_len].copy_from_slice(&ack_buf[..ack_len]);
    init_session.handle_ack(&ack_stored[..ack_len]).unwrap();

    let mut msg3_buf = [0u8; 512];
    let msg3_len = init_session.build_msg3(&EPOCH_I, &mut msg3_buf).unwrap();

    resp_session.handle_msg3(&msg3_buf[..msg3_len]).unwrap();

    assert_eq!(init_session.state(), fsp::FspInitiatorState::Established);
    assert_eq!(resp_session.state(), fsp::FspSessionState::Established);

    (init_session, resp_session, initiator_addr, responder_addr)
}

#[test]
fn test_duplicate_session_setup_direct_returns_invalid_state() {
    let resp_pub = resp_pub();
    let (mut init, _e_pub) = NoiseXkInitiator::new(&INIT_EPH, &INIT_SECRET, &resp_pub).unwrap();

    let mut msg1 = [0u8; 64];
    let msg1_len = init.write_message1(&mut msg1).unwrap();

    let src = [make_addr(0x01)];
    let dst = [make_addr(0x02)];
    let mut setup_buf = [0u8; 512];
    let setup_len =
        build_session_setup(0x03, &src, &dst, &msg1[..msg1_len], &mut setup_buf).unwrap();

    let mut session = FspSession::new();
    let mut ack = [0u8; 512];
    session
        .handle_setup(
            &RESP_SECRET,
            &RESP_EPH,
            &EPOCH_R,
            &setup_buf[..setup_len],
            &mut ack,
        )
        .unwrap();
    assert_eq!(session.state(), fsp::FspSessionState::AwaitingMsg3);

    let result = session.handle_setup(
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &setup_buf[..setup_len],
        &mut ack,
    );
    assert_eq!(
        result,
        Err(fsp::FspSessionError::InvalidState),
        "second handle_setup while AwaitingMsg3 should return InvalidState"
    );
    assert_eq!(session.state(), fsp::FspSessionState::AwaitingMsg3);
}

#[test]
fn test_duplicate_session_setup_via_handler_resets_and_retries() {
    let resp_pub = resp_pub();
    let init_pub = init_pub();
    let initiator_addr = addr_from_pub(&init_pub);
    let responder_addr = addr_from_pub(&resp_pub);

    let (mut init1, _e_pub1) = NoiseXkInitiator::new(&INIT_EPH, &INIT_SECRET, &resp_pub).unwrap();
    let mut msg1_buf = [0u8; 64];
    let msg1_len = init1.write_message1(&mut msg1_buf).unwrap();

    let src_coords = [initiator_addr];
    let dst_coords = [responder_addr];
    let mut setup_buf = [0u8; 512];
    let setup_len = build_session_setup(
        0x03,
        &src_coords,
        &dst_coords,
        &msg1_buf[..msg1_len],
        &mut setup_buf,
    )
    .unwrap();

    let dg_body = build_session_datagram_body(&initiator_addr, &responder_addr);
    let mut payload1 = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + setup_len];
    payload1[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    payload1[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&setup_buf[..setup_len]);

    let mut session = FspSession::new();
    let mut resp_buf = [0u8; 512];

    let r1 = handle_fsp_datagram(
        &mut session,
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &payload1,
        &mut resp_buf,
    )
    .unwrap();
    assert!(
        matches!(r1, fsp::FspHandlerResult::SendDatagram(_)),
        "first setup should produce SendDatagram"
    );
    assert_eq!(session.state(), fsp::FspSessionState::AwaitingMsg3);

    let r2 = handle_fsp_datagram(
        &mut session,
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &payload1,
        &mut resp_buf,
    )
    .unwrap();
    assert!(
        matches!(r2, fsp::FspHandlerResult::SendDatagram(_)),
        "duplicate setup via handler should succeed after reset"
    );
    assert_eq!(session.state(), fsp::FspSessionState::AwaitingMsg3);
}

#[test]
fn test_msg3_before_session_ack_rejected() {
    let resp_pub = resp_pub();
    let init_pub = init_pub();
    let init_eph2: [u8; 32] = [0x02; 32];

    let (mut init, _) = NoiseXkInitiator::new(&init_eph2, &INIT_SECRET, &resp_pub).unwrap();
    let mut msg1 = [0u8; 64];
    let msg1_len = init.write_message1(&mut msg1).unwrap();

    let mut resp_session = FspSession::new();
    let src = [addr_from_pub(&init_pub)];
    let dst = [addr_from_pub(&resp_pub)];
    let mut setup_buf = [0u8; 512];
    let setup_len =
        build_session_setup(0x03, &src, &dst, &msg1[..msg1_len], &mut setup_buf).unwrap();

    let mut ack_buf = [0u8; 512];
    let ack_len = resp_session
        .handle_setup(
            &RESP_SECRET,
            &RESP_EPH,
            &EPOCH_R,
            &setup_buf[..setup_len],
            &mut ack_buf,
        )
        .unwrap();

    let xk_msg2 = parse_session_ack(&ack_buf[..ack_len]).unwrap();
    init.read_message2(xk_msg2).unwrap();

    let init_pub_key = ecdh_pubkey(&INIT_SECRET).unwrap();
    let mut msg3_noise = [0u8; 128];
    let msg3_noise_len = init
        .write_message3(&init_pub_key, &EPOCH_I, &mut msg3_noise)
        .unwrap();

    let mut msg3_buf = [0u8; 512];
    let msg3_len = build_session_msg3(&msg3_noise[..msg3_noise_len], &mut msg3_buf).unwrap();

    let mut fresh_session = FspSession::new();
    let result = fresh_session.handle_msg3(&msg3_buf[..msg3_len]);
    assert_eq!(
        result,
        Err(fsp::FspSessionError::InvalidState),
        "Msg3 sent to an Idle session should return InvalidState"
    );
    assert_eq!(fresh_session.state(), fsp::FspSessionState::Idle);
}

#[test]
fn test_session_setup_wrong_target_addr_with_wrong_key_fails() {
    let wrong_secret: [u8; 32] = [0x42; 32];
    let wrong_pub = ecdh_pubkey(&wrong_secret).unwrap();

    let init_eph2: [u8; 32] = [0x05; 32];
    let (mut init_wrong, _) = NoiseXkInitiator::new(&init_eph2, &INIT_SECRET, &wrong_pub).unwrap();
    let mut msg1 = [0u8; 64];
    let msg1_len = init_wrong.write_message1(&mut msg1).unwrap();

    let src = [make_addr(0x01)];
    let dst = [make_addr(0x99)];
    let mut setup_buf = [0u8; 512];
    let setup_len =
        build_session_setup(0x03, &src, &dst, &msg1[..msg1_len], &mut setup_buf).unwrap();

    let mut resp_session = FspSession::new();
    let mut ack_buf = [0u8; 512];
    let ack_result = resp_session.handle_setup(
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &setup_buf[..setup_len],
        &mut ack_buf,
    );
    assert!(
        ack_result.is_ok(),
        "handle_setup with wrong-target XK msg1 returns Ok (mismatch deferred to msg3)"
    );
    assert_eq!(resp_session.state(), fsp::FspSessionState::AwaitingMsg3);
}

#[test]
fn test_session_setup_to_self() {
    let init_pub = init_pub();
    let initiator_addr = addr_from_pub(&init_pub);

    let init_eph_self: [u8; 32] = [0x07; 32];
    let (mut init_self, _) =
        NoiseXkInitiator::new(&init_eph_self, &INIT_SECRET, &init_pub).unwrap();
    let mut msg1 = [0u8; 64];
    let msg1_len = init_self.write_message1(&mut msg1).unwrap();

    let src = [initiator_addr];
    let dst = [initiator_addr];
    let mut setup_buf = [0u8; 512];
    let setup_len =
        build_session_setup(0x03, &src, &dst, &msg1[..msg1_len], &mut setup_buf).unwrap();

    let mut self_session = FspSession::new();
    let mut ack_buf = [0u8; 512];
    let ack_result = self_session.handle_setup(
        &INIT_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &setup_buf[..setup_len],
        &mut ack_buf,
    );
    assert!(
        ack_result.is_ok(),
        "self-targeted setup should be accepted by responder"
    );
    assert_eq!(self_session.state(), fsp::FspSessionState::AwaitingMsg3);
    assert_eq!(
        self_session.session_keys(),
        None,
        "keys not available until msg3"
    );
}

#[test]
fn test_maximum_payload_in_established_session() {
    let (init_session, mut resp_session, initiator_addr, responder_addr) = do_fsp_handshake();

    let (_init_k_recv, init_k_send) = init_session.session_keys().unwrap();

    let large_payload = vec![0xAB_u8; 300];
    let mut plaintext = vec![0u8; 512];
    let inner_len =
        fsp_prepend_inner_header(9999, FSP_MSG_DATA, 0x00, &large_payload, &mut plaintext);
    assert!(inner_len > 0, "inner_len must be non-zero");

    let header = build_fsp_header(0, 0x00, (inner_len + TAG_SIZE) as u16);
    let mut ciphertext = vec![0u8; inner_len + TAG_SIZE];
    aead_encrypt(
        &init_k_send,
        0,
        &header,
        &plaintext[..inner_len],
        &mut ciphertext,
    )
    .unwrap();

    let mut fsp_enc = vec![0u8; FSP_HEADER_SIZE + ciphertext.len()];
    build_fsp_encrypted(&header, &ciphertext, &mut fsp_enc);

    let dg_body = build_session_datagram_body(&initiator_addr, &responder_addr);
    let mut payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + fsp_enc.len()];
    payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&fsp_enc);

    let mut resp_buf = vec![0u8; 1024];
    let result = handle_fsp_datagram(
        &mut resp_session,
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &payload,
        &mut resp_buf,
    )
    .unwrap();

    assert_eq!(
        result,
        fsp::FspHandlerResult::None,
        "large non-PING payload returns None (no reply)"
    );

    let mut dec = [0u8; 512];
    let dl = aead_decrypt(&init_k_send, 0, &header, &ciphertext, &mut dec).unwrap();
    assert_eq!(dl, inner_len);
    let (_ts, mt, _ifl, inner) = fsp::fsp_strip_inner_header(&dec[..dl]).unwrap();
    assert_eq!(mt, FSP_MSG_DATA);
    assert_eq!(inner, large_payload.as_slice());
}

#[test]
fn test_ping_before_established_session_returns_none() {
    let resp_pub = resp_pub();
    let init_pub = init_pub();
    let initiator_addr = addr_from_pub(&init_pub);
    let responder_addr = addr_from_pub(&resp_pub);

    let fake_key = [0x55u8; 32];
    let msg = b"PING";
    let mut plaintext = [0u8; 512];
    let inner = fsp_prepend_inner_header(100, FSP_MSG_DATA, 0x00, msg, &mut plaintext);
    let header = build_fsp_header(0, 0x00, (inner + TAG_SIZE) as u16);
    let mut ct = vec![0u8; inner + TAG_SIZE];
    aead_encrypt(&fake_key, 0, &header, &plaintext[..inner], &mut ct).unwrap();
    let mut fsp_pkt = vec![0u8; FSP_HEADER_SIZE + ct.len()];
    build_fsp_encrypted(&header, &ct, &mut fsp_pkt);

    let dg_body = build_session_datagram_body(&initiator_addr, &responder_addr);
    let mut payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + fsp_pkt.len()];
    payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&fsp_pkt);

    let mut session = FspSession::new();
    let mut resp_buf = [0u8; 512];
    let result = handle_fsp_datagram(
        &mut session,
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &payload,
        &mut resp_buf,
    )
    .unwrap();

    assert_eq!(
        result,
        fsp::FspHandlerResult::None,
        "PING to Idle session returns None (session not established)"
    );
    assert_eq!(
        session.state(),
        fsp::FspSessionState::Idle,
        "state stays Idle"
    );
}

#[test]
fn test_unsolicited_pong_returns_none() {
    let (init_session, mut resp_session, initiator_addr, responder_addr) = do_fsp_handshake();
    let (_init_k_recv, init_k_send) = init_session.session_keys().unwrap();

    let pong_data = b"PONG";
    let mut plaintext = [0u8; 512];
    let inner = fsp_prepend_inner_header(200, FSP_MSG_DATA, 0x00, pong_data, &mut plaintext);
    let header = build_fsp_header(0, 0x00, (inner + TAG_SIZE) as u16);
    let mut ct = vec![0u8; inner + TAG_SIZE];
    aead_encrypt(&init_k_send, 0, &header, &plaintext[..inner], &mut ct).unwrap();
    let mut fsp_pkt = vec![0u8; FSP_HEADER_SIZE + ct.len()];
    build_fsp_encrypted(&header, &ct, &mut fsp_pkt);

    let dg_body = build_session_datagram_body(&initiator_addr, &responder_addr);
    let mut payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + fsp_pkt.len()];
    payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&fsp_pkt);

    let mut resp_buf = vec![0u8; 1024];
    let result = handle_fsp_datagram(
        &mut resp_session,
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &payload,
        &mut resp_buf,
    )
    .unwrap();

    assert_eq!(
        result,
        fsp::FspHandlerResult::None,
        "unsolicited PONG (not PING/GET) returns None from responder"
    );
}

#[test]
fn test_multiple_sessions_from_same_initiator() {
    let resp_pub = resp_pub();
    let init_pub = init_pub();
    let initiator_addr = addr_from_pub(&init_pub);
    let responder_addr = addr_from_pub(&resp_pub);

    let init_eph_a: [u8; 32] = [0x0A; 32];
    let mut init_a = FspInitiatorSession::new(&INIT_SECRET, &init_eph_a, &resp_pub).unwrap();
    let mut setup_a = [0u8; 512];
    let len_a = init_a
        .build_setup(&initiator_addr, &responder_addr, &mut setup_a)
        .unwrap();

    let mut resp_a = FspSession::new();
    let mut ack_a = [0u8; 512];
    let ack_len_a = resp_a
        .handle_setup(
            &RESP_SECRET,
            &[0xAA; 32],
            &EPOCH_R,
            &setup_a[..len_a],
            &mut ack_a,
        )
        .unwrap();
    let mut ack_a_stored = [0u8; 512];
    ack_a_stored[..ack_len_a].copy_from_slice(&ack_a[..ack_len_a]);
    init_a.handle_ack(&ack_a_stored[..ack_len_a]).unwrap();
    let mut msg3_a = [0u8; 512];
    let msg3_len_a = init_a.build_msg3(&EPOCH_I, &mut msg3_a).unwrap();
    resp_a.handle_msg3(&msg3_a[..msg3_len_a]).unwrap();

    let init_eph_b: [u8; 32] = [0x0B; 32];
    let mut init_b = FspInitiatorSession::new(&INIT_SECRET, &init_eph_b, &resp_pub).unwrap();
    let mut setup_b = [0u8; 512];
    let len_b = init_b
        .build_setup(&initiator_addr, &responder_addr, &mut setup_b)
        .unwrap();

    let mut resp_b = FspSession::new();
    let mut ack_b = [0u8; 512];
    let ack_len_b = resp_b
        .handle_setup(
            &RESP_SECRET,
            &[0xBB; 32],
            &EPOCH_R,
            &setup_b[..len_b],
            &mut ack_b,
        )
        .unwrap();
    let mut ack_b_stored = [0u8; 512];
    ack_b_stored[..ack_len_b].copy_from_slice(&ack_b[..ack_len_b]);
    init_b.handle_ack(&ack_b_stored[..ack_len_b]).unwrap();
    let mut msg3_b = [0u8; 512];
    let msg3_len_b = init_b.build_msg3(&EPOCH_I, &mut msg3_b).unwrap();
    resp_b.handle_msg3(&msg3_b[..msg3_len_b]).unwrap();

    assert_eq!(init_a.state(), fsp::FspInitiatorState::Established);
    assert_eq!(resp_a.state(), fsp::FspSessionState::Established);
    assert_eq!(init_b.state(), fsp::FspInitiatorState::Established);
    assert_eq!(resp_b.state(), fsp::FspSessionState::Established);

    let (_, k_send_a) = init_a.session_keys().unwrap();
    let (_, k_send_b) = init_b.session_keys().unwrap();
    assert_ne!(
        k_send_a, k_send_b,
        "sessions from different ephemerals must have different keys"
    );
}

#[test]
fn test_zero_length_session_payload() {
    let (init_session, mut resp_session, initiator_addr, responder_addr) = do_fsp_handshake();
    let (_init_k_recv, init_k_send) = init_session.session_keys().unwrap();

    let empty_payload: &[u8] = &[];
    let mut plaintext = [0u8; 512];
    let inner = fsp_prepend_inner_header(0, FSP_MSG_DATA, 0x00, empty_payload, &mut plaintext);
    assert_eq!(
        inner, 6,
        "inner header with empty payload should be 6 bytes (FSP_INNER_HEADER_SIZE)"
    );

    let header = build_fsp_header(0, 0x00, (inner + TAG_SIZE) as u16);
    let mut ct = vec![0u8; inner + TAG_SIZE];
    aead_encrypt(&init_k_send, 0, &header, &plaintext[..inner], &mut ct).unwrap();
    let mut fsp_pkt = vec![0u8; FSP_HEADER_SIZE + ct.len()];
    build_fsp_encrypted(&header, &ct, &mut fsp_pkt);

    let dg_body = build_session_datagram_body(&initiator_addr, &responder_addr);
    let mut payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + fsp_pkt.len()];
    payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&fsp_pkt);

    let mut resp_buf = vec![0u8; 1024];
    let result = handle_fsp_datagram(
        &mut resp_session,
        &RESP_SECRET,
        &RESP_EPH,
        &EPOCH_R,
        &payload,
        &mut resp_buf,
    )
    .unwrap();

    assert_eq!(
        result,
        fsp::FspHandlerResult::None,
        "zero-length FSP data payload returns None (no matching handler)"
    );
    assert_eq!(
        resp_session.state(),
        fsp::FspSessionState::Established,
        "session stays Established after empty payload"
    );
}

#[test]
fn test_initiator_handle_ack_while_idle_returns_invalid_state() {
    let resp_pub = resp_pub();
    let init_session = FspInitiatorSession::new(&INIT_SECRET, &INIT_EPH, &resp_pub).unwrap();

    assert_eq!(init_session.state(), fsp::FspInitiatorState::Idle);
    let mut fresh = FspInitiatorSession::new(&INIT_SECRET, &INIT_EPH, &resp_pub).unwrap();
    let dummy_ack = [0u8; 64];
    let result = fresh.handle_ack(&dummy_ack);
    assert_eq!(
        result,
        Err(fsp::FspInitiatorError::InvalidState),
        "handle_ack on Idle initiator must return InvalidState"
    );
}

#[test]
fn test_truncated_session_setup_rejected() {
    let truncated = [0x01u8; 3];
    let mut session = FspSession::new();
    let mut ack_buf = [0u8; 512];
    let result = session.handle_setup(&RESP_SECRET, &RESP_EPH, &EPOCH_R, &truncated, &mut ack_buf);
    assert!(
        result.is_err(),
        "truncated SessionSetup must return an error"
    );
    assert_eq!(
        session.state(),
        fsp::FspSessionState::Idle,
        "state stays Idle after failed setup"
    );
}

#[test]
fn test_msg3_after_established_rejected() {
    let (_init_session, mut resp_session, _, _) = do_fsp_handshake();
    assert_eq!(resp_session.state(), fsp::FspSessionState::Established);

    let dummy_noise = [0xEE; 80];
    let mut msg3_buf = [0u8; 512];
    let msg3_len = build_session_msg3(&dummy_noise, &mut msg3_buf).unwrap();
    let result = resp_session.handle_msg3(&msg3_buf[..msg3_len]);
    assert_eq!(
        result,
        Err(fsp::FspSessionError::InvalidState),
        "handle_msg3 on Established session must return InvalidState"
    );
}
