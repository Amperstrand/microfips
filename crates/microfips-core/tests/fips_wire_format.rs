//! Byte-exact wire format comparison tests against FIPS reference.
//!
//! These tests verify that our wire format output matches the FIPS reference
//! implementation at commit `bd085050022ef298b9fd918824e7d983c079ae3c`.
//!
//! FIPS source: `/root/src/fips/src/`
//! - `node/wire.rs` — FMP common prefix, MSG1, MSG2, established frame
//! - `node/session_wire.rs` — FSP common prefix, encrypted header, inner header
//! - `protocol/link.rs` — SessionDatagram
//! - `protocol/session.rs` — SessionSetup, SessionAck, SessionMsg3
//! - `noise/mod.rs` — Noise constants, CipherState
//! - `noise/handshake.rs` — HandshakeState, SymmetricState

use microfips_core::fmp;
use microfips_core::fsp;
use microfips_core::noise;

fn gen_key() -> [u8; 32] {
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

// ---- FMP Wire Format Tests ----

#[test]
fn test_fmp_prefix_version_phase_encoding() {
    // FIPS: wire.rs:114-116 ver_phase_byte() = (version << 4) | (phase & 0x0F)
    // FIPS: wire.rs:28 FMP_VERSION=0
    let p1 = fmp::build_prefix(fmp::PHASE_MSG1, 0x00, 0);
    assert_eq!(p1[0], 0x01, "phase 1: version=0, phase=1");
    assert_eq!(p1[1], 0x00, "flags=0");
    assert_eq!(p1[2], 0x00, "payload_len low=0");
    assert_eq!(p1[3], 0x00, "payload_len high=0");

    let p2 = fmp::build_prefix(fmp::PHASE_MSG2, 0x03, 65);
    assert_eq!(p2[0], 0x02, "phase 2: version=0, phase=2");
    assert_eq!(p2[1], 0x03, "flags=3");
    assert_eq!(u16::from_le_bytes([p2[2], p2[3]]), 65);

    let pe = fmp::build_prefix(fmp::PHASE_ESTABLISHED, 0x00, 100);
    assert_eq!(pe[0], 0x00, "phase 0: version=0, phase=0");
    assert_eq!(u16::from_le_bytes([pe[2], pe[3]]), 100);
}

#[test]
fn test_fmp_msg1_wire_layout() {
    // FIPS: wire.rs:314-326 build_msg1()
    // Layout: [0x01][0x00][payload_len:2LE][sender_idx:4LE][noise_payload:106]
    let noise_payload = [0x42u8; fmp::HANDSHAKE_MSG1_SIZE];
    let mut out = [0u8; 256];
    let len = fmp::build_msg1(0xDEADBEEF, &noise_payload, &mut out).unwrap();

    assert_eq!(len, fmp::MSG1_WIRE_SIZE, "MSG1 total size");
    assert_eq!(len, 114, "MSG1 = 4+4+106");

    // Byte 0: ver_phase
    assert_eq!(out[0], 0x01, "version=0, phase=1");
    // Byte 1: flags
    assert_eq!(out[1], 0x00, "flags=0");
    // Bytes 2-3: payload_len = IDX_SIZE + 106 = 110
    assert_eq!(
        u16::from_le_bytes([out[2], out[3]]),
        110,
        "payload_len=4+106=110"
    );
    // Bytes 4-7: sender_idx
    assert_eq!(
        u32::from_le_bytes(out[4..8].try_into().unwrap()),
        0xDEADBEEF
    );
    // Bytes 8-113: noise payload
    assert_eq!(&out[8..114], &noise_payload[..]);
}

#[test]
fn test_fmp_msg2_wire_layout() {
    // FIPS: wire.rs:331-344 build_msg2()
    // Layout: [0x02][0x00][payload_len:2LE][sender_idx:4LE][receiver_idx:4LE][noise_payload:57]
    let noise_payload = [0x42u8; fmp::HANDSHAKE_MSG2_SIZE];
    let mut out = [0u8; 256];
    let len = fmp::build_msg2(1, 2, &noise_payload, &mut out).unwrap();

    assert_eq!(len, fmp::MSG2_WIRE_SIZE, "MSG2 total size");
    assert_eq!(len, 69, "MSG2 = 4+4+4+57");

    assert_eq!(out[0], 0x02, "version=0, phase=2");
    assert_eq!(out[1], 0x00, "flags=0");
    assert_eq!(
        u16::from_le_bytes([out[2], out[3]]),
        65,
        "payload_len=4+4+57=65"
    );
    assert_eq!(
        u32::from_le_bytes(out[4..8].try_into().unwrap()),
        1,
        "sender_idx"
    );
    assert_eq!(
        u32::from_le_bytes(out[8..12].try_into().unwrap()),
        2,
        "receiver_idx"
    );
    assert_eq!(&out[12..69], &noise_payload[..]);
}

#[test]
fn test_fmp_established_header_is_16_bytes_aad() {
    // FIPS: wire.rs:349-362 build_established_header()
    // FIPS: wire.rs:43 ESTABLISHED_HEADER_SIZE=16
    // FIPS: encrypted.rs:97 uses header_bytes (first 16 bytes) as AEAD AAD
    let key = [0x42u8; 32];
    let mut out = [0u8; 256];
    let len =
        fmp::build_established(5, 42, fmp::MSG_HEARTBEAT, 99999, &[], &key, &mut out).unwrap();

    assert!(
        len >= fmp::ESTABLISHED_HEADER_SIZE,
        "must have at least 16-byte header"
    );

    // First 16 bytes = AEAD AAD
    let aad = &out[..fmp::ESTABLISHED_HEADER_SIZE];
    // Byte 0: ver_phase = (0<<4)|0x0 = 0x00
    assert_eq!(aad[0], 0x00, "established phase=0");
    // Byte 1: flags = 0x00
    assert_eq!(aad[1], 0x00, "flags=0");
    // Bytes 4-7: receiver_idx = 5
    assert_eq!(
        u32::from_le_bytes(aad[4..8].try_into().unwrap()),
        5,
        "receiver_idx"
    );
    // Bytes 8-15: counter = 42
    assert_eq!(
        u64::from_le_bytes(aad[8..16].try_into().unwrap()),
        42,
        "counter"
    );

    // Verify AEAD decrypt with these 16 bytes as AAD produces correct plaintext
    let encrypted = &out[fmp::ESTABLISHED_HEADER_SIZE..len];
    let mut dec = [0u8; 512];
    let dl = noise::aead_decrypt(&key, 42, aad, encrypted, &mut dec).unwrap();
    assert_eq!(
        dl,
        fmp::INNER_HEADER_SIZE,
        "heartbeat has 5-byte inner header"
    );
    let ts = u32::from_le_bytes(dec[..4].try_into().unwrap());
    assert_eq!(ts, 99999, "timestamp preserved");
    assert_eq!(dec[4], fmp::MSG_HEARTBEAT, "msg_type=heartbeat");
}

// ---- FSP Wire Format Tests ----

#[test]
fn test_fsp_header_is_12_bytes_aad() {
    // FIPS: session_wire.rs:245-256 build_fsp_header()
    // FIPS: session_wire.rs:61 FSP_HEADER_SIZE=12
    // FIPS: session.rs:199 uses header_bytes (first 12 bytes) as AEAD AAD
    let header = fsp::build_fsp_header(99, 0x00, 42);

    assert_eq!(header.len(), fsp::FSP_HEADER_SIZE, "FSP header = 12 bytes");
    // Byte 0: ver_phase = (0<<4)|0x0 = 0x00
    assert_eq!(header[0], 0x00, "FSP established phase=0");
    // Byte 1: flags = 0x00
    assert_eq!(header[1], 0x00, "flags=0");
    // Bytes 2-3: payload_len = 42
    assert_eq!(
        u16::from_le_bytes([header[2], header[3]]),
        42,
        "payload_len"
    );
    // Bytes 4-11: counter = 99
    assert_eq!(
        u64::from_le_bytes(header[4..12].try_into().unwrap()),
        99,
        "counter"
    );
}

#[test]
fn test_fsp_inner_header_is_6_bytes() {
    // FIPS: session_wire.rs:305-317 fsp_prepend_inner_header()
    // FIPS: session_wire.rs:64 FSP_INNER_HEADER_SIZE=6
    // Layout: [timestamp:4LE][msg_type:1][inner_flags:1]
    let payload = b"hello world";
    let mut out = [0u8; 64];
    let len = fsp::fsp_prepend_inner_header(12345, 0x10, 0x01, payload, &mut out);

    assert_eq!(
        len,
        fsp::FSP_INNER_HEADER_SIZE + payload.len(),
        "6 + payload"
    );
    assert_eq!(
        u32::from_le_bytes(out[..4].try_into().unwrap()),
        12345,
        "timestamp"
    );
    assert_eq!(out[4], 0x10, "msg_type=DATA");
    assert_eq!(out[5], 0x01, "inner_flags=spin");
    assert_eq!(&out[fsp::FSP_INNER_HEADER_SIZE..len], payload);
}

#[test]
fn test_fsp_inner_header_strip_roundtrip() {
    // FIPS: session_wire.rs:322-332 fsp_strip_inner_header()
    let payload = b"data";
    let mut out = [0u8; 64];
    fsp::fsp_prepend_inner_header(0, 0x10, 0x00, payload, &mut out);
    let (ts, mt, ifl, rest) =
        fsp::fsp_strip_inner_header(&out[..fsp::FSP_INNER_HEADER_SIZE + payload.len()]).unwrap();
    assert_eq!(ts, 0);
    assert_eq!(mt, 0x10);
    assert_eq!(ifl, 0x00);
    assert_eq!(rest, payload);
}

#[test]
fn test_session_datagram_body_layout() {
    // FIPS: link.rs:355-378 SessionDatagram::encode()
    // Layout: [ttl:1][path_mtu:2LE][src_addr:16][dest_addr:16] = 35 bytes
    // FIPS: link.rs:301 SESSION_DATAGRAM_HEADER_SIZE=36 (includes msg_type byte, which is in FMP inner header)
    let src = [0xAA; 16];
    let dst = [0xBB; 16];
    let body = fsp::build_session_datagram_body(&src, &dst);

    assert_eq!(body.len(), fsp::SESSION_DATAGRAM_BODY_SIZE, "35 bytes");
    assert_eq!(body.len(), 35);
    assert_eq!(fsp::SESSION_DATAGRAM_HEADER_SIZE, 36);
    assert_eq!(
        fsp::SESSION_DATAGRAM_HEADER_SIZE,
        fsp::SESSION_DATAGRAM_BODY_SIZE + 1
    );

    // Byte 0: TTL
    assert_eq!(body[0], 64, "TTL=64");

    // Bytes 1-2: path_mtu LE
    assert_eq!(
        u16::from_le_bytes([body[1], body[2]]),
        1400,
        "path_mtu=1400"
    );

    // Bytes 3-18: src_addr
    assert_eq!(&body[3..19], &src, "src_addr");

    // Bytes 19-34: dest_addr
    assert_eq!(&body[19..35], &dst, "dest_addr");
}

#[test]
fn test_session_setup_wire_layout() {
    // FIPS: session.rs:384-402 SessionSetup::encode()
    // Layout: [prefix:4][flags:1][src_count:2LE][src_coords:16*n][dst_count:2LE][dst_coords:16*m][hs_len:2LE][hs]
    let src_coord = [0x01u8; 16];
    let dst_coord = [0x02u8; 16];
    let handshake = [0xAA; fsp::XK_HANDSHAKE_MSG1_SIZE]; // 33 bytes
    let mut out = [0u8; 256];
    let len =
        fsp::build_session_setup(0x03, &[src_coord], &[dst_coord], &handshake, &mut out).unwrap();

    // Prefix: [0x01][0x00][payload_len:2LE]
    assert_eq!(out[0], 0x01, "phase=SESSION_SETUP");
    assert_eq!(out[1], 0x00, "flags=0 in prefix");

    // Body starts at offset 4
    let body_len = u16::from_le_bytes([out[2], out[3]]) as usize;
    assert_eq!(4 + body_len, len, "total = prefix + body");

    // flags byte
    assert_eq!(out[4], 0x03, "session_flags");

    // src_count = 1
    assert_eq!(u16::from_le_bytes([out[5], out[6]]), 1, "src_count=1");

    // src_coord at offset 7
    assert_eq!(&out[7..23], &src_coord, "src_coord");

    // dst_count = 1
    let dst_count_off = 7 + 16;
    assert_eq!(
        u16::from_le_bytes([out[dst_count_off], out[dst_count_off + 1]]),
        1,
        "dst_count=1"
    );

    // dst_coord at offset 25
    assert_eq!(
        &out[dst_count_off + 2..dst_count_off + 18],
        &dst_coord,
        "dst_coord"
    );

    // hs_len
    let hs_len_off = dst_count_off + 18;
    assert_eq!(
        u16::from_le_bytes([out[hs_len_off], out[hs_len_off + 1]]),
        33,
        "hs_len=XK_MSG1_SIZE=33"
    );

    // handshake payload
    assert_eq!(
        &out[hs_len_off + 2..len],
        &handshake[..],
        "handshake payload"
    );
}

#[test]
fn test_session_ack_wire_layout() {
    // FIPS: session.rs:504-522 SessionAck::encode()
    // Same structure as SessionSetup but with phase 0x02 and flags=0
    let src_coord = [0x01u8; 16];
    let dst_coord = [0x02u8; 16];
    let handshake = [0xCC; fsp::XK_HANDSHAKE_MSG2_SIZE]; // 57 bytes
    let mut out = [0u8; 256];
    let len = fsp::build_session_ack(&[src_coord], &[dst_coord], &handshake, &mut out).unwrap();

    assert_eq!(out[0], 0x02, "phase=SESSION_ACK");
    assert_eq!(out[1], 0x00, "flags=0 in prefix");
    assert_eq!(out[4], 0x00, "ack flags=0");

    // src_count = 1
    assert_eq!(u16::from_le_bytes([out[5], out[6]]), 1, "src_count=1");
    assert_eq!(&out[7..23], &src_coord, "src_coord");

    // dst_count = 1
    assert_eq!(u16::from_le_bytes([out[23], out[24]]), 1, "dst_count=1");
    assert_eq!(&out[25..41], &dst_coord, "dst_coord");

    // hs_len
    assert_eq!(
        u16::from_le_bytes([out[41], out[42]]),
        57,
        "hs_len=XK_MSG2_SIZE=57"
    );
    assert_eq!(&out[43..len], &handshake[..], "handshake payload");
}

#[test]
fn test_session_msg3_wire_layout() {
    // FIPS: session.rs:605-621 SessionMsg3::encode()
    // Layout: [prefix:4][flags:1][hs_len:2LE][hs] — NO coordinates
    let handshake = [0xDD; fsp::XK_HANDSHAKE_MSG3_SIZE]; // 73 bytes
    let mut out = [0u8; 256];
    let len = fsp::build_session_msg3(&handshake, &mut out).unwrap();

    assert_eq!(out[0], 0x03, "phase=SESSION_MSG3");
    assert_eq!(out[1], 0x00, "flags=0 in prefix");
    assert_eq!(out[4], 0x00, "msg3 flags=0");
    assert_eq!(
        u16::from_le_bytes([out[5], out[6]]),
        73,
        "hs_len=XK_MSG3_SIZE=73"
    );
    assert_eq!(&out[7..len], &handshake[..], "handshake payload");
}

// ---- Noise Key Derivation Tests ----

#[test]
fn test_noise_ik_transport_key_direction_matches_fips() {
    // FIPS: handshake.rs:85-97 split()
    // FIPS: handshake.rs:837-862 into_session()
    // Initiator: send=k1, recv=k2
    // Responder: send=k2, recv=k1
    //
    // This test verifies our IK initiator produces non-zero, distinct k1 and k2
    // from finalize(), and that a matching responder produces swapped keys.
    use noise::{ecdh_pubkey, NoiseIkInitiator, NoiseIkResponder};

    let init_secret = gen_key();
    let resp_secret = gen_key();
    let resp_pub = ecdh_pubkey(&resp_secret).unwrap();
    let init_pub = ecdh_pubkey(&init_secret).unwrap();
    let epoch_r = [0x02; 8];
    let epoch_i = [0x01; 8];
    let eph_init = gen_key();
    let eph_resp = gen_key();

    let (mut initiator, _) = NoiseIkInitiator::new(&eph_init, &init_secret, &resp_pub).unwrap();
    let mut n1 = [0u8; 256];
    let n1_len = initiator
        .write_message1(&init_pub, &epoch_i, &mut n1)
        .unwrap();
    assert_eq!(n1_len, 106);

    let mut responder = NoiseIkResponder::new(&resp_secret, &n1[..33].try_into().unwrap()).unwrap();
    let (_, recv_epoch) = responder.read_message1(&n1[33..n1_len]).unwrap();
    assert_eq!(recv_epoch, epoch_i);

    let mut msg2 = [0u8; 128];
    let msg2_len = responder
        .write_message2(&eph_resp, &epoch_r, &mut msg2)
        .unwrap();
    assert_eq!(msg2_len, 57);

    initiator.read_message2(&msg2[..msg2_len]).unwrap();

    let (k_send_i, k_recv_i) = initiator.finalize();
    let (k_recv_r, k_send_r) = responder.finalize();

    // FIPS: initiator send=k1, recv=k2. responder send=k2, recv=k1.
    assert_ne!(k_send_i, [0u8; 32], "k_send is non-zero");
    assert_ne!(k_recv_i, [0u8; 32], "k_recv is non-zero");
    assert_ne!(k_send_i, k_recv_i, "k_send != k_recv");

    assert_eq!(k_recv_r, k_send_i, "responder k_recv == initiator k_send");
    assert_eq!(k_send_r, k_recv_i, "responder k_send == initiator k_recv");
}

#[test]
fn test_noise_ik_transport_key_symmetry_randomized() {
    use noise::{ecdh_pubkey, NoiseIkInitiator, NoiseIkResponder};

    for _ in 0..8 {
        let init_secret = gen_key();
        let resp_secret = gen_key();
        let resp_pub = ecdh_pubkey(&resp_secret).unwrap();
        let init_pub = ecdh_pubkey(&init_secret).unwrap();
        let epoch_i = [0x01; 8];
        let epoch_r = [0x02; 8];
        let eph_init = gen_key();
        let eph_resp = gen_key();

        let (mut initiator, _) = NoiseIkInitiator::new(&eph_init, &init_secret, &resp_pub).unwrap();
        let mut msg1 = [0u8; 256];
        let msg1_len = initiator
            .write_message1(&init_pub, &epoch_i, &mut msg1)
            .unwrap();

        let e_init: [u8; 33] = msg1[..33].try_into().unwrap();
        let mut responder = NoiseIkResponder::new(&resp_secret, &e_init).unwrap();
        let (_peer_pub, recv_epoch) = responder.read_message1(&msg1[33..msg1_len]).unwrap();
        assert_eq!(recv_epoch, epoch_i);

        let mut msg2 = [0u8; 128];
        let msg2_len = responder
            .write_message2(&eph_resp, &epoch_r, &mut msg2)
            .unwrap();
        initiator.read_message2(&msg2[..msg2_len]).unwrap();

        let (k_send_i, k_recv_i) = initiator.finalize();
        let (k_recv_r, k_send_r) = responder.finalize();
        assert_eq!(k_recv_r, k_send_i);
        assert_eq!(k_send_r, k_recv_i);
    }
}

#[test]
fn test_noise_xk_transport_key_symmetry() {
    // FIPS: handshake.rs:85-97 split()
    // FIPS: handshake.rs:837-862 into_session()
    // XK: Initiator send=k1, recv=k2. Responder send=k2, recv=k1.
    // Our XK implementation MUST produce matching keys (unlike IK where D2 breaks symmetry).
    use fsp::FspSession;
    use noise::{ecdh_pubkey, NoiseXkInitiator};

    let init_secret = gen_key();
    let resp_secret = gen_key();
    let resp_pub = ecdh_pubkey(&resp_secret).unwrap();
    let init_pub = ecdh_pubkey(&init_secret).unwrap();
    let eph_init = gen_key();
    let eph_resp = gen_key();
    let epoch_r = [0x01; 8];
    let epoch_i = [0x02; 8];

    // Build XK msg1
    let (mut initiator, _) = NoiseXkInitiator::new(&eph_init, &init_secret, &resp_pub).unwrap();
    let mut xk_msg1 = [0u8; 64];
    let msg1_len = initiator.write_message1(&mut xk_msg1).unwrap();
    assert_eq!(msg1_len, 33);

    // Responder processes msg1, sends msg2
    let mut session = FspSession::new();
    let initiator_addr = [0x02u8; 16];
    let responder_addr = [0x01u8; 16];
    let mut setup_buf = [0u8; 512];
    let setup_len = fsp::build_session_setup(
        0x03,
        &[responder_addr],
        &[initiator_addr],
        &xk_msg1[..msg1_len],
        &mut setup_buf,
    )
    .unwrap();

    let mut ack_buf = [0u8; 512];
    let ack_len = session
        .handle_setup(
            &resp_secret,
            &eph_resp,
            &epoch_r,
            &setup_buf[..setup_len],
            &mut ack_buf,
        )
        .unwrap();

    // Initiator processes msg2, sends msg3
    let msg2_payload = fsp::parse_session_ack(&ack_buf[..ack_len]).unwrap();
    let _resp_epoch = initiator.read_message2(msg2_payload).unwrap();

    let mut msg3_noise = [0u8; 128];
    let msg3_len = initiator
        .write_message3(&init_pub, &epoch_i, &mut msg3_noise)
        .unwrap();
    assert_eq!(msg3_len, 73);

    let mut msg3_buf = [0u8; 512];
    let msg3_fsp_len = fsp::build_session_msg3(&msg3_noise[..msg3_len], &mut msg3_buf).unwrap();

    // Responder processes msg3, derives keys
    session.handle_msg3(&msg3_buf[..msg3_fsp_len]).unwrap();

    // Initiator finalizes
    let (k_send_i, k_recv_i) = initiator.finalize();

    // Verify key symmetry: responder's k_recv == initiator's k_send
    let (k_recv, k_send) = session.session_keys().unwrap();
    assert_eq!(k_recv, k_send_i, "session k_recv == initiator k_send");
    assert_eq!(k_send, k_recv_i, "session k_send == initiator k_recv");
    assert_ne!(k_send, k_recv, "send and recv keys are different");
}

#[test]
fn test_noise_constants_match_fips() {
    // FIPS: mod.rs:65-92
    assert_eq!(noise::TAG_SIZE, 16, "FIPS: mod.rs:65");
    assert_eq!(noise::EPOCH_SIZE, 8, "FIPS: mod.rs:71");
    assert_eq!(noise::PUBKEY_SIZE, 33, "FIPS: mod.rs:68");
    assert_eq!(fmp::HANDSHAKE_MSG1_SIZE, 106, "FIPS: mod.rs:77 — 33+49+24");
    assert_eq!(fmp::HANDSHAKE_MSG2_SIZE, 57, "FIPS: mod.rs:80 — 33+24");
    assert_eq!(fsp::XK_HANDSHAKE_MSG1_SIZE, 33, "FIPS: mod.rs:83");
    assert_eq!(fsp::XK_HANDSHAKE_MSG2_SIZE, 57, "FIPS: mod.rs:86");
    assert_eq!(fsp::XK_HANDSHAKE_MSG3_SIZE, 73, "FIPS: mod.rs:89 — 49+24");
}

#[test]
fn test_fmp_constants_match_fips() {
    // FIPS: wire.rs:28-67
    assert_eq!(fmp::FMP_VERSION, 0, "FIPS: wire.rs:28");
    assert_eq!(fmp::COMMON_PREFIX_SIZE, 4, "FIPS: wire.rs:40");
    assert_eq!(fmp::ESTABLISHED_HEADER_SIZE, 16, "FIPS: wire.rs:43 — 4+4+8");
    assert_eq!(fmp::INNER_HEADER_SIZE, 5, "FIPS: wire.rs:55 — 4+1");
    assert_eq!(fmp::ENCRYPTED_MIN_SIZE, 32, "FIPS: wire.rs:52 — 16+16");
    assert_eq!(fmp::MSG1_WIRE_SIZE, 114, "FIPS: wire.rs:46 — 4+4+106");
    assert_eq!(fmp::MSG2_WIRE_SIZE, 69, "FIPS: wire.rs:49 — 4+4+4+57");
    assert_eq!(fmp::PHASE_ESTABLISHED, 0x00, "FIPS: wire.rs:31");
    assert_eq!(fmp::PHASE_MSG1, 0x01, "FIPS: wire.rs:34");
    assert_eq!(fmp::PHASE_MSG2, 0x02, "FIPS: wire.rs:37");
    assert_eq!(fmp::FLAG_KEY_EPOCH, 0x01, "FIPS: wire.rs:61");
    assert_eq!(fmp::FLAG_CE, 0x02, "FIPS: wire.rs:64");
    assert_eq!(fmp::FLAG_SP, 0x04, "FIPS: wire.rs:67");
}

#[test]
fn test_fsp_constants_match_fips() {
    // FIPS: session_wire.rs:43-96
    assert_eq!(fsp::FSP_VERSION, 0, "FIPS: session_wire.rs:43");
    assert_eq!(fsp::FSP_COMMON_PREFIX_SIZE, 4, "FIPS: session_wire.rs:58");
    assert_eq!(
        fsp::FSP_HEADER_SIZE,
        12,
        "FIPS: session_wire.rs:61 — prefix(4)+counter(8)"
    );
    assert_eq!(
        fsp::FSP_INNER_HEADER_SIZE,
        6,
        "FIPS: session_wire.rs:64 — ts(4)+type(1)+flags(1)"
    );
    assert_eq!(
        fsp::FSP_ENCRYPTED_MIN_SIZE,
        28,
        "FIPS: session_wire.rs:70 — 12+16"
    );
    assert_eq!(fsp::FSP_PORT_IPV6_SHIM, 256, "FIPS: session_wire.rs:78");
    assert_eq!(fsp::FLAG_COORDS_PRESENT, 0x01, "FIPS: session_wire.rs:83");
    assert_eq!(fsp::FLAG_KEY_EPOCH, 0x02, "FIPS: session_wire.rs:87");
    assert_eq!(fsp::FLAG_UNENCRYPTED, 0x04, "FIPS: session_wire.rs:90");
    assert_eq!(fsp::SESSION_DATAGRAM_BODY_SIZE, 35, "FIPS: link.rs:355-378");
}

#[test]
fn test_fsp_encrypted_roundtrip_with_realistic_payload() {
    use noise::aead_decrypt;

    let key = [0xAB; 32];
    let counter = 7u64;
    let timestamp_ms = 42u32;
    let msg_type = fsp::FSP_MSG_DATA;
    let inner_flags = 0x00;
    let app_payload = b"PING";

    let mut packet = [0u8; 256];
    let pkt_len =
        fsp::build_fsp_data_message(counter, timestamp_ms, app_payload, &key, &mut packet).unwrap();

    let (flags, parsed_counter, parsed_header, parsed_ct) =
        fsp::parse_fsp_encrypted_header(&packet[..pkt_len]).unwrap();
    assert_eq!(flags, 0x00);
    assert_eq!(parsed_counter, counter);
    assert_eq!(parsed_header.len(), fsp::FSP_HEADER_SIZE);
    assert_eq!(parsed_ct.len(), pkt_len - fsp::FSP_HEADER_SIZE);

    let mut dec = [0u8; 64];
    let dl = aead_decrypt(&key, counter, parsed_header, parsed_ct, &mut dec).unwrap();
    let (ts, mt, ifl, rest) = fsp::fsp_strip_inner_header(&dec[..dl]).unwrap();
    assert_eq!(ts, timestamp_ms);
    assert_eq!(mt, msg_type);
    assert_eq!(ifl, inner_flags);
    assert_eq!(rest, app_payload);
}
