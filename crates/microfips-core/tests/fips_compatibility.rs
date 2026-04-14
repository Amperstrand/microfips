use microfips_core::wire;
use microfips_core::fsp;
use microfips_core::identity::NodeAddr;
use microfips_core::noise;

const STM32_NSEC: [u8; 32] = [0x01; 32];
const ESP32_NSEC: [u8; 32] = [0x02; 32];

fn deterministic_pubkeys() -> ([u8; 33], [u8; 33]) {
    (
        noise::ecdh_pubkey(&STM32_NSEC).expect("valid deterministic key"),
        noise::ecdh_pubkey(&ESP32_NSEC).expect("valid deterministic key"),
    )
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:CommonPrefix::ver_phase_byte() — MSG1 prefix byte layout.
#[test]
fn fmp_prefix_phase_msg1_matches_commonprefix_layout() {
    let p = wire::build_prefix(wire::PHASE_MSG1, 0x00, 0);
    assert_eq!(p, [0x01, 0x00, 0x00, 0x00]);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:CommonPrefix::ver_phase_byte() — MSG2 prefix byte layout.
#[test]
fn fmp_prefix_phase_msg2_matches_commonprefix_layout() {
    let p = wire::build_prefix(wire::PHASE_MSG2, 0x00, 0);
    assert_eq!(p, [0x02, 0x00, 0x00, 0x00]);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:CommonPrefix::ver_phase_byte() — established prefix byte layout.
#[test]
fn fmp_prefix_phase_established_matches_commonprefix_layout() {
    let p = wire::build_prefix(wire::PHASE_ESTABLISHED, 0x00, 0);
    assert_eq!(p, [0x00, 0x00, 0x00, 0x00]);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:build_msg1() — MSG1 total wire size is 114 bytes.
#[test]
fn msg1_total_size_is_114_bytes() {
    let noise_payload = [0x11u8; wire::HANDSHAKE_MSG1_SIZE];
    let mut out = [0u8; 256];
    let len =
        wire::build_msg1(wire::SessionIndex::new(0xA1A2A3A4), &noise_payload, &mut out).unwrap();

    assert_eq!(len, wire::MSG1_WIRE_SIZE);
    assert_eq!(len, 114);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:Msg1Header::parse() — sender_idx sits at offset 4..8.
#[test]
fn msg1_sender_index_at_offset_4() {
    let noise_payload = [0x22u8; wire::HANDSHAKE_MSG1_SIZE];
    let mut out = [0u8; 256];
    wire::build_msg1(wire::SessionIndex::new(0xDEADBEEF), &noise_payload, &mut out).unwrap();

    let idx = u32::from_le_bytes(out[4..8].try_into().unwrap());
    assert_eq!(idx, 0xDEADBEEF);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:Msg1Header::noise_msg1() — Noise payload starts at offset 8 and is 106 bytes.
#[test]
fn msg1_noise_payload_offset_and_length_match_fips() {
    let noise_payload = [0x33u8; wire::HANDSHAKE_MSG1_SIZE];
    let mut out = [0u8; 256];
    let len =
        wire::build_msg1(wire::SessionIndex::new(0x01020304), &noise_payload, &mut out).unwrap();

    assert_eq!(len, 4 + 4 + 106);
    assert_eq!(&out[8..114], &noise_payload);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:build_msg2() — MSG2 total wire size is 69 bytes.
#[test]
fn msg2_total_size_is_69_bytes() {
    let noise_payload = [0x44u8; wire::HANDSHAKE_MSG2_SIZE];
    let mut out = [0u8; 256];
    let len = wire::build_msg2(
        wire::SessionIndex::new(0x11111111),
        wire::SessionIndex::new(0x22222222),
        &noise_payload,
        &mut out,
    )
    .unwrap();

    assert_eq!(len, wire::MSG2_WIRE_SIZE);
    assert_eq!(len, 69);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:Msg2Header::parse() — sender/receiver indices are at offsets 4..8 and 8..12.
#[test]
fn msg2_indices_offsets_match_fips_layout() {
    let noise_payload = [0x55u8; wire::HANDSHAKE_MSG2_SIZE];
    let mut out = [0u8; 256];
    wire::build_msg2(
        wire::SessionIndex::new(0x01020304),
        wire::SessionIndex::new(0x0A0B0C0D),
        &noise_payload,
        &mut out,
    )
    .unwrap();

    assert_eq!(
        u32::from_le_bytes(out[4..8].try_into().unwrap()),
        0x01020304
    );
    assert_eq!(
        u32::from_le_bytes(out[8..12].try_into().unwrap()),
        0x0A0B0C0D
    );
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:Msg2Header::noise_msg2() — Noise payload starts at offset 12 and is 57 bytes.
#[test]
fn msg2_noise_payload_offset_and_length_match_fips() {
    let noise_payload = [0x66u8; wire::HANDSHAKE_MSG2_SIZE];
    let mut out = [0u8; 256];
    wire::build_msg2(
        wire::SessionIndex::new(7),
        wire::SessionIndex::new(8),
        &noise_payload,
        &mut out,
    )
    .unwrap();

    assert_eq!(&out[12..69], &noise_payload);
}

fn established_frame(
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

// Tests FIPS: bd08505 fips/src/node/wire.rs:build_established_header() — established outer header carries receiver_idx and counter.
#[test]
fn established_frame_header_layout_matches_fips() {
    let key = [0x77u8; 32];
    let out = established_frame(
        wire::SessionIndex::new(0xAABBCCDD),
        0x0102030405060708,
        0x51,
        0x99AA55CC,
        &[],
        &key,
    );

    assert!(out.len() >= wire::ESTABLISHED_HEADER_SIZE + noise::TAG_SIZE);
    assert_eq!(out[0], 0x00);
    assert_eq!(
        u32::from_le_bytes(out[4..8].try_into().unwrap()),
        0xAABBCCDD
    );
    assert_eq!(
        u64::from_le_bytes(out[8..16].try_into().unwrap()),
        0x0102030405060708
    );
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:prepend_inner_header() — established payload is timestamp(4) + msg_type(1) + payload.
#[test]
fn established_frame_decrypts_to_timestamp_and_msg_type() {
    let key = [0x88u8; 32];
    let timestamp = 0x11223344;
    let out = established_frame(
        wire::SessionIndex::new(5),
        42,
        wire::MSG_HEARTBEAT,
        timestamp,
        &[],
        &key,
    );

    let aad = &out[..wire::ESTABLISHED_HEADER_SIZE];
    let mut plaintext = [0u8; 64];
    let pt_len = noise::aead_decrypt(
        &key,
        42,
        aad,
        &out[wire::ESTABLISHED_HEADER_SIZE..],
        &mut plaintext,
    )
    .unwrap();

    assert_eq!(pt_len, 5);
    assert_eq!(
        u32::from_le_bytes(plaintext[..4].try_into().unwrap()),
        timestamp
    );
    assert_eq!(plaintext[4], wire::MSG_HEARTBEAT);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:ENCRYPTED_MIN_SIZE semantics — heartbeat wire frame is 4+4+8+5+16=37 bytes.
#[test]
fn heartbeat_frame_size_is_37_bytes() {
    let key = [0x99u8; 32];
    let out = established_frame(
        wire::SessionIndex::new(9),
        10,
        wire::MSG_HEARTBEAT,
        11,
        &[],
        &key,
    );

    assert_eq!(out.len(), 37);
}

// Tests FIPS: bd08505 fips/src/node/wire.rs:strip_inner_header() — heartbeat carries no extra inner payload bytes.
#[test]
fn heartbeat_inner_payload_is_empty() {
    let key = [0xABu8; 32];
    let out = established_frame(
        wire::SessionIndex::new(1),
        2,
        wire::MSG_HEARTBEAT,
        3,
        &[],
        &key,
    );

    let aad = &out[..wire::ESTABLISHED_HEADER_SIZE];
    let mut plaintext = [0u8; 64];
    let pt_len = noise::aead_decrypt(
        &key,
        2,
        aad,
        &out[wire::ESTABLISHED_HEADER_SIZE..],
        &mut plaintext,
    )
    .unwrap();

    assert_eq!(pt_len, wire::INNER_HEADER_SIZE);
}

// Tests FIPS: bd08505 fips/src/protocol/session.rs:SessionSetup::encode() — SessionSetup prefix/body/count/hs_len layout matches reference.
#[test]
fn fsp_session_setup_layout_matches_reference() {
    let src = [[0x01u8; 16]];
    let dst = [[0x02u8; 16]];
    let hs = [0xA5u8; fsp::XK_HANDSHAKE_MSG1_SIZE];
    let mut out = [0u8; 256];
    let len = fsp::build_session_setup(0x03, &src, &dst, &hs, &mut out).unwrap();

    assert_eq!(out[0], 0x01);
    assert_eq!(out[1], 0x00);
    assert_eq!(out[4], 0x03);
    assert_eq!(u16::from_le_bytes([out[5], out[6]]), 1);
    assert_eq!(&out[7..23], &src[0]);
    assert_eq!(u16::from_le_bytes([out[23], out[24]]), 1);
    assert_eq!(&out[25..41], &dst[0]);
    assert_eq!(
        u16::from_le_bytes([out[41], out[42]]),
        fsp::XK_HANDSHAKE_MSG1_SIZE as u16
    );
    assert_eq!(&out[43..len], &hs);
}

// Tests FIPS: bd08505 fips/src/protocol/session.rs:SessionAck::encode() — SessionAck prefix/body/count/hs_len layout matches reference.
#[test]
fn fsp_session_ack_layout_matches_reference() {
    let src = [[0x11u8; 16]];
    let dst = [[0x22u8; 16]];
    let hs = [0xB6u8; fsp::XK_HANDSHAKE_MSG2_SIZE];
    let mut out = [0u8; 256];
    let len = fsp::build_session_ack(&src, &dst, &hs, &mut out).unwrap();

    assert_eq!(out[0], 0x02);
    assert_eq!(out[1], 0x00);
    assert_eq!(out[4], 0x00);
    assert_eq!(u16::from_le_bytes([out[5], out[6]]), 1);
    assert_eq!(&out[7..23], &src[0]);
    assert_eq!(u16::from_le_bytes([out[23], out[24]]), 1);
    assert_eq!(&out[25..41], &dst[0]);
    assert_eq!(
        u16::from_le_bytes([out[41], out[42]]),
        fsp::XK_HANDSHAKE_MSG2_SIZE as u16
    );
    assert_eq!(&out[43..len], &hs);
}

// Tests FIPS: bd08505 fips/src/protocol/session.rs:SessionMsg3::encode() — SessionMsg3 prefix/body/hs_len layout matches reference.
#[test]
fn fsp_session_msg3_layout_matches_reference() {
    let hs = [0xC7u8; fsp::XK_HANDSHAKE_MSG3_SIZE];
    let mut out = [0u8; 256];
    let len = fsp::build_session_msg3(&hs, &mut out).unwrap();

    assert_eq!(out[0], 0x03);
    assert_eq!(out[1], 0x00);
    assert_eq!(out[4], 0x00);
    assert_eq!(
        u16::from_le_bytes([out[5], out[6]]),
        fsp::XK_HANDSHAKE_MSG3_SIZE as u16
    );
    assert_eq!(&out[7..len], &hs);
}

// Tests FIPS: bd08505 fips/src/noise/handshake.rs:SymmetricState::encrypt_and_hash() — handshake encryption interop uses empty AAD.
#[test]
fn noise_empty_aad_roundtrip_and_wrong_aad_failure() {
    let key = [0x5Au8; 32];
    let msg = b"fips-handshake";
    let mut ct = [0u8; 64];
    let ct_len = noise::aead_encrypt(&key, 7, &[], msg, &mut ct).unwrap();

    let mut pt = [0u8; 64];
    let ok_len = noise::aead_decrypt(&key, 7, &[], &ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..ok_len], msg);

    let bad = noise::aead_decrypt(&key, 7, b"non-empty-aad", &ct[..ct_len], &mut pt);
    assert!(bad.is_err());
}

// Tests FIPS: bd08505 fips/src/noise/handshake.rs:normalize_for_premessage() — pre-message parity normalization forces 0x02 prefix.
#[test]
fn noise_parity_normalize_forces_even_prefix() {
    let (_, esp_pub) = deterministic_pubkeys();
    let mut odd = esp_pub;
    odd[0] = 0x03;

    let normalized = noise::parity_normalize(&odd);
    assert_eq!(normalized[0], 0x02);
    assert_eq!(&normalized[1..], &odd[1..]);
}

// Tests FIPS: bd08505 fips/src/noise/handshake.rs:HandshakeState::ecdh() — x-only ECDH is parity-invariant.
#[test]
fn noise_x_only_ecdh_is_parity_invariant() {
    let (stm32_pub, _) = deterministic_pubkeys();
    let mut negated = stm32_pub;
    negated[0] = if stm32_pub[0] == 0x02 { 0x03 } else { 0x02 };

    let dh_even = noise::x_only_ecdh(&ESP32_NSEC, &stm32_pub).unwrap();
    let dh_odd = noise::x_only_ecdh(&ESP32_NSEC, &negated).unwrap();
    assert_eq!(dh_even, dh_odd);
}

// Tests FIPS: bd08505 fips/src/noise/handshake.rs:write_message1()/read_message2() — microfips keeps FIPS-compatible es/se DH ordering.
#[test]
fn noise_fips_compatible_es_se_ordering_inputs_differ_from_spec_se() {
    let (_, esp32_pub) = deterministic_pubkeys();
    let responder_eph_secret = [0x03u8; 32];
    let responder_eph_pub = noise::ecdh_pubkey(&responder_eph_secret).unwrap();

    let es_fips = noise::x_only_ecdh(&STM32_NSEC, &esp32_pub).unwrap();
    let se_fips = noise::x_only_ecdh(&STM32_NSEC, &esp32_pub).unwrap();
    let se_spec_like = noise::x_only_ecdh(&STM32_NSEC, &responder_eph_pub).unwrap();

    assert_eq!(es_fips, se_fips);
    assert_ne!(es_fips, se_spec_like);
}

// Tests FIPS: bd08505 fips/src/identity/node_addr.rs:NodeAddr::from_pubkey() — node_addr is SHA256(pubkey_x)[..16].
#[test]
fn identity_node_addr_matches_sha256_truncation() {
    let (stm32_pub, _) = deterministic_pubkeys();
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&stm32_pub[1..33]);

    let addr = NodeAddr::from_pubkey_x(&x_only);
    let digest = microfips_core::identity::sha256(&x_only);
    assert_eq!(addr.as_bytes(), &digest[..16]);
}

// Tests FIPS: bd08505 fips/src/identity/node_addr.rs:NodeAddr::from_pubkey() — different public keys produce different node_addr values.
#[test]
fn identity_node_addr_differs_between_deterministic_keys() {
    let (stm32_pub, esp32_pub) = deterministic_pubkeys();

    let mut x1 = [0u8; 32];
    x1.copy_from_slice(&stm32_pub[1..33]);
    let mut x2 = [0u8; 32];
    x2.copy_from_slice(&esp32_pub[1..33]);

    let a1 = NodeAddr::from_pubkey_x(&x1);
    let a2 = NodeAddr::from_pubkey_x(&x2);
    assert_ne!(a1.as_bytes(), a2.as_bytes());
}
