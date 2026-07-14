//! Golden vector tests for Noise IK handshake.
//!
//! These vectors are generated from microfips-core's Noise implementation
//! using deterministic keys. They serve as regression tests: if any crypto
//! code changes, these tests fail. They can also be verified against the
//! upstream FIPS daemon's Noise implementation for cross-validation.
//!
//! To regenerate vectors: `cargo run -p microfips-core --example gen_golden_vectors --features std`

use microfips_core::noise::{self, PUBKEY_SIZE};

const INIT_STATIC_SECRET: [u8; 32] = [0x11; 32];
const INIT_EPH_SECRET: [u8; 32] = [0x01; 32];
const RESP_STATIC_SECRET: [u8; 32] = [0x22; 32];
const RESP_EPH_SECRET: [u8; 32] = [0xAA; 32];
const EPOCH_A: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const EPOCH_B: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

const GOLDEN_MSG1_HEX: &str = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f8fbabc9585161aace9b5957f305bdb278db340ca4389a1367b62ebfef36a1562f8baf6b700e6982034fe68dfeecc1a39d50186304acbfef02b0128a140ebb783ecb92b6c938d87a4f7";
const GOLDEN_MSG2_HEX: &str = "026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb313e610c8ebe1ddc15b4e06d076b72407bc9bce0c5319f58a";
const GOLDEN_K1_HEX: &str = "f17534b1ee1585e86ca578c5d040f413bb4291927e2cd2754a05950ea8aeb2b3";
const GOLDEN_K2_HEX: &str = "3bcaf03c8ce78d3d221c59b1d59f9f38242f491f640f5d52c7f62c7f6f9a3e6b";

const GOLDEN_INIT_STATIC_PUB_HEX: &str =
    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const GOLDEN_RESP_STATIC_PUB_HEX: &str =
    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
const GOLDEN_INIT_EPH_PUB_HEX: &str =
    "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

fn decode_hex_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).unwrap();
    assert_eq!(bytes.len(), 32);
    bytes.try_into().unwrap()
}

fn decode_hex_vec(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn golden_vector_ik_msg1_bytes() {
    let resp_pub = noise::ecdh_pubkey(&RESP_STATIC_SECRET).unwrap();
    let init_pub = noise::ecdh_pubkey(&INIT_STATIC_SECRET).unwrap();
    let (mut init, _e_pub) =
        noise::NoiseIkInitiator::new(&INIT_EPH_SECRET, &INIT_STATIC_SECRET, &resp_pub).unwrap();

    let mut msg1 = [0u8; 256];
    let msg1_len = init.write_message1(&init_pub, &EPOCH_A, &mut msg1).unwrap();

    assert_eq!(msg1_len, 106);
    assert_eq!(
        &msg1[..msg1_len],
        decode_hex_vec(GOLDEN_MSG1_HEX).as_slice()
    );
}

#[test]
fn golden_vector_ik_msg2_bytes() {
    let resp_pub = noise::ecdh_pubkey(&RESP_STATIC_SECRET).unwrap();
    let init_pub = noise::ecdh_pubkey(&INIT_STATIC_SECRET).unwrap();
    let (mut init, _) =
        noise::NoiseIkInitiator::new(&INIT_EPH_SECRET, &INIT_STATIC_SECRET, &resp_pub).unwrap();

    let mut msg1 = [0u8; 256];
    let msg1_len = init.write_message1(&init_pub, &EPOCH_A, &mut msg1).unwrap();

    let e_init_pub: &[u8; PUBKEY_SIZE] = msg1[..PUBKEY_SIZE].try_into().unwrap();
    let mut resp = noise::NoiseIkResponder::new(&RESP_STATIC_SECRET, e_init_pub).unwrap();
    resp.read_message1(&msg1[PUBKEY_SIZE..msg1_len]).unwrap();

    let mut msg2 = [0u8; 128];
    let msg2_len = resp
        .write_message2(&RESP_EPH_SECRET, &EPOCH_B, &mut msg2)
        .unwrap();

    assert_eq!(msg2_len, 57);
    assert_eq!(
        &msg2[..msg2_len],
        decode_hex_vec(GOLDEN_MSG2_HEX).as_slice()
    );
}

#[test]
fn golden_vector_ik_transport_keys_match() {
    let resp_pub = noise::ecdh_pubkey(&RESP_STATIC_SECRET).unwrap();
    let init_pub = noise::ecdh_pubkey(&INIT_STATIC_SECRET).unwrap();
    let (mut init, _) =
        noise::NoiseIkInitiator::new(&INIT_EPH_SECRET, &INIT_STATIC_SECRET, &resp_pub).unwrap();

    let mut msg1 = [0u8; 256];
    let msg1_len = init.write_message1(&init_pub, &EPOCH_A, &mut msg1).unwrap();

    let e_init_pub: &[u8; PUBKEY_SIZE] = msg1[..PUBKEY_SIZE].try_into().unwrap();
    let mut resp = noise::NoiseIkResponder::new(&RESP_STATIC_SECRET, e_init_pub).unwrap();
    resp.read_message1(&msg1[PUBKEY_SIZE..msg1_len]).unwrap();

    let mut msg2 = [0u8; 128];
    let msg2_len = resp
        .write_message2(&RESP_EPH_SECRET, &EPOCH_B, &mut msg2)
        .unwrap();

    init.read_message2(&msg2[..msg2_len]).unwrap();

    let (k1_init, k2_init) = init.finalize();
    let (k1_resp, k2_resp) = resp.finalize();

    assert_eq!(
        k1_init, k1_resp,
        "initiator and responder must agree on k1 (init→resp)"
    );
    assert_eq!(
        k2_init, k2_resp,
        "initiator and responder must agree on k2 (resp→init)"
    );

    assert_eq!(k1_init, decode_hex_32(GOLDEN_K1_HEX));
    assert_eq!(k2_init, decode_hex_32(GOLDEN_K2_HEX));
}

#[test]
fn golden_vector_ik_pubkeys_deterministic() {
    let init_pub = noise::ecdh_pubkey(&INIT_STATIC_SECRET).unwrap();
    let resp_pub = noise::ecdh_pubkey(&RESP_STATIC_SECRET).unwrap();
    let (_, e_pub) =
        noise::NoiseIkInitiator::new(&INIT_EPH_SECRET, &INIT_STATIC_SECRET, &resp_pub).unwrap();

    assert_eq!(hex::encode(init_pub), GOLDEN_INIT_STATIC_PUB_HEX);
    assert_eq!(hex::encode(resp_pub), GOLDEN_RESP_STATIC_PUB_HEX);
    assert_eq!(hex::encode(e_pub), GOLDEN_INIT_EPH_PUB_HEX);
}

#[test]
fn golden_vector_ik_identity_recovery() {
    let resp_pub = noise::ecdh_pubkey(&RESP_STATIC_SECRET).unwrap();
    let init_pub = noise::ecdh_pubkey(&INIT_STATIC_SECRET).unwrap();
    let (mut init, _) =
        noise::NoiseIkInitiator::new(&INIT_EPH_SECRET, &INIT_STATIC_SECRET, &resp_pub).unwrap();

    let mut msg1 = [0u8; 256];
    let msg1_len = init.write_message1(&init_pub, &EPOCH_A, &mut msg1).unwrap();

    let e_init_pub: &[u8; PUBKEY_SIZE] = msg1[..PUBKEY_SIZE].try_into().unwrap();
    let mut resp = noise::NoiseIkResponder::new(&RESP_STATIC_SECRET, e_init_pub).unwrap();
    let (recv_init_pub, recv_epoch_a) = resp.read_message1(&msg1[PUBKEY_SIZE..msg1_len]).unwrap();

    assert_eq!(
        recv_init_pub, init_pub,
        "responder must recover initiator's static pubkey"
    );
    assert_eq!(
        recv_epoch_a, EPOCH_A,
        "responder must recover initiator's epoch"
    );
}

/// Cross-validation: feed a FIPS-generated MSG1 into microfips's NoiseIkResponder.
///
/// This MSG1 was generated by the upstream FIPS daemon's Noise implementation
/// (src/noise/handshake.rs) using the same deterministic static keys:
///   initiator_static_secret = [0x11; 32]
///   responder_static_secret = [0x22; 32]
///   initiator_epoch = [0x01, 0x00, ...]
///   ephemeral key = random (FIPS generates internally)
///
/// If microfips can decrypt the initiator's static pubkey from this FIPS-generated
/// MSG1, the two implementations are byte-level compatible at the crypto layer.
#[test]
fn cross_validate_fips_generated_msg1() {
    let fips_msg1_hex = "0214a9a0411a87f1343b3ccc62bb3ce58041e292d5a001dafe992837db62fb6d939714ea8349e47cddea5b408b565aa82cca65ef3b0e87a9da209f2acd0a0c9d36dfe9939ee515d06cd5e435ab0513a08077abced26ba4b497e02523455fdcb031a6237feba618f0a4aa";
    let fips_msg1 = hex::decode(fips_msg1_hex).unwrap();
    assert_eq!(fips_msg1.len(), 106, "FIPS MSG1 must be 106 bytes");

    let e_init_pub: &[u8; PUBKEY_SIZE] = fips_msg1[..PUBKEY_SIZE].try_into().unwrap();

    let mut responder = noise::NoiseIkResponder::new(&RESP_STATIC_SECRET, e_init_pub).unwrap();
    let (recv_init_pub, recv_epoch) = responder
        .read_message1(&fips_msg1[PUBKEY_SIZE..])
        .expect("microfips must be able to process FIPS-generated MSG1");

    let expected_init_pub = noise::ecdh_pubkey(&INIT_STATIC_SECRET).unwrap();
    assert_eq!(
        recv_init_pub, expected_init_pub,
        "microfips must recover FIPS's initiator static pubkey from FIPS-generated MSG1"
    );
    assert_eq!(
        recv_epoch, EPOCH_A,
        "microfips must recover FIPS's initiator epoch from FIPS-generated MSG1"
    );
}
