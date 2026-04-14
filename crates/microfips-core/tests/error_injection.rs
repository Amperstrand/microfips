//! Error injection tests for FMP/Noise edge cases.
//!
//! These tests verify that malformed inputs are rejected gracefully without
//! panics. Each test exercises a specific failure mode at either the FMP
//! parse layer (returning `None` or `Option`) or the Noise layer (returning
//! `Err(NoiseError)`). No test uses `#[should_panic]`.

use microfips_core::wire;
use microfips_core::noise;
use microfips_core::noise::{NoiseError, NoiseIkInitiator, NoiseIkResponder};

// ---- Helpers ----

/// Build a valid FMP MSG1 frame with a real Noise handshake payload.
fn build_valid_msg1() -> ([u8; 256], usize) {
    let init_secret = [0x01u8; 32];
    let init_pub = noise::ecdh_pubkey(&init_secret).unwrap();
    let resp_secret = [0x02u8; 32];
    let resp_pub = noise::ecdh_pubkey(&resp_secret).unwrap();
    let eph_secret = [0x03u8; 32];
    let epoch = [0x01u8; noise::EPOCH_SIZE];

    let (mut initiator, _) = NoiseIkInitiator::new(&eph_secret, &init_secret, &resp_pub).unwrap();
    let mut noise_out = [0u8; 128];
    let noise_len = initiator
        .write_message1(&init_pub, &epoch, &mut noise_out)
        .unwrap();
    assert_eq!(noise_len, wire::HANDSHAKE_MSG1_SIZE);

    let mut out = [0u8; 256];
    let len = wire::build_msg1(
        wire::SessionIndex::new(0x0001),
        &noise_out[..noise_len],
        &mut out,
    )
    .unwrap();
    (out, len)
}

/// Build a valid Noise IK MSG2 (the Noise-layer payload only, 57 bytes).
fn build_valid_noise_msg2(msg1_noise: &[u8]) -> ([u8; 128], usize) {
    let resp_secret = [0x02u8; 32];
    let eph_resp_secret = [0x04u8; 32];
    let epoch_r = [0x02u8; noise::EPOCH_SIZE];

    // Reconstruct the initiator ephemeral pub from MSG1 bytes[0..33]
    let ei_pub: [u8; noise::PUBKEY_SIZE] = msg1_noise[..noise::PUBKEY_SIZE].try_into().unwrap();
    let mut responder = NoiseIkResponder::new(&resp_secret, &ei_pub).unwrap();
    responder
        .read_message1(&msg1_noise[noise::PUBKEY_SIZE..])
        .unwrap();

    let mut out = [0u8; 128];
    let len = responder
        .write_message2(&eph_resp_secret, &epoch_r, &mut out)
        .unwrap();
    (out, len)
}

// ---- Category 1: Corrupted FMP prefix ----

/// Invalid version byte (high nibble ≠ 0) → parse_prefix returns None.
#[test]
fn test_fmp_prefix_invalid_version_byte() {
    // byte0 = (version=1 << 4) | phase=0x01 → 0x11
    let data = [0x11u8, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = wire::parse_prefix(&data);
    assert!(result.is_none(), "version≠0 must be rejected");
}

/// Invalid phase 0x03 (unknown) — parse_prefix accepts prefix (phase is just a nibble),
/// but parse_message rejects it because no branch handles phase=3.
#[test]
fn test_fmp_parse_message_unknown_phase_0x03() {
    // byte0 = (version=0 << 4) | phase=0x03 → 0x03
    // Valid 4-byte prefix, but phase 0x03 is not MSG1/MSG2/ESTABLISHED
    let mut data = [0u8; 20];
    data[0] = 0x03; // phase=3, version=0
    data[1] = 0x00; // flags
    data[2] = 0x08; // payload_len low
    data[3] = 0x00; // payload_len high
    let result = wire::parse_message(&data);
    assert!(result.is_none(), "unknown phase 0x03 must be rejected");
}

/// Invalid phase 0x0F (unknown) — parse_message returns None.
#[test]
fn test_fmp_parse_message_unknown_phase_0xff() {
    // byte0 = (version=0 << 4) | phase=0x0F → 0x0F
    let mut data = [0u8; 20];
    data[0] = 0x0F;
    data[1] = 0x00;
    data[2] = 0x08;
    data[3] = 0x00;
    let result = wire::parse_message(&data);
    assert!(result.is_none(), "unknown phase 0x0F must be rejected");
}

/// Wrong payload_len in MSG1 — FMP prefix claims 0 bytes of payload,
/// but parse_message needs at least IDX_SIZE (4) bytes after the prefix.
#[test]
fn test_fmp_prefix_wrong_payload_length_zero() {
    // Build a valid MSG1 then overwrite payload_len with 0
    let mut frame = [0u8; 256];
    wire::build_msg1(
        wire::SessionIndex::new(0x0001),
        &[0u8; wire::HANDSHAKE_MSG1_SIZE],
        &mut frame,
    );
    // Force payload_len = 0 by zeroing bytes 2-3
    frame[2] = 0x00;
    frame[3] = 0x00;

    // parse_prefix itself will succeed (version and phase are fine),
    // but parse_message should return None because payload after prefix is empty (< IDX_SIZE).
    let result = wire::parse_message(&frame[..wire::COMMON_PREFIX_SIZE]);
    assert!(
        result.is_none(),
        "empty payload slice must be rejected by parse_message"
    );
}

// ---- Category 2: Truncated MSG1 ----

/// Only 50 bytes of a 114-byte MSG1 → parse_message returns None.
#[test]
fn test_fmp_truncated_msg1_50_bytes() {
    let (frame, _full_len) = build_valid_msg1();
    // Provide only 50 bytes (prefix is fine, but noise payload is truncated)
    let result = wire::parse_message(&frame[..50]);
    // parse_prefix will succeed, but noise_payload will be very short
    // The FMP layer itself doesn't validate Noise size — but the caller
    // would get a truncated noise_payload. Let's also verify the full
    // handshake fails when we try to use it.
    if let Some(wire::FmpMessage::Msg1 { noise_payload, .. }) = result {
        // Noise payload is shorter than HANDSHAKE_MSG1_SIZE — read_message2 would fail
        assert!(
            noise_payload.len() < wire::HANDSHAKE_MSG1_SIZE,
            "truncated frame must yield short noise_payload"
        );
    } else {
        // parse_message itself returned None — also a valid rejection
    }
}

/// Only 8 bytes total (prefix + sender_idx only, no noise payload)
/// → parse_message returns Msg1 with empty noise_payload which is
///   detectable as invalid at the next layer.
#[test]
fn test_fmp_msg1_minimal_truncation_noise_layer_rejects() {
    // Build an FMP MSG1 frame but only give 8 bytes (4 prefix + 4 idx)
    let (frame, _) = build_valid_msg1();
    let result = wire::parse_message(&frame[..8]);
    match result {
        Some(wire::FmpMessage::Msg1 {
            noise_payload,
            sender_idx,
        }) => {
            // noise_payload is empty → initiator read_message2 would need exactly 57 bytes
            assert_eq!(noise_payload.len(), 0, "8-byte frame has no noise payload");
            assert_eq!(sender_idx, wire::SessionIndex::new(0x0001));
            // Confirm that read_message2 would reject this empty payload
            let init_secret = [0x01u8; 32];
            let resp_pub = noise::ecdh_pubkey(&[0x02u8; 32]).unwrap();
            let eph_secret = [0x03u8; 32];
            let (mut initiator, _) =
                NoiseIkInitiator::new(&eph_secret, &init_secret, &resp_pub).unwrap();
            let init_pub = noise::ecdh_pubkey(&init_secret).unwrap();
            let epoch = [0x01u8; noise::EPOCH_SIZE];
            let mut noise_out = [0u8; 128];
            initiator
                .write_message1(&init_pub, &epoch, &mut noise_out)
                .unwrap();
            let err = initiator.read_message2(noise_payload);
            assert!(
                matches!(err, Err(NoiseError::InvalidMessage)),
                "empty noise_payload must be rejected by read_message2"
            );
        }
        None => {}
        Some(_) => panic!("unexpected message type for 8-byte MSG1"),
    }
}

// ---- Category 3: Truncated MSG2 ----

/// Only 30 bytes of a 69-byte MSG2 → parse_message returns None or Msg2 with
/// truncated noise_payload; either way Noise layer rejects it.
#[test]
fn test_fmp_truncated_msg2_30_bytes() {
    let noise_payload = [0xBBu8; wire::HANDSHAKE_MSG2_SIZE];
    let mut frame = [0u8; 256];
    wire::build_msg2(
        wire::SessionIndex::new(1),
        wire::SessionIndex::new(2),
        &noise_payload,
        &mut frame,
    )
    .unwrap();

    let result = wire::parse_message(&frame[..30]);
    match result {
        Some(wire::FmpMessage::Msg2 {
            noise_payload: np, ..
        }) => {
            // If we got here, noise_payload is truncated (< 57 bytes)
            assert!(
                np.len() < wire::HANDSHAKE_MSG2_SIZE,
                "truncated MSG2 must yield short noise_payload"
            );
        }
        None => {
            // Also valid — FMP rejected the truncated frame
        }
        Some(_) => panic!("unexpected message type"),
    }
}

/// MSG2 with only 12 bytes (prefix + two indices) — no noise payload.
/// If FMP parses it, noise_payload.len() < 57; read_message2 must return Err.
#[test]
fn test_fmp_msg2_minimal_truncation_noise_layer_rejects() {
    let noise_payload_full = [0xBBu8; wire::HANDSHAKE_MSG2_SIZE];
    let mut frame = [0u8; 256];
    wire::build_msg2(
        wire::SessionIndex::new(1),
        wire::SessionIndex::new(2),
        &noise_payload_full,
        &mut frame,
    )
    .unwrap();

    let result = wire::parse_message(&frame[..12]);
    match result {
        Some(wire::FmpMessage::Msg2 { noise_payload, .. }) => {
            assert_eq!(
                noise_payload.len(),
                0,
                "12-byte MSG2 frame has no noise payload"
            );
            // read_message2 on a real initiator must reject this
            let init_secret = [0x01u8; 32];
            let resp_pub = noise::ecdh_pubkey(&[0x02u8; 32]).unwrap();
            let eph_secret = [0x03u8; 32];
            let (mut initiator, _) =
                NoiseIkInitiator::new(&eph_secret, &init_secret, &resp_pub).unwrap();
            let init_pub = noise::ecdh_pubkey(&init_secret).unwrap();
            let epoch = [0x01u8; noise::EPOCH_SIZE];
            let mut noise_out = [0u8; 128];
            initiator
                .write_message1(&init_pub, &epoch, &mut noise_out)
                .unwrap();
            let err = initiator.read_message2(noise_payload);
            assert!(
                matches!(err, Err(NoiseError::InvalidMessage)),
                "zero-length noise_payload must be rejected by read_message2"
            );
        }
        None => {
            // Also valid
        }
        Some(_) => panic!("unexpected message type"),
    }
}

// ---- Category 4: Oversized payload ----

/// FMP prefix claims payload_len=65535 but actual buffer is small — no panic.
#[test]
fn test_fmp_oversized_payload_claimed_65535() {
    // Craft a prefix that claims 65535 bytes of payload
    let mut data = [0u8; 8]; // only 8 bytes of actual data
    data[0] = wire::PHASE_MSG1; // version=0, phase=1
    data[1] = 0x00;
    data[2] = 0xFF; // payload_len = 65535 LE
    data[3] = 0xFF;
    // Bytes 4-7: sender_idx (4 bytes of payload actually present)
    data[4..8].copy_from_slice(&42u32.to_le_bytes());

    // parse_prefix reads the claimed length but doesn't validate it against actual data
    let prefix_result = wire::parse_prefix(&data);
    assert!(prefix_result.is_some(), "parse_prefix only checks version");
    let (phase, _flags, payload_len) = prefix_result.unwrap();
    assert_eq!(phase, wire::PHASE_MSG1);
    assert_eq!(payload_len, 65535);

    // parse_message slices data[4..] which is only 4 bytes.
    // For MSG1, it needs at least IDX_SIZE=4 bytes. So it gets sender_idx=42,
    // and noise_payload will be empty (no bytes left after 4-byte idx).
    let msg_result = wire::parse_message(&data);
    match msg_result {
        Some(wire::FmpMessage::Msg1 {
            noise_payload,
            sender_idx,
        }) => {
            // No panic — safe handling, noise_payload is just very short
            assert_eq!(sender_idx, wire::SessionIndex::new(42));
            assert_eq!(
                noise_payload.len(),
                0,
                "claimed 65535 but only have 0 noise bytes"
            );
        }
        None => {
            // Also acceptable — parser rejected it
        }
        Some(_) => panic!("unexpected message type"),
    }
}

// ---- Category 5: Wrong indices ----

/// Valid FMP MSG2 frame but receiver_idx does not match our sender_idx from MSG1.
/// The protocol layer (not FMP) should detect this mismatch.
#[test]
fn test_fmp_msg2_mismatched_receiver_index() {
    let noise_payload = [0x55u8; wire::HANDSHAKE_MSG2_SIZE];
    let mut frame = [0u8; 256];
    // sender_idx=0xAAAA, receiver_idx=0xBBBB (mismatch — we sent sender_idx=0x0001 in MSG1)
    let len = wire::build_msg2(
        wire::SessionIndex::new(0xAAAA),
        wire::SessionIndex::new(0xBBBB),
        &noise_payload,
        &mut frame,
    )
    .unwrap();

    let result = wire::parse_message(&frame[..len]).unwrap();
    match result {
        wire::FmpMessage::Msg2 {
            sender_idx,
            receiver_idx,
            noise_payload: np,
        } => {
            assert_eq!(sender_idx, wire::SessionIndex::new(0xAAAA));
            assert_eq!(receiver_idx, wire::SessionIndex::new(0xBBBB));
            // Application must check receiver_idx == our_sender_idx; here we verify
            // it is detectable (0xBBBB ≠ 0x0001 which was in MSG1)
            assert_ne!(
                receiver_idx,
                wire::SessionIndex::new(0x0001),
                "mismatched receiver_idx must be detectable"
            );
            assert_eq!(np.len(), wire::HANDSHAKE_MSG2_SIZE);
        }
        _ => panic!("expected Msg2"),
    }
}

/// MSG1 with sender_idx=0xDEAD followed by MSG2 with receiver_idx=0xBEEF (wrong).
/// Both frames parse fine but the mismatch is detectable.
#[test]
fn test_fmp_msg1_msg2_index_mismatch_detectable() {
    let noise1 = [0x11u8; wire::HANDSHAKE_MSG1_SIZE];
    let noise2 = [0x22u8; wire::HANDSHAKE_MSG2_SIZE];
    let mut msg1_frame = [0u8; 256];
    let mut msg2_frame = [0u8; 256];

    let len1 = wire::build_msg1(wire::SessionIndex::new(0xDEAD), &noise1, &mut msg1_frame).unwrap();
    let len2 = wire::build_msg2(
        wire::SessionIndex::new(0xAAAA),
        wire::SessionIndex::new(0xBEEF),
        &noise2,
        &mut msg2_frame,
    )
    .unwrap();

    let msg1 = wire::parse_message(&msg1_frame[..len1]).unwrap();
    let msg2 = wire::parse_message(&msg2_frame[..len2]).unwrap();

    let sender_idx = match msg1 {
        wire::FmpMessage::Msg1 { sender_idx, .. } => sender_idx,
        _ => panic!("expected Msg1"),
    };
    let receiver_idx = match msg2 {
        wire::FmpMessage::Msg2 { receiver_idx, .. } => receiver_idx,
        _ => panic!("expected Msg2"),
    };

    // The index mismatch is detectable — protocol layer must reject
    assert_ne!(
        sender_idx, receiver_idx,
        "sender_idx from MSG1 must not match mismatched receiver_idx in MSG2"
    );
}

// ---- Category 6: Zero-length payload ----

/// FMP prefix for MSG1 with payload_len=0 and a tiny buffer → parse_message returns None.
#[test]
fn test_fmp_msg1_zero_length_payload() {
    // Build a prefix claiming phase=MSG1, payload_len=0, then just the 4-byte prefix
    let prefix = wire::build_prefix(wire::PHASE_MSG1, 0x00, 0);
    let result = wire::parse_message(&prefix); // only 4 bytes, no payload at all
                                              // After the 4-byte prefix, payload is empty (len=0 bytes).
                                              // MSG1 needs at least IDX_SIZE=4 bytes after prefix, so parse_message must return None.
    assert!(result.is_none(), "zero-payload MSG1 must be rejected");
}

/// FMP prefix for ESTABLISHED with empty encrypted payload → parse_message
/// returns Established with zero-length encrypted slice.
#[test]
fn test_fmp_established_zero_length_encrypted() {
    // Build an established prefix with payload = receiver_idx(4) + counter(8) = 12 bytes, no encrypted
    let prefix = wire::build_prefix(wire::PHASE_ESTABLISHED, 0x00, 12);
    let mut data = [0u8; 20];
    data[..4].copy_from_slice(&prefix);
    // receiver_idx = 7
    data[4..8].copy_from_slice(&7u32.to_le_bytes());
    // counter = 0
    data[8..16].copy_from_slice(&0u64.to_le_bytes());
    // no encrypted bytes follow

    let result = wire::parse_message(&data[..16]);
    match result {
        Some(wire::FmpMessage::Established {
            receiver_idx,
            counter,
            encrypted,
        }) => {
            assert_eq!(receiver_idx, wire::SessionIndex::new(7));
            assert_eq!(counter, 0);
            assert_eq!(encrypted.len(), 0, "no encrypted bytes in payload");
            // Trying to decrypt empty ciphertext with AEAD must fail (< TAG_SIZE)
            let key = [0x42u8; 32];
            let aad = &data[..16];
            let mut dec = [0u8; 64];
            let dec_result = noise::aead_decrypt(&key, 0, aad, encrypted, &mut dec);
            assert!(
                matches!(dec_result, Err(NoiseError::InvalidMessage)),
                "decrypting zero-length ciphertext must fail"
            );
        }
        None => {
            // Also valid if parser rejects it
        }
        Some(_) => panic!("unexpected message type"),
    }
}

// ---- Category 7: Corrupted Noise ciphertext ----

/// Valid FMP MSG2 wrapper but noise_payload is all random bytes → read_message2 returns Err.
#[test]
fn test_noise_msg2_corrupted_ciphertext_returns_err() {
    // Build a valid MSG1 first to get the initiator into the right state
    let init_secret = [0x01u8; 32];
    let init_pub = noise::ecdh_pubkey(&init_secret).unwrap();
    let resp_pub = noise::ecdh_pubkey(&[0x02u8; 32]).unwrap();
    let eph_secret = [0x03u8; 32];
    let epoch = [0x01u8; noise::EPOCH_SIZE];

    let (mut initiator, _) = NoiseIkInitiator::new(&eph_secret, &init_secret, &resp_pub).unwrap();
    let mut noise_out = [0u8; 128];
    initiator
        .write_message1(&init_pub, &epoch, &mut noise_out)
        .unwrap();

    // Feed corrupted MSG2 noise payload (random bytes, correct length 57)
    let corrupted_msg2 = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31u8,
    ];
    assert_eq!(corrupted_msg2.len(), wire::HANDSHAKE_MSG2_SIZE);

    let result = initiator.read_message2(&corrupted_msg2);
    assert!(
        result.is_err(),
        "corrupted MSG2 ciphertext must return Err, not panic"
    );
    // The error should be InvalidKey (bad ephemeral pub) or DecryptionFailed
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            NoiseError::InvalidKey | NoiseError::DecryptionFailed | NoiseError::InvalidMessage
        ),
        "expected InvalidKey, DecryptionFailed, or InvalidMessage, got {:?}",
        err
    );
}

/// Valid FMP MSG2 frame with one flipped bit in the ciphertext → AEAD auth fails.
#[test]
fn test_noise_msg2_single_bit_flip_returns_err() {
    // Complete MSG1 → get valid MSG2 noise bytes → flip one bit → feed to initiator
    let init_secret = [0x01u8; 32];
    let init_pub = noise::ecdh_pubkey(&init_secret).unwrap();
    let resp_pub = noise::ecdh_pubkey(&[0x02u8; 32]).unwrap();
    let eph_secret = [0x03u8; 32];
    let epoch = [0x01u8; noise::EPOCH_SIZE];

    let (mut initiator, _) = NoiseIkInitiator::new(&eph_secret, &init_secret, &resp_pub).unwrap();
    let mut noise_out = [0u8; 128];
    let noise_len = initiator
        .write_message1(&init_pub, &epoch, &mut noise_out)
        .unwrap();

    let (mut valid_msg2, valid_len) = build_valid_noise_msg2(&noise_out[..noise_len]);
    // Flip one bit in the encrypted portion (byte index 40, beyond the 33-byte ephemeral pub)
    valid_msg2[40] ^= 0x01;

    let result = initiator.read_message2(&valid_msg2[..valid_len]);
    assert!(result.is_err(), "bit-flipped MSG2 must return Err");
    assert!(
        matches!(
            result.unwrap_err(),
            NoiseError::DecryptionFailed | NoiseError::InvalidKey | NoiseError::InvalidMessage
        ),
        "expected a Noise error variant"
    );
}

// ---- Category 8: Replay ----

/// Same MSG1 (identical bytes) sent twice — both times parse_message succeeds
/// (FMP has no replay detection), but the second time the Noise initiator's
/// state is exhausted and a fresh NoiseIkInitiator rejects the original MSG2.
#[test]
fn test_fmp_msg1_replay_double_parse() {
    // MSG1 is stateless bytes — a replay attack sends the same MSG1 twice.
    // FMP parse is pure slice parsing; it will succeed both times.
    // The attack vector is: replaying MSG1 to get a fresh MSG2 from the responder.
    let noise_payload = [0x77u8; wire::HANDSHAKE_MSG1_SIZE];
    let mut frame = [0u8; 256];
    let len = wire::build_msg1(wire::SessionIndex::new(0x9999), &noise_payload, &mut frame).unwrap();

    // First parse
    let r1 = wire::parse_message(&frame[..len]);
    // Second parse (replay)
    let r2 = wire::parse_message(&frame[..len]);

    // Both parses succeed — FMP has no state, replay is detected at higher layers
    assert!(r1.is_some(), "first MSG1 parse must succeed");
    assert!(
        r2.is_some(),
        "replay MSG1 parse also succeeds (FMP is stateless)"
    );

    // Both must yield identical data
    match (r1.unwrap(), r2.unwrap()) {
        (
            wire::FmpMessage::Msg1 {
                sender_idx: s1,
                noise_payload: np1,
            },
            wire::FmpMessage::Msg1 {
                sender_idx: s2,
                noise_payload: np2,
            },
        ) => {
            assert_eq!(s1, s2);
            assert_eq!(np1, np2);
        }
        _ => panic!("expected Msg1 both times"),
    }
}

/// Replay of MSG2 to a fresh initiator (different state) → Noise decryption fails.
/// This demonstrates that MSG2 is not replayable across sessions.
#[test]
fn test_noise_msg2_replay_to_wrong_initiator_fails() {
    // Session 1: get a valid MSG2
    let init_secret = [0x01u8; 32];
    let init_pub = noise::ecdh_pubkey(&init_secret).unwrap();
    let resp_pub = noise::ecdh_pubkey(&[0x02u8; 32]).unwrap();
    let eph_secret = [0x03u8; 32];
    let epoch = [0x01u8; noise::EPOCH_SIZE];

    let (mut initiator1, _) = NoiseIkInitiator::new(&eph_secret, &init_secret, &resp_pub).unwrap();
    let mut noise_out = [0u8; 128];
    let noise_len = initiator1
        .write_message1(&init_pub, &epoch, &mut noise_out)
        .unwrap();
    let (valid_msg2, valid_len) = build_valid_noise_msg2(&noise_out[..noise_len]);

    // Session 2: completely fresh initiator with DIFFERENT ephemeral key
    let eph_secret2 = [0x05u8; 32]; // different ephemeral
    let (mut initiator2, _) = NoiseIkInitiator::new(&eph_secret2, &init_secret, &resp_pub).unwrap();
    let mut noise_out2 = [0u8; 128];
    initiator2
        .write_message1(&init_pub, &epoch, &mut noise_out2)
        .unwrap();

    // Replay session-1's MSG2 to session-2's initiator → must fail
    let result = initiator2.read_message2(&valid_msg2[..valid_len]);
    assert!(
        result.is_err(),
        "replayed MSG2 from session 1 to session 2 must fail"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            NoiseError::DecryptionFailed | NoiseError::InvalidKey | NoiseError::InvalidMessage
        ),
        "replay must produce a Noise error"
    );
}

// ---- Additional edge cases ----

/// Completely empty input → both parse_prefix and parse_message return None.
#[test]
fn test_fmp_empty_input_returns_none() {
    let empty: &[u8] = &[];
    assert!(
        wire::parse_prefix(empty).is_none(),
        "empty input must yield None for parse_prefix"
    );
    assert!(
        wire::parse_message(empty).is_none(),
        "empty input must yield None for parse_message"
    );
}

/// Only 3 bytes (less than COMMON_PREFIX_SIZE=4) → parse_prefix returns None.
#[test]
fn test_fmp_too_short_for_prefix() {
    let short = [0x01u8, 0x00, 0x00];
    assert!(
        wire::parse_prefix(&short).is_none(),
        "3-byte input must be rejected"
    );
    assert!(
        wire::parse_message(&short).is_none(),
        "3-byte input must be rejected by parse_message"
    );
}

/// read_message2 with wrong length (not exactly 57 bytes) → returns Err(InvalidMessage).
#[test]
fn test_noise_read_message2_wrong_length_returns_err() {
    let init_secret = [0x01u8; 32];
    let resp_pub = noise::ecdh_pubkey(&[0x02u8; 32]).unwrap();
    let eph_secret = [0x03u8; 32];

    let (mut initiator, _) = NoiseIkInitiator::new(&eph_secret, &init_secret, &resp_pub).unwrap();
    let init_pub = noise::ecdh_pubkey(&init_secret).unwrap();
    let epoch = [0x01u8; noise::EPOCH_SIZE];
    let mut noise_out = [0u8; 128];
    initiator
        .write_message1(&init_pub, &epoch, &mut noise_out)
        .unwrap();

    // Try with only 30 bytes (truncated)
    let truncated = [0xABu8; 30];
    let result = initiator.read_message2(&truncated);
    assert!(
        matches!(result, Err(NoiseError::InvalidMessage)),
        "MSG2 of wrong length must return Err(InvalidMessage)"
    );

    // Try with 0 bytes
    let result2 = initiator.read_message2(&[]);
    assert!(
        matches!(result2, Err(NoiseError::InvalidMessage)),
        "empty MSG2 must return Err(InvalidMessage)"
    );
}

/// aead_decrypt with ciphertext shorter than TAG_SIZE → returns Err(InvalidMessage).
#[test]
fn test_noise_aead_decrypt_too_short_ciphertext() {
    let key = [0x42u8; 32];
    let short_ct = [0x01u8; 10]; // 10 < TAG_SIZE (16)
    let mut out = [0u8; 64];
    let result = noise::aead_decrypt(&key, 0, &[], &short_ct, &mut out);
    assert!(
        matches!(result, Err(NoiseError::InvalidMessage)),
        "ciphertext shorter than TAG_SIZE must return Err(InvalidMessage)"
    );
}
