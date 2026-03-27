pub const FMP_VERSION: u8 = 0;
pub const COMMON_PREFIX_SIZE: usize = 4;
pub const IDX_SIZE: usize = 4;
pub const ESTABLISHED_HEADER_SIZE: usize = 16;
pub const INNER_HEADER_SIZE: usize = 5; // 4-byte timestamp + at least 1 byte msg_type
pub const ENCRYPTED_MIN_SIZE: usize = 32;

pub const HANDSHAKE_MSG1_SIZE: usize = 106;
pub const HANDSHAKE_MSG2_SIZE: usize = 57;
pub const EPOCH_ENCRYPTED_SIZE: usize = 24;

pub const MSG1_WIRE_SIZE: usize = 114;
pub const MSG2_WIRE_SIZE: usize = 69;

pub const PHASE_ESTABLISHED: u8 = 0x00;
pub const PHASE_MSG1: u8 = 0x01;
pub const PHASE_MSG2: u8 = 0x02;

pub const MSG_HEARTBEAT: u8 = 0x51;
pub const MSG_SESSION_DATAGRAM: u8 = 0x00;
pub const MSG_SENDER_REPORT: u8 = 0x01;
pub const MSG_RECEIVER_REPORT: u8 = 0x02;
pub const MSG_DISCONNECT: u8 = 0x50;

pub const FLAG_KEY_EPOCH: u8 = 0x01;
pub const FLAG_CONGESTION: u8 = 0x02;
pub const FLAG_SPIN: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FmpMessage<'a> {
    Msg1 {
        sender_idx: u32,
        noise_payload: &'a [u8],
    },
    Msg2 {
        sender_idx: u32,
        receiver_idx: u32,
        noise_payload: &'a [u8],
    },
    Established {
        receiver_idx: u32,
        counter: u64,
        encrypted: &'a [u8],
    },
}

pub fn build_prefix(phase: u8, flags: u8, payload_len: u16) -> [u8; COMMON_PREFIX_SIZE] {
    let byte0 = (FMP_VERSION << 4) | (phase & 0x0F);
    [byte0, flags, payload_len as u8, (payload_len >> 8) as u8]
}

pub fn parse_prefix(data: &[u8]) -> Option<(u8, u8, u16)> {
    if data.len() < COMMON_PREFIX_SIZE {
        return None;
    }
    let version = data[0] >> 4;
    let phase = data[0] & 0x0F;
    let flags = data[1];
    let payload_len = u16::from_le_bytes([data[2], data[3]]);
    if version != FMP_VERSION {
        return None;
    }
    Some((phase, flags, payload_len))
}

pub fn build_msg1(sender_idx: u32, noise_payload: &[u8], out: &mut [u8]) -> usize {
    let needed = COMMON_PREFIX_SIZE + IDX_SIZE + noise_payload.len();
    assert!(out.len() >= needed);
    let payload_len = (IDX_SIZE + noise_payload.len()) as u16;
    let prefix = build_prefix(PHASE_MSG1, 0x00, payload_len);
    out[..COMMON_PREFIX_SIZE].copy_from_slice(&prefix);
    out[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
        .copy_from_slice(&sender_idx.to_le_bytes());
    out[COMMON_PREFIX_SIZE + IDX_SIZE..needed].copy_from_slice(noise_payload);
    needed
}

pub fn build_msg2(
    sender_idx: u32,
    receiver_idx: u32,
    noise_payload: &[u8],
    out: &mut [u8],
) -> usize {
    let needed = COMMON_PREFIX_SIZE + IDX_SIZE * 2 + noise_payload.len();
    assert!(out.len() >= needed);
    let payload_len = (IDX_SIZE * 2 + noise_payload.len()) as u16;
    let prefix = build_prefix(PHASE_MSG2, 0x00, payload_len);
    out[..COMMON_PREFIX_SIZE].copy_from_slice(&prefix);
    out[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
        .copy_from_slice(&sender_idx.to_le_bytes());
    out[COMMON_PREFIX_SIZE + IDX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE * 2]
        .copy_from_slice(&receiver_idx.to_le_bytes());
    out[COMMON_PREFIX_SIZE + IDX_SIZE * 2..needed].copy_from_slice(noise_payload);
    needed
}

pub fn build_established(
    receiver_idx: u32,
    counter: u64,
    msg_type: u8,
    timestamp: u32,
    inner_payload: &[u8],
    key: &[u8; 32],
    out: &mut [u8],
) -> usize {
    let inner_len = INNER_HEADER_SIZE + inner_payload.len();
    let encrypted_len = inner_len + crate::noise::TAG_SIZE;
    let payload_len = IDX_SIZE + 8 + encrypted_len;
    let total = COMMON_PREFIX_SIZE + payload_len;

    assert!(out.len() >= total);

    let prefix = build_prefix(PHASE_ESTABLISHED, 0x00, payload_len as u16);
    out[..COMMON_PREFIX_SIZE].copy_from_slice(&prefix);
    let mut pos = COMMON_PREFIX_SIZE;

    out[pos..pos + IDX_SIZE].copy_from_slice(&receiver_idx.to_le_bytes());
    pos += IDX_SIZE;
    out[pos..pos + 8].copy_from_slice(&counter.to_le_bytes());
    pos += 8;

    let mut outer_header = [0u8; ESTABLISHED_HEADER_SIZE];
    outer_header[..pos].copy_from_slice(&out[..pos]);
    let outer_header_ref = &outer_header[..pos];

    let mut inner = [0u8; 512];
    inner[..4].copy_from_slice(&timestamp.to_le_bytes());
    inner[4] = msg_type;
    if !inner_payload.is_empty() {
        inner[INNER_HEADER_SIZE..INNER_HEADER_SIZE + inner_payload.len()]
            .copy_from_slice(inner_payload);
    }

    let _enc_len = crate::noise::aead_encrypt(
        key,
        counter,
        outer_header_ref,
        &inner[..inner_len],
        &mut out[pos..],
    )
    .unwrap();

    total
}

pub fn parse_message(data: &[u8]) -> Option<FmpMessage<'_>> {
    let (phase, _flags, _payload_len) = parse_prefix(data)?;
    let payload = &data[COMMON_PREFIX_SIZE..];

    match phase {
        PHASE_MSG1 => {
            if payload.len() < IDX_SIZE {
                return None;
            }
            let sender_idx = u32::from_le_bytes(payload[..IDX_SIZE].try_into().ok()?);
            let noise_payload = &payload[IDX_SIZE..];
            Some(FmpMessage::Msg1 {
                sender_idx,
                noise_payload,
            })
        }
        PHASE_MSG2 => {
            if payload.len() < IDX_SIZE * 2 {
                return None;
            }
            let sender_idx = u32::from_le_bytes(payload[..IDX_SIZE].try_into().ok()?);
            let receiver_idx = u32::from_le_bytes(payload[IDX_SIZE..IDX_SIZE * 2].try_into().ok()?);
            let noise_payload = &payload[IDX_SIZE * 2..];
            Some(FmpMessage::Msg2 {
                sender_idx,
                receiver_idx,
                noise_payload,
            })
        }
        PHASE_ESTABLISHED => {
            if payload.len() < IDX_SIZE + 8 {
                return None;
            }
            let receiver_idx = u32::from_le_bytes(payload[..IDX_SIZE].try_into().ok()?);
            let counter = u64::from_le_bytes(payload[IDX_SIZE..IDX_SIZE + 8].try_into().ok()?);
            let encrypted = &payload[IDX_SIZE + 8..];
            Some(FmpMessage::Established {
                receiver_idx,
                counter,
                encrypted,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_prefix_msg1() {
        let p = build_prefix(PHASE_MSG1, 0x00, 110);
        assert_eq!(p[0], 0x01);
        assert_eq!(p[1], 0x00);
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 110);
    }

    #[test]
    fn build_prefix_msg2() {
        let p = build_prefix(PHASE_MSG2, 0x00, 65);
        assert_eq!(p[0], 0x02);
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 65);
    }

    #[test]
    fn build_prefix_established() {
        let p = build_prefix(PHASE_ESTABLISHED, 0x00, 100);
        assert_eq!(p[0], 0x00);
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 100);
    }

    #[test]
    fn parse_prefix_roundtrip() {
        let p = build_prefix(PHASE_MSG1, 0x03, 256);
        let data = [p[0], p[1], p[2], p[3], 0xFF, 0xFF];
        let (phase, flags, len) = parse_prefix(&data).unwrap();
        assert_eq!(phase, PHASE_MSG1);
        assert_eq!(flags, 0x03);
        assert_eq!(len, 256);
    }

    #[test]
    fn parse_prefix_rejects_bad_version() {
        let data = [0x50, 0x00, 0x00, 0x00];
        assert!(parse_prefix(&data).is_none());
    }

    #[test]
    fn parse_prefix_too_short() {
        let data = [0x01, 0x00, 0x00];
        assert!(parse_prefix(&data).is_none());
    }

    #[test]
    fn build_msg1_size() {
        let noise_payload = [0u8; 106];
        let mut out = [0u8; 256];
        let len = build_msg1(42, &noise_payload, &mut out);
        assert_eq!(len, MSG1_WIRE_SIZE);
    }

    #[test]
    fn build_msg1_has_correct_prefix() {
        let noise_payload = [0u8; 106];
        let mut out = [0u8; 256];
        build_msg1(42, &noise_payload, &mut out);
        assert_eq!(out[0], 0x01);
        assert_eq!(out[1], 0x00);
    }

    #[test]
    fn build_msg1_has_sender_idx() {
        let noise_payload = [0u8; 106];
        let mut out = [0u8; 256];
        build_msg1(0xDEADBEEF, &noise_payload, &mut out);
        let idx = u32::from_le_bytes(out[4..8].try_into().unwrap());
        assert_eq!(idx, 0xDEADBEEF);
    }

    #[test]
    fn build_msg2_size() {
        let noise_payload = [0u8; 57];
        let mut out = [0u8; 256];
        let len = build_msg2(1, 0, &noise_payload, &mut out);
        assert_eq!(len, MSG2_WIRE_SIZE);
    }

    #[test]
    fn build_msg2_has_both_indices() {
        let noise_payload = [0u8; 57];
        let mut out = [0u8; 256];
        build_msg2(1, 0, &noise_payload, &mut out);
        let sender = u32::from_le_bytes(out[4..8].try_into().unwrap());
        let receiver = u32::from_le_bytes(out[8..12].try_into().unwrap());
        assert_eq!(sender, 1);
        assert_eq!(receiver, 0);
    }

    #[test]
    fn parse_msg1_roundtrip() {
        let noise_payload = [0xAA; 106];
        let mut out = [0u8; 256];
        let len = build_msg1(42, &noise_payload, &mut out);
        let msg = parse_message(&out[..len]).unwrap();
        match msg {
            FmpMessage::Msg1 {
                sender_idx,
                noise_payload: parsed,
            } => {
                assert_eq!(sender_idx, 42);
                assert_eq!(parsed, &noise_payload[..]);
            }
            _ => panic!("expected Msg1"),
        }
    }

    #[test]
    fn parse_msg2_roundtrip() {
        let noise_payload = [0xBB; 57];
        let mut out = [0u8; 256];
        let len = build_msg2(1, 0, &noise_payload, &mut out);
        let msg = parse_message(&out[..len]).unwrap();
        match msg {
            FmpMessage::Msg2 {
                sender_idx,
                receiver_idx,
                noise_payload: parsed,
            } => {
                assert_eq!(sender_idx, 1);
                assert_eq!(receiver_idx, 0);
                assert_eq!(parsed, &noise_payload[..]);
            }
            _ => panic!("expected Msg2"),
        }
    }

    #[test]
    fn build_established_size() {
        let key = [0x42u8; 32];
        let mut out = [0u8; 1024];
        let len = build_established(0, 1, MSG_HEARTBEAT, 12345, &[], &key, &mut out);
        let header_size = COMMON_PREFIX_SIZE + IDX_SIZE + 8;
        let encrypted_size = INNER_HEADER_SIZE + crate::noise::TAG_SIZE;
        assert_eq!(len, header_size + encrypted_size);
    }

    #[test]
    fn parse_established_roundtrip() {
        let key = [0x42u8; 32];
        let mut out = [0u8; 1024];
        let len = build_established(1, 42, MSG_HEARTBEAT, 12345, &[], &key, &mut out);
        let msg = parse_message(&out[..len]).unwrap();
        match msg {
            FmpMessage::Established {
                receiver_idx,
                counter,
                encrypted,
            } => {
                assert_eq!(receiver_idx, 1);
                assert_eq!(counter, 42);
                assert!(!encrypted.is_empty());
            }
            _ => panic!("expected Established"),
        }
    }

    #[test]
    fn established_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let payload = b"test data";
        let mut out = [0u8; 1024];
        let len = build_established(1, 42, MSG_SESSION_DATAGRAM, 99999, payload, &key, &mut out);

        let msg = parse_message(&out[..len]).unwrap();
        match msg {
            FmpMessage::Established {
                counter, encrypted, ..
            } => {
                let outer_header = &out[..ESTABLISHED_HEADER_SIZE];
                let mut decrypted = [0u8; 512];
                let dec_len = crate::noise::aead_decrypt(
                    &key,
                    counter,
                    outer_header,
                    encrypted,
                    &mut decrypted,
                )
                .unwrap();
                let timestamp = u32::from_le_bytes(decrypted[..4].try_into().unwrap());
                assert_eq!(timestamp, 99999);
                assert_eq!(decrypted[4], MSG_SESSION_DATAGRAM);
                assert_eq!(&decrypted[INNER_HEADER_SIZE..dec_len], payload);
            }
            _ => panic!("expected Established"),
        }
    }

    #[test]
    fn msg1_wire_size_matches_bridge_expectation() {
        // Bridge reads 2-byte LE length prefix, then payload bytes.
        // MSG1 = 4 (prefix) + 4 (sender_idx) + 106 (noise) = 114 bytes.
        // On the wire over serial: [72, 00] (114 LE) + [114 bytes of FMP frame]
        // Total serial bytes for MSG1: 2 + 114 = 116
        assert_eq!(MSG1_WIRE_SIZE, 114);
        assert_eq!(
            COMMON_PREFIX_SIZE + IDX_SIZE + HANDSHAKE_MSG1_SIZE,
            MSG1_WIRE_SIZE
        );
    }

    #[test]
    fn msg2_wire_size_matches_vps_response() {
        // VPS sends MSG2 = 4 (prefix) + 4 (sender) + 4 (receiver) + 57 (noise) = 69 bytes.
        // Wire over serial: [45, 00] (69 LE) + [69 bytes of FMP frame]
        assert_eq!(MSG2_WIRE_SIZE, 69);
        assert_eq!(
            COMMON_PREFIX_SIZE + IDX_SIZE * 2 + HANDSHAKE_MSG2_SIZE,
            MSG2_WIRE_SIZE
        );
    }

    #[test]
    fn established_heartbeat_minimum_size() {
        // Heartbeat: 4 (prefix) + 4 (receiver_idx) + 8 (counter) +
        //            37 (encrypted = 5 inner + 16 tag) = 53 bytes
        let key = [0x42u8; 32];
        let mut out = [0u8; 256];
        let len = build_established(1, 0, MSG_HEARTBEAT, 0, &[], &key, &mut out);
        assert_eq!(
            len,
            COMMON_PREFIX_SIZE + IDX_SIZE + 8 + INNER_HEADER_SIZE + crate::noise::TAG_SIZE
        );
        assert!(
            len <= 84,
            "heartbeat must fit in single 64-byte CDC packet + 2-byte len prefix"
        );
    }

    #[test]
    fn parse_rejects_unknown_phase() {
        let data = [0x0F, 0x00, 0x00, 0x00]; // version=0, phase=15
        assert!(parse_message(&data).is_none());
    }

    #[test]
    fn msg1_sender_idx_zero_for_initiator() {
        // Initiator sends sender_idx=0 (hasn't received an index from responder yet)
        let noise_payload = [0u8; 106];
        let mut out = [0u8; 256];
        let len = build_msg1(0, &noise_payload, &mut out);
        let idx = u32::from_le_bytes(
            out[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
                .try_into()
                .unwrap(),
        );
        assert_eq!(idx, 0);
        assert_eq!(len, MSG1_WIRE_SIZE);
    }
}
