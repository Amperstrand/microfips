//! FMP (FIPS Messaging Protocol) — link-layer framing for FIPS.
//!
//! Reference implementation: FIPS commit [`bd085050`](https://github.com/nickeltech/fips/commit/bd085050022ef298b9fd918824e7d983c079ae3c),
//! source path `/root/src/fips/src/node/wire.rs` (and `noise/mod.rs` / `link.rs` where noted).
//!
//! # Deviations from FIPS
//!
//! | ID | Field | microfips | FIPS | Impact |
//! |----|-------|-----------|------|--------|
//! | ~~N1~~ | `payload_len` in established phase | ~~was `4+8+inner_len+16`~~ → now `inner_len` | `inner_len` (plaintext size before encryption) | **Fixed**: was benign on UDP but broke BLE L2CAP (FIPS `calculate_frame_len` depends on this field for frame splitting). |
//! | N2 | `path_mtu` default | hardcoded 1400 | `u16::MAX` | FIPS caps during forwarding. No functional impact. |
//! | N3 | `session_flags` | initiator sends 0x03 | defaults to 0x00 | FIPS doesn't validate flags. No functional impact. |

// FIPS: bd08505 node/wire.rs:CommonPrefix::parse()
pub const FMP_VERSION: u8 = 0;
// FIPS: bd08505 node/wire.rs:CommonPrefix::parse()
pub const COMMON_PREFIX_SIZE: usize = 4;
// FIPS: bd08505 node/wire.rs:CommonPrefix::parse()
pub const IDX_SIZE: usize = 4;
// FIPS: bd08505 node/wire.rs:EncryptedHeader::parse()
pub const ESTABLISHED_HEADER_SIZE: usize = 16;
// FIPS: bd08505 node/wire.rs:EncryptedHeader::parse()
pub const INNER_HEADER_SIZE: usize = 5; // 4-byte timestamp + at least 1 byte msg_type
                                        // FIPS: bd08505 node/wire.rs:EncryptedHeader::parse()
pub const ENCRYPTED_MIN_SIZE: usize = 32;

// FIPS: bd08505 noise/handshake.rs:write_message_1()
pub const HANDSHAKE_MSG1_SIZE: usize = 106;
// FIPS: bd08505 noise/handshake.rs:read_message_2()
pub const HANDSHAKE_MSG2_SIZE: usize = 57;
// FIPS: bd08505 noise/handshake.rs:write_message_1()
pub const EPOCH_ENCRYPTED_SIZE: usize = 24;

// FIPS: bd08505 node/wire.rs:build_msg1()
pub const MSG1_WIRE_SIZE: usize = 114;
// FIPS: bd08505 node/wire.rs:build_msg2()
pub const MSG2_WIRE_SIZE: usize = 69;

// FIPS: bd08505 node/wire.rs:CommonPrefix::parse()
pub const PHASE_ESTABLISHED: u8 = 0x00;
// FIPS: bd08505 node/wire.rs:CommonPrefix::parse()
pub const PHASE_MSG1: u8 = 0x01;
// FIPS: bd08505 node/wire.rs:CommonPrefix::parse()
pub const PHASE_MSG2: u8 = 0x02;

// FIPS: bd08505 node/link.rs:handle_heartbeat()
/// Link-layer message types (inner header byte, after 4-byte LE timestamp).
///
/// These occupy the same wire position as FMP `flags` in established frames
/// but have a different semantic namespace. FIPS defines them in `session_wire.rs`.
pub const MSG_HEARTBEAT: u8 = 0x51;
// FIPS: bd08505 node/link.rs:handle_session_datagram()
pub const MSG_SESSION_DATAGRAM: u8 = 0x00;
// FIPS: bd08505 node/link.rs:handle_sender_report()
pub const MSG_SENDER_REPORT: u8 = 0x01;
// FIPS: bd08505 node/link.rs:handle_receiver_report()
pub const MSG_RECEIVER_REPORT: u8 = 0x02;
// FIPS: bd08505 node/link.rs:handle_disconnect()
pub const MSG_DISCONNECT: u8 = 0x50;

pub const FLAG_KEY_EPOCH: u8 = 0x01;
pub const FLAG_CE: u8 = 0x02;
pub const FLAG_SP: u8 = 0x04;

/// Wire-level session index (mirrors FIPS `utils::SessionIndex`).
///
/// Wraps a `u32` to prevent accidental conflation with `NodeAddr` or
/// other 32-bit identifiers. Only used in the 4-byte sender/receiver
/// index fields of MSG1, MSG2, and established-frame headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionIndex(pub u32);

impl SessionIndex {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(bytes))
    }
}

impl core::fmt::Display for SessionIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

// FIPS: bd08505 node/wire.rs:build_msg1() / build_msg2() / build_established_header()
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

// FIPS: bd08505 node/wire.rs:ver_phase_byte()
pub fn build_prefix(phase: u8, flags: u8, payload_len: u16) -> [u8; COMMON_PREFIX_SIZE] {
    let byte0 = (FMP_VERSION << 4) | (phase & 0x0F);
    [byte0, flags, payload_len as u8, (payload_len >> 8) as u8]
}

// FIPS: bd08505 node/wire.rs:CommonPrefix::parse()
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

// FIPS: bd08505 node/wire.rs:build_msg1()
pub fn build_msg1(sender_idx: u32, noise_payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let needed = COMMON_PREFIX_SIZE + IDX_SIZE + noise_payload.len();
    if out.len() < needed {
        return None;
    }
    let payload_len = (IDX_SIZE + noise_payload.len()) as u16;
    let prefix = build_prefix(PHASE_MSG1, 0x00, payload_len);
    out[..COMMON_PREFIX_SIZE].copy_from_slice(&prefix);
    out[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
        .copy_from_slice(&sender_idx.to_le_bytes());
    out[COMMON_PREFIX_SIZE + IDX_SIZE..needed].copy_from_slice(noise_payload);
    Some(needed)
}

// FIPS: bd08505 node/wire.rs:build_msg2()
pub fn build_msg2(
    sender_idx: u32,
    receiver_idx: u32,
    noise_payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let needed = COMMON_PREFIX_SIZE + IDX_SIZE * 2 + noise_payload.len();
    if out.len() < needed {
        return None;
    }
    let payload_len = (IDX_SIZE * 2 + noise_payload.len()) as u16;
    let prefix = build_prefix(PHASE_MSG2, 0x00, payload_len);
    out[..COMMON_PREFIX_SIZE].copy_from_slice(&prefix);
    out[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
        .copy_from_slice(&sender_idx.to_le_bytes());
    out[COMMON_PREFIX_SIZE + IDX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE * 2]
        .copy_from_slice(&receiver_idx.to_le_bytes());
    out[COMMON_PREFIX_SIZE + IDX_SIZE * 2..needed].copy_from_slice(noise_payload);
    Some(needed)
}

// FIPS: bd08505 node/wire.rs:build_established_header()
// FIPS: bd08505 noise/mod.rs:send_encrypted_link_message_with_ce()
pub fn build_established(
    receiver_idx: u32,
    counter: u64,
    msg_type: u8,
    timestamp: u32,
    inner_payload: &[u8],
    key: &[u8; 32],
    out: &mut [u8],
) -> Option<usize> {
    let inner_len = INNER_HEADER_SIZE + inner_payload.len();
    let encrypted_len = inner_len + crate::noise::TAG_SIZE;
    let payload_len = inner_len as u16;
    let total = ESTABLISHED_HEADER_SIZE + encrypted_len;

    #[cfg(feature = "std")]
    log::debug!(
        "FMP build_established: msg_type=0x{:02x} counter={} inner_len={} total={}",
        msg_type,
        counter,
        inner_len,
        total
    );

    if out.len() < total {
        return None;
    }

    let prefix = build_prefix(PHASE_ESTABLISHED, 0x00, payload_len);
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
    .ok()?;

    Some(total)
}

/// Common 4-byte FMP prefix present on every frame.
///
/// ```text
/// [ver+phase:1][flags:1][payload_len:2 LE]
/// ```
pub struct CommonPrefix {
    pub version: u8,
    pub phase: u8,
    pub flags: u8,
    pub payload_len: u16,
}

impl CommonPrefix {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < COMMON_PREFIX_SIZE {
            return None;
        }
        let ver_phase = data[0];
        let version = ver_phase >> 4;
        let phase = ver_phase & 0x0F;
        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);
        Some(Self {
            version,
            phase,
            flags,
            payload_len,
        })
    }

    pub fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

/// 16-byte established-frame header. Carries `header_bytes` for AEAD AAD.
pub struct EncryptedHeader {
    #[allow(dead_code)]
    pub flags: u8,
    #[allow(dead_code)]
    pub payload_len: u16,
    pub receiver_idx: SessionIndex,
    pub counter: u64,
    pub header_bytes: [u8; ESTABLISHED_HEADER_SIZE],
}

impl EncryptedHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ESTABLISHED_HEADER_SIZE {
            return None;
        }
        let (phase, _flags, payload_len) = parse_prefix(data)?;
        if phase != PHASE_ESTABLISHED {
            return None;
        }
        let receiver_idx = SessionIndex::from_le_bytes(data[4..8].try_into().ok()?);
        let counter = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let mut header_bytes = [0u8; ESTABLISHED_HEADER_SIZE];
        header_bytes[..ESTABLISHED_HEADER_SIZE].copy_from_slice(&data[..ESTABLISHED_HEADER_SIZE]);
        Some(Self {
            flags: _flags,
            payload_len,
            receiver_idx,
            counter,
            header_bytes,
        })
    }

    pub fn ciphertext_offset(&self) -> usize {
        ESTABLISHED_HEADER_SIZE
    }
}

pub struct Msg1Header {
    pub sender_idx: SessionIndex,
    pub noise_msg1_offset: usize,
}

impl Msg1Header {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG1_WIRE_SIZE {
            return None;
        }
        let (_, flags, _payload_len) = parse_prefix(data)?;
        if flags != 0 {
            return None;
        }
        let sender_idx = SessionIndex::from_le_bytes(
            data[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
                .try_into()
                .ok()?,
        );
        Some(Self {
            sender_idx,
            noise_msg1_offset: COMMON_PREFIX_SIZE + IDX_SIZE + IDX_SIZE,
        })
    }
}

pub struct Msg2Header {
    pub sender_idx: SessionIndex,
    pub receiver_idx: SessionIndex,
    pub noise_msg2_offset: usize,
}

impl Msg2Header {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG2_WIRE_SIZE {
            return None;
        }
        let (_, flags, _payload_len) = parse_prefix(data)?;
        if flags != 0 {
            return None;
        }
        let sender_idx = SessionIndex::from_le_bytes(
            data[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
                .try_into()
                .ok()?,
        );
        let receiver_idx = SessionIndex::from_le_bytes(
            data[COMMON_PREFIX_SIZE + IDX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE + IDX_SIZE]
                .try_into()
                .ok()?,
        );
        Some(Self {
            sender_idx,
            receiver_idx,
            noise_msg2_offset: COMMON_PREFIX_SIZE + IDX_SIZE + IDX_SIZE + IDX_SIZE,
        })
    }
}

// FIPS: bd08505 node/wire.rs:Msg1Header::parse()
// FIPS: bd08505 node/wire.rs:Msg2Header::parse()
// FIPS: bd08505 node/wire.rs:EncryptedHeader::parse()
pub fn parse_message(data: &[u8]) -> Option<FmpMessage<'_>> {
    let (phase, _flags, _payload_len) = parse_prefix(data)?;
    let payload = &data[COMMON_PREFIX_SIZE..];

    #[cfg(feature = "std")]
    log::debug!(
        "FMP parse_message: phase=0x{:02x} data_len={}",
        phase,
        data.len()
    );

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
        let len = build_msg1(42, &noise_payload, &mut out).unwrap();
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
        let len = build_msg2(1, 0, &noise_payload, &mut out).unwrap();
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
        let len = build_msg1(42, &noise_payload, &mut out).unwrap();
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
        let len = build_msg2(1, 0, &noise_payload, &mut out).unwrap();
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
        let len = build_established(0, 1, MSG_HEARTBEAT, 12345, &[], &key, &mut out).unwrap();
        let header_size = COMMON_PREFIX_SIZE + IDX_SIZE + 8;
        let encrypted_size = INNER_HEADER_SIZE + crate::noise::TAG_SIZE;
        assert_eq!(len, header_size + encrypted_size);
    }

    #[test]
    fn parse_established_roundtrip() {
        let key = [0x42u8; 32];
        let mut out = [0u8; 1024];
        let len = build_established(1, 42, MSG_HEARTBEAT, 12345, &[], &key, &mut out).unwrap();
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
        let len =
            build_established(1, 42, MSG_SESSION_DATAGRAM, 99999, payload, &key, &mut out).unwrap();

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
        let len = build_established(1, 0, MSG_HEARTBEAT, 0, &[], &key, &mut out).unwrap();
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
        let len = build_msg1(0, &noise_payload, &mut out).unwrap();
        let idx = u32::from_le_bytes(
            out[COMMON_PREFIX_SIZE..COMMON_PREFIX_SIZE + IDX_SIZE]
                .try_into()
                .unwrap(),
        );
        assert_eq!(idx, 0);
        assert_eq!(len, MSG1_WIRE_SIZE);
    }

    #[test]
    fn msg1_noise_payload_structure() {
        // Noise IK MSG1 payload: 33 (e_pub) + 49 (enc_s = 33 pubkey + 16 tag) + 24 (enc_epoch = 8 epoch + 16 tag) = 106
        assert_eq!(
            HANDSHAKE_MSG1_SIZE,
            crate::noise::PUBKEY_SIZE
                + (crate::noise::PUBKEY_SIZE + crate::noise::TAG_SIZE)
                + (crate::noise::EPOCH_SIZE + crate::noise::TAG_SIZE)
        );
        assert_eq!(HANDSHAKE_MSG1_SIZE, 106);
    }

    #[test]
    fn msg2_noise_payload_structure() {
        // Noise IK MSG2 payload: 33 (re_pub) + 24 (enc_epoch = 8 epoch + 16 tag) = 57
        assert_eq!(
            HANDSHAKE_MSG2_SIZE,
            crate::noise::PUBKEY_SIZE + (crate::noise::EPOCH_SIZE + crate::noise::TAG_SIZE)
        );
        assert_eq!(HANDSHAKE_MSG2_SIZE, 57);
    }

    #[test]
    fn established_heartbeat_exact_size() {
        // Heartbeat with no inner payload:
        // 4 (prefix) + 4 (receiver_idx) + 8 (counter) + 5 (inner: 4 ts + 1 msg_type) + 16 (tag) = 37
        let expected =
            COMMON_PREFIX_SIZE + IDX_SIZE + 8 + INNER_HEADER_SIZE + crate::noise::TAG_SIZE;
        assert_eq!(expected, 37);
        assert_eq!(
            expected,
            ESTABLISHED_HEADER_SIZE + INNER_HEADER_SIZE + crate::noise::TAG_SIZE
        );
    }

    #[test]
    fn noise_ik_initiator_msg1_exact_size() {
        // Full Noise IK initiator produces exactly 106 bytes for write_message1
        use crate::noise::{NoiseIkInitiator, EPOCH_SIZE, PUBKEY_SIZE};
        let eph_secret = [0x01u8; 32];
        let s_secret = [0x11u8; 32];
        let responder_pub = [0x02u8; PUBKEY_SIZE];
        let (mut initiator, _) =
            NoiseIkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();
        let my_static = crate::noise::ecdh_pubkey(&s_secret).unwrap();
        let epoch = [0u8; EPOCH_SIZE];
        let mut out = [0u8; 256];
        let n = initiator
            .write_message1(&my_static, &epoch, &mut out)
            .unwrap();
        assert_eq!(n, HANDSHAKE_MSG1_SIZE);
        assert_eq!(n, 106);
    }

    #[test]
    fn parse_msg1_noise_payload_sections() {
        // Build a real MSG1, parse it, verify noise_payload has correct structure
        use crate::noise::{NoiseIkInitiator, EPOCH_SIZE, PUBKEY_SIZE, TAG_SIZE};
        let eph_secret = [0x01u8; 32];
        let s_secret = [0x11u8; 32];
        let responder_pub = [0x02u8; PUBKEY_SIZE];
        let (mut initiator, _) =
            NoiseIkInitiator::new(&eph_secret, &s_secret, &responder_pub).unwrap();
        let my_static = crate::noise::ecdh_pubkey(&s_secret).unwrap();
        let epoch = [0u8; EPOCH_SIZE];
        let mut noise_out = [0u8; 128];
        let noise_len = initiator
            .write_message1(&my_static, &epoch, &mut noise_out)
            .unwrap();
        assert_eq!(noise_len, 106);

        // Wrap in FMP MSG1 frame
        let mut fmp_out = [0u8; 256];
        let fmp_len = build_msg1(0, &noise_out[..noise_len], &mut fmp_out).unwrap();
        assert_eq!(fmp_len, MSG1_WIRE_SIZE);

        // Parse and verify noise_payload section offsets
        let msg = parse_message(&fmp_out[..fmp_len]).unwrap();
        match msg {
            FmpMessage::Msg1 { noise_payload, .. } => {
                assert_eq!(noise_payload.len(), 106);
                // e_pub at offset 0, 33 bytes
                assert_eq!(&noise_payload[..PUBKEY_SIZE], &noise_out[..PUBKEY_SIZE]);
                // enc_static at offset 33, 49 bytes (33 pubkey + 16 tag)
                let enc_static_len = PUBKEY_SIZE + TAG_SIZE;
                assert_eq!(
                    &noise_payload[PUBKEY_SIZE..PUBKEY_SIZE + enc_static_len],
                    &noise_out[PUBKEY_SIZE..PUBKEY_SIZE + enc_static_len]
                );
                // enc_epoch at offset 82, 24 bytes (8 epoch + 16 tag)
                let enc_epoch_len = EPOCH_SIZE + TAG_SIZE;
                let epoch_offset = PUBKEY_SIZE + enc_static_len;
                assert_eq!(
                    &noise_payload[epoch_offset..epoch_offset + enc_epoch_len],
                    &noise_out[epoch_offset..epoch_offset + enc_epoch_len]
                );
            }
            _ => panic!("expected Msg1"),
        }
    }

    #[test]
    fn build_established_returns_none_on_small_buffer() {
        let key = [0x42u8; 32];
        // A heartbeat needs at least 37 bytes (4+4+8+5+16). A 10-byte buffer is too small.
        let mut out = [0u8; 10];
        assert!(build_established(0, 0, MSG_HEARTBEAT, 0, &[], &key, &mut out).is_none());
    }

    #[test]
    fn build_msg1_returns_none_on_small_buffer() {
        let noise_payload = [0u8; 106];
        let mut out = [0u8; 10];
        assert!(build_msg1(0, &noise_payload, &mut out).is_none());
    }

    #[test]
    fn payload_len_satisfies_fips_calculate_frame_len_contract() {
        let key = [0x42u8; 32];
        let mut out = [0u8; 512];

        for (msg_type, payload) in [
            (MSG_HEARTBEAT, &[][..]),
            (MSG_SESSION_DATAGRAM, &b"hello"[..]),
            (MSG_SESSION_DATAGRAM, &[0u8; 200][..]),
            (MSG_DISCONNECT, &[][..]),
        ] {
            let len = build_established(0, 1, msg_type, 99999, payload, &key, &mut out).unwrap();
            let payload_len = u16::from_le_bytes([out[2], out[3]]) as usize;
            let fips_frame_len = ESTABLISHED_HEADER_SIZE + payload_len + crate::noise::TAG_SIZE;
            assert_eq!(
                fips_frame_len,
                len,
                "payload_len={} (msg_type=0x{:02x}, payload_len={}) must satisfy \
                 FIPS BLE calculate_frame_len contract: \
                 ESTABLISHED_HEADER_SIZE({}) + payload_len({}) + TAG_SIZE({}) = {} \
                 but actual frame is {} bytes",
                payload_len,
                msg_type,
                payload_len,
                ESTABLISHED_HEADER_SIZE,
                payload_len,
                crate::noise::TAG_SIZE,
                fips_frame_len,
                len,
            );
        }
    }
}
