//! FIPS Session Protocol (FSP) — session-layer protocol over FMP in FIPS.
//!
//! Reference commit: `bd085050022ef298b9fd918824e7d983c079ae3c`
//!
//! Key FIPS source files:
//! - `session_wire.rs` — wire format definitions, header parsing/serialization
//! - `session.rs` — SessionSetup/SessionAck/SessionMsg3 encode/decode, session state
//! - `link.rs` — SessionDatagram framing, forwarding logic
//! - `forwarding.rs` — session datagram routing between peers
//! - `handlers/session.rs` — responder/initiator state machines, handshake orchestration
//!
//! This module implements a minimal subset of FSP: XK handshake (3-way), session
//! datagram framing, and encrypted data exchange with inner headers.

// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const FSP_VERSION: u8 = 0;
// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const FSP_COMMON_PREFIX_SIZE: usize = 4;
// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const FSP_HEADER_SIZE: usize = 12;
// FIPS: bd08505 node/session_wire.rs:FspInnerHeader::parse()
pub const FSP_INNER_HEADER_SIZE: usize = 6;
// FIPS: bd08505 node/session_wire.rs:FspEncryptedHeader::parse()
pub const FSP_ENCRYPTED_MIN_SIZE: usize = 28;

// FIPS: bd08505 node/session_wire.rs:FspDatagram::parse()
pub const FSP_PORT_IPV6_SHIM: u16 = 256;

// FIPS: bd08505 noise/mod.rs:write_xk_message_1()
pub const XK_HANDSHAKE_MSG1_SIZE: usize = 33;
// FIPS: bd08505 noise/mod.rs:write_xk_message_2()
pub const XK_HANDSHAKE_MSG2_SIZE: usize = 57;
// FIPS: bd08505 noise/mod.rs:write_xk_message_3()
pub const XK_HANDSHAKE_MSG3_SIZE: usize = 73;

// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const PHASE_ESTABLISHED: u8 = 0x00;
// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const PHASE_SESSION_SETUP: u8 = 0x01;
// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const PHASE_SESSION_ACK: u8 = 0x02;
// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const PHASE_SESSION_MSG3: u8 = 0x03;

// FIPS: bd08505 protocol/session.rs:SessionSetup::encode()
pub const FSP_MSG_DATA: u8 = 0x10;

// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const FLAG_COORDS_PRESENT: u8 = 0x01;
// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const FLAG_KEY_EPOCH: u8 = 0x02;
// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::parse()
pub const FLAG_UNENCRYPTED: u8 = 0x04;

// FIPS: bd08505 node/link.rs:FipsLink::send_udp()
/// Configuration constant (not in wire format)
pub const FIPS_UDP_PORT: u16 = 2121;
// FIPS: bd08505 protocol/session.rs:compress_ipv6_shim()
/// Configuration constant
pub const FIPS_IPV6_OVERHEAD: usize = 77;

// FIPS: bd08505 node/session_wire.rs:FspDatagram::parse()
pub const FSP_DATAGRAM_HEADER_SIZE: usize = 4;
/// 16 bytes, standard NodeAddr size
pub const NODE_ADDR_SIZE: usize = 16;

// FIPS: bd08505 node/link.rs:SessionDatagram::encode()
pub const SESSION_DATAGRAM_BODY_SIZE: usize = 35;
// FIPS: bd08505 node/link.rs:SessionDatagram::encode()
pub const SESSION_DATAGRAM_HEADER_SIZE: usize = 36;

// FIPS: bd08505 node/link.rs:SessionDatagram::encode()
pub fn build_session_datagram_body(
    src: &[u8; NODE_ADDR_SIZE],
    dst: &[u8; NODE_ADDR_SIZE],
) -> [u8; SESSION_DATAGRAM_BODY_SIZE] {
    let mut body = [0u8; SESSION_DATAGRAM_BODY_SIZE];
    body[0] = 64;
    body[1] = u16::MAX.to_le_bytes()[0];
    body[2] = u16::MAX.to_le_bytes()[1];
    body[3..19].copy_from_slice(src);
    body[19..35].copy_from_slice(dst);
    body
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspError {
    BufferTooSmall,
    InvalidFrame,
    InvalidCoords,
}

// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::serialize()
fn fsp_prefix_byte(phase: u8) -> u8 {
    (FSP_VERSION << 4) | (phase & 0x0F)
}

// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::serialize()
fn fsp_prefix(phase: u8, flags: u8, payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    [
        fsp_prefix_byte(phase),
        flags,
        payload_len as u8,
        (payload_len >> 8) as u8,
    ]
}

// FIPS: bd08505 protocol/session.rs:SessionSetup::encode()
// FIPS: bd08505 handlers/session.rs:initiate_session()
pub fn build_session_setup(
    session_flags: u8,
    src_coords: &[[u8; NODE_ADDR_SIZE]],
    dest_coords: &[[u8; NODE_ADDR_SIZE]],
    handshake: &[u8],
    out: &mut [u8],
) -> Result<usize, FspError> {
    if src_coords.is_empty() || dest_coords.is_empty() {
        return Err(FspError::InvalidCoords);
    }
    let body_len = 1
        + (2 + src_coords.len() * NODE_ADDR_SIZE)
        + (2 + dest_coords.len() * NODE_ADDR_SIZE)
        + 2
        + handshake.len();
    let total = FSP_COMMON_PREFIX_SIZE + body_len;
    if out.len() < total {
        return Err(FspError::BufferTooSmall);
    }
    if body_len > u16::MAX as usize {
        return Err(FspError::BufferTooSmall);
    }
    let prefix = fsp_prefix(PHASE_SESSION_SETUP, 0x00, body_len as u16);
    out[..FSP_COMMON_PREFIX_SIZE].copy_from_slice(&prefix);

    let mut pos = FSP_COMMON_PREFIX_SIZE;
    out[pos] = session_flags;
    pos += 1;

    out[pos..pos + 2].copy_from_slice(&(src_coords.len() as u16).to_le_bytes());
    pos += 2;
    for coord in src_coords {
        out[pos..pos + NODE_ADDR_SIZE].copy_from_slice(coord);
        pos += NODE_ADDR_SIZE;
    }

    out[pos..pos + 2].copy_from_slice(&(dest_coords.len() as u16).to_le_bytes());
    pos += 2;
    for coord in dest_coords {
        out[pos..pos + NODE_ADDR_SIZE].copy_from_slice(coord);
        pos += NODE_ADDR_SIZE;
    }

    out[pos..pos + 2].copy_from_slice(&(handshake.len() as u16).to_le_bytes());
    pos += 2;
    out[pos..pos + handshake.len()].copy_from_slice(handshake);
    pos += handshake.len();

    Ok(pos)
}

// FIPS: bd08505 protocol/session.rs:SessionSetup::decode()
// FIPS: bd08505 handlers/session.rs:handle_session_setup()
pub fn parse_session_setup(data: &[u8]) -> Result<(u8, &[u8]), FspError> {
    if data.len() < FSP_COMMON_PREFIX_SIZE {
        return Err(FspError::InvalidFrame);
    }
    let ver_phase = data[0];
    if (ver_phase >> 4) != FSP_VERSION || (ver_phase & 0x0F) != PHASE_SESSION_SETUP {
        return Err(FspError::InvalidFrame);
    }
    let payload_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    let body = &data[FSP_COMMON_PREFIX_SIZE..];
    if body.len() < payload_len {
        return Err(FspError::InvalidFrame);
    }
    let body = &body[..payload_len];

    if body.is_empty() {
        return Err(FspError::InvalidFrame);
    }
    let session_flags = body[0];
    let mut pos = 1;

    let src_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + src_count * NODE_ADDR_SIZE;
    if body.len() < pos {
        return Err(FspError::InvalidCoords);
    }

    let dst_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + dst_count * NODE_ADDR_SIZE;
    if body.len() < pos {
        return Err(FspError::InvalidCoords);
    }

    if body.len() < pos + 2 {
        return Err(FspError::InvalidFrame);
    }
    let hs_len = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if body.len() < pos + hs_len {
        return Err(FspError::InvalidFrame);
    }
    Ok((session_flags, &body[pos..pos + hs_len]))
}

// FIPS: bd08505 protocol/session.rs:SessionAck::encode()
// FIPS: bd08505 handlers/session.rs:handle_session_setup()
pub fn build_session_ack(
    src_coords: &[[u8; NODE_ADDR_SIZE]],
    dest_coords: &[[u8; NODE_ADDR_SIZE]],
    handshake: &[u8],
    out: &mut [u8],
) -> Result<usize, FspError> {
    if src_coords.is_empty() || dest_coords.is_empty() {
        return Err(FspError::InvalidCoords);
    }
    let body_len = 1
        + (2 + src_coords.len() * NODE_ADDR_SIZE)
        + (2 + dest_coords.len() * NODE_ADDR_SIZE)
        + 2
        + handshake.len();
    let total = FSP_COMMON_PREFIX_SIZE + body_len;
    if out.len() < total {
        return Err(FspError::BufferTooSmall);
    }
    if body_len > u16::MAX as usize {
        return Err(FspError::BufferTooSmall);
    }
    let prefix = fsp_prefix(PHASE_SESSION_ACK, 0x00, body_len as u16);
    out[..FSP_COMMON_PREFIX_SIZE].copy_from_slice(&prefix);

    let mut pos = FSP_COMMON_PREFIX_SIZE;
    out[pos] = 0x00;
    pos += 1;

    out[pos..pos + 2].copy_from_slice(&(src_coords.len() as u16).to_le_bytes());
    pos += 2;
    for coord in src_coords {
        out[pos..pos + NODE_ADDR_SIZE].copy_from_slice(coord);
        pos += NODE_ADDR_SIZE;
    }

    out[pos..pos + 2].copy_from_slice(&(dest_coords.len() as u16).to_le_bytes());
    pos += 2;
    for coord in dest_coords {
        out[pos..pos + NODE_ADDR_SIZE].copy_from_slice(coord);
        pos += NODE_ADDR_SIZE;
    }

    out[pos..pos + 2].copy_from_slice(&(handshake.len() as u16).to_le_bytes());
    pos += 2;
    out[pos..pos + handshake.len()].copy_from_slice(handshake);
    pos += handshake.len();

    #[cfg(feature = "std")]
    log::debug!(
        "build_session_ack: total={} src_count={} dst_count={} hs_len={} body_bytes[0..8]={:02x?}",
        pos,
        src_coords.len(),
        dest_coords.len(),
        handshake.len(),
        &out[FSP_COMMON_PREFIX_SIZE..FSP_COMMON_PREFIX_SIZE + 8.min(pos - FSP_COMMON_PREFIX_SIZE)]
    );

    Ok(pos)
}

// FIPS: bd08505 protocol/session.rs:SessionAck::decode()
// FIPS: bd08505 handlers/session.rs:handle_session_ack()
pub fn parse_session_ack(data: &[u8]) -> Result<&[u8], FspError> {
    if data.len() < FSP_COMMON_PREFIX_SIZE {
        return Err(FspError::InvalidFrame);
    }
    let ver_phase = data[0];
    if (ver_phase >> 4) != FSP_VERSION || (ver_phase & 0x0F) != PHASE_SESSION_ACK {
        return Err(FspError::InvalidFrame);
    }
    let payload_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    let body = &data[FSP_COMMON_PREFIX_SIZE..];
    if body.len() < payload_len {
        return Err(FspError::InvalidFrame);
    }
    let body = &body[..payload_len];

    if body.is_empty() {
        return Err(FspError::InvalidFrame);
    }
    let _flags = body[0];
    let mut pos = 1;

    let src_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + src_count * NODE_ADDR_SIZE;
    if body.len() < pos {
        return Err(FspError::InvalidCoords);
    }

    let dst_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + dst_count * NODE_ADDR_SIZE;
    if body.len() < pos {
        return Err(FspError::InvalidCoords);
    }

    if body.len() < pos + 2 {
        return Err(FspError::InvalidFrame);
    }
    let hs_len = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if body.len() < pos + hs_len {
        return Err(FspError::InvalidFrame);
    }
    Ok(&body[pos..pos + hs_len])
}

// FIPS: bd08505 protocol/session.rs:SessionMsg3::encode()
// FIPS: bd08505 handlers/session.rs:build_session_msg3()
pub fn build_session_msg3(handshake: &[u8], out: &mut [u8]) -> Result<usize, FspError> {
    let body_len = 1 + 2 + handshake.len();
    let total = FSP_COMMON_PREFIX_SIZE + body_len;
    if out.len() < total {
        return Err(FspError::BufferTooSmall);
    }
    let prefix = fsp_prefix(PHASE_SESSION_MSG3, 0x00, body_len as u16);
    out[..FSP_COMMON_PREFIX_SIZE].copy_from_slice(&prefix);

    let mut pos = FSP_COMMON_PREFIX_SIZE;
    out[pos] = 0x00;
    pos += 1;

    out[pos..pos + 2].copy_from_slice(&(handshake.len() as u16).to_le_bytes());
    pos += 2;
    out[pos..pos + handshake.len()].copy_from_slice(handshake);
    pos += handshake.len();

    Ok(pos)
}

// FIPS: bd08505 protocol/session.rs:SessionMsg3::decode()
// FIPS: bd08505 handlers/session.rs:handle_session_msg3()
pub fn parse_session_msg3(data: &[u8]) -> Result<&[u8], FspError> {
    if data.len() < FSP_COMMON_PREFIX_SIZE {
        return Err(FspError::InvalidFrame);
    }
    let ver_phase = data[0];
    if (ver_phase >> 4) != FSP_VERSION || (ver_phase & 0x0F) != PHASE_SESSION_MSG3 {
        return Err(FspError::InvalidFrame);
    }
    let payload_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    let body = &data[FSP_COMMON_PREFIX_SIZE..];
    if body.len() < payload_len {
        return Err(FspError::InvalidFrame);
    }
    let body = &body[..payload_len];

    if body.len() < 3 {
        return Err(FspError::InvalidFrame);
    }
    let _flags = body[0];
    let hs_len = u16::from_le_bytes([body[1], body[2]]) as usize;
    if body.len() < 3 + hs_len {
        return Err(FspError::InvalidFrame);
    }
    Ok(&body[3..3 + hs_len])
}

// FIPS: bd08505 node/session_wire.rs:FspDatagram::parse()
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FspDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> FspDatagram<'a> {
    // FIPS: bd08505 node/session_wire.rs:FspDatagram::serialize()
    pub fn serialize(&self, out: &mut [u8]) -> usize {
        let total = FSP_DATAGRAM_HEADER_SIZE + self.payload.len();
        assert!(out.len() >= total);
        out[..2].copy_from_slice(&self.src_port.to_le_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_le_bytes());
        out[FSP_DATAGRAM_HEADER_SIZE..total].copy_from_slice(self.payload);
        total
    }

    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < FSP_DATAGRAM_HEADER_SIZE {
            return None;
        }
        let src_port = u16::from_le_bytes(data[..2].try_into().ok()?);
        let dst_port = u16::from_le_bytes(data[2..4].try_into().ok()?);
        let payload = &data[FSP_DATAGRAM_HEADER_SIZE..];
        Some(Self {
            src_port,
            dst_port,
            payload,
        })
    }
}

// FIPS: bd08505 protocol/session.rs:decompress_ipv6_shim()
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Shim<'a> {
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

impl<'a> Ipv6Shim<'a> {
    pub const HEADER_SIZE: usize = 6;

    // FIPS: bd08505 protocol/session.rs:compress_ipv6_shim()
    pub fn serialize(&self, out: &mut [u8]) -> usize {
        let total = Self::HEADER_SIZE + self.payload.len();
        assert!(out.len() >= total);
        out[0] = 0x00;
        out[1] = 0x00;
        out[2] = 0x00;
        out[3] = 0x00;
        out[4] = self.next_header;
        out[5] = self.hop_limit;
        out[Self::HEADER_SIZE..total].copy_from_slice(self.payload);
        total
    }

    // FIPS: bd08505 protocol/session.rs:decompress_ipv6_shim()
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }
        let next_header = data[4];
        let hop_limit = data[5];
        let payload = &data[Self::HEADER_SIZE..];
        Some(Self {
            next_header,
            hop_limit,
            payload,
        })
    }
}

// FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::serialize()
pub fn build_fsp_header(counter: u64, flags: u8, payload_len: u16) -> [u8; FSP_HEADER_SIZE] {
    let mut header = [0u8; FSP_HEADER_SIZE];
    header[0] = fsp_prefix_byte(PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..12].copy_from_slice(&counter.to_le_bytes());
    header
}

// FIPS: bd08505 node/session_wire.rs:FspEncryptedHeader::serialize()
pub fn build_fsp_encrypted(
    header: &[u8; FSP_HEADER_SIZE],
    ciphertext: &[u8],
    out: &mut [u8],
) -> usize {
    let total = FSP_HEADER_SIZE + ciphertext.len();
    if out.len() < total {
        return 0;
    }
    out[..FSP_HEADER_SIZE].copy_from_slice(header);
    out[FSP_HEADER_SIZE..total].copy_from_slice(ciphertext);
    total
}

// FIPS: bd08505 node/session_wire.rs:FspInnerHeader::serialize()
pub fn fsp_prepend_inner_header(
    timestamp_ms: u32,
    msg_type: u8,
    inner_flags: u8,
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    let total = FSP_INNER_HEADER_SIZE + payload.len();
    if out.len() < total {
        return 0;
    }
    out[..4].copy_from_slice(&timestamp_ms.to_le_bytes());
    out[4] = msg_type;
    out[5] = inner_flags;
    out[FSP_INNER_HEADER_SIZE..total].copy_from_slice(payload);
    total
}

pub fn build_fsp_data_message(
    counter: u64,
    timestamp_ms: u32,
    payload: &[u8],
    key: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, NoiseError> {
    let mut inner = [0u8; 512];
    let inner_len = fsp_prepend_inner_header(timestamp_ms, FSP_MSG_DATA, 0x00, payload, &mut inner);
    if inner_len == 0 {
        return Err(NoiseError::BufferTooSmall);
    }

    let header = build_fsp_header(counter, 0x00, (inner_len + crate::noise::TAG_SIZE) as u16);
    let mut ciphertext = [0u8; 512];
    let ciphertext_len =
        crate::noise::aead_encrypt(key, counter, &header, &inner[..inner_len], &mut ciphertext)?;

    let total = build_fsp_encrypted(&header, &ciphertext[..ciphertext_len], out);
    if total == 0 {
        return Err(NoiseError::BufferTooSmall);
    }
    Ok(total)
}

// FIPS: bd08505 node/session_wire.rs:FspInnerHeader::parse()
pub fn fsp_strip_inner_header(data: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    if data.len() < FSP_INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let msg_type = data[4];
    let inner_flags = data[5];
    Some((
        timestamp,
        msg_type,
        inner_flags,
        &data[FSP_INNER_HEADER_SIZE..],
    ))
}

// FIPS: bd08505 node/session_wire.rs:FspEncryptedHeader::parse()
pub fn parse_fsp_encrypted_header(data: &[u8]) -> Option<(u8, u64, &[u8], &[u8])> {
    if data.len() < FSP_ENCRYPTED_MIN_SIZE {
        return None;
    }
    let ver = data[0] >> 4;
    let phase = data[0] & 0x0F;
    if ver != FSP_VERSION || phase != PHASE_ESTABLISHED {
        return None;
    }
    let flags = data[1];
    let counter = u64::from_le_bytes(data[4..12].try_into().ok()?);
    let header = &data[..FSP_HEADER_SIZE];
    let mut payload = &data[FSP_HEADER_SIZE..];

    if flags & FLAG_COORDS_PRESENT != 0 {
        let remaining = payload.len();
        if remaining < 2 {
            return None;
        }
        let src_count = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let after_src = 2 + src_count * NODE_ADDR_SIZE;
        if remaining < after_src + 2 {
            return None;
        }
        let dst_count = u16::from_le_bytes([payload[after_src], payload[after_src + 1]]) as usize;
        let after_dst = after_src + 2 + dst_count * NODE_ADDR_SIZE;
        if remaining < after_dst {
            return None;
        }
        payload = &payload[after_dst..];
    }

    Some((flags, counter, header, payload))
}

use crate::noise::{NoiseError, NoiseXkInitiator, NoiseXkResponder, EPOCH_SIZE, PUBKEY_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspSessionState {
    Idle,
    AwaitingMsg3,
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspSessionError {
    InvalidState,
    InvalidMessage,
    CryptoError,
    BufferTooSmall,
}

impl From<FspError> for FspSessionError {
    fn from(e: FspError) -> Self {
        match e {
            FspError::BufferTooSmall => FspSessionError::BufferTooSmall,
            FspError::InvalidFrame | FspError::InvalidCoords => FspSessionError::InvalidMessage,
        }
    }
}

impl From<NoiseError> for FspSessionError {
    fn from(e: NoiseError) -> Self {
        match e {
            NoiseError::BufferTooSmall => FspSessionError::BufferTooSmall,
            NoiseError::InvalidMessage | NoiseError::InvalidState => {
                FspSessionError::InvalidMessage
            }
            _ => FspSessionError::CryptoError,
        }
    }
}

// FIPS: bd08505 handlers/session.rs:handle_session_setup()
// FIPS: bd08505 handlers/session.rs:handle_session_payload()
pub struct FspSession {
    state: FspSessionState,
    responder: Option<NoiseXkResponder>,
    k_recv: Option<[u8; 32]>,
    k_send: Option<[u8; 32]>,
    initiator_pub: Option<[u8; PUBKEY_SIZE]>,
    send_counter: u64,
}

impl FspSession {
    // FIPS: bd08505 handlers/session.rs:handle_session_setup()
    pub fn new() -> Self {
        Self {
            state: FspSessionState::Idle,
            responder: None,
            k_recv: None,
            k_send: None,
            initiator_pub: None,
            send_counter: 0,
        }
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_setup()
    pub fn state(&self) -> FspSessionState {
        self.state
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_payload()
    pub fn session_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        self.k_recv.zip(self.k_send)
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_setup()
    pub fn initiator_pub(&self) -> Option<[u8; PUBKEY_SIZE]> {
        self.initiator_pub
    }

    // FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::serialize()
    pub fn next_send_counter(&mut self) -> u64 {
        let c = self.send_counter;
        self.send_counter += 1;
        c
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_payload()
    pub fn send_key(&self) -> Option<&[u8; 32]> {
        self.k_send.as_ref()
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_setup()
    pub fn handle_setup(
        &mut self,
        my_secret: &[u8; 32],
        my_ephemeral: &[u8; 32],
        my_epoch: &[u8; EPOCH_SIZE],
        setup_data: &[u8],
        ack_out: &mut [u8],
    ) -> Result<usize, FspSessionError> {
        if self.state != FspSessionState::Idle {
            return Err(FspSessionError::InvalidState);
        }

        let (_flags, handshake_payload) = parse_session_setup(setup_data)?;

        if handshake_payload.len() != XK_HANDSHAKE_MSG1_SIZE {
            return Err(FspSessionError::InvalidMessage);
        }

        let ei_pub: [u8; PUBKEY_SIZE] = handshake_payload[..PUBKEY_SIZE]
            .try_into()
            .map_err(|_| FspSessionError::InvalidMessage)?;

        let mut responder = NoiseXkResponder::new(my_secret, &ei_pub)?;

        let mut msg2_noise = [0u8; 128];
        let msg2_len = responder.write_message2(my_ephemeral, my_epoch, &mut msg2_noise)?;

        let my_pub = crate::noise::ecdh_pubkey(my_secret)?;
        let normalized = crate::noise::parity_normalize(&my_pub);
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&normalized[1..]);
        let my_addr = crate::identity::NodeAddr::from_pubkey_x(&x_only);
        let src = [my_addr.0];
        let mut ei_x_only = [0u8; 32];
        ei_x_only.copy_from_slice(&ei_pub[1..]);
        let initiator_addr = crate::identity::NodeAddr::from_pubkey_x(&ei_x_only);
        let dst = [initiator_addr.0];

        let ack_len = build_session_ack(&src, &dst, &msg2_noise[..msg2_len], ack_out)?;

        self.responder = Some(responder);
        self.state = FspSessionState::AwaitingMsg3;

        #[cfg(feature = "std")]
        log::debug!("FSP session: setup processed, SessionAck sent, awaiting msg3");

        Ok(ack_len)
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_msg3()
    pub fn handle_msg3(&mut self, msg3_data: &[u8]) -> Result<(), FspSessionError> {
        if self.state != FspSessionState::AwaitingMsg3 {
            return Err(FspSessionError::InvalidState);
        }

        let handshake_payload = parse_session_msg3(msg3_data)?;

        if handshake_payload.len() != XK_HANDSHAKE_MSG3_SIZE {
            return Err(FspSessionError::InvalidMessage);
        }

        let responder = self
            .responder
            .as_mut()
            .ok_or(FspSessionError::InvalidState)?;
        let (initiator_static_pub, _initiator_epoch) =
            responder.read_message3(handshake_payload)?;

        let (k_recv, k_send) = responder.finalize();

        self.k_recv = Some(k_recv);
        self.k_send = Some(k_send);
        self.initiator_pub = Some(initiator_static_pub);
        self.responder = None;
        self.state = FspSessionState::Established;

        #[cfg(feature = "std")]
        log::info!("FSP session: established (responder, XK)");

        Ok(())
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_setup()
    pub fn reset(&mut self) {
        self.state = FspSessionState::Idle;
        self.responder = None;
        self.k_recv = None;
        self.k_send = None;
        self.initiator_pub = None;
        self.send_counter = 0;
    }
}

impl Default for FspSession {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspInitiatorState {
    Idle,
    AwaitingAck,
    AwaitingEstablished,
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspInitiatorError {
    InvalidState,
    InvalidMessage,
    DecryptFailed,
    BufferTooSmall,
    Noise(NoiseError),
}

impl From<NoiseError> for FspInitiatorError {
    fn from(e: NoiseError) -> Self {
        FspInitiatorError::Noise(e)
    }
}

impl From<FspError> for FspInitiatorError {
    fn from(e: FspError) -> Self {
        match e {
            FspError::BufferTooSmall => FspInitiatorError::BufferTooSmall,
            FspError::InvalidFrame | FspError::InvalidCoords => FspInitiatorError::InvalidMessage,
        }
    }
}

// FIPS: bd08505 handlers/session.rs:handle_session_ack()
// FIPS: bd08505 handlers/session.rs:initiate_session()
pub struct FspInitiatorSession {
    state: FspInitiatorState,
    initiator: Option<NoiseXkInitiator>,
    k_recv: Option<[u8; 32]>,
    k_send: Option<[u8; 32]>,
    my_pub: [u8; PUBKEY_SIZE],
    send_counter: u64,
}

impl FspInitiatorSession {
    // FIPS: bd08505 handlers/session.rs:initiate_session()
    pub fn new(
        my_static_secret: &[u8; 32],
        my_ephemeral_secret: &[u8; 32],
        responder_static_pub: &[u8; PUBKEY_SIZE],
    ) -> Result<Self, FspInitiatorError> {
        let (initiator, _e_pub) =
            NoiseXkInitiator::new(my_ephemeral_secret, my_static_secret, responder_static_pub)?;
        let my_pub = crate::noise::ecdh_pubkey(my_static_secret)?;
        Ok(Self {
            state: FspInitiatorState::Idle,
            initiator: Some(initiator),
            k_recv: None,
            k_send: None,
            my_pub,
            send_counter: 0,
        })
    }

    // FIPS: bd08505 handlers/session.rs:initiate_session()
    pub fn state(&self) -> FspInitiatorState {
        self.state
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_payload()
    pub fn session_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        self.k_recv.zip(self.k_send)
    }

    // FIPS: bd08505 node/session_wire.rs:FspCommonPrefix::serialize()
    pub fn next_send_counter(&mut self) -> u64 {
        let c = self.send_counter;
        self.send_counter += 1;
        c
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_payload()
    pub fn send_key(&self) -> Option<&[u8; 32]> {
        self.k_send.as_ref()
    }

    // FIPS: bd08505 handlers/session.rs:initiate_session()
    pub fn build_setup(
        &mut self,
        src_addr: &[u8; NODE_ADDR_SIZE],
        dst_addr: &[u8; NODE_ADDR_SIZE],
        out: &mut [u8],
    ) -> Result<usize, FspInitiatorError> {
        if self.state != FspInitiatorState::Idle {
            return Err(FspInitiatorError::InvalidState);
        }
        let initiator = self
            .initiator
            .as_mut()
            .ok_or(FspInitiatorError::InvalidState)?;
        let mut xk_msg1 = [0u8; 64];
        let xk_msg1_len = initiator.write_message1(&mut xk_msg1)?;

        let src_coords = [*src_addr];
        let dst_coords = [*dst_addr];
        let setup_len =
            build_session_setup(0x00, &src_coords, &dst_coords, &xk_msg1[..xk_msg1_len], out)?;
        self.state = FspInitiatorState::AwaitingAck;

        #[cfg(feature = "std")]
        log::debug!("FSP initiator: setup sent ({}B), awaiting ack", setup_len);

        Ok(setup_len)
    }

    // FIPS: bd08505 handlers/session.rs:handle_session_ack()
    pub fn handle_ack(&mut self, ack_data: &[u8]) -> Result<(), FspInitiatorError> {
        if self.state != FspInitiatorState::AwaitingAck {
            return Err(FspInitiatorError::InvalidState);
        }
        let xk_msg2_payload =
            parse_session_ack(ack_data).map_err(|_| FspInitiatorError::InvalidMessage)?;
        let initiator = self
            .initiator
            .as_mut()
            .ok_or(FspInitiatorError::InvalidState)?;
        let _responder_epoch = initiator.read_message2(xk_msg2_payload)?;
        self.state = FspInitiatorState::AwaitingEstablished;

        #[cfg(feature = "std")]
        log::debug!("FSP initiator: ack received, sending msg3");

        Ok(())
    }

    // FIPS: bd08505 handlers/session.rs:build_session_msg3()
    pub fn build_msg3(
        &mut self,
        epoch: &[u8; EPOCH_SIZE],
        out: &mut [u8],
    ) -> Result<usize, FspInitiatorError> {
        if self.state != FspInitiatorState::AwaitingEstablished {
            return Err(FspInitiatorError::InvalidState);
        }
        let initiator = self
            .initiator
            .as_mut()
            .ok_or(FspInitiatorError::InvalidState)?;
        let mut msg3_noise = [0u8; 128];
        let msg3_len = initiator.write_message3(&self.my_pub, epoch, &mut msg3_noise)?;
        let msg3_fsp_len = build_session_msg3(&msg3_noise[..msg3_len], out)?;
        self.state = FspInitiatorState::Established;

        #[cfg(feature = "std")]
        log::info!("FSP initiator: established (XK)");

        let (k_send, k_recv) = initiator.finalize();
        self.k_send = Some(k_send);
        self.k_recv = Some(k_recv);
        Ok(msg3_fsp_len)
    }

    // FIPS: bd08505 handlers/session.rs:initiate_session()
    pub fn reset(&mut self) {
        self.state = FspInitiatorState::Idle;
        self.initiator = None;
        self.k_recv = None;
        self.k_send = None;
        self.send_counter = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspHandlerResult {
    None,
    SendDatagram(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspHandlerError {
    Setup(FspSessionError),
    Msg3(FspSessionError),
    DecryptFailed,
    InnerHeaderTooShort,
    BufferTooSmall,
    UnknownPhase,
}

// FIPS: bd08505 handlers/session.rs:handle_session_payload()
// FIPS: bd08505 forwarding.rs:handle_session_datagram()
pub fn handle_fsp_datagram(
    session: &mut FspSession,
    secret: &[u8; 32],
    ephemeral: &[u8; 32],
    epoch: &[u8; 8],
    payload: &[u8],
    resp: &mut [u8],
) -> Result<FspHandlerResult, FspHandlerError> {
    if payload.len() < SESSION_DATAGRAM_BODY_SIZE {
        return Ok(FspHandlerResult::None);
    }
    let src_addr: [u8; NODE_ADDR_SIZE] = payload[3..19]
        .try_into()
        .map_err(|_| FspHandlerError::UnknownPhase)?;
    let dst_addr: [u8; NODE_ADDR_SIZE] = payload[19..35]
        .try_into()
        .map_err(|_| FspHandlerError::UnknownPhase)?;
    let reply_body = build_session_datagram_body(&dst_addr, &src_addr);

    let fsp_data = &payload[SESSION_DATAGRAM_BODY_SIZE..];
    if fsp_data.is_empty() {
        return Ok(FspHandlerResult::None);
    }
    let fsp_phase = fsp_data[0] & 0x0F;
    #[cfg(feature = "std")]
    log::debug!(
        "FSP datagram: src={:02x?} dst={:02x?} phase=0x{:02x} session_state={:?}",
        &src_addr[..4],
        &dst_addr[..4],
        fsp_phase,
        session.state()
    );
    match fsp_phase {
        PHASE_SESSION_SETUP => {
            let mut tmp = [0u8; 512];
            let ack_len = match session.handle_setup(secret, ephemeral, epoch, fsp_data, &mut tmp) {
                Ok(len) => len,
                Err(FspSessionError::InvalidState) => {
                    session.reset();
                    session
                        .handle_setup(secret, ephemeral, epoch, fsp_data, &mut tmp)
                        .map_err(FspHandlerError::Setup)?
                }
                Err(e) => return Err(FspHandlerError::Setup(e)),
            };
            let total = SESSION_DATAGRAM_BODY_SIZE + ack_len;
            if resp.len() < total {
                return Err(FspHandlerError::BufferTooSmall);
            }
            resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&reply_body);
            resp[SESSION_DATAGRAM_BODY_SIZE..total].copy_from_slice(&tmp[..ack_len]);
            Ok(FspHandlerResult::SendDatagram(total))
        }
        PHASE_SESSION_MSG3 => {
            session
                .handle_msg3(fsp_data)
                .map_err(FspHandlerError::Msg3)?;
            Ok(FspHandlerResult::None)
        }
        PHASE_ESTABLISHED => {
            if session.state() != FspSessionState::Established {
                return Ok(FspHandlerResult::None);
            }
            let (k_recv, _k_send) = session.session_keys().unwrap();
            let Some((flags, counter, header, encrypted)) = parse_fsp_encrypted_header(fsp_data)
            else {
                return Ok(FspHandlerResult::None);
            };
            if flags & FLAG_UNENCRYPTED != 0 {
                return Ok(FspHandlerResult::None);
            }
            let mut dec = [0u8; 512];
            let dl = crate::noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut dec)
                .map_err(|_| FspHandlerError::DecryptFailed)?;
            let Some((_timestamp, _inner_msg_type, _inner_flags, _inner_payload)) =
                fsp_strip_inner_header(&dec[..dl])
            else {
                return Err(FspHandlerError::InnerHeaderTooShort);
            };
            Ok(FspHandlerResult::None)
        }
        _ => Err(FspHandlerError::UnknownPhase),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsp_datagram_roundtrip() {
        let d = FspDatagram {
            src_port: 256,
            dst_port: 2121,
            payload: b"hello",
        };
        let mut out = [0u8; 256];
        let len = d.serialize(&mut out);
        assert_eq!(len, 9);
        let parsed = FspDatagram::parse(&out[..len]).unwrap();
        assert_eq!(parsed.src_port, 256);
        assert_eq!(parsed.dst_port, 2121);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn fsp_datagram_empty_payload() {
        let d = FspDatagram {
            src_port: 0,
            dst_port: 0,
            payload: &[],
        };
        let mut out = [0u8; 256];
        let len = d.serialize(&mut out);
        assert_eq!(len, 4);
    }

    #[test]
    fn fsp_datagram_too_short() {
        assert!(FspDatagram::parse(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn ipv6_shim_roundtrip() {
        let s = Ipv6Shim {
            next_header: 58,
            hop_limit: 64,
            payload: &[0x80, 0x00, 0x12, 0x34],
        };
        let mut out = [0u8; 256];
        let len = s.serialize(&mut out);
        assert_eq!(len, 10);
        let parsed = Ipv6Shim::parse(&out[..len]).unwrap();
        assert_eq!(parsed.next_header, 58);
        assert_eq!(parsed.hop_limit, 64);
        assert_eq!(parsed.payload, &[0x80, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn ipv6_shim_too_short() {
        assert!(Ipv6Shim::parse(&[0, 1, 2]).is_none());
    }

    #[test]
    fn ipv6_shim_empty_payload() {
        let s = Ipv6Shim {
            next_header: 6,
            hop_limit: 255,
            payload: &[],
        };
        let mut out = [0u8; 256];
        let len = s.serialize(&mut out);
        assert_eq!(len, 6);
    }

    #[test]
    fn fsp_ipv6_shim_nested() {
        let shim = Ipv6Shim {
            next_header: 58,
            hop_limit: 64,
            payload: &[0x80, 0x00, 0x12, 0x34],
        };
        let mut shim_buf = [0u8; 256];
        let shim_len = shim.serialize(&mut shim_buf);

        let d = FspDatagram {
            src_port: FSP_PORT_IPV6_SHIM,
            dst_port: FSP_PORT_IPV6_SHIM,
            payload: &shim_buf[..shim_len],
        };
        let mut out = [0u8; 512];
        let len = d.serialize(&mut out);

        let parsed = FspDatagram::parse(&out[..len]).unwrap();
        assert_eq!(parsed.src_port, FSP_PORT_IPV6_SHIM);
        assert_eq!(parsed.dst_port, FSP_PORT_IPV6_SHIM);

        let inner_shim = Ipv6Shim::parse(parsed.payload).unwrap();
        assert_eq!(inner_shim.next_header, 58);
        assert_eq!(inner_shim.hop_limit, 64);
    }

    fn make_addr(val: u8) -> [u8; NODE_ADDR_SIZE] {
        let mut a = [0u8; NODE_ADDR_SIZE];
        a[0] = val;
        a
    }

    #[test]
    fn session_setup_roundtrip() {
        let src = [make_addr(0x01)];
        let dst = [make_addr(0x02)];
        let handshake = [0xAA; XK_HANDSHAKE_MSG1_SIZE];
        let mut out = [0u8; 256];
        let len = build_session_setup(0x00, &src, &dst, &handshake, &mut out).unwrap();

        assert_eq!(out[0], fsp_prefix_byte(PHASE_SESSION_SETUP));
        assert_eq!(out[1], 0x00);
        let payload_len = u16::from_le_bytes([out[2], out[3]]) as usize;
        assert_eq!(payload_len + 4, len);

        let (flags, hs_out) = parse_session_setup(&out[..len]).unwrap();
        assert_eq!(flags, 0x00);
        assert_eq!(hs_out, &handshake);
    }

    #[test]
    fn session_setup_multi_coords() {
        let src = [make_addr(0x01), make_addr(0x02), make_addr(0x03)];
        let dst = [make_addr(0x10), make_addr(0x11)];
        let handshake = [0xBB; 33];
        let mut out = [0u8; 512];
        let len = build_session_setup(0x01, &src, &dst, &handshake, &mut out).unwrap();

        let (_, hs_out) = parse_session_setup(&out[..len]).unwrap();
        assert_eq!(hs_out, &handshake);
    }

    #[test]
    fn session_setup_rejects_empty_coords() {
        let handshake = [0xAA; 33];
        let mut out = [0u8; 256];
        assert_eq!(
            build_session_setup(0x00, &[], &[make_addr(0x01)], &handshake, &mut out),
            Err(FspError::InvalidCoords)
        );
    }

    #[test]
    fn session_setup_too_short() {
        assert!(parse_session_setup(&[0x00]).is_err());
        assert!(parse_session_setup(&[0x11, 0x00, 0x01, 0x00]).is_err());
    }

    #[test]
    fn session_ack_roundtrip() {
        let src = [make_addr(0x01)];
        let dst = [make_addr(0x02)];
        let handshake = [0xCC; XK_HANDSHAKE_MSG2_SIZE];
        let mut out = [0u8; 256];
        let len = build_session_ack(&src, &dst, &handshake, &mut out).unwrap();

        assert_eq!(out[0], fsp_prefix_byte(PHASE_SESSION_ACK));

        let hs_out = parse_session_ack(&out[..len]).unwrap();
        assert_eq!(hs_out, &handshake);
    }

    #[test]
    fn session_ack_too_short() {
        assert!(parse_session_ack(&[0x00]).is_err());
    }

    #[test]
    fn session_msg3_roundtrip() {
        let handshake = [0xDD; XK_HANDSHAKE_MSG3_SIZE];
        let mut out = [0u8; 256];
        let len = build_session_msg3(&handshake, &mut out).unwrap();

        assert_eq!(out[0], fsp_prefix_byte(PHASE_SESSION_MSG3));

        let hs_out = parse_session_msg3(&out[..len]).unwrap();
        assert_eq!(hs_out, &handshake);
    }

    #[test]
    fn session_msg3_too_short() {
        assert!(parse_session_msg3(&[0x00]).is_err());
    }

    #[test]
    fn session_msg3_wrong_phase() {
        let mut data = [0u8; 16];
        data[0] = fsp_prefix_byte(PHASE_SESSION_ACK);
        assert!(parse_session_msg3(&data).is_err());
    }

    #[test]
    fn fsp_prefix_encoding() {
        assert_eq!(fsp_prefix_byte(PHASE_SESSION_SETUP), 0x01);
        assert_eq!(fsp_prefix_byte(PHASE_SESSION_ACK), 0x02);
        assert_eq!(fsp_prefix_byte(PHASE_SESSION_MSG3), 0x03);
        assert_eq!(fsp_prefix_byte(PHASE_ESTABLISHED), 0x00);
    }

    use super::{FspSession, FspSessionError, FspSessionState};

    fn test_keys() -> ([u8; 32], [u8; 32], [u8; 32]) {
        use k256::SecretKey;
        use rand::RngCore;

        let mut rng = rand::rng();
        let mut gen_key = || -> [u8; 32] {
            let mut key = [0u8; 32];
            loop {
                rng.fill_bytes(&mut key);
                if SecretKey::from_slice(&key).is_ok() {
                    return key;
                }
            }
        };
        let responder_secret = gen_key();
        let responder_eph = gen_key();
        let initiator_secret = gen_key();
        (responder_secret, responder_eph, initiator_secret)
    }

    #[test]
    fn fsp_session_starts_idle() {
        let session = FspSession::new();
        assert_eq!(session.state(), FspSessionState::Idle);
        assert_eq!(session.session_keys(), None);
    }

    #[test]
    fn fsp_session_rejects_msg3_when_idle() {
        let mut session = FspSession::new();
        let msg3_data = [0xDD; 80];
        let result = session.handle_msg3(&msg3_data);
        assert_eq!(result, Err(FspSessionError::InvalidState));
    }

    #[test]
    fn fsp_session_full_flow() {
        use crate::noise::{ecdh_pubkey, NoiseXkInitiator};

        let (responder_secret, responder_eph, initiator_secret) = test_keys();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let initiator_pub = ecdh_pubkey(&initiator_secret).unwrap();
        let epoch_r = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_i = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let initiator_eph: [u8; 32] = [0x01; 32];
        let (mut initiator, _) =
            NoiseXkInitiator::new(&initiator_eph, &initiator_secret, &responder_pub).unwrap();

        let mut xk_msg1 = [0u8; 64];
        let msg1_len = initiator.write_message1(&mut xk_msg1).unwrap();
        assert_eq!(msg1_len, XK_HANDSHAKE_MSG1_SIZE);

        let responder_addr = make_addr(0x01);
        let initiator_addr = make_addr(0x02);
        let mut setup_buf = [0u8; 512];
        let setup_len = build_session_setup(
            0x00,
            &[responder_addr],
            &[initiator_addr],
            &xk_msg1[..msg1_len],
            &mut setup_buf,
        )
        .unwrap();

        let mut session = FspSession::new();
        let mut ack_buf = [0u8; 512];
        let ack_len = session
            .handle_setup(
                &responder_secret,
                &responder_eph,
                &epoch_r,
                &setup_buf[..setup_len],
                &mut ack_buf,
            )
            .unwrap();

        assert_eq!(session.state(), FspSessionState::AwaitingMsg3);
        assert_eq!(session.session_keys(), None);

        let mut ack_stored = [0u8; 512];
        ack_stored[..ack_len].copy_from_slice(&ack_buf[..ack_len]);
        let xk_msg2_payload = parse_session_ack(&ack_stored[..ack_len]).unwrap();
        assert_eq!(xk_msg2_payload.len(), XK_HANDSHAKE_MSG2_SIZE);

        let received_epoch = initiator.read_message2(xk_msg2_payload).unwrap();
        assert_eq!(received_epoch, epoch_r);

        let mut msg3_noise = [0u8; 128];
        let msg3_len = initiator
            .write_message3(&initiator_pub, &epoch_i, &mut msg3_noise)
            .unwrap();
        assert_eq!(msg3_len, XK_HANDSHAKE_MSG3_SIZE);

        let _responder_addr = make_addr(0x01);
        let _initiator_addr = make_addr(0x02);
        let mut msg3_buf = [0u8; 512];
        let msg3_fsp_len = build_session_msg3(&msg3_noise[..msg3_len], &mut msg3_buf).unwrap();

        session.handle_msg3(&msg3_buf[..msg3_fsp_len]).unwrap();

        assert_eq!(session.state(), FspSessionState::Established);
        let (k_recv, k_send) = session.session_keys().unwrap();
        assert_ne!(k_recv, [0u8; 32]);
        assert_ne!(k_send, [0u8; 32]);
        assert_eq!(session.initiator_pub(), Some(initiator_pub));

        let (k_send_i, k_recv_i) = initiator.finalize();
        assert_eq!(k_recv, k_send_i, "session k_recv == initiator k_send");
        assert_eq!(k_send, k_recv_i, "session k_send == initiator k_recv");
    }

    #[test]
    fn fsp_session_reset() {
        let mut session = FspSession::new();
        session.state = FspSessionState::Established;
        session.k_recv = Some([0x42; 32]);
        session.k_send = Some([0x99; 32]);
        session.reset();
        assert_eq!(session.state(), FspSessionState::Idle);
        assert_eq!(session.session_keys(), None);
    }

    #[test]
    fn fsp_session_rejects_double_setup() {
        use crate::noise::{ecdh_pubkey, NoiseXkInitiator};

        let (responder_secret, responder_eph, initiator_secret) = test_keys();
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let (initiator_eph, _) = {
            use k256::SecretKey;
            use rand::RngCore;
            let mut key = [0u8; 32];
            loop {
                rand::rng().fill_bytes(&mut key);
                if SecretKey::from_slice(&key).is_ok() {
                    break;
                }
            }
            let pub_key = ecdh_pubkey(&key).unwrap();
            (key, pub_key)
        };
        let epoch_r = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) =
            NoiseXkInitiator::new(&initiator_eph, &initiator_secret, &responder_pub).unwrap();
        let mut xk_msg1 = [0u8; 64];
        let msg1_len = initiator.write_message1(&mut xk_msg1).unwrap();

        let src = [make_addr(0x01)];
        let dst = [make_addr(0x02)];
        let mut setup_buf = [0u8; 512];
        let setup_len =
            build_session_setup(0x00, &src, &dst, &xk_msg1[..msg1_len], &mut setup_buf).unwrap();

        let mut session = FspSession::new();
        let mut ack = [0u8; 512];
        session
            .handle_setup(
                &responder_secret,
                &responder_eph,
                &epoch_r,
                &setup_buf[..setup_len],
                &mut ack,
            )
            .unwrap();
        assert_eq!(session.state(), FspSessionState::AwaitingMsg3);

        let result = session.handle_setup(
            &responder_secret,
            &responder_eph,
            &epoch_r,
            &setup_buf[..setup_len],
            &mut ack,
        );
        assert_eq!(result, Err(FspSessionError::InvalidState));
    }

    #[test]
    fn fsp_encrypted_header_roundtrip() {
        use crate::noise::aead_encrypt;

        let key = [0xAB; 32];
        let counter = 42u64;
        let flags = 0u8;
        let timestamp_ms = 12345u32;
        let msg_type = FSP_MSG_DATA;
        let inner_flags = 0u8;
        let app_payload = b"hello world";

        let mut inner = [0u8; 64];
        let inner_len =
            fsp_prepend_inner_header(timestamp_ms, msg_type, inner_flags, app_payload, &mut inner);
        assert_eq!(inner_len, FSP_INNER_HEADER_SIZE + app_payload.len());

        let mut ct = [0u8; 128];
        let header = build_fsp_header(counter, flags, inner_len as u16);
        let ct_len = aead_encrypt(&key, counter, &header, &inner[..inner_len], &mut ct).unwrap();

        let mut packet = [0u8; 256];
        let pkt_len = build_fsp_encrypted(&header, &ct[..ct_len], &mut packet);
        assert_eq!(pkt_len, FSP_HEADER_SIZE + ct_len);

        let (parsed_flags, parsed_counter, parsed_header, parsed_ct) =
            parse_fsp_encrypted_header(&packet[..pkt_len]).unwrap();
        assert_eq!(parsed_flags, flags);
        assert_eq!(parsed_counter, counter);
        assert_eq!(parsed_header, &header[..]);
        assert_eq!(parsed_ct.len(), ct_len);

        let mut dec = [0u8; 64];
        let dl =
            crate::noise::aead_decrypt(&key, counter, parsed_header, parsed_ct, &mut dec).unwrap();
        let (ts, mt, ifl, rest) = fsp_strip_inner_header(&dec[..dl]).unwrap();
        assert_eq!(ts, timestamp_ms);
        assert_eq!(mt, msg_type);
        assert_eq!(ifl, inner_flags);
        assert_eq!(rest, app_payload);
    }

    #[test]
    fn fsp_encrypted_header_rejects_wrong_phase() {
        let mut data = [0u8; FSP_ENCRYPTED_MIN_SIZE];
        data[0] = 0x01;
        assert!(parse_fsp_encrypted_header(&data).is_none());
    }

    #[test]
    fn fsp_encrypted_header_rejects_too_short() {
        assert!(parse_fsp_encrypted_header(&[0u8; FSP_ENCRYPTED_MIN_SIZE - 1]).is_none());
    }

    #[test]
    fn fsp_strip_inner_header_too_short() {
        assert!(fsp_strip_inner_header(&[0u8; 5]).is_none());
        assert!(fsp_strip_inner_header(&[]).is_none());
    }

    #[test]
    fn fsp_build_header_fields() {
        let header = build_fsp_header(0xDEADBEEF, FLAG_COORDS_PRESENT | FLAG_KEY_EPOCH, 200);
        assert_eq!(header[0], fsp_prefix_byte(PHASE_ESTABLISHED));
        assert_eq!(header[1], FLAG_COORDS_PRESENT | FLAG_KEY_EPOCH);
        assert_eq!(u16::from_le_bytes([header[2], header[3]]), 200);
        assert_eq!(
            u64::from_le_bytes(header[4..12].try_into().unwrap()),
            0xDEADBEEF
        );
    }

    #[test]
    fn fsp_cp_flag_skips_coordinates() {
        use crate::noise::aead_encrypt;

        let key = [0xAB; 32];
        let counter = 7u64;
        let flags = FLAG_COORDS_PRESENT;
        let timestamp_ms = 100u32;
        let msg_type = FSP_MSG_DATA;
        let inner_flags = 0u8;
        let app_payload = b"test";

        let mut inner = [0u8; 64];
        let inner_len =
            fsp_prepend_inner_header(timestamp_ms, msg_type, inner_flags, app_payload, &mut inner);

        let mut ct = [0u8; 128];
        let header = build_fsp_header(counter, flags, inner_len as u16);
        let ct_len = aead_encrypt(&key, counter, &header, &inner[..inner_len], &mut ct).unwrap();

        let src_coord = [0xAA; NODE_ADDR_SIZE];
        let dst_coord = [0xBB; NODE_ADDR_SIZE];
        let coord_data_len = 2 + NODE_ADDR_SIZE + 2 + NODE_ADDR_SIZE;
        let total = FSP_HEADER_SIZE + coord_data_len + ct_len;

        let mut packet = [0u8; 256];
        packet[..FSP_HEADER_SIZE].copy_from_slice(&header);
        packet[FSP_HEADER_SIZE..FSP_HEADER_SIZE + 2].copy_from_slice(&1u16.to_le_bytes());
        packet[FSP_HEADER_SIZE + 2..FSP_HEADER_SIZE + 2 + NODE_ADDR_SIZE]
            .copy_from_slice(&src_coord);
        let dst_off = FSP_HEADER_SIZE + 2 + NODE_ADDR_SIZE;
        packet[dst_off..dst_off + 2].copy_from_slice(&1u16.to_le_bytes());
        packet[dst_off + 2..dst_off + 2 + NODE_ADDR_SIZE].copy_from_slice(&dst_coord);
        packet[dst_off + 2 + NODE_ADDR_SIZE..total].copy_from_slice(&ct[..ct_len]);

        let (parsed_flags, parsed_counter, parsed_header, parsed_ct) =
            parse_fsp_encrypted_header(&packet[..total]).unwrap();
        assert_eq!(parsed_flags, flags);
        assert_eq!(parsed_counter, counter);
        assert_eq!(parsed_ct.len(), ct_len);
        assert_eq!(parsed_ct, &ct[..ct_len]);

        let mut dec = [0u8; 64];
        let dl =
            crate::noise::aead_decrypt(&key, counter, parsed_header, parsed_ct, &mut dec).unwrap();
        let (ts, mt, _, rest) = fsp_strip_inner_header(&dec[..dl]).unwrap();
        assert_eq!(ts, timestamp_ms);
        assert_eq!(mt, msg_type);
        assert_eq!(rest, app_payload);
    }

    #[test]
    fn fsp_cp_flag_too_short_coords_rejected() {
        let mut data = [0u8; FSP_HEADER_SIZE + 3];
        data[0] = fsp_prefix_byte(PHASE_ESTABLISHED);
        data[1] = FLAG_COORDS_PRESENT;
        data[2] = 1;
        data[3] = 0;
        data[FSP_HEADER_SIZE] = 1;
        data[FSP_HEADER_SIZE + 1] = 0;
        data[FSP_HEADER_SIZE + 2] = 0xAA;
        assert!(parse_fsp_encrypted_header(&data).is_none());
    }
}
