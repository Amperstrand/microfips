pub const FSP_VERSION: u8 = 0;
pub const FSP_COMMON_PREFIX_SIZE: usize = 4;
pub const FSP_HEADER_SIZE: usize = 12;
pub const FSP_INNER_HEADER_SIZE: usize = 6;
pub const FSP_ENCRYPTED_MIN_SIZE: usize = 28;

pub const FSP_PORT_IPV6_SHIM: u16 = 256;

pub const XK_HANDSHAKE_MSG1_SIZE: usize = 33;
pub const XK_HANDSHAKE_MSG2_SIZE: usize = 57;
pub const XK_HANDSHAKE_MSG3_SIZE: usize = 73;

pub const PHASE_ESTABLISHED: u8 = 0x00;
pub const PHASE_SESSION_SETUP: u8 = 0x01;
pub const PHASE_SESSION_ACK: u8 = 0x02;
pub const PHASE_SESSION_MSG3: u8 = 0x03;

pub const FSP_MSG_DATA: u8 = 0x10;

pub const FLAG_COORDS_PRESENT: u8 = 0x01;
pub const FLAG_KEY_EPOCH: u8 = 0x02;
pub const FLAG_UNENCRYPTED: u8 = 0x04;

pub const FIPS_UDP_PORT: u16 = 2121;
pub const FIPS_IPV6_OVERHEAD: usize = 77;

pub const FSP_DATAGRAM_HEADER_SIZE: usize = 4;
pub const NODE_ADDR_SIZE: usize = 16;

pub const SESSION_DATAGRAM_BODY_SIZE: usize = 35;
pub const SESSION_DATAGRAM_HEADER_SIZE: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspError {
    BufferTooSmall,
    InvalidFrame,
    InvalidCoords,
}

fn fsp_prefix_byte(phase: u8) -> u8 {
    (FSP_VERSION << 4) | (phase & 0x0F)
}

fn fsp_prefix(phase: u8, flags: u8, payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    [
        fsp_prefix_byte(phase),
        flags,
        payload_len as u8,
        (payload_len >> 8) as u8,
    ]
}

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

    Ok(pos)
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FspDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> FspDatagram<'a> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Shim<'a> {
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

impl<'a> Ipv6Shim<'a> {
    pub const HEADER_SIZE: usize = 6;

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

pub fn build_fsp_header(counter: u64, flags: u8, payload_len: u16) -> [u8; FSP_HEADER_SIZE] {
    let mut header = [0u8; FSP_HEADER_SIZE];
    header[0] = fsp_prefix_byte(PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..12].copy_from_slice(&counter.to_le_bytes());
    header
}

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

use crate::noise::{EPOCH_SIZE, NoiseError, NoiseXkResponder, PUBKEY_SIZE};

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

pub struct FspSession {
    state: FspSessionState,
    responder: Option<NoiseXkResponder>,
    k_recv: Option<[u8; 32]>,
    k_send: Option<[u8; 32]>,
    initiator_pub: Option<[u8; PUBKEY_SIZE]>,
}

impl FspSession {
    pub fn new() -> Self {
        Self {
            state: FspSessionState::Idle,
            responder: None,
            k_recv: None,
            k_send: None,
            initiator_pub: None,
        }
    }

    pub fn state(&self) -> FspSessionState {
        self.state
    }

    pub fn session_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        self.k_recv.zip(self.k_send)
    }

    pub fn initiator_pub(&self) -> Option<[u8; PUBKEY_SIZE]> {
        self.initiator_pub
    }

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

        Ok(ack_len)
    }

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

        Ok(())
    }

    pub fn reset(&mut self) {
        self.state = FspSessionState::Idle;
        self.responder = None;
        self.k_recv = None;
        self.k_send = None;
        self.initiator_pub = None;
    }
}

impl Default for FspSession {
    fn default() -> Self {
        Self::new()
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
        let len = build_session_setup(0x03, &src, &dst, &handshake, &mut out).unwrap();

        assert_eq!(out[0], fsp_prefix_byte(PHASE_SESSION_SETUP));
        assert_eq!(out[1], 0x00);
        let payload_len = u16::from_le_bytes([out[2], out[3]]) as usize;
        assert_eq!(payload_len + 4, len);

        let (flags, hs_out) = parse_session_setup(&out[..len]).unwrap();
        assert_eq!(flags, 0x03);
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
        let responder_secret: [u8; 32] = [0x22; 32];
        let responder_eph: [u8; 32] = [0xAA; 32];
        let initiator_secret: [u8; 32] = [0x11; 32];
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
        use crate::noise::{NoiseXkInitiator, ecdh_pubkey};

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
            0x03,
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
        use crate::noise::{NoiseXkInitiator, ecdh_pubkey};

        let responder_secret: [u8; 32] = [0x22; 32];
        let responder_eph: [u8; 32] = [0xAA; 32];
        let initiator_secret: [u8; 32] = [0x11; 32];
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let initiator_eph: [u8; 32] = [0x01; 32];
        let epoch_r = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) =
            NoiseXkInitiator::new(&initiator_eph, &initiator_secret, &responder_pub).unwrap();
        let mut xk_msg1 = [0u8; 64];
        let msg1_len = initiator.write_message1(&mut xk_msg1).unwrap();

        let src = [make_addr(0x01)];
        let dst = [make_addr(0x02)];
        let mut setup_buf = [0u8; 512];
        let setup_len =
            build_session_setup(0x03, &src, &dst, &xk_msg1[..msg1_len], &mut setup_buf).unwrap();

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
