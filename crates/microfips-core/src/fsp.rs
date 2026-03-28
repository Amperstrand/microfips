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
}
