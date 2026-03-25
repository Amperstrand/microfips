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
}
