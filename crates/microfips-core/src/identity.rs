use sha2::{Digest, Sha256};

pub const DEFAULT_SECRET: [u8; 32] = [
    0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4, 0xee, 0xb5,
    0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7, 0x84, 0x3f, 0x83, 0x2e,
];

pub const DEFAULT_PEER_PUB: [u8; 33] = [
    0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4, 0xf5, 0x73,
    0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a, 0x2a, 0x3a, 0x03, 0x7d,
    0x21,
];

pub struct NodeAddr(pub [u8; 16]);

impl NodeAddr {
    pub fn from_pubkey_x(x_only: &[u8; 32]) -> Self {
        let hash = Sha256::digest(x_only);
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&hash[..16]);
        Self(addr)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

pub struct FipsAddress(pub [u8; 16]);

impl FipsAddress {
    pub fn from_node_addr(node_addr: &NodeAddr) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfd;
        bytes[1..].copy_from_slice(&node_addr.0[..15]);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(input);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Load the FIPS secret key from the `FIPS_SECRET` env var (64 hex chars),
/// falling back to `DEFAULT_SECRET` if not set.
///
/// Panics on invalid hex or wrong length — acceptable for host-side tools.
#[cfg(feature = "std")]
pub fn load_secret() -> [u8; 32] {
    match std::env::var("FIPS_SECRET") {
        Ok(h) => {
            let b = hex::decode(h.trim()).expect("FIPS_SECRET: invalid hex");
            assert!(
                b.len() == 32,
                "FIPS_SECRET: must be 32 bytes (64 hex chars)"
            );
            b.try_into().unwrap()
        }
        Err(_) => DEFAULT_SECRET,
    }
}

/// Load the FIPS peer public key from the `FIPS_PEER_PUB` env var (66 hex chars),
/// falling back to `DEFAULT_PEER_PUB` if not set.
///
/// Panics on invalid hex or wrong length — acceptable for host-side tools.
#[cfg(feature = "std")]
pub fn load_peer_pub() -> [u8; 33] {
    match std::env::var("FIPS_PEER_PUB") {
        Ok(h) => {
            let b = hex::decode(h.trim()).expect("FIPS_PEER_PUB: invalid hex");
            assert!(
                b.len() == 33,
                "FIPS_PEER_PUB: must be 33 bytes (66 hex chars)"
            );
            b.try_into().unwrap()
        }
        Err(_) => DEFAULT_PEER_PUB,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_addr_from_known_key() {
        let x_only: [u8; 32] = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let addr = NodeAddr::from_pubkey_x(&x_only);
        let expected_hash = Sha256::digest(&x_only);
        assert_eq!(addr.as_bytes(), &expected_hash[..16]);
    }

    #[test]
    fn fips_address_starts_with_fd() {
        let x_only = [0u8; 32];
        let addr = NodeAddr::from_pubkey_x(&x_only);
        let fips = FipsAddress::from_node_addr(&addr);
        assert_eq!(fips.as_bytes()[0], 0xfd);
    }

    #[test]
    fn fips_address_truncates_node_addr() {
        let x_only = [0xAA; 32];
        let addr = NodeAddr::from_pubkey_x(&x_only);
        let fips = FipsAddress::from_node_addr(&addr);
        assert_eq!(&fips.as_bytes()[1..16], &addr.as_bytes()[..15]);
    }

    #[test]
    fn sha256_known_vector() {
        let input = b"";
        let hash = sha256(input);
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        let input = b"abc";
        let hash = sha256(input);
        assert_eq!(
            hex::encode(hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
