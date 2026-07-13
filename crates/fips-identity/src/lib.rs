#![no_std]

use sha2::{Digest, Sha256};

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

pub const TEST_KEY_SEED: &[u8] = b"fips-test";

pub fn derive_test_nsec(role: &[u8], sequence: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TEST_KEY_SEED);
    hasher.update(b"-");
    hasher.update(role);
    hasher.update(b"-");
    hasher.update(sequence.to_be_bytes());
    let result = hasher.finalize();
    let mut nsec = [0u8; 32];
    nsec.copy_from_slice(&result);
    nsec
}

pub fn derive_test_npub(role: &[u8], sequence: u32) -> [u8; 33] {
    let nsec = derive_test_nsec(role, sequence);
    fips_noise::ecdh_pubkey(&nsec).expect("derived test key must be valid")
}

pub fn derive_test_node_addr(role: &[u8], sequence: u32) -> [u8; 16] {
    let npub = derive_test_npub(role, sequence);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&npub[1..]);
    let addr = NodeAddr::from_pubkey_x(&x_only);
    let mut result = [0u8; 16];
    result.copy_from_slice(addr.as_bytes());
    result
}

pub fn hex_encode(input: &[u8], output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in input.iter().enumerate() {
        output[i * 2] = HEX[(b >> 4) as usize];
        output[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
}

pub fn encode_nsec(secret: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    hex_encode(secret, &mut out);
    out
}

#[cfg(feature = "std")]
pub fn load_secret() -> [u8; 32] {
    let (h, from_var) = match std::env::var("FIPS_NSEC") {
        Ok(v) => (v, "FIPS_NSEC"),
        Err(_) => {
            let v = std::env::var("FIPS_SECRET").expect(
                "FIPS_NSEC is required; no default device identity is allowed. \
                 (FIPS_SECRET is accepted but deprecated — use FIPS_NSEC instead.) \
                 See microfips issue #64 for secure on-device key provisioning.",
            );
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                b"WARNING: FIPS_SECRET is deprecated, use FIPS_NSEC instead\n",
            );
            (v, "FIPS_SECRET")
        }
    };
    let b = hex::decode(h.trim()).unwrap_or_else(|_| panic!("{}: invalid hex", from_var));
    assert!(
        b.len() == 32,
        "{}: must be 32 bytes (64 hex chars)",
        from_var
    );
    b.try_into().unwrap()
}

#[cfg(feature = "std")]
pub fn load_peer_pub() -> [u8; 33] {
    let (h, from_var) = match std::env::var("FIPS_PEER_NPUB") {
        Ok(v) => (v, "FIPS_PEER_NPUB"),
        Err(_) => {
            let v = std::env::var("FIPS_PEER_PUB").expect(
                "FIPS_PEER_NPUB is required; no default peer identity is allowed. \
                 (FIPS_PEER_PUB is accepted but deprecated — use FIPS_PEER_NPUB instead.) \
                 See microfips issue #64 for secure on-device key provisioning.",
            );
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                b"WARNING: FIPS_PEER_PUB is deprecated, use FIPS_PEER_NPUB instead\n",
            );
            (v, "FIPS_PEER_PUB")
        }
    };
    let b = hex::decode(h.trim()).unwrap_or_else(|_| panic!("{}: invalid hex", from_var));
    assert!(
        b.len() == 33,
        "{}: must be 33 bytes (66 hex chars)",
        from_var
    );
    b.try_into().unwrap()
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
        let expected_hash = Sha256::digest(x_only);
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
