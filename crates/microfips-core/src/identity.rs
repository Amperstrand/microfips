//! FIPS identity and address derivation.
//!
//! FIPS nodes are identified by secp256k1 public keys (from Nostr npubs).
//! Network addresses are derived deterministically from these keys:
//!
//! 1. **Node address**: `SHA256(x_only_pubkey)[0..16]` — 16-byte identifier
//!    FIPS: node address derivation in the FIPS source.
//! 2. **FIPS address**: `0xfd || node_addr[0..15]` — 16-byte IPv6-like ULA
//!    address with `0xfd` prefix (RFC 4193 Unique Local Address space).
//!
//! ## References
//!
//! - **FIPS 180-4**: Secure Hash Standard (SHA-256)
//! - **RFC 4193**: Unique Local IPv6 Unicast Addresses (ULA prefix `fc00::/7`,
//!   FIPS uses `fd00::/8`)

use sha2::{Digest, Sha256};

/// 16-byte node address derived from a public key.
///
/// Derivation: `SHA256(x_only_pubkey)[0..16]`.
///
/// FIPS: node address derivation function in the FIPS source computes
/// `SHA256(pubkey_x_bytes)` and truncates to 16 bytes.
pub struct NodeAddr(pub [u8; 16]);

impl NodeAddr {
    /// Derive a node address from an x-only (32-byte) public key.
    ///
    /// Computes `SHA256(x_only)[0..16]`.
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

/// 16-byte FIPS network address (IPv6-like ULA).
///
/// Derivation: `0xfd || node_addr[0..15]`.
///
/// The `0xfd` prefix places FIPS addresses in the IPv6 Unique Local Address
/// space (RFC 4193, `fc00::/7`). FIPS uses the `fd00::/8` subset.
pub struct FipsAddress(pub [u8; 16]);

impl FipsAddress {
    /// Create a FIPS address from a node address.
    ///
    /// Prepends `0xfd` (ULA prefix) and takes the first 15 bytes of the node
    /// address to form a 16-byte IPv6-compatible address.
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

/// Compute SHA-256 hash of `input`.
///
/// Reference: FIPS 180-4 — Secure Hash Standard.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(input);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
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
