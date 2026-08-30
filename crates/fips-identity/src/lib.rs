#![no_std]

#[cfg(feature = "std")]
extern crate std;

use sha2::{Digest, Sha256};

pub mod bech32;

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

pub const PEER_ALLOWLIST_MAX: usize = 16;

/// WireGuard-style set of expected peer static keys (microfips issue #134).
///
/// A responder with an allowlist answers only initiators whose static key is
/// a member; unknown initiators are dropped silently — "the server does not
/// even respond at all to an unauthorized client" (Donenfeld, WireGuard,
/// NDSS 2017). Identity mapping stays above the protocol: a public key is
/// valid until removed from the list. No PKI, no CRL.
pub struct PeerAllowlist {
    npubs: [[u8; 33]; PEER_ALLOWLIST_MAX],
    len: usize,
}

impl Default for PeerAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerAllowlist {
    pub const fn new() -> Self {
        Self {
            npubs: [[0u8; 33]; PEER_ALLOWLIST_MAX],
            len: 0,
        }
    }

    /// Returns false when the key is already listed or the list is full.
    pub fn insert(&mut self, npub: &[u8; 33]) -> bool {
        if self.contains(npub) || self.len == PEER_ALLOWLIST_MAX {
            return false;
        }
        self.npubs[self.len] = *npub;
        self.len += 1;
        true
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Membership by x-only comparison (02/03 prefix-insensitive), matching
    /// the responder's static-key checks in microfips-protocol node.rs.
    pub fn contains(&self, npub: &[u8; 33]) -> bool {
        self.npubs[..self.len]
            .iter()
            .any(|k| k[1..33] == npub[1..33])
    }
}

fn decode_npub(s: &str) -> Option<[u8; 33]> {
    let bytes = s.as_bytes();
    if bytes.len() != 66 {
        return None;
    }
    let mut npub = [0u8; 33];
    for i in 0..33 {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        npub[i] = ((hi << 4) | lo) as u8;
    }
    if npub[0] != 0x02 && npub[0] != 0x03 {
        return None;
    }
    Some(npub)
}

/// Parse a comma-separated list of 66-hex compressed pubkeys, the format
/// accepted by the FIPS_PEER_ALLOWLIST env var. Any malformed entry
/// invalidates the whole list — fail closed, never silently truncate.
pub fn parse_peer_allowlist(s: &str) -> Option<PeerAllowlist> {
    let mut list = PeerAllowlist::new();
    for part in s.split(',') {
        let npub = decode_npub(part.trim())?;
        if !list.insert(&npub) {
            return None;
        }
    }
    if list.is_empty() {
        return None;
    }
    Some(list)
}

/// Responder-side allowlist from the FIPS_PEER_ALLOWLIST env var
/// (comma-separated 66-hex npubs). Unset or empty → None (allowlist not
/// configured; the single-peer pin stays the enforcement). Set but malformed
/// → panic, mirroring load_peer_pub: a responder must never silently widen
/// who it answers.
#[cfg(feature = "std")]
pub fn load_peer_allowlist() -> Option<PeerAllowlist> {
    let raw = std::env::var("FIPS_PEER_ALLOWLIST").ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    Some(parse_peer_allowlist(&raw).unwrap_or_else(|| {
        panic!("FIPS_PEER_ALLOWLIST must be comma-separated 66-hex npubs (fail closed)")
    }))
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

    // secp256k1 generator·1 / ·2 compressed pubkeys (public test vectors).
    const G1_02: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G1_03: &str = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G2_02: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const LIST_1_2: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,\
03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn npub(s: &str) -> [u8; 33] {
        decode_npub(s).unwrap()
    }

    fn random_npub(seed: u8) -> [u8; 33] {
        let mut key = [0x02u8; 33];
        key[1..].copy_from_slice(&sha256(&[seed]));
        key
    }

    #[test]
    fn peer_allowlist_parse_and_membership() {
        let list = parse_peer_allowlist(LIST_1_2).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&npub(G1_02)));
        assert!(list.contains(&npub(G1_03)), "prefix-insensitive");
        assert!(list.contains(&npub(G2_02)));
        assert!(!list.contains(&random_npub(1)));
    }

    #[test]
    fn peer_allowlist_rejects_malformed_input() {
        assert!(parse_peer_allowlist("").is_none());
        assert!(parse_peer_allowlist(",").is_none());
        assert!(parse_peer_allowlist("02nothex").is_none());
        assert!(parse_peer_allowlist("02ab").is_none());
        assert!(parse_peer_allowlist("0479be").is_none());
        assert!(parse_peer_allowlist(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, broken"
        )
        .is_none());
        assert!(parse_peer_allowlist(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8"
        )
        .is_none());
    }

    #[test]
    fn peer_allowlist_rejects_duplicates_and_overfill() {
        let mut list = PeerAllowlist::new();
        assert!(list.insert(&npub(G1_02)));
        assert!(!list.insert(&npub(G1_03)), "x-only duplicate");
        for i in 0..PEER_ALLOWLIST_MAX - 1 {
            assert!(list.insert(&random_npub(i as u8)));
        }
        let overflow = npub(G2_02);
        assert!(!list.insert(&overflow), "capacity {}", PEER_ALLOWLIST_MAX);
        assert_eq!(list.len(), PEER_ALLOWLIST_MAX);
        assert!(!list.contains(&overflow));
    }

    #[test]
    fn peer_allowlist_empty_contains_nothing() {
        let list = PeerAllowlist::new();
        assert!(list.is_empty());
        assert!(!list.contains(&npub(G1_02)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn peer_allowlist_env_absent_and_present() {
        // Mutates process-global env — the only test touching this var.
        std::env::remove_var("FIPS_PEER_ALLOWLIST");
        assert!(load_peer_allowlist().is_none(), "unset → not configured");

        std::env::set_var("FIPS_PEER_ALLOWLIST", "   ");
        assert!(load_peer_allowlist().is_none(), "blank → not configured");

        std::env::set_var("FIPS_PEER_ALLOWLIST", LIST_1_2);
        let list = load_peer_allowlist().expect("set + valid → Some");
        assert_eq!(list.len(), 2);
        assert!(list.contains(&npub(G1_03)));

        std::env::remove_var("FIPS_PEER_ALLOWLIST");
    }
}
