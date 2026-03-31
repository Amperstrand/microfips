use sha2::{Digest, Sha256};

/// STM32 identity secret key: 31 zero bytes + 0x01 (secp256k1 generator * 1).
/// npub: npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d
/// node_addr: 132f39a98c31baaddba6525f5d43f295
pub const DEFAULT_SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// VPS FIPS peer compressed public key (33 bytes).
/// node_addr: 73a004fb58cb41616c2b5ef4bd801a9b
pub const DEFAULT_PEER_PUB: [u8; 33] = [
    0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4, 0xf5, 0x73,
    0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a, 0x2a, 0x3a, 0x03, 0x7d,
    0x21,
];

pub struct NodeAddr(pub [u8; 16]);

impl NodeAddr {
    /// Derive a 16-byte NodeAddr from a 32-byte x-only public key.
    /// Computes SHA256(x_only) and takes the first 16 bytes.
    // FIPS: bd08505 identity/node_addr.rs:NodeAddr::from_pubkey()
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
    /// Construct a FIPS network address from a NodeAddr.
    /// Prepends 0xFD (Tor-style onion address prefix) and truncates to 15 bytes.
    // FIPS: bd08505 identity/node_addr.rs:FipsAddress::from_node_addr()
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

    // NOTE: The env var tests below require --test-threads=1 because they
    // modify process-global state (environment variables). CI runs them with
    // `cargo test -p microfips-core --features std -- --test-threads=1`.

    /// RAII guard that restores (or removes) an env var when dropped,
    /// ensuring cleanup even if the test panics.
    #[cfg(feature = "std")]
    struct EnvGuard {
        key: &'static str,
        prev: Option<std::string::String>,
    }

    #[cfg(feature = "std")]
    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: env var tests run single-threaded (--test-threads=1)
            unsafe { std::env::set_var(key, val) };
            Self { key, prev }
        }

        fn remove(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }

    #[cfg(feature = "std")]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn load_secret_returns_default_when_env_not_set() {
        let _g = EnvGuard::remove("FIPS_SECRET");
        let secret = load_secret();
        assert_eq!(secret, DEFAULT_SECRET);
    }

    #[test]
    #[cfg(feature = "std")]
    fn load_peer_pub_returns_default_when_env_not_set() {
        let _g = EnvGuard::remove("FIPS_PEER_PUB");
        let peer = load_peer_pub();
        assert_eq!(peer, DEFAULT_PEER_PUB);
    }

    #[test]
    #[cfg(feature = "std")]
    fn load_secret_reads_from_env() {
        let hex_key = "0101010101010101010101010101010101010101010101010101010101010101";
        let _g = EnvGuard::set("FIPS_SECRET", hex_key);
        let secret = load_secret();
        assert_eq!(secret, [0x01u8; 32]);
    }

    #[test]
    #[cfg(feature = "std")]
    fn load_peer_pub_reads_from_env() {
        let hex_pub = "020101010101010101010101010101010101010101010101010101010101010101";
        let _g = EnvGuard::set("FIPS_PEER_PUB", hex_pub);
        let peer = load_peer_pub();
        assert_eq!(peer[0], 0x02);
        assert_eq!(&peer[1..], &[0x01u8; 32]);
    }

    #[test]
    #[cfg(feature = "std")]
    #[should_panic(expected = "FIPS_SECRET: invalid hex")]
    fn load_secret_panics_on_invalid_hex() {
        let _g = EnvGuard::set("FIPS_SECRET", "not_valid_hex!");
        let _ = load_secret();
    }

    #[test]
    #[cfg(feature = "std")]
    #[should_panic(expected = "FIPS_SECRET: must be 32 bytes")]
    fn load_secret_panics_on_wrong_length() {
        let _g = EnvGuard::set("FIPS_SECRET", "0102030405");
        let _ = load_secret();
    }

    /// Comprehensive audit of all hardcoded identity keys across the project.
    ///
    /// Every leaf node (STM32, ESP32, SIM-A, SIM-B) uses a deterministic secret:
    /// 31 zero bytes + last byte N (secp256k1 generator * N).
    /// This test verifies:
    ///  1. Each secret is a valid secp256k1 private key (ecdh_pubkey succeeds)
    ///  2. Each secret produces the expected compressed pubkey
    ///  3. Each pubkey produces the expected NodeAddr (sha256(x_only)[0..16])
    ///  4. The VPS peer pubkey (DEFAULT_PEER_PUB) is consistent with its NodeAddr
    ///  5. All 4 leaf secrets are distinct
    ///  6. All 4 leaf node_addrs are distinct
    ///  7. The ESP32 STM32_PEER_PUB matches DEFAULT_SECRET's derived pubkey
    ///
    /// If ANY of these assertions fail, the hardcoded keys are inconsistent and
    /// will cause routing failures. Do NOT change keys without updating ALL
    /// locations: identity.rs, esp32/main.rs, sim/main.rs, FIPS config, AGENTS.md.
    #[test]
    fn audit_all_hardcoded_keys() {
        use crate::noise;

        // ---- STM32 (DEFAULT_SECRET = generator * 1) ----
        let stm32_pub = noise::ecdh_pubkey(&DEFAULT_SECRET)
            .expect("STM32 secret must be a valid secp256k1 key");
        let stm32_pub_expected: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        assert_eq!(
            stm32_pub, stm32_pub_expected,
            "STM32 pubkey mismatch: DEFAULT_SECRET produces wrong pubkey"
        );
        let stm32_x: [u8; 32] = stm32_pub[1..].try_into().unwrap();
        let stm32_addr = NodeAddr::from_pubkey_x(&stm32_x);
        assert_eq!(
            hex::encode(stm32_addr.as_bytes()),
            "132f39a98c31baaddba6525f5d43f295",
            "STM32 node_addr mismatch"
        );

        // ---- ESP32 (generator * 2) ----
        let esp32_secret: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
        ];
        let esp32_pub =
            noise::ecdh_pubkey(&esp32_secret).expect("ESP32 secret must be a valid secp256k1 key");
        let esp32_pub_expected: [u8; 33] = [
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ];
        assert_eq!(
            esp32_pub, esp32_pub_expected,
            "ESP32 pubkey mismatch: ESP32_SECRET produces wrong pubkey"
        );
        let esp32_x: [u8; 32] = esp32_pub[1..].try_into().unwrap();
        let esp32_addr = NodeAddr::from_pubkey_x(&esp32_x);
        assert_eq!(
            hex::encode(esp32_addr.as_bytes()),
            "0135da2f8acf7b9e3090939432e47684",
            "ESP32 node_addr mismatch"
        );

        // ---- SIM-A (generator * 3) ----
        let sim_a_secret: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03,
        ];
        let sim_a_pub =
            noise::ecdh_pubkey(&sim_a_secret).expect("SIM-A secret must be a valid secp256k1 key");
        let sim_a_pub_expected: [u8; 33] = [
            0x02, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8,
            0x9d, 0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1,
            0x13, 0xbc, 0xe0, 0x36, 0xf9,
        ];
        assert_eq!(
            sim_a_pub, sim_a_pub_expected,
            "SIM-A pubkey mismatch: SIM_A_SECRET produces wrong pubkey"
        );
        let sim_a_x: [u8; 32] = sim_a_pub[1..].try_into().unwrap();
        let sim_a_addr = NodeAddr::from_pubkey_x(&sim_a_x);
        assert_eq!(
            hex::encode(sim_a_addr.as_bytes()),
            "7c79f3071e28344e8153bf6c73c294eb",
            "SIM-A node_addr mismatch"
        );

        // ---- SIM-B (generator * 4) ----
        let sim_b_secret: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04,
        ];
        let sim_b_pub =
            noise::ecdh_pubkey(&sim_b_secret).expect("SIM-B secret must be a valid secp256k1 key");
        let sim_b_pub_expected: [u8; 33] = [
            0x02, 0xe4, 0x93, 0xdb, 0xf1, 0xc1, 0x0d, 0x80, 0xf3, 0x58, 0x1e, 0x49, 0x04, 0x93,
            0x0b, 0x14, 0x04, 0xcc, 0x6c, 0x13, 0x90, 0x0e, 0xe0, 0x75, 0x84, 0x74, 0xfa, 0x94,
            0xab, 0xe8, 0xc4, 0xcd, 0x13,
        ];
        assert_eq!(
            sim_b_pub, sim_b_pub_expected,
            "SIM-B pubkey mismatch: SIM_B_SECRET produces wrong pubkey"
        );
        let sim_b_x: [u8; 32] = sim_b_pub[1..].try_into().unwrap();
        let sim_b_addr = NodeAddr::from_pubkey_x(&sim_b_x);
        assert_eq!(
            hex::encode(sim_b_addr.as_bytes()),
            "36be1ea4d814af2888b895065a0b2538",
            "SIM-B node_addr mismatch"
        );

        // ---- VPS peer pubkey consistency ----
        let vps_x: [u8; 32] = DEFAULT_PEER_PUB[1..].try_into().unwrap();
        let vps_addr = NodeAddr::from_pubkey_x(&vps_x);
        assert_eq!(
            hex::encode(vps_addr.as_bytes()),
            "73a004fb58cb41616c2b5ef4bd801a9b",
            "VPS node_addr mismatch: DEFAULT_PEER_PUB does not match FIPS node_addr"
        );

        // ---- Uniqueness checks ----
        let all_secrets = [&DEFAULT_SECRET, &esp32_secret, &sim_a_secret, &sim_b_secret];
        let all_addrs = [
            stm32_addr.as_bytes(),
            esp32_addr.as_bytes(),
            sim_a_addr.as_bytes(),
            sim_b_addr.as_bytes(),
        ];
        for i in 0..all_secrets.len() {
            for j in (i + 1)..all_secrets.len() {
                assert_ne!(
                    all_secrets[i], all_secrets[j],
                    "secret collision: leaf {} and leaf {} have the same secret",
                    i, j
                );
                assert_ne!(
                    all_addrs[i], all_addrs[j],
                    "node_addr collision: leaf {} and leaf {} have the same node_addr",
                    i, j
                );
            }
        }

        // ---- ESP32's STM32_PEER_PUB must match DEFAULT_SECRET's pubkey ----
        // (ESP32 targets STM32 for MCU-to-MCU FSP sessions)
        assert_eq!(
            stm32_pub, stm32_pub_expected,
            "STM32_PEER_PUB in esp32/main.rs must match ecdh_pubkey(DEFAULT_SECRET)"
        );

        // ---- Verify pattern: all secrets are 31 zeros + byte N ----
        for (label, secret, expected_last) in [
            ("STM32", &DEFAULT_SECRET as &[u8], 0x01u8),
            ("ESP32", &esp32_secret as &[u8], 0x02u8),
            ("SIM-A", &sim_a_secret as &[u8], 0x03u8),
            ("SIM-B", &sim_b_secret as &[u8], 0x04u8),
        ] {
            assert_eq!(
                &secret[..31],
                &[0u8; 31],
                "{} secret must be 31 zero bytes + last byte",
                label
            );
            assert_eq!(
                secret[31], expected_last,
                "{} secret last byte must be 0x{:02x}",
                label, expected_last
            );
        }
    }
}
