use sha2::{Digest, Sha256};

use crate::hex::{hex_bytes_16, hex_bytes_32, hex_bytes_33};

pub const STM32_NSEC: [u8; 32] = hex_bytes_32(env!("DEVICE_NSEC_HEX_stm32"));
pub const VPS_NPUB: [u8; 33] = hex_bytes_33(env!("DEVICE_NPUB_HEX_vps"));
pub const STM32_NPUB: [u8; 33] = hex_bytes_33(env!("DEVICE_NPUB_HEX_stm32"));
pub const STM32_NODE_ADDR: [u8; 16] = hex_bytes_16(env!("DEVICE_NODE_ADDR_stm32"));
pub const ESP32_NPUB: [u8; 33] = hex_bytes_33(env!("DEVICE_NPUB_HEX_esp32"));
pub const ESP32_NODE_ADDR: [u8; 16] = hex_bytes_16(env!("DEVICE_NODE_ADDR_esp32"));

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

    // FIPS: bd08505 identity/node_addr.rs:NodeAddr::from_pubkey()
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

    // FIPS: bd08505 identity/node_addr.rs:FipsAddress::from_node_addr()
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// FIPS: bd08505 noise/mod.rs:sha256()
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(input);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Load the FIPS secret key from the `FIPS_SECRET` env var (64 hex chars).
///
/// Panics if the env var is missing, invalid, or the wrong length.
/// Host-side tools must now choose their identity explicitly instead of
/// implicitly impersonating a firmware default. Secure on-device key
/// provisioning is tracked in microfips issue #64.
// FIPS: bd08505 identity/node_addr.rs:NodeAddr::from_pubkey()
#[cfg(feature = "std")]
pub fn load_secret() -> [u8; 32] {
    let h = std::env::var("FIPS_SECRET").expect(
        "FIPS_SECRET is required; no default device identity is allowed anymore. See microfips issue #64 for secure on-device key provisioning.",
    );
    let b = hex::decode(h.trim()).expect("FIPS_SECRET: invalid hex");
    assert!(
        b.len() == 32,
        "FIPS_SECRET: must be 32 bytes (64 hex chars)"
    );
    b.try_into().unwrap()
}

/// Load the FIPS peer public key from the `FIPS_PEER_PUB` env var (66 hex chars).
///
/// Panics if the env var is missing, invalid, or the wrong length.
/// Host-side tools must now choose the remote peer explicitly instead of
/// inheriting a built-in VPS pubkey. Secure on-device key provisioning is
/// tracked in microfips issue #64.
// FIPS: bd08505 identity/node_addr.rs:NodeAddr::from_pubkey()
#[cfg(feature = "std")]
pub fn load_peer_pub() -> [u8; 33] {
    let h = std::env::var("FIPS_PEER_PUB").expect(
        "FIPS_PEER_PUB is required; no default peer identity is allowed anymore. See microfips issue #64 for secure on-device key provisioning.",
    );
    let b = hex::decode(h.trim()).expect("FIPS_PEER_PUB: invalid hex");
    assert!(
        b.len() == 33,
        "FIPS_PEER_PUB: must be 33 bytes (66 hex chars)"
    );
    b.try_into().unwrap()
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
    #[should_panic(expected = "FIPS_SECRET is required")]
    fn load_secret_panics_when_env_not_set() {
        let _g = EnvGuard::remove("FIPS_SECRET");
        let _ = load_secret();
    }

    #[test]
    #[cfg(feature = "std")]
    #[should_panic(expected = "FIPS_PEER_PUB is required")]
    fn load_peer_pub_panics_when_env_not_set() {
        let _g = EnvGuard::remove("FIPS_PEER_PUB");
        let _ = load_peer_pub();
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

    /// Verify keys.json-derived constants are internally consistent:
    ///  1. Each secret produces a valid secp256k1 pubkey
    ///  2. STM32_NPUB matches ecdh_pubkey(STM32_NSEC)
    ///  3. ESP32_NPUB matches ecdh_pubkey(esp32 nsec from keys.json)
    ///   4. VPS peer pubkey matches its node_addr
    ///  5. All leaf secrets and node_addrs are distinct
    #[test]
    #[cfg(feature = "std")]
    fn audit_keys_json_consistency() {
        use crate::noise;

        let stm32_pub =
            noise::ecdh_pubkey(&STM32_NSEC).expect("STM32 nsec must be a valid secp256k1 key");
        assert_eq!(
            stm32_pub, STM32_NPUB,
            "STM32_NPUB must match ecdh_pubkey(STM32_NSEC)"
        );

        let stm32_x: [u8; 32] = stm32_pub[1..].try_into().unwrap();
        let stm32_addr = NodeAddr::from_pubkey_x(&stm32_x);
        assert_eq!(
            stm32_addr.as_bytes(),
            &STM32_NODE_ADDR,
            "STM32_NODE_ADDR must match sha256(pubkey_x)[0..16]"
        );

        let esp32_secret = hex_bytes_32(env!("DEVICE_NSEC_HEX_esp32"));
        let esp32_pub =
            noise::ecdh_pubkey(&esp32_secret).expect("ESP32 nsec must be a valid secp256k1 key");
        assert_eq!(
            esp32_pub, ESP32_NPUB,
            "ESP32_NPUB must match ecdh_pubkey(ESP32_NSEC)"
        );

        let esp32_x: [u8; 32] = esp32_pub[1..].try_into().unwrap();
        let esp32_addr = NodeAddr::from_pubkey_x(&esp32_x);
        assert_eq!(
            esp32_addr.as_bytes(),
            &ESP32_NODE_ADDR,
            "ESP32_NODE_ADDR must match sha256(pubkey_x)[0..16]"
        );

        let vps_x: [u8; 32] = VPS_NPUB[1..].try_into().unwrap();
        let vps_addr = NodeAddr::from_pubkey_x(&vps_x);
        assert_eq!(
            vps_addr.as_bytes(),
            &hex_bytes_16(env!("DEVICE_NODE_ADDR_vps")),
            "VPS NODE_ADDR must match sha256(pubkey_x)[0..16]"
        );

        // Uniqueness: all 4 leaf secrets produce distinct addresses
        let sim_a_secret = hex_bytes_32(env!("DEVICE_NSEC_HEX_sim-a"));
        let sim_b_secret = hex_bytes_32(env!("DEVICE_NSEC_HEX_sim-b"));
        let sim_a_pub = noise::ecdh_pubkey(&sim_a_secret).unwrap();
        let sim_b_pub = noise::ecdh_pubkey(&sim_b_secret).unwrap();
        let sim_a_addr = NodeAddr::from_pubkey_x(&sim_a_pub[1..].try_into().unwrap());
        let sim_b_addr = NodeAddr::from_pubkey_x(&sim_b_pub[1..].try_into().unwrap());

        let all_addrs = [
            stm32_addr.as_bytes(),
            esp32_addr.as_bytes(),
            sim_a_addr.as_bytes(),
            sim_b_addr.as_bytes(),
        ];
        for i in 0..all_addrs.len() {
            for j in (i + 1)..all_addrs.len() {
                assert_ne!(
                    all_addrs[i], all_addrs[j],
                    "node_addr collision: leaf {} and leaf {}",
                    i, j
                );
            }
        }
    }
}
