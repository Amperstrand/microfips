//! FIPS identity — device constants + re-exports from fips-identity crate.
//!
//! Device constants (STM32_NSEC, VPS_NPUB, etc.) remain here because they
//! use compile-time env!() macros and the hex_bytes_* helpers from crate::hex.
//! All pure protocol logic (NodeAddr, sha256, key derivation) lives in the
//! standalone fips-identity crate.

pub use fips_identity::*;

use crate::hex::{hex_bytes_16, hex_bytes_32, hex_bytes_33};

pub const STM32_NSEC: [u8; 32] = hex_bytes_32(env!("DEVICE_NSEC_HEX_stm32"));
pub const VPS_NPUB: [u8; 33] = hex_bytes_33(env!("DEVICE_NPUB_HEX_vps"));
pub const STM32_NPUB: [u8; 33] = hex_bytes_33(env!("DEVICE_NPUB_HEX_stm32"));
pub const STM32_NODE_ADDR: [u8; 16] = hex_bytes_16(env!("DEVICE_NODE_ADDR_stm32"));
pub const ESP32_NPUB: [u8; 33] = hex_bytes_33(env!("DEVICE_NPUB_HEX_esp32"));
pub const ESP32_NODE_ADDR: [u8; 16] = hex_bytes_16(env!("DEVICE_NODE_ADDR_esp32"));

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify keys.json-derived constants are internally consistent.
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

        let vps_x: [u8; 32] = VPS_NPUB[1..].try_into().unwrap();
        let vps_addr = NodeAddr::from_pubkey_x(&vps_x);
        assert_eq!(
            vps_addr.as_bytes(),
            &hex_bytes_16(env!("DEVICE_NODE_ADDR_vps")),
            "VPS NODE_ADDR must match sha256(pubkey_x)[0..16]"
        );
    }
}
