use microfips_core::identity::NodeAddr;
use microfips_core::noise;

use crate::config::ESP32_SECRET;

pub struct NodeIdentity {
    pub node_addr_hex: [u8; 32],
    pub pubkey_hex: [u8; 66],
}

impl NodeIdentity {
    pub fn compute() -> Self {
        let pub_key = noise::ecdh_pubkey(&ESP32_SECRET).expect("ecdh_pubkey");
        let normalized = noise::parity_normalize(&pub_key);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        let node_addr = NodeAddr::from_pubkey_x(&x_only);

        let mut node_addr_hex = [0u8; 32];
        hex_encode(&node_addr.0, &mut node_addr_hex);

        let mut pubkey_hex = [0u8; 66];
        hex_encode(&pub_key, &mut pubkey_hex);

        NodeIdentity {
            node_addr_hex,
            pubkey_hex,
        }
    }

    pub fn node_addr_str(&self) -> &str {
        core::str::from_utf8(&self.node_addr_hex).unwrap_or("?")
    }

    pub fn pubkey_str(&self) -> &str {
        core::str::from_utf8(&self.pubkey_hex).unwrap_or("?")
    }
}

pub struct PeerInfo {
    pub pubkey_hex: [u8; 66],
    pub node_addr_hex: [u8; 32],
}

impl PeerInfo {
    pub fn from_pubkey(pubkey: &[u8; 33]) -> Self {
        let normalized = noise::parity_normalize(pubkey);
        let x_only: [u8; 32] = normalized[1..].try_into().unwrap();
        let node_addr = NodeAddr::from_pubkey_x(&x_only);

        let mut pubkey_hex = [0u8; 66];
        hex_encode(pubkey, &mut pubkey_hex);

        let mut node_addr_hex = [0u8; 32];
        hex_encode(&node_addr.0, &mut node_addr_hex);

        PeerInfo {
            pubkey_hex,
            node_addr_hex,
        }
    }

    pub fn node_addr_str(&self) -> &str {
        core::str::from_utf8(&self.node_addr_hex).unwrap_or("?")
    }

    pub fn pubkey_str(&self) -> &str {
        core::str::from_utf8(&self.pubkey_hex).unwrap_or("?")
    }
}

fn hex_encode(input: &[u8], output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in input.iter().enumerate() {
        output[i * 2] = HEX[(b >> 4) as usize];
        output[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
}
