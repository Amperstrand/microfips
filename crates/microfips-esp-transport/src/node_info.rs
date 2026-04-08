use microfips_core::identity::NodeAddr;
use microfips_core::noise;
pub use microfips_esp_common::node_info::{hex_encode, PeerInfo};

pub struct NodeIdentity {
    pub node_addr_hex: [u8; 32],
    pub pubkey_hex: [u8; 66],
}

impl NodeIdentity {
    /// Convenience: compute identity from `crate::config::DEVICE_SECRET`.
    pub fn compute() -> Self {
        Self::from_secret(&crate::config::DEVICE_SECRET)
    }

    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let pub_key = noise::ecdh_pubkey(secret).expect("ecdh_pubkey");
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

pub fn compute_node_identity(secret: &[u8; 32]) -> NodeIdentity {
    NodeIdentity::from_secret(secret)
}
