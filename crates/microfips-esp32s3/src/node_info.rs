pub use microfips_esp_transport::node_info::{hex_encode, PeerInfo};

use crate::config::ESP32S3_SECRET;

pub struct NodeIdentity {
    pub node_addr_hex: [u8; 32],
    pub pubkey_hex: [u8; 66],
}

impl NodeIdentity {
    pub fn compute() -> Self {
        let identity = microfips_esp_transport::node_info::compute_node_identity(&ESP32S3_SECRET);

        NodeIdentity {
            node_addr_hex: identity.node_addr_hex,
            pubkey_hex: identity.pubkey_hex,
        }
    }

    pub fn node_addr_str(&self) -> &str {
        core::str::from_utf8(&self.node_addr_hex).unwrap_or("?")
    }

    pub fn pubkey_str(&self) -> &str {
        core::str::from_utf8(&self.pubkey_hex).unwrap_or("?")
    }
}
