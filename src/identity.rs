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
