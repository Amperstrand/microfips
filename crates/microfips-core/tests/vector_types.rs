#![allow(dead_code)]

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VectorFile {
    pub version: u32,
    pub generator: String,
    pub generated_at: String,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Vector {
    Pubkey(PubkeyVector),
    Ecdh(EcdhVector),
    Hkdf(HkdfVector),
    Aead(AeadVector),
    Ik(IkVector),
    Xk(XkVector),
    Transport(TransportVector),
    MixKey(MixKeyVector),
    Split(SplitVector),
}

#[derive(Debug, Deserialize)]
pub struct PubkeyVector {
    pub name: String,
    pub comment: String,
    pub secret_hex: String,
    pub pubkey_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct EcdhVector {
    pub name: String,
    pub comment: String,
    pub initiator_secret_hex: String,
    pub responder_pubkey_hex: String,
    pub shared_secret_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct HkdfVector {
    pub name: String,
    pub comment: String,
    pub salt_hex: String,
    pub ikm_hex: String,
    pub output_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct AeadVector {
    pub name: String,
    pub comment: String,
    pub key_hex: String,
    pub nonce: u64,
    pub plaintext_hex: String,
    pub aad_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct IkVector {
    pub name: String,
    pub comment: String,
    pub deviations: Vec<String>,
    pub initiator_static_secret_hex: String,
    pub initiator_static_pubkey_hex: String,
    pub initiator_ephemeral_secret_hex: String,
    pub initiator_ephemeral_pubkey_hex: String,
    pub responder_static_secret_hex: String,
    pub responder_static_pubkey_hex: String,
    pub responder_ephemeral_secret_hex: String,
    pub responder_ephemeral_pubkey_hex: String,
    pub epoch: u64,
    pub msg1_hex: String,
    pub msg1_payload_hex: String,
    pub msg2_hex: String,
    pub msg2_payload_hex: String,
    pub handshake_hash_hex: String,
    pub initiator_transport_send_key_hex: String,
    pub initiator_transport_recv_key_hex: String,
    pub responder_transport_send_key_hex: String,
    pub responder_transport_recv_key_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct XkVector {
    pub name: String,
    pub comment: String,
    pub deviations: Vec<String>,
    pub initiator_static_secret_hex: String,
    pub initiator_static_pubkey_hex: String,
    pub initiator_ephemeral_secret_hex: String,
    pub initiator_ephemeral_pubkey_hex: String,
    pub responder_static_secret_hex: String,
    pub responder_static_pubkey_hex: String,
    pub responder_ephemeral_secret_hex: String,
    pub responder_ephemeral_pubkey_hex: String,
    pub epoch: u64,
    pub msg1_hex: String,
    pub msg1_payload_hex: String,
    pub msg2_hex: String,
    pub msg2_payload_hex: String,
    pub msg3_hex: String,
    pub msg3_payload_hex: String,
    pub handshake_hash_hex: String,
    pub initiator_transport_send_key_hex: String,
    pub initiator_transport_recv_key_hex: String,
    pub responder_transport_send_key_hex: String,
    pub responder_transport_recv_key_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct TransportVector {
    pub name: String,
    pub comment: String,
    pub derived_from: String,
    pub direction: String,
    pub key_hex: String,
    pub frames: Vec<TransportFrame>,
}

#[derive(Debug, Deserialize)]
pub struct TransportFrame {
    pub nonce: u64,
    pub plaintext_hex: String,
    pub aad_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct MixKeyVector {
    pub name: String,
    pub comment: String,
    pub chaining_key_hex: String,
    pub dh_output_hex: String,
    pub new_chaining_key_hex: String,
    pub new_key_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct SplitVector {
    pub name: String,
    pub comment: String,
    pub chaining_key_hex: String,
    pub k1_hex: String,
    pub k2_hex: String,
}
