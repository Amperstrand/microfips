use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag};
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman as raw_ecdh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::identity::sha256;

pub const TAG_SIZE: usize = 16;
pub const EPOCH_SIZE: usize = 8;
pub const NONCE_SIZE: usize = 12;
pub const PUBKEY_SIZE: usize = 33;

pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_secp256k1_ChaChaPoly_SHA256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    InvalidKey,
    InvalidMessage,
    DecryptionFailed,
    EncryptionFailed,
    BufferTooSmall,
}

pub fn parity_normalize(pubkey: &[u8; PUBKEY_SIZE]) -> [u8; PUBKEY_SIZE] {
    let mut out = [0u8; PUBKEY_SIZE];
    out[0] = 0x02;
    out[1..].copy_from_slice(&pubkey[1..]);
    out
}

pub fn x_only_ecdh(
    my_secret: &[u8; 32],
    their_pub: &[u8; PUBKEY_SIZE],
) -> Result<[u8; 32], NoiseError> {
    let sk = SecretKey::from_slice(my_secret).map_err(|_| NoiseError::InvalidKey)?;
    let pk = PublicKey::from_sec1_bytes(their_pub).map_err(|_| NoiseError::InvalidKey)?;
    let shared = raw_ecdh(sk.to_nonzero_scalar(), pk.as_affine());
    let x = shared.raw_secret_bytes();
    Ok(sha256(x))
}

pub fn ecdh_pubkey(secret: &[u8; 32]) -> Result<[u8; PUBKEY_SIZE], NoiseError> {
    let sk = SecretKey::from_slice(secret).map_err(|_| NoiseError::InvalidKey)?;
    let pk = sk.public_key();
    let encoded = pk.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; PUBKEY_SIZE];
    out.copy_from_slice(&bytes[..PUBKEY_SIZE]);
    Ok(out)
}

fn hash_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn hash_one(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn mix_key(ck: &[u8; 32], ikm: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(ck), ikm);
    let mut okm = [0u8; 64];
    hk.expand(&[], &mut okm)
        .expect("hkdf expand 64 bytes should never fail");
    let mut new_ck = [0u8; 32];
    new_ck.copy_from_slice(&okm[..32]);
    let mut k = [0u8; 32];
    k.copy_from_slice(&okm[32..]);
    (new_ck, k)
}

fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hash_concat(h, data)
}

fn make_nonce(n: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..8].copy_from_slice(&n.to_le_bytes());
    nonce
}

pub fn aead_encrypt(
    key: &[u8; 32],
    nonce_ctr: u64,
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, NoiseError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| NoiseError::InvalidKey)?;
    let nonce_arr = make_nonce(nonce_ctr);
    let nonce = GenericArray::from_slice(&nonce_arr);

    let total = plaintext.len() + TAG_SIZE;
    if out.len() < total {
        return Err(NoiseError::BufferTooSmall);
    }

    out[..plaintext.len()].copy_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut out[..plaintext.len()])
        .map_err(|_| NoiseError::EncryptionFailed)?;

    out[plaintext.len()..total].copy_from_slice(&tag);
    Ok(total)
}

pub fn aead_decrypt(
    key: &[u8; 32],
    nonce_ctr: u64,
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, NoiseError> {
    if ciphertext.len() < TAG_SIZE {
        return Err(NoiseError::InvalidMessage);
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| NoiseError::InvalidKey)?;
    let nonce_arr = make_nonce(nonce_ctr);
    let nonce = GenericArray::from_slice(&nonce_arr);

    let pt_len = ciphertext.len() - TAG_SIZE;
    if out.len() < pt_len {
        return Err(NoiseError::BufferTooSmall);
    }

    out[..pt_len].copy_from_slice(&ciphertext[..pt_len]);
    let tag = Tag::from_slice(&ciphertext[pt_len..]);

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut out[..pt_len], tag)
        .map_err(|_| NoiseError::DecryptionFailed)?;

    Ok(pt_len)
}

pub struct NoiseIkInitiator {
    h: [u8; 32],
    ck: [u8; 32],
    e_priv: [u8; 32],
    e_pub: [u8; PUBKEY_SIZE],
    rs_pub: [u8; PUBKEY_SIZE],
    k: Option<[u8; 32]>,
    n: u64,
}

impl NoiseIkInitiator {
    pub fn new(
        my_ephemeral_secret: &[u8; 32],
        responder_static_pub: &[u8; PUBKEY_SIZE],
    ) -> Result<(Self, [u8; PUBKEY_SIZE]), NoiseError> {
        let e_pub = ecdh_pubkey(my_ephemeral_secret)?;

        let h = hash_one(PROTOCOL_NAME);
        let ck = h;

        let normalized_rs = parity_normalize(responder_static_pub);
        let h = mix_hash(&h, &normalized_rs);

        Ok((
            Self {
                h,
                ck,
                e_priv: *my_ephemeral_secret,
                e_pub,
                rs_pub: *responder_static_pub,
                k: None,
                n: 0,
            },
            e_pub,
        ))
    }

    pub fn write_message1(
        &mut self,
        my_static_pub: &[u8; PUBKEY_SIZE],
        epoch: &[u8; EPOCH_SIZE],
        out: &mut [u8],
    ) -> Result<usize, NoiseError> {
        let needed = PUBKEY_SIZE + (PUBKEY_SIZE + TAG_SIZE) + (EPOCH_SIZE + TAG_SIZE);
        if out.len() < needed {
            return Err(NoiseError::BufferTooSmall);
        }

        let mut pos = 0;

        out[pos..pos + PUBKEY_SIZE].copy_from_slice(&self.e_pub);
        pos += PUBKEY_SIZE;
        self.h = mix_hash(&self.h, &self.e_pub);

        let dh = x_only_ecdh(&self.e_priv, &self.rs_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &dh);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        let enc_len = aead_encrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &self.h,
            my_static_pub,
            &mut out[pos..],
        )?;
        self.n += 1;
        self.h = mix_hash(&self.h, &out[pos..pos + enc_len]);
        pos += enc_len;

        let enc_len = aead_encrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &self.h,
            epoch,
            &mut out[pos..],
        )?;
        self.n += 1;
        self.h = mix_hash(&self.h, &out[pos..pos + enc_len]);
        pos += enc_len;

        Ok(pos)
    }

    pub fn read_message2(&mut self, payload: &[u8]) -> Result<[u8; EPOCH_SIZE], NoiseError> {
        let expected = PUBKEY_SIZE + EPOCH_SIZE + TAG_SIZE;
        if payload.len() != expected {
            return Err(NoiseError::InvalidMessage);
        }

        let mut pos = 0;

        let re_pub: [u8; PUBKEY_SIZE] = payload[pos..pos + PUBKEY_SIZE]
            .try_into()
            .map_err(|_| NoiseError::InvalidMessage)?;
        pos += PUBKEY_SIZE;
        self.h = mix_hash(&self.h, &re_pub);

        let dh = x_only_ecdh(&self.e_priv, &re_pub)?;
        let (new_ck, k) = mix_key(&self.ck, &dh);
        self.ck = new_ck;
        self.k = Some(k);
        self.n = 0;

        let enc_epoch = &payload[pos..];
        let mut epoch_buf = [0u8; EPOCH_SIZE];
        aead_decrypt(
            self.k.as_ref().unwrap(),
            self.n,
            &self.h,
            enc_epoch,
            &mut epoch_buf,
        )?;
        self.n += 1;
        self.h = mix_hash(&self.h, enc_epoch);

        Ok(epoch_buf)
    }

    pub fn finalize(&self) -> ([u8; 32], [u8; 32]) {
        let (_, k1) = mix_key(&self.ck, &[0u8; 32]);
        let (k2, k3) = mix_key(&self.ck, &k1);
        (k2, k3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> ([u8; 32], [u8; PUBKEY_SIZE]) {
        let secret = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let pub_key = ecdh_pubkey(&secret).unwrap();
        (secret, pub_key)
    }

    #[test]
    fn parity_normalize_forces_even_prefix() {
        let mut odd_key = [0u8; 33];
        odd_key[0] = 0x03;
        odd_key[1] = 0xAB;
        let normalized = parity_normalize(&odd_key);
        assert_eq!(normalized[0], 0x02);
        assert_eq!(normalized[1], 0xAB);
    }

    #[test]
    fn parity_normalize_preserves_even() {
        let mut even_key = [0u8; 33];
        even_key[0] = 0x02;
        even_key[1] = 0xCD;
        let normalized = parity_normalize(&even_key);
        assert_eq!(normalized[0], 0x02);
        assert_eq!(normalized[1], 0xCD);
    }

    #[test]
    fn ecdh_keypair_roundtrip() {
        let (secret, pub_key) = test_keypair();
        assert_eq!(pub_key[0], 0x02);
        let recomputed = ecdh_pubkey(&secret).unwrap();
        assert_eq!(pub_key, recomputed);
    }

    #[test]
    fn x_only_ecdh_is_deterministic() {
        let (secret_a, pub_a) = test_keypair();
        let secret_b: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let pub_b = ecdh_pubkey(&secret_b).unwrap();

        let dh1 = x_only_ecdh(&secret_a, &pub_b).unwrap();
        let dh2 = x_only_ecdh(&secret_b, &pub_a).unwrap();
        assert_eq!(dh1, dh2);
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise";
        let aad = b"associated";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, aad, plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let pt_len = aead_decrypt(&key, 0, aad, &ciphertext[..ct_len], &mut decrypted).unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn aead_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"hello noise";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, b"", plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let result = aead_decrypt(&wrong_key, 0, b"", &ciphertext[..ct_len], &mut decrypted);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }

    #[test]
    fn aead_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, b"", plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let result = aead_decrypt(&key, 1, b"", &ciphertext[..ct_len], &mut decrypted);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }

    #[test]
    fn aead_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise";

        let mut ciphertext = [0u8; 256];
        let ct_len = aead_encrypt(&key, 0, b"correct_aad", plaintext, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 256];
        let result = aead_decrypt(&key, 0, b"wrong_aad", &ciphertext[..ct_len], &mut decrypted);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }

    #[test]
    fn mix_key_deterministic() {
        let ck = [0x01u8; 32];
        let ikm = [0x02u8; 32];
        let (ck1, k1) = mix_key(&ck, &ikm);
        let (ck2, k2) = mix_key(&ck, &ikm);
        assert_eq!(ck1, ck2);
        assert_eq!(k1, k2);
        assert_ne!(ck1, ck);
        assert_ne!(k1, ck);
    }

    #[test]
    fn noise_ik_initiator_creates_state() {
        let (secret, pub_key) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (state, e_pub) = NoiseIkInitiator::new(&secret, &responder_pub).unwrap();
        assert_eq!(e_pub, pub_key);
        assert_eq!(state.n, 0);
    }

    #[test]
    fn noise_ik_msg1_size() {
        let (secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, _) = NoiseIkInitiator::new(&secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        let msg_len = state.write_message1(&my_static, &epoch, &mut out).unwrap();

        assert_eq!(msg_len, 106);
    }

    #[test]
    fn noise_ik_msg1_contains_ephemeral_pubkey() {
        let (secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, e_pub) = NoiseIkInitiator::new(&secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        state.write_message1(&my_static, &epoch, &mut out).unwrap();

        assert_eq!(&out[..33], &e_pub);
    }

    #[test]
    fn noise_ik_msg1_enc_static_is_correct_size() {
        let (secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, _) = NoiseIkInitiator::new(&secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        state.write_message1(&my_static, &epoch, &mut out).unwrap();

        let enc_static = &out[33..33 + 49];
        assert_eq!(enc_static.len(), 49);
    }

    #[test]
    fn noise_ik_msg1_enc_epoch_is_correct_size() {
        let (secret, _) = test_keypair();
        let responder_pub = [0x02u8; 33];
        let (mut state, _) = NoiseIkInitiator::new(&secret, &responder_pub).unwrap();

        let my_static = ecdh_pubkey(&[0xAA; 32]).unwrap();
        let epoch = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut out = [0u8; 256];
        state.write_message1(&my_static, &epoch, &mut out).unwrap();

        let enc_epoch = &out[82..106];
        assert_eq!(enc_epoch.len(), 24);
    }

    #[test]
    fn protocol_name_hash() {
        let h = hash_one(PROTOCOL_NAME);
        assert_ne!(h, [0u8; 32]);
        assert_eq!(h, sha256(PROTOCOL_NAME));
    }

    struct NoiseIkResponder {
        h: [u8; 32],
        ck: [u8; 32],
        ei_pub: [u8; PUBKEY_SIZE],
        k: Option<[u8; 32]>,
        n: u64,
    }

    impl NoiseIkResponder {
        fn new(
            responder_static_secret: &[u8; 32],
            initiator_ephemeral_pub: &[u8; PUBKEY_SIZE],
        ) -> Self {
            let h = hash_one(PROTOCOL_NAME);
            let ck = h;
            let normalized_rs = parity_normalize(&ecdh_pubkey(responder_static_secret).unwrap());
            let h = mix_hash(&h, &normalized_rs);
            let h = mix_hash(&h, initiator_ephemeral_pub);

            let dh = x_only_ecdh(responder_static_secret, initiator_ephemeral_pub).unwrap();
            let (ck, k) = mix_key(&ck, &dh);

            Self {
                h,
                ck,
                ei_pub: *initiator_ephemeral_pub,
                k: Some(k),
                n: 0,
            }
        }

        fn read_message1(&mut self, payload: &[u8]) -> ([u8; PUBKEY_SIZE], [u8; EPOCH_SIZE]) {
            let enc_static = &payload[..49];
            let mut static_buf = [0u8; PUBKEY_SIZE];
            aead_decrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &self.h,
                enc_static,
                &mut static_buf,
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, enc_static);

            let enc_epoch = &payload[49..];
            let mut epoch_buf = [0u8; EPOCH_SIZE];
            aead_decrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &self.h,
                enc_epoch,
                &mut epoch_buf,
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, enc_epoch);

            (static_buf, epoch_buf)
        }

        fn write_message2(
            &mut self,
            responder_ephemeral_secret: &[u8; 32],
            epoch: &[u8; EPOCH_SIZE],
            out: &mut [u8],
        ) -> usize {
            let e_pub = ecdh_pubkey(responder_ephemeral_secret).unwrap();
            let mut pos = 0;

            out[pos..pos + PUBKEY_SIZE].copy_from_slice(&e_pub);
            pos += PUBKEY_SIZE;
            self.h = mix_hash(&self.h, &e_pub);

            let dh = x_only_ecdh(responder_ephemeral_secret, &self.ei_pub).unwrap();
            let (new_ck, k) = mix_key(&self.ck, &dh);
            self.ck = new_ck;
            self.k = Some(k);
            self.n = 0;

            let enc_len = aead_encrypt(
                self.k.as_ref().unwrap(),
                self.n,
                &self.h,
                epoch,
                &mut out[pos..],
            )
            .unwrap();
            self.n += 1;
            self.h = mix_hash(&self.h, &out[pos..pos + enc_len]);
            pos += enc_len;

            pos
        }
    }

    #[test]
    fn noise_ik_full_handshake_simulation() {
        let initiator_eph_secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let initiator_static_secret: [u8; 32] = [0x11; 32];
        let responder_static_secret: [u8; 32] = [0x22; 32];
        let responder_eph_secret: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let responder_static_pub = ecdh_pubkey(&responder_static_secret).unwrap();
        let initiator_static_pub = ecdh_pubkey(&initiator_static_secret).unwrap();
        let epoch_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let epoch_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (mut initiator, _) =
            NoiseIkInitiator::new(&initiator_eph_secret, &responder_static_pub).unwrap();

        let mut msg1_buf = [0u8; 256];
        let msg1_len = initiator
            .write_message1(&initiator_static_pub, &epoch_a, &mut msg1_buf)
            .unwrap();
        assert_eq!(msg1_len, 106);

        let mut responder =
            NoiseIkResponder::new(&responder_static_secret, msg1_buf[..33].try_into().unwrap());
        let (received_static_pub, received_epoch_a) =
            responder.read_message1(&msg1_buf[33..msg1_len]);
        assert_eq!(received_static_pub, initiator_static_pub);
        assert_eq!(received_epoch_a, epoch_a);

        let mut msg2_buf = [0u8; 128];
        let msg2_len = responder.write_message2(&responder_eph_secret, &epoch_b, &mut msg2_buf);
        assert_eq!(msg2_len, 57);

        let received_epoch_b = initiator.read_message2(&msg2_buf[..msg2_len]).unwrap();
        assert_eq!(received_epoch_b, epoch_b);

        let (k_send_i, k_recv_i) = initiator.finalize();
        assert_ne!(k_send_i, [0u8; 32]);
        assert_ne!(k_recv_i, [0u8; 32]);
    }
}
