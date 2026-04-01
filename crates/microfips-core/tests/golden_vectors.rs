// Integration test for golden cross-implementation vectors.

#[path = "vector_types.rs"]
mod vector_types;

use hkdf::Hkdf;
use microfips_core::noise::{aead_encrypt, ecdh_pubkey, x_only_ecdh, PUBKEY_SIZE, TAG_SIZE};
use sha2::Sha256;
use vector_types::*;

fn load_vectors() -> VectorFile {
    let json = include_str!("golden_vectors.json");
    serde_json::from_str(json).expect("valid golden_vectors.json")
}

fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex::decode(hex).expect("hex decode");
    match bytes.try_into() {
        Ok(arr) => arr,
        Err(b) => panic!("expected {N} bytes, got {}", b.len()),
    }
}

fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("hex decode")
}

#[test]
fn test_pubkey_vectors() {
    let vf = load_vectors();
    let mut count = 0;

    for v in &vf.vectors {
        if let Vector::Pubkey(pv) = v {
            let secret = hex_to_bytes::<32>(&pv.secret_hex);
            let expected = hex_to_bytes::<PUBKEY_SIZE>(&pv.pubkey_hex);
            let got = ecdh_pubkey(&secret).expect("pubkey derivation");
            assert_eq!(got, expected, "FAILED {}: pubkey mismatch", pv.name);
            count += 1;
        }
    }

    assert!(
        count >= 5,
        "expected at least 5 pubkey vectors, got {count}"
    );
    println!("pubkey vectors: {count} passed");
}

#[test]
fn test_ecdh_vectors() {
    let vf = load_vectors();
    let mut count = 0;

    for v in &vf.vectors {
        if let Vector::Ecdh(ev) = v {
            let initiator_secret = hex_to_bytes::<32>(&ev.initiator_secret_hex);
            let responder_pub = hex_to_bytes::<PUBKEY_SIZE>(&ev.responder_pubkey_hex);
            let expected = hex_to_bytes::<32>(&ev.shared_secret_hex);
            let got = x_only_ecdh(&initiator_secret, &responder_pub).expect("x-only ECDH");
            assert_eq!(got, expected, "FAILED {}: shared secret mismatch", ev.name);
            count += 1;
        }
    }

    assert!(count >= 4, "expected at least 4 ECDH vectors, got {count}");
    println!("ecdh vectors: {count} passed");
}

#[test]
fn test_hkdf_vectors() {
    let vf = load_vectors();
    let mut count = 0;

    for v in &vf.vectors {
        if let Vector::Hkdf(hv) = v {
            let salt = hex_to_bytes::<32>(&hv.salt_hex);
            let ikm = hex_to_bytes::<32>(&hv.ikm_hex);
            let expected = hex_to_bytes::<64>(&hv.output_hex);

            let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
            let mut okm = [0u8; 64];
            hk.expand(&[], &mut okm)
                .expect("64-byte HKDF expand should succeed");

            assert_eq!(okm, expected, "FAILED {}: HKDF output mismatch", hv.name);
            count += 1;
        }
    }

    assert!(count >= 4, "expected at least 4 HKDF vectors, got {count}");
    println!("hkdf vectors: {count} passed");
}

#[test]
fn test_aead_vectors() {
    let vf = load_vectors();
    let mut count = 0;

    for v in &vf.vectors {
        if let Vector::Aead(av) = v {
            let key = hex_to_bytes::<32>(&av.key_hex);
            let plaintext = hex_to_vec(&av.plaintext_hex);
            let aad = hex_to_vec(&av.aad_hex);
            let expected = hex_to_vec(&av.ciphertext_hex);

            let mut out = vec![0u8; plaintext.len() + TAG_SIZE];
            let written = aead_encrypt(&key, av.nonce, &aad, &plaintext, &mut out)
                .expect("aead encrypt should succeed");

            assert_eq!(
                written,
                expected.len(),
                "FAILED {}: length mismatch",
                av.name
            );
            assert_eq!(
                &out[..written],
                expected.as_slice(),
                "FAILED {}: ciphertext mismatch",
                av.name
            );
            count += 1;
        }
    }

    assert!(count >= 4, "expected at least 4 AEAD vectors, got {count}");
    println!("aead vectors: {count} passed");
}

#[test]
fn test_mix_key_vectors() {
    let vf = load_vectors();
    let mut count = 0;
    for v in &vf.vectors {
        if let Vector::MixKey(mv) = v {
            let ck = hex_to_bytes::<32>(&mv.chaining_key_hex);
            let dh = hex_to_bytes::<32>(&mv.dh_output_hex);
            let expected_new_ck = hex_to_bytes::<32>(&mv.new_chaining_key_hex);
            let expected_key = hex_to_bytes::<32>(&mv.new_key_hex);

            let hk = Hkdf::<Sha256>::new(Some(&ck), &dh);
            let mut okm = [0u8; 64];
            hk.expand(&[], &mut okm).expect("hkdf expand");
            let got_ck: [u8; 32] = okm[..32].try_into().unwrap();
            let got_key: [u8; 32] = okm[32..].try_into().unwrap();

            assert_eq!(
                got_ck, expected_new_ck,
                "FAILED {}: new_ck mismatch",
                mv.name
            );
            assert_eq!(
                got_key, expected_key,
                "FAILED {}: new_key mismatch",
                mv.name
            );
            count += 1;
        }
    }
    assert!(
        count >= 4,
        "expected at least 4 mix_key vectors, got {count}"
    );
    println!("mix_key vectors: {count} passed");
}

#[test]
fn test_split_vectors() {
    let vf = load_vectors();
    let mut count = 0;
    for v in &vf.vectors {
        if let Vector::Split(sv) = v {
            let ck = hex_to_bytes::<32>(&sv.chaining_key_hex);
            let expected_k1 = hex_to_bytes::<32>(&sv.k1_hex);
            let expected_k2 = hex_to_bytes::<32>(&sv.k2_hex);

            let hk = Hkdf::<Sha256>::new(Some(&ck), b"");
            let mut okm = [0u8; 64];
            hk.expand(&[], &mut okm).expect("hkdf expand");
            let got_k1: [u8; 32] = okm[..32].try_into().unwrap();
            let got_k2: [u8; 32] = okm[32..].try_into().unwrap();

            assert_eq!(got_k1, expected_k1, "FAILED {}: k1 mismatch", sv.name);
            assert_eq!(got_k2, expected_k2, "FAILED {}: k2 mismatch", sv.name);
            count += 1;
        }
    }
    assert!(count >= 4, "expected at least 4 split vectors, got {count}");
    println!("split vectors: {count} passed");
}
