// Integration test for golden cross-implementation vectors.

#[path = "vector_types.rs"]
mod vector_types;

use hkdf::Hkdf;
use microfips_core::noise::{
    aead_encrypt, ecdh_pubkey, x_only_ecdh, NoiseIkInitiator, NoiseIkResponder, NoiseXkInitiator,
    NoiseXkResponder, EPOCH_SIZE, PUBKEY_SIZE, TAG_SIZE,
};
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

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex decode")
}

fn assert_ik_vector(ik: &IkVector) {
    let initiator_static_secret = hex_to_bytes::<32>(&ik.initiator_static_secret_hex);
    let initiator_static_pub = hex_to_bytes::<PUBKEY_SIZE>(&ik.initiator_static_pubkey_hex);
    let initiator_ephemeral_secret = hex_to_bytes::<32>(&ik.initiator_ephemeral_secret_hex);
    let initiator_ephemeral_pub = hex_to_bytes::<PUBKEY_SIZE>(&ik.initiator_ephemeral_pubkey_hex);

    let responder_static_secret = hex_to_bytes::<32>(&ik.responder_static_secret_hex);
    let responder_static_pub = hex_to_bytes::<PUBKEY_SIZE>(&ik.responder_static_pubkey_hex);
    let responder_ephemeral_secret = hex_to_bytes::<32>(&ik.responder_ephemeral_secret_hex);
    let responder_ephemeral_pub = hex_to_bytes::<PUBKEY_SIZE>(&ik.responder_ephemeral_pubkey_hex);

    let initiator_epoch = hex_to_bytes::<EPOCH_SIZE>(&ik.initiator_epoch_hex);
    let responder_epoch = hex_to_bytes::<EPOCH_SIZE>(&ik.responder_epoch_hex);

    let expected_msg1 = hex_decode(&ik.msg1_hex);
    let expected_msg2 = hex_decode(&ik.msg2_hex);

    let expected_i_send = hex_to_bytes::<32>(&ik.initiator_transport_send_key_hex);
    let expected_i_recv = hex_to_bytes::<32>(&ik.initiator_transport_recv_key_hex);
    let expected_r_send = hex_to_bytes::<32>(&ik.responder_transport_send_key_hex);
    let expected_r_recv = hex_to_bytes::<32>(&ik.responder_transport_recv_key_hex);

    let (mut initiator, got_init_eph_pub) = NoiseIkInitiator::new(
        &initiator_ephemeral_secret,
        &initiator_static_secret,
        &responder_static_pub,
    )
    .expect("ik initiator init");
    assert_eq!(
        got_init_eph_pub, initiator_ephemeral_pub,
        "FAILED {}: initiator ephemeral pub mismatch",
        ik.name
    );

    let mut msg1 = [0u8; 256];
    let msg1_len = initiator
        .write_message1(&initiator_static_pub, &initiator_epoch, &mut msg1)
        .expect("ik write msg1");
    assert_eq!(msg1_len, 106, "FAILED {}: msg1 size mismatch", ik.name);
    assert_eq!(
        &msg1[..msg1_len],
        expected_msg1.as_slice(),
        "FAILED {}: msg1 mismatch",
        ik.name
    );

    let mut responder = NoiseIkResponder::new(
        &responder_static_secret,
        (&msg1[..PUBKEY_SIZE]).try_into().expect("msg1 eph pub"),
    )
    .expect("ik responder init");

    let (got_init_static_pub, got_init_epoch) = responder
        .read_message1(&msg1[PUBKEY_SIZE..msg1_len])
        .expect("ik read msg1");
    assert_eq!(
        got_init_static_pub, initiator_static_pub,
        "FAILED {}: recovered initiator static pub mismatch",
        ik.name
    );
    assert_eq!(
        got_init_epoch, initiator_epoch,
        "FAILED {}: recovered initiator epoch mismatch",
        ik.name
    );

    let mut msg2 = [0u8; 128];
    let msg2_len = responder
        .write_message2(&responder_ephemeral_secret, &responder_epoch, &mut msg2)
        .expect("ik write msg2");
    assert_eq!(msg2_len, 57, "FAILED {}: msg2 size mismatch", ik.name);
    assert_eq!(
        &msg2[..msg2_len],
        expected_msg2.as_slice(),
        "FAILED {}: msg2 mismatch",
        ik.name
    );
    let got_responder_ephemeral_pub: [u8; PUBKEY_SIZE] =
        msg2[..PUBKEY_SIZE].try_into().expect("msg2 eph pub");
    assert_eq!(
        responder_ephemeral_pub, got_responder_ephemeral_pub,
        "FAILED {}: responder ephemeral pub mismatch",
        ik.name
    );

    let got_responder_epoch = initiator
        .read_message2(&msg2[..msg2_len])
        .expect("ik read msg2");
    assert_eq!(
        got_responder_epoch, responder_epoch,
        "FAILED {}: recovered responder epoch mismatch",
        ik.name
    );

    let (i_send, i_recv) = initiator.finalize();
    let (r_recv, r_send) = responder.finalize();

    assert_eq!(
        i_send, expected_i_send,
        "FAILED {}: initiator transport send key mismatch",
        ik.name
    );
    assert_eq!(
        i_recv, expected_i_recv,
        "FAILED {}: initiator transport recv key mismatch",
        ik.name
    );
    assert_eq!(
        r_send, expected_r_send,
        "FAILED {}: responder transport send key mismatch",
        ik.name
    );
    assert_eq!(
        r_recv, expected_r_recv,
        "FAILED {}: responder transport recv key mismatch",
        ik.name
    );

    println!("{} ok: msg1={}B msg2={}B", ik.name, msg1_len, msg2_len);
}

fn assert_xk_vector(xk: &XkVector) {
    let initiator_static_secret = hex_to_bytes::<32>(&xk.initiator_static_secret_hex);
    let initiator_static_pub = hex_to_bytes::<PUBKEY_SIZE>(&xk.initiator_static_pubkey_hex);
    let initiator_ephemeral_secret = hex_to_bytes::<32>(&xk.initiator_ephemeral_secret_hex);
    let initiator_ephemeral_pub = hex_to_bytes::<PUBKEY_SIZE>(&xk.initiator_ephemeral_pubkey_hex);

    let responder_static_secret = hex_to_bytes::<32>(&xk.responder_static_secret_hex);
    let responder_static_pub = hex_to_bytes::<PUBKEY_SIZE>(&xk.responder_static_pubkey_hex);
    let responder_ephemeral_secret = hex_to_bytes::<32>(&xk.responder_ephemeral_secret_hex);
    let responder_ephemeral_pub = hex_to_bytes::<PUBKEY_SIZE>(&xk.responder_ephemeral_pubkey_hex);

    let initiator_epoch = hex_to_bytes::<EPOCH_SIZE>(&xk.initiator_epoch_hex);
    let responder_epoch = hex_to_bytes::<EPOCH_SIZE>(&xk.responder_epoch_hex);

    let expected_msg1 = hex_decode(&xk.msg1_hex);
    let expected_msg2 = hex_decode(&xk.msg2_hex);
    let expected_msg3 = hex_decode(&xk.msg3_hex);

    let expected_i_send = hex_to_bytes::<32>(&xk.initiator_transport_send_key_hex);
    let expected_i_recv = hex_to_bytes::<32>(&xk.initiator_transport_recv_key_hex);
    let expected_r_send = hex_to_bytes::<32>(&xk.responder_transport_send_key_hex);
    let expected_r_recv = hex_to_bytes::<32>(&xk.responder_transport_recv_key_hex);

    let (mut initiator, got_init_eph_pub) = NoiseXkInitiator::new(
        &initiator_ephemeral_secret,
        &initiator_static_secret,
        &responder_static_pub,
    )
    .expect("xk initiator init");
    assert_eq!(
        got_init_eph_pub, initiator_ephemeral_pub,
        "FAILED {}: initiator ephemeral pub mismatch",
        xk.name
    );

    let mut msg1 = [0u8; 128];
    let msg1_len = initiator.write_message1(&mut msg1).expect("xk write msg1");
    assert_eq!(msg1_len, 33, "FAILED {}: msg1 size mismatch", xk.name);
    assert_eq!(
        &msg1[..msg1_len],
        expected_msg1.as_slice(),
        "FAILED {}: msg1 mismatch",
        xk.name
    );

    let mut responder = NoiseXkResponder::new(
        &responder_static_secret,
        (&msg1[..PUBKEY_SIZE]).try_into().expect("msg1 eph pub"),
    )
    .expect("xk responder init");

    let mut msg2 = [0u8; 128];
    let msg2_len = responder
        .write_message2(&responder_ephemeral_secret, &responder_epoch, &mut msg2)
        .expect("xk write msg2");
    assert_eq!(msg2_len, 57, "FAILED {}: msg2 size mismatch", xk.name);
    assert_eq!(
        &msg2[..msg2_len],
        expected_msg2.as_slice(),
        "FAILED {}: msg2 mismatch",
        xk.name
    );
    let got_responder_ephemeral_pub: [u8; PUBKEY_SIZE] =
        msg2[..PUBKEY_SIZE].try_into().expect("msg2 eph pub");
    assert_eq!(
        responder_ephemeral_pub, got_responder_ephemeral_pub,
        "FAILED {}: responder ephemeral pub mismatch",
        xk.name
    );

    let got_responder_epoch = initiator
        .read_message2(&msg2[..msg2_len])
        .expect("xk read msg2");
    assert_eq!(
        got_responder_epoch, responder_epoch,
        "FAILED {}: recovered responder epoch mismatch",
        xk.name
    );

    let mut msg3 = [0u8; 128];
    let msg3_len = initiator
        .write_message3(&initiator_static_pub, &initiator_epoch, &mut msg3)
        .expect("xk write msg3");
    assert_eq!(msg3_len, 73, "FAILED {}: msg3 size mismatch", xk.name);
    assert_eq!(
        &msg3[..msg3_len],
        expected_msg3.as_slice(),
        "FAILED {}: msg3 mismatch",
        xk.name
    );

    let (got_init_static_pub, got_init_epoch) = responder
        .read_message3(&msg3[..msg3_len])
        .expect("xk read msg3");
    assert_eq!(
        got_init_static_pub, initiator_static_pub,
        "FAILED {}: recovered initiator static pub mismatch",
        xk.name
    );
    assert_eq!(
        got_init_epoch, initiator_epoch,
        "FAILED {}: recovered initiator epoch mismatch",
        xk.name
    );

    let (i_send, i_recv) = initiator.finalize();
    let (r_recv, r_send) = responder.finalize();

    assert_eq!(
        i_send, expected_i_send,
        "FAILED {}: initiator transport send key mismatch",
        xk.name
    );
    assert_eq!(
        i_recv, expected_i_recv,
        "FAILED {}: initiator transport recv key mismatch",
        xk.name
    );
    assert_eq!(
        r_send, expected_r_send,
        "FAILED {}: responder transport send key mismatch",
        xk.name
    );
    assert_eq!(
        r_recv, expected_r_recv,
        "FAILED {}: responder transport recv key mismatch",
        xk.name
    );

    println!(
        "{} ok: msg1={}B msg2={}B msg3={}B",
        xk.name, msg1_len, msg2_len, msg3_len
    );
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

#[test]
fn test_ik_handshake_vectors() {
    let vf = load_vectors();
    let mut count = 0;

    for v in &vf.vectors {
        if let Vector::Ik(ik) = v {
            assert_ik_vector(ik);
            count += 1;
        }
    }

    assert_eq!(count, 11, "expected 11 IK vectors, got {count}");
    println!("ik vectors: {count} passed");
}

#[test]
fn test_xk_handshake_vectors() {
    let vf = load_vectors();
    let mut count = 0;

    for v in &vf.vectors {
        if let Vector::Xk(xk) = v {
            assert_xk_vector(xk);
            count += 1;
        }
    }

    assert_eq!(count, 7, "expected 7 XK vectors, got {count}");
    println!("xk vectors: {count} passed");
}

#[test]
fn test_transport_vectors() {
    let vf = load_vectors();
    let mut count = 0;

    for v in &vf.vectors {
        if let Vector::Transport(tv) = v {
            let i_send = hex_to_bytes::<32>(&tv.initiator_transport_send_key_hex);
            let i_recv = hex_to_bytes::<32>(&tv.initiator_transport_recv_key_hex);
            let r_send = hex_to_bytes::<32>(&tv.responder_transport_send_key_hex);
            let r_recv = hex_to_bytes::<32>(&tv.responder_transport_recv_key_hex);

            assert_eq!(
                i_send, r_recv,
                "FAILED {}: initiator send key must match responder recv key",
                tv.name
            );
            assert_eq!(
                i_recv, r_send,
                "FAILED {}: initiator recv key must match responder send key",
                tv.name
            );

            for frame in &tv.frames {
                let plaintext = hex_to_vec(&frame.plaintext_hex);
                let aad = hex_to_vec(&frame.aad_hex);
                let expected = hex_to_vec(&frame.ciphertext_hex);
                let key = match frame.direction.as_str() {
                    "initiator_to_responder" => &i_send,
                    "responder_to_initiator" => &r_send,
                    other => panic!("FAILED {}: unknown frame direction {other}", tv.name),
                };

                let mut out = vec![0u8; plaintext.len() + TAG_SIZE];
                let written = aead_encrypt(key, frame.nonce, &aad, &plaintext, &mut out)
                    .expect("transport frame encryption should succeed");

                assert_eq!(
                    written,
                    expected.len(),
                    "FAILED {} frame nonce {}: ciphertext length mismatch",
                    tv.name,
                    frame.nonce
                );
                assert_eq!(
                    &out[..written],
                    expected.as_slice(),
                    "FAILED {} frame nonce {}: ciphertext mismatch",
                    tv.name,
                    frame.nonce
                );
            }

            println!(
                "{} ok: {} {} frames",
                tv.name,
                tv.handshake_type,
                tv.frames.len()
            );
            count += 1;
        }
    }

    assert_eq!(count, 4, "expected 4 transport vectors, got {count}");
    println!("transport vectors: {count} passed");
}

#[test]
fn test_edge_case_vectors() {
    let vf = load_vectors();

    let mut ik_edges = Vec::new();
    let mut xk_edges = Vec::new();

    for v in &vf.vectors {
        match v {
            Vector::Ik(ik) if ik.name.contains("edge") => {
                assert_ik_vector(ik);
                ik_edges.push(ik);
            }
            Vector::Xk(xk) if xk.name.contains("edge") => {
                assert_xk_vector(xk);
                xk_edges.push(xk);
            }
            _ => {}
        }
    }

    assert_eq!(
        ik_edges.len() + xk_edges.len(),
        6,
        "expected 6 edge vectors"
    );

    let ik_reuse = ik_edges.iter().find(|v| v.name == "edge-key-reuse-ik");
    let xk_reuse = xk_edges.iter().find(|v| v.name == "edge-key-reuse-xk");
    if let (Some(ik), Some(xk)) = (ik_reuse, xk_reuse) {
        assert_ne!(
            ik.initiator_transport_send_key_hex, xk.initiator_transport_send_key_hex,
            "Key reuse across IK/XK must produce different transport keys"
        );
    } else {
        panic!("missing edge-key-reuse vectors in golden set");
    }

    println!(
        "edge vectors: {} IK + {} XK passed",
        ik_edges.len(),
        xk_edges.len()
    );
}
