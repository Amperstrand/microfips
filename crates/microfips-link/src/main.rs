use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::Duration;

use k256::SecretKey;
use microfips_core::identity::{load_peer_pub, load_secret};
use microfips_core::noise;
use microfips_core::wire;
use rand::RngCore;

fn keygen() -> ExitCode {
    let mut rng = rand::rng();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    // Validate it's a valid secp256k1 scalar
    let _ =
        SecretKey::from_slice(&secret).expect("generated invalid key (astronomically unlikely)");
    let pubkey = noise::ecdh_pubkey(&secret).expect("pubkey derivation failed");
    println!("FIPS_NSEC={}", hex::encode(secret));
    println!("FIPS_PUB={}", hex::encode(pubkey));
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--keygen") {
        return keygen();
    }

    log::info!("[LINK] microfips FIPS handshake test starting");

    let local_secret = load_secret();
    let peer_pub = load_peer_pub();

    let target = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:2121");

    let local_pub = match noise::ecdh_pubkey(&local_secret) {
        Ok(pk) => pk,
        Err(e) => {
            log::error!("[LINK] failed to compute pubkey: {e:?}");
            return ExitCode::from(2);
        }
    };
    log::debug!("[LINK] local pubkey: {}", hex::encode(local_pub));
    log::debug!("[LINK] peer pubkey:  {}", hex::encode(peer_pub));

    let mut rng = rand::rng();
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);
    let eph_secret = match SecretKey::from_slice(&eph_bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[LINK] invalid ephemeral key: {e:?}");
            return ExitCode::from(2);
        }
    };
    let eph_secret_bytes: [u8; 32] = eph_secret.to_bytes().into();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            log::error!("[LINK] failed to bind socket: {e:?}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(5))) {
        log::error!("[LINK] failed to set timeout: {e:?}");
        return ExitCode::from(2);
    }
    log::info!("[LINK] bound to {}", socket.local_addr().unwrap());
    log::info!("[LINK] target: {}", target);

    #[cfg(feature = "noise-xx")]
    let code = xx_handshake(
        &socket,
        target,
        &local_secret,
        &local_pub,
        &eph_secret_bytes,
    );
    #[cfg(not(feature = "noise-xx"))]
    let code = ik_handshake(
        &socket,
        target,
        &local_secret,
        &local_pub,
        &peer_pub,
        &eph_secret_bytes,
    );
    code
}

#[cfg(not(feature = "noise-xx"))]
fn ik_handshake(
    socket: &UdpSocket,
    target: &str,
    local_secret: &[u8; 32],
    local_pub: &[u8; 33],
    peer_pub: &[u8; 33],
    eph_secret_bytes: &[u8; 32],
) -> ExitCode {
    let (mut noise_state, e_pub) =
        match noise::NoiseIkInitiator::new(eph_secret_bytes, local_secret, peer_pub) {
            Ok(state) => state,
            Err(e) => {
                log::error!("[LINK] failed to create Noise state: {e:?}");
                return ExitCode::from(2);
            }
        };

    log::debug!("[LINK] ephemeral pubkey: {}", hex::encode(e_pub));

    let epoch: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let mut noise_msg1 = [0u8; 256];
    let noise_len = match noise_state.write_message1(local_pub, &epoch, &mut noise_msg1) {
        Ok(len) => len,
        Err(e) => {
            log::error!("[LINK] failed to write Noise msg1: {e:?}");
            return ExitCode::from(2);
        }
    };

    let mut fmp_msg1 = [0u8; 256];
    let fmp_len = wire::build_msg1(
        wire::SessionIndex::new(0),
        &noise_msg1[..noise_len],
        &mut fmp_msg1,
    )
    .unwrap();
    log::debug!("[LINK → FIPS] MSG1 frame ready: {}B", fmp_len);

    if let Err(e) = socket.send_to(&fmp_msg1[..fmp_len], target) {
        log::error!("[LINK → FIPS] send MSG1 failed: {e:?}");
        return ExitCode::from(2);
    }
    log::info!("[LINK → FIPS] TX MSG1 {}B", fmp_len);

    let mut recv_buf = [0u8; 2048];
    match socket.recv_from(&mut recv_buf) {
        Ok((len, addr)) => {
            log::info!("[FIPS → LINK] RX {}B from {}", len, addr);

            match wire::parse_message(&recv_buf[..len]) {
                Some(msg) => match msg {
                    wire::FmpMessage::Msg2 {
                        sender_idx,
                        receiver_idx,
                        noise_payload,
                    } => {
                        log::debug!(
                            "[FIPS → LINK] MSG2 sender_idx={} receiver_idx={} noise={}B",
                            sender_idx,
                            receiver_idx,
                            noise_payload.len()
                        );
                        match noise_state.read_message2(noise_payload) {
                            Ok(received_epoch) => {
                                log::info!(
                                    "[LINK] handshake complete — epoch: {:02x?}",
                                    received_epoch
                                );
                                let (k_send, k_recv) = noise_state.finalize();
                                log::debug!("[LINK] k_send: {}", hex::encode(k_send));
                                log::debug!("[LINK] k_recv: {}", hex::encode(k_recv));
                                log::info!("[LINK] SUCCESS: FIPS handshake completed!");
                                ExitCode::SUCCESS
                            }
                            Err(e) => {
                                log::error!("[LINK] failed to read Noise msg2: {e:?}");
                                ExitCode::from(2)
                            }
                        }
                    }
                    wire::FmpMessage::Msg1 { .. } => {
                        log::error!("[FIPS → LINK] received MSG1 (expected MSG2)");
                        ExitCode::from(2)
                    }
                    wire::FmpMessage::Established { .. } => {
                        log::error!("[FIPS → LINK] received Established (expected MSG2)");
                        ExitCode::from(2)
                    }
                    wire::FmpMessage::Msg3 { .. } => {
                        log::error!("[FIPS → LINK] received MSG3 (expected MSG2)");
                        ExitCode::from(2)
                    }
                },
                None => {
                    log::error!("[FIPS → LINK] failed to parse FMP message");
                    log::debug!(
                        "[FIPS → LINK] first 4 bytes: {:02x?}",
                        &recv_buf[..4.min(len)]
                    );
                    ExitCode::from(2)
                }
            }
        }
        Err(e) => {
            log::warn!("[FIPS → LINK] receive error (timeout?): {e:?}");
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock
            {
                log::warn!("[FIPS → LINK] TIMEOUT: no response from peer (IP not configured)");
                ExitCode::from(1)
            } else {
                ExitCode::from(2)
            }
        }
    }
}

/// One-shot Noise XX + FMP v1 negotiation exchange (FIPS next wire),
/// mirroring `Node::handshake_xx`'s initiator path: msg1, then msg2 with
/// the peer's negotiation block decrypted and validated, then msg3 with
/// ours, then transport keys. The link tool speaks Leaf, the daemon Full.
#[cfg(feature = "noise-xx")]
fn xx_handshake(
    socket: &UdpSocket,
    target: &str,
    local_secret: &[u8; 32],
    local_pub: &[u8; 33],
    eph_secret_bytes: &[u8; 32],
) -> ExitCode {
    use microfips_core::wire::negotiation::{self, NodeProfile, NEGOTIATION_MAX_SIZE};

    let (mut noise_st, _e_pub) = match noise::NoiseXxInitiator::new(eph_secret_bytes, local_secret)
    {
        Ok(state) => state,
        Err(e) => {
            log::error!("[LINK] failed to create Noise XX state: {e:?}");
            return ExitCode::from(2);
        }
    };

    let mut n1 = [0u8; 256];
    let n1len = match noise_st.write_message1(&mut n1) {
        Ok(len) => len,
        Err(e) => {
            log::error!("[LINK] failed to write XX msg1: {e:?}");
            return ExitCode::from(2);
        }
    };

    let mut f1 = [0u8; 256];
    let f1len = match wire::build_msg1(wire::SessionIndex::new(0), &n1[..n1len], &mut f1) {
        Some(len) => len,
        None => {
            log::error!("[LINK] failed to build FMP msg1 frame");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = socket.send_to(&f1[..f1len], target) {
        log::error!("[LINK → FIPS] send MSG1 failed: {e:?}");
        return ExitCode::from(2);
    }
    log::info!("[LINK → FIPS] TX MSG1 {}B", f1len);

    let mut recv_buf = [0u8; 2048];
    let (len, addr) = match socket.recv_from(&mut recv_buf) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[FIPS → LINK] receive error (timeout?): {e:?}");
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock
            {
                log::warn!("[FIPS → LINK] TIMEOUT: no response from peer");
                return ExitCode::from(1);
            }
            return ExitCode::from(2);
        }
    };
    log::info!("[FIPS → LINK] RX {}B from {}", len, addr);

    let sender_idx = match wire::parse_message(&recv_buf[..len]) {
        Some(wire::FmpMessage::Msg2 {
            sender_idx,
            noise_payload,
            ..
        }) => {
            let (base2, neg2) = negotiation::split_msg2_noise(noise_payload);
            match noise_st.read_message2(base2) {
                Ok((_resp_pub, resp_epoch)) => {
                    log::info!("[LINK] XX msg2 read — responder epoch: {:02x?}", resp_epoch);
                }
                Err(e) => {
                    log::error!("[LINK] failed to read XX msg2: {e:?}");
                    return ExitCode::from(2);
                }
            }
            match neg2 {
                Some(encrypted) => {
                    let mut plain = [0u8; NEGOTIATION_MAX_SIZE];
                    let n = match noise_st.decrypt_payload(encrypted, &mut plain) {
                        Ok(n) => n,
                        Err(e) => {
                            log::error!("[LINK] negotiation decrypt failed: {e:?}");
                            return ExitCode::from(2);
                        }
                    };
                    if let Err(msg) = validate_negotiation(&plain[..n]) {
                        log::error!("[LINK] fmp negotiation rejected: {msg}");
                        return ExitCode::from(2);
                    }
                }
                None => log::warn!("[LINK] peer msg2 carried no negotiation block"),
            }
            sender_idx
        }
        Some(_) => {
            log::error!("[FIPS → LINK] expected MSG2 on the XX wire");
            return ExitCode::from(2);
        }
        None => {
            log::error!("[FIPS → LINK] failed to parse FMP message");
            log::debug!(
                "[FIPS → LINK] first 4 bytes: {:02x?}",
                &recv_buf[..4.min(len)]
            );
            return ExitCode::from(2);
        }
    };

    let epoch: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut n3 = [0u8; noise::XX_HANDSHAKE_MSG3_SIZE + NEGOTIATION_MAX_SIZE + noise::TAG_SIZE];
    let n3len = match noise_st.write_message3(local_pub, &epoch, &mut n3) {
        Ok(len) => len,
        Err(e) => {
            log::error!("[LINK] failed to write XX msg3: {e:?}");
            return ExitCode::from(2);
        }
    };
    let mut neg = [0u8; NEGOTIATION_MAX_SIZE];
    let neglen = match negotiation::encode_payload(
        &mut neg,
        wire::FMP_VERSION,
        wire::FMP_VERSION,
        negotiation::fmp_features(NodeProfile::Leaf),
        None,
    ) {
        Some(len) => len,
        None => {
            log::error!("[LINK] failed to encode negotiation payload");
            return ExitCode::from(2);
        }
    };
    let neg_enc_len = match noise_st.encrypt_payload(&neg[..neglen], &mut n3[n3len..]) {
        Ok(len) => len,
        Err(e) => {
            log::error!("[LINK] failed to encrypt negotiation payload: {e:?}");
            return ExitCode::from(2);
        }
    };

    let mut f3 = [0u8; 512];
    let f3len = match wire::build_msg3(
        wire::SessionIndex::new(0),
        sender_idx,
        &n3[..n3len + neg_enc_len],
        &mut f3,
    ) {
        Some(len) => len,
        None => {
            log::error!("[LINK] failed to build FMP msg3 frame");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = socket.send_to(&f3[..f3len], target) {
        log::error!("[LINK → FIPS] send MSG3 failed: {e:?}");
        return ExitCode::from(2);
    }
    log::info!("[LINK → FIPS] TX MSG3 {}B", f3len);

    let (k_send, k_recv) = noise_st.finalize();
    log::debug!("[LINK] k_send: {}", hex::encode(k_send));
    log::debug!("[LINK] k_recv: {}", hex::encode(k_recv));
    log::info!("[LINK] SUCCESS: FIPS XX handshake completed!");
    ExitCode::SUCCESS
}

/// Version-agreement + profile-pairing checks for a decrypted peer
/// negotiation block — same rules as `Node::apply_fmp_negotiation`.
#[cfg(feature = "noise-xx")]
fn validate_negotiation(neg_bytes: &[u8]) -> Result<(), String> {
    use microfips_core::wire::negotiation::{self, NegotiationHeader, NodeProfile};

    let ours = NegotiationHeader {
        version_min: wire::FMP_VERSION,
        version_max: wire::FMP_VERSION,
        features: negotiation::fmp_features(NodeProfile::Leaf),
    };
    let theirs = NegotiationHeader::parse(neg_bytes).map_err(|e| format!("bad payload: {e}"))?;
    let version = ours.agree_version(&theirs).map_err(|_| {
        format!(
            "no version overlap (our {}..{}, their {}..{})",
            ours.version_min, ours.version_max, theirs.version_min, theirs.version_max
        )
    })?;
    let their_profile = theirs.node_profile().ok_or_else(|| {
        format!(
            "unknown profile bits {:b}",
            theirs.features & negotiation::FMP_FEAT_PROFILE_MASK
        )
    })?;
    if !NodeProfile::valid_pairing(NodeProfile::Leaf, their_profile) {
        return Err(format!("invalid pairing leaf+{their_profile}"));
    }
    log::info!("[LINK] fmp negotiation: agreed version {version}, peer profile {their_profile}");
    Ok(())
}
