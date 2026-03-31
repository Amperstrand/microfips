use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::Duration;

use k256::SecretKey;
use microfips_core::fmp;
use microfips_core::identity::{load_peer_pub, load_secret};
use microfips_core::noise;
use rand::RngCore;

fn keygen() -> ExitCode {
    let mut rng = rand::rng();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    // Validate it's a valid secp256k1 scalar
    let _ =
        SecretKey::from_slice(&secret).expect("generated invalid key (astronomically unlikely)");
    let pubkey = noise::ecdh_pubkey(&secret).expect("pubkey derivation failed");
    println!("FIPS_SECRET={}", hex::encode(secret));
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

    let (mut noise_state, e_pub) =
        match noise::NoiseIkInitiator::new(&eph_secret_bytes, &local_secret, &peer_pub) {
            Ok(state) => state,
            Err(e) => {
                log::error!("[LINK] failed to create Noise state: {e:?}");
                return ExitCode::from(2);
            }
        };

    log::debug!("[LINK] ephemeral pubkey: {}", hex::encode(e_pub));

    let epoch: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let mut noise_msg1 = [0u8; 256];
    let noise_len = match noise_state.write_message1(&local_pub, &epoch, &mut noise_msg1) {
        Ok(len) => len,
        Err(e) => {
            log::error!("[LINK] failed to write Noise msg1: {e:?}");
            return ExitCode::from(2);
        }
    };

    let mut fmp_msg1 = [0u8; 256];
    let fmp_len = fmp::build_msg1(0, &noise_msg1[..noise_len], &mut fmp_msg1).unwrap();
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

            match fmp::parse_message(&recv_buf[..len]) {
                Some(msg) => match msg {
                    fmp::FmpMessage::Msg2 {
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
                    fmp::FmpMessage::Msg1 { .. } => {
                        log::error!("[FIPS → LINK] received MSG1 (expected MSG2)");
                        ExitCode::from(2)
                    }
                    fmp::FmpMessage::Established { .. } => {
                        log::error!("[FIPS → LINK] received Established (expected MSG2)");
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
