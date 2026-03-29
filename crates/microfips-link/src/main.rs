use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::Duration;

use k256::SecretKey;
use microfips_core::fmp;
use microfips_core::identity::{DEFAULT_PEER_PUB, DEFAULT_SECRET};
use microfips_core::noise;
use rand::RngCore;

fn load_secret() -> [u8; 32] {
    match std::env::var("FIPS_SECRET") {
        Ok(h) => {
            let b = hex::decode(h.trim()).expect("FIPS_SECRET: invalid hex");
            assert!(
                b.len() == 32,
                "FIPS_SECRET: must be 32 bytes (64 hex chars)"
            );
            b.try_into().unwrap()
        }
        Err(_) => DEFAULT_SECRET,
    }
}

fn load_peer_pub() -> [u8; 33] {
    match std::env::var("FIPS_PEER_PUB") {
        Ok(h) => {
            let b = hex::decode(h.trim()).expect("FIPS_PEER_PUB: invalid hex");
            assert!(
                b.len() == 33,
                "FIPS_PEER_PUB: must be 33 bytes (66 hex chars)"
            );
            b.try_into().unwrap()
        }
        Err(_) => DEFAULT_PEER_PUB,
    }
}

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
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--keygen") {
        return keygen();
    }

    println!("=== microfips FIPS handshake test ===");

    let local_secret = load_secret();
    let peer_pub = load_peer_pub();

    let target = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:2121");

    let local_pub = match noise::ecdh_pubkey(&local_secret) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("ERROR: failed to compute pubkey: {e:?}");
            return ExitCode::from(2);
        }
    };
    println!("Local pubkey: {}", hex::encode(local_pub));
    println!("Peer pubkey:  {}", hex::encode(peer_pub));

    let mut rng = rand::rng();
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);
    let eph_secret = match SecretKey::from_slice(&eph_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: invalid ephemeral key: {e:?}");
            return ExitCode::from(2);
        }
    };
    let eph_secret_bytes: [u8; 32] = eph_secret.to_bytes().into();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: failed to bind socket: {e:?}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(5))) {
        eprintln!("ERROR: failed to set timeout: {e:?}");
        return ExitCode::from(2);
    }
    println!("Bound to local: {}", socket.local_addr().unwrap());
    println!("Target: {}", target);

    let (mut noise_state, e_pub) =
        match noise::NoiseIkInitiator::new(&eph_secret_bytes, &local_secret, &peer_pub) {
            Ok(state) => state,
            Err(e) => {
                eprintln!("ERROR: failed to create Noise state: {e:?}");
                return ExitCode::from(2);
            }
        };

    println!("Ephemeral pubkey: {}", hex::encode(e_pub));

    let epoch: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let mut noise_msg1 = [0u8; 256];
    let noise_len = match noise_state.write_message1(&local_pub, &epoch, &mut noise_msg1) {
        Ok(len) => len,
        Err(e) => {
            eprintln!("ERROR: failed to write Noise msg1: {e:?}");
            return ExitCode::from(2);
        }
    };

    let mut fmp_msg1 = [0u8; 256];
    let fmp_len = fmp::build_msg1(0, &noise_msg1[..noise_len], &mut fmp_msg1).unwrap();
    println!("FMP msg1: {fmp_len} bytes");

    if let Err(e) = socket.send_to(&fmp_msg1[..fmp_len], target) {
        eprintln!("ERROR: failed to send msg1: {e:?}");
        return ExitCode::from(2);
    }
    println!("Sent FMP msg1 to {target}");

    let mut recv_buf = [0u8; 2048];
    match socket.recv_from(&mut recv_buf) {
        Ok((len, addr)) => {
            println!("Received {len} bytes from {addr}");

            match fmp::parse_message(&recv_buf[..len]) {
                Some(msg) => match msg {
                    fmp::FmpMessage::Msg2 {
                        sender_idx,
                        receiver_idx,
                        noise_payload,
                    } => {
                        println!(
                            "  sender_idx={sender_idx}, receiver_idx={receiver_idx}, noise_payload={} bytes",
                            noise_payload.len()
                        );
                        match noise_state.read_message2(noise_payload) {
                            Ok(received_epoch) => {
                                println!(
                                    "Handshake complete! Received epoch: {received_epoch:02x?}"
                                );
                                let (k_send, k_recv) = noise_state.finalize();
                                println!("k_send: {}", hex::encode(k_send));
                                println!("k_recv: {}", hex::encode(k_recv));
                                println!("SUCCESS: FIPS handshake completed!");
                                ExitCode::SUCCESS
                            }
                            Err(e) => {
                                eprintln!("ERROR: failed to read Noise msg2: {e:?}");
                                ExitCode::from(2)
                            }
                        }
                    }
                    fmp::FmpMessage::Msg1 { .. } => {
                        eprintln!("ERROR: received Msg1 (expected Msg2)");
                        ExitCode::from(2)
                    }
                    fmp::FmpMessage::Established { .. } => {
                        eprintln!("ERROR: received Established (expected Msg2)");
                        ExitCode::from(2)
                    }
                },
                None => {
                    eprintln!("ERROR: failed to parse FMP message");
                    eprintln!("First 4 bytes: {:02x?}", &recv_buf[..4.min(len)]);
                    ExitCode::from(2)
                }
            }
        }
        Err(e) => {
            eprintln!("Receive error (timeout?): {e:?}");
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock
            {
                eprintln!("TIMEOUT: no response from peer (IP not configured)");
                ExitCode::from(1)
            } else {
                ExitCode::from(2)
            }
        }
    }
}
