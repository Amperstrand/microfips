use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::Duration;

use k256::SecretKey;
use microfips_core::fmp;
use microfips_core::noise;
use rand::RngCore;

fn main() -> ExitCode {
    println!("=== microfips FIPS handshake test ===");

    let local_secret: [u8; 32] = [
        0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4, 0xee,
        0xb5, 0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7, 0x84, 0x3f,
        0x83, 0x2e,
    ];

    let vps_pub_compressed: [u8; 33] = [
        0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4, 0xf5,
        0x73, 0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a, 0x2a, 0x3a,
        0x03, 0x7d, 0x21,
    ];

    let args: Vec<String> = std::env::args().collect();
    let target = if args.len() > 1 {
        &args[1]
    } else {
        "127.0.0.1:2121"
    };

    let local_pub = match noise::ecdh_pubkey(&local_secret) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("ERROR: failed to compute pubkey: {e:?}");
            return ExitCode::from(2);
        }
    };
    println!("Local pubkey: {}", hex::encode(local_pub));

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
        match noise::NoiseIkInitiator::new(&eph_secret_bytes, &local_secret, &vps_pub_compressed) {
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
    let fmp_len = fmp::build_msg1(0, &noise_msg1[..noise_len], &mut fmp_msg1);
    println!("FMP msg1: {fmp_len} bytes");
    println!("FMP msg1 hex: {}", hex::encode(&fmp_msg1[..fmp_len]));

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
