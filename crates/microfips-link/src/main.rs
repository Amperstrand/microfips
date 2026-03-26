use std::net::UdpSocket;
use std::time::Duration;

use k256::SecretKey;
use microfips_core::fmp;
use microfips_core::noise;
use rand::RngCore;

fn main() {
    println!("=== microfips FIPS handshake test (from VPS localhost) ===");

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

    let local_pub = noise::ecdh_pubkey(&local_secret).expect("failed to compute pubkey");
    println!("Local pubkey: {}", hex::encode(&local_pub));

    let mut rng = rand::rng();
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);
    let eph_secret =
        SecretKey::from_slice(&eph_bytes).expect("32 random bytes is valid secret key");
    let eph_secret_bytes: [u8; 32] = eph_secret.to_bytes().into();

    let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("failed to set timeout");
    println!("Bound to local: {}", socket.local_addr().unwrap());
    println!("Target: {}", target);

    let (mut noise_state, e_pub) =
        noise::NoiseIkInitiator::new(&eph_secret_bytes, &local_secret, &vps_pub_compressed)
            .expect("failed to create Noise state");

    println!("Ephemeral pubkey: {}", hex::encode(&e_pub));

    let epoch: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let mut noise_msg1 = [0u8; 256];
    let noise_len = noise_state
        .write_message1(&local_pub, &epoch, &mut noise_msg1)
        .expect("failed to write Noise msg1");

    let mut fmp_msg1 = [0u8; 256];
    let fmp_len = fmp::build_msg1(0, &noise_msg1[..noise_len], &mut fmp_msg1);
    println!("FMP msg1: {} bytes", fmp_len);
    println!("FMP msg1 hex: {}", hex::encode(&fmp_msg1[..fmp_len]));

    socket
        .send_to(&fmp_msg1[..fmp_len], target)
        .expect("failed to send msg1");
    println!("Sent FMP msg1 to {}", target);

    let mut recv_buf = [0u8; 2048];
    match socket.recv_from(&mut recv_buf) {
        Ok((len, addr)) => {
            println!("Received {} bytes from {}", len, addr);
            println!("Response hex: {}", hex::encode(&recv_buf[..len.min(128)]));

            match fmp::parse_message(&recv_buf[..len]) {
                Some(msg) => {
                    println!("Parsed FMP message: {:?}", msg);
                    match msg {
                        fmp::FmpMessage::Msg2 {
                            sender_idx,
                            receiver_idx,
                            noise_payload,
                        } => {
                            println!(
                                "  sender_idx={}, receiver_idx={}, noise_payload={} bytes",
                                sender_idx,
                                receiver_idx,
                                noise_payload.len()
                            );
                            match noise_state.read_message2(noise_payload) {
                                Ok(received_epoch) => {
                                    println!(
                                        "Handshake complete! Received epoch: {:02x?}",
                                        received_epoch
                                    );
                                    let (k_send, k_recv) = noise_state.finalize();
                                    println!("k_send: {}", hex::encode(&k_send));
                                    println!("k_recv: {}", hex::encode(&k_recv));
                                }
                                Err(e) => {
                                    println!("Failed to read Noise msg2: {:?}", e);
                                }
                            }
                        }
                        fmp::FmpMessage::Msg1 { .. } => {
                            println!("Unexpected: received Msg1 (should be Msg2)");
                        }
                        fmp::FmpMessage::Established { .. } => {
                            println!("Unexpected: received Established (should be Msg2)");
                        }
                    }
                }
                None => {
                    println!("Failed to parse FMP message");
                    println!("First 4 bytes: {:02x?}", &recv_buf[..4.min(len)]);
                }
            }
        }
        Err(e) => {
            println!("Receive error (timeout?): {}", e);
        }
    }
}
