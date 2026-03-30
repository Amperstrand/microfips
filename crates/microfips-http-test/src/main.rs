use std::net::UdpSocket;
use std::time::Duration;

use k256::SecretKey;
use microfips_core::fmp;
use microfips_core::identity::load_secret;
use microfips_core::noise;
use rand::RngCore;

fn main() {
    let listen_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:31338".to_string());

    let static_secret = load_secret();
    let static_pub = noise::ecdh_pubkey(&static_secret).expect("pubkey derivation failed");

    println!("=== microfips HTTP test (FIPS responder) ===");
    println!("Listening on UDP {listen_addr}");
    println!("Responder pubkey: {}", hex::encode(static_pub));
    println!("Waiting for MCU handshake...");

    let sock = UdpSocket::bind(&listen_addr).expect("bind failed");
    sock.set_read_timeout(Some(Duration::from_secs(60)))
        .expect("set_read_timeout failed");

    let mut buf = [0u8; 4096];
    let (len, peer) = sock.recv_from(&mut buf).expect("recv MSG1");
    println!("Received {len} bytes from {peer}");

    let msg1 = match fmp::parse_message(&buf[..len]) {
        Some(fmp::FmpMessage::Msg1 {
            sender_idx,
            noise_payload,
        }) => {
            println!(
                "  MSG1: sender_idx={sender_idx}, noise_payload={}B",
                noise_payload.len()
            );
            (sender_idx, noise_payload)
        }
        other => {
            eprintln!("ERROR: expected MSG1, got {:?}", other);
            std::process::exit(2);
        }
    };

    let e_init: [u8; 33] = msg1.1[..33].try_into().expect("ephemeral pubkey size");
    let mut responder =
        noise::NoiseIkResponder::new(&static_secret, &e_init).expect("IK responder init failed");
    let (initiator_static_pub, epoch) = responder
        .read_message1(&msg1.1[33..])
        .expect("read_message1 failed");
    println!("  Initiator pubkey: {}", hex::encode(initiator_static_pub));
    println!("  Epoch: {}", hex::encode(epoch));

    let mut rng = rand::rng();
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);
    let eph_secret = SecretKey::from_slice(&eph_bytes).expect("ephemeral key");
    let eph_secret_bytes: [u8; 32] = eph_secret.to_bytes().into();

    let mut noise_msg2 = [0u8; 256];
    let noise_len = responder
        .write_message2(&eph_secret_bytes, &epoch, &mut noise_msg2)
        .expect("write_message2 failed");

    let mut fmp_msg2 = [0u8; 256];
    let fmp_len = fmp::build_msg2(msg1.0, msg1.0, &noise_msg2[..noise_len], &mut fmp_msg2).unwrap();
    println!("  Sending MSG2: {} bytes to {peer}", fmp_len);
    sock.send_to(&fmp_msg2[..fmp_len], peer).expect("send MSG2");

    let (k1, k2) = responder.finalize();
    let k_send = k2;
    let k_recv = k1;
    println!("  k_send: {}", hex::encode(k_send));
    println!("  k_recv: {}", hex::encode(k_recv));

    let http_request = b"GET / HTTP/1.1\r\nHost: microfips-stm32\r\n\r\n";
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    let mut out = [0u8; 512];
    let fl = fmp::build_established(
        msg1.0,
        0,
        fmp::MSG_SESSION_DATAGRAM,
        ts,
        http_request,
        &k_send,
        &mut out,
    ).expect("build_established failed");
    println!("  Sending HTTP GET: {} bytes (FMP)", fl);
    sock.send_to(&out[..fl], peer).expect("send HTTP GET");

    println!("  Waiting for HTTP response...");
    let mut _recv_ctr: u64 = 0;
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(30) {
            eprintln!("TIMEOUT: no HTTP response in 30s");
            std::process::exit(1);
        }
        match sock.recv_from(&mut buf) {
            Ok((len, addr)) => {
                let resp_msg = match fmp::parse_message(&buf[..len]) {
                    Some(m) => m,
                    None => {
                        println!("  Non-FMP: {}B from {addr}", len);
                        continue;
                    }
                };
                match resp_msg {
                    fmp::FmpMessage::Established {
                        counter: rx_ctr,
                        encrypted,
                        ..
                    } => {
                        let hdr = &buf[..fmp::ESTABLISHED_HEADER_SIZE];
                        let mut dec = [0u8; 2048];
                        match noise::aead_decrypt(&k_recv, rx_ctr, hdr, encrypted, &mut dec) {
                            Ok(dl) => {
                                if dl < fmp::INNER_HEADER_SIZE {
                                    println!("  Decrypted too short: {}B", dl);
                                    continue;
                                }
                                let msg_type = dec[4];
                                let ts_val = u32::from_le_bytes([dec[0], dec[1], dec[2], dec[3]]);
                                let payload = &dec[fmp::INNER_HEADER_SIZE..dl];
                                match msg_type {
                                    fmp::MSG_HEARTBEAT => {
                                        println!("  Heartbeat (ctr={rx_ctr}, ts={ts_val})");
                                        _recv_ctr = rx_ctr + 1;
                                    }
                                    fmp::MSG_SESSION_DATAGRAM => {
                                        println!(
                                            "  DATA (ctr={rx_ctr}, ts={ts_val}, {}B):",
                                            payload.len()
                                        );
                                        match std::str::from_utf8(payload) {
                                            Ok(s) => println!("{}", s),
                                            Err(_) => println!("  hex: {}", hex::encode(payload)),
                                        }
                                        println!("\nSUCCESS: MCU responded with HTTP data!");
                                        return;
                                    }
                                    fmp::MSG_DISCONNECT => {
                                        println!("  Peer disconnected");
                                        break;
                                    }
                                    other => {
                                        println!(
                                            "  Unknown msg type 0x{:02x} ({}B payload)",
                                            other,
                                            payload.len()
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  Decrypt failed (ctr={rx_ctr}): {:?}", e);
                            }
                        }
                    }
                    fmp::FmpMessage::Msg1 { .. } => {
                        println!("  Received MSG1 (MCU retrying handshake)");
                    }
                    other => {
                        println!("  Received: {:?}", other);
                    }
                }
            }
            Err(e) => {
                eprintln!("  Recv error: {e}");
                break;
            }
        }
    }

    println!("\nFAIL: no HTTP response received");
    std::process::exit(1);
}
