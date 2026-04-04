use std::net::UdpSocket;
use std::time::Duration;

use k256::SecretKey;
use microfips_core::fmp;
use microfips_core::fsp::{self, SESSION_DATAGRAM_BODY_SIZE};
use microfips_core::identity::{load_peer_pub, load_secret, NodeAddr};
use microfips_core::noise;
use microfips_service::{decode_response, encode_request, ServiceMethod};
use rand::RngCore;

fn make_session_datagram_body(src: &[u8; 16], dst: &[u8; 16]) -> [u8; SESSION_DATAGRAM_BODY_SIZE] {
    let mut body = [0u8; SESSION_DATAGRAM_BODY_SIZE];
    body[0] = 64;
    body[1] = 1400u16.to_le_bytes()[0];
    body[2] = 1400u16.to_le_bytes()[1];
    body[3..19].copy_from_slice(src);
    body[19..35].copy_from_slice(dst);
    body
}

fn build_fsp_established_msg(
    fsp_counter: u64,
    timestamp_ms: u32,
    app_payload: &[u8],
    fsp_k_send: &[u8; 32],
) -> Vec<u8> {
    let mut out = vec![0u8; 512];
    let len =
        fsp::build_fsp_data_message(fsp_counter, timestamp_ms, app_payload, fsp_k_send, &mut out)
            .unwrap();
    out.truncate(len);
    out
}

fn main() {
    let listen_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:31338".to_string());

    let ik_secret = load_secret();
    let ik_pub = noise::ecdh_pubkey(&ik_secret).expect("pubkey derivation failed");

    let mcu_pub = load_peer_pub();

    let mcu_x_only = &mcu_pub[1..];
    let mcu_addr = NodeAddr::from_pubkey_x(mcu_x_only.try_into().unwrap());

    let ik_pub_normalized = noise::parity_normalize(&ik_pub);
    let ik_x_only = &ik_pub_normalized[1..];
    let ik_addr = NodeAddr::from_pubkey_x(ik_x_only.try_into().unwrap());

    println!("=== microfips HTTP test (FIPS responder + FSP initiator) ===");
    println!("Listening on UDP {listen_addr}");
    println!("IK responder pubkey: {}", hex::encode(ik_pub));
    println!("MCU pubkey (FSP target): {}", hex::encode(mcu_pub));
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
            log::error!("expected MSG1, got {:?}", other);
            std::process::exit(2);
        }
    };

    let e_init: [u8; 33] = msg1.1[..33].try_into().expect("ephemeral pubkey size");
    let sender_idx = msg1.0;
    let mut responder =
        noise::NoiseIkResponder::new(&ik_secret, &e_init).expect("IK responder init failed");
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
    let fmp_len = fmp::build_msg2(
        sender_idx,
        sender_idx,
        &noise_msg2[..noise_len],
        &mut fmp_msg2,
    )
    .unwrap();
    println!("  Sending MSG2: {} bytes to {peer}", fmp_len);
    sock.send_to(&fmp_msg2[..fmp_len], peer).expect("send MSG2");

    let (k1, k2) = responder.finalize();
    let ik_k_send = k2;
    let ik_k_recv = k1;
    println!("  IK k_send: {}", hex::encode(ik_k_send));
    println!("  IK k_recv: {}", hex::encode(ik_k_recv));

    let mut fmp_ctr: u64 = 0;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    let dg_body = make_session_datagram_body(ik_addr.as_bytes(), mcu_addr.as_bytes());

    println!("\n--- FSP XK handshake ---");

    let mut xk_eph = [0u8; 32];
    rng.fill_bytes(&mut xk_eph);
    let (mut xk_init, xk_e_pub) =
        noise::NoiseXkInitiator::new(&xk_eph, &ik_secret, &mcu_pub).unwrap();
    println!("  XK initiator ephemeral pub: {}", hex::encode(xk_e_pub));

    let mut xk_msg1 = [0u8; 64];
    let xk_msg1_len = xk_init.write_message1(&mut xk_msg1).unwrap();

    let mut setup_out = [0u8; 512];
    let src_coords = [*ik_addr.as_bytes()];
    let dst_coords = [*mcu_addr.as_bytes()];
    let setup_len = fsp::build_session_setup(
        0x03,
        &src_coords,
        &dst_coords,
        &xk_msg1[..xk_msg1_len],
        &mut setup_out,
    )
    .unwrap();

    let mut dg_payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + setup_len];
    dg_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    dg_payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&setup_out[..setup_len]);

    let mut fmp_out = [0u8; 1024];
    let fsp_setup_fmp_len = fmp::build_established(
        sender_idx,
        fmp_ctr,
        fmp::MSG_SESSION_DATAGRAM,
        ts,
        &dg_payload,
        &ik_k_send,
        &mut fmp_out,
    )
    .expect("build_established failed for FSP setup");
    fmp_ctr += 1;
    println!(
        "  Sending FSP SessionSetup: {}B (FMP Established)",
        fsp_setup_fmp_len
    );
    sock.send_to(&fmp_out[..fsp_setup_fmp_len], peer)
        .expect("send FSP setup");

    println!("  Waiting for FSP SessionAck...");
    let ack_fsp = loop {
        match recv_established_datagram(&sock, &mut buf, &ik_k_recv) {
            RecvResult::Datagram(payload) => break payload,
            RecvResult::Heartbeat(ctr) => {
                println!("  Heartbeat (ctr={ctr})");
            }
            RecvResult::Other => continue,
            RecvResult::Timeout => {
                log::error!("TIMEOUT: no SessionAck in 15s");
                std::process::exit(1);
            }
        }
    };

    if ack_fsp.len() < SESSION_DATAGRAM_BODY_SIZE {
        log::error!("SessionAck too short: {}B", ack_fsp.len());
        std::process::exit(1);
    }
    let ack_fsp_data = &ack_fsp[SESSION_DATAGRAM_BODY_SIZE..];
    let xk_msg2_payload = fsp::parse_session_ack(ack_fsp_data).unwrap();
    println!(
        "  Received FSP SessionAck: XK msg2 = {}B",
        xk_msg2_payload.len()
    );

    let received_epoch = xk_init.read_message2(xk_msg2_payload).unwrap();
    println!("  XK responder epoch: {}", hex::encode(received_epoch));

    let initiator_pub = noise::ecdh_pubkey(&ik_secret).unwrap();
    let epoch_i = [0x02, 0, 0, 0, 0, 0, 0, 0];

    let mut xk_msg3_noise = [0u8; 128];
    let xk_msg3_len = xk_init
        .write_message3(&initiator_pub, &epoch_i, &mut xk_msg3_noise)
        .unwrap();

    let mut msg3_fsp = [0u8; 512];
    let msg3_fsp_len =
        fsp::build_session_msg3(&xk_msg3_noise[..xk_msg3_len], &mut msg3_fsp).unwrap();

    let mut dg3_payload = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + msg3_fsp_len];
    dg3_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    dg3_payload[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&msg3_fsp[..msg3_fsp_len]);

    let fsp_msg3_fmp_len = fmp::build_established(
        sender_idx,
        fmp_ctr,
        fmp::MSG_SESSION_DATAGRAM,
        ts,
        &dg3_payload,
        &ik_k_send,
        &mut fmp_out,
    )
    .expect("build_established failed for FSP msg3");
    fmp_ctr += 1;
    println!(
        "  Sending FSP Msg3: {}B (FMP Established)",
        fsp_msg3_fmp_len
    );
    sock.send_to(&fmp_out[..fsp_msg3_fmp_len], peer)
        .expect("send FSP msg3");

    let (fsp_k_send, fsp_k_recv) = xk_init.finalize();
    println!("  FSP session established!");
    println!("  FSP k_send: {}", hex::encode(fsp_k_send));
    println!("  FSP k_recv: {}", hex::encode(fsp_k_recv));

    println!("\n--- Sending service GET /health via FSP ---");

    let mut service_request = [0u8; 256];
    let service_request_len =
        encode_request(ServiceMethod::Get, "/health", b"", &mut service_request)
            .expect("service request");
    let fsp_encrypted =
        build_fsp_established_msg(0, ts, &service_request[..service_request_len], &fsp_k_send);

    let mut dg_http = vec![0u8; SESSION_DATAGRAM_BODY_SIZE + fsp_encrypted.len()];
    dg_http[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
    dg_http[SESSION_DATAGRAM_BODY_SIZE..].copy_from_slice(&fsp_encrypted);

    let fsp_http_fmp_len = fmp::build_established(
        sender_idx,
        fmp_ctr,
        fmp::MSG_SESSION_DATAGRAM,
        ts,
        &dg_http,
        &ik_k_send,
        &mut fmp_out,
    )
    .expect("build_established failed for service request");
    println!(
        "  Sending service request: {}B (FMP Established)",
        fsp_http_fmp_len
    );
    sock.send_to(&fmp_out[..fsp_http_fmp_len], peer)
        .expect("send service request");

    println!("  Waiting for service response...");
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(30) {
            log::error!("TIMEOUT: no service response in 30s");
            std::process::exit(1);
        }
        match recv_established_datagram(&sock, &mut buf, &ik_k_recv) {
            RecvResult::Datagram(payload) => {
                println!("  Received MSG_SESSION_DATAGRAM: {}B", payload.len());
                if payload.len() < SESSION_DATAGRAM_BODY_SIZE {
                    println!("  Too short for session datagram body, skipping");
                    continue;
                }
                let fsp_data = &payload[SESSION_DATAGRAM_BODY_SIZE..];
                let Some((flags, counter, header, encrypted)) =
                    fsp::parse_fsp_encrypted_header(fsp_data)
                else {
                    println!("  Cannot parse FSP encrypted header");
                    match std::str::from_utf8(fsp_data) {
                        Ok(s) => println!("  text: {}", s),
                        Err(_) => println!("  hex: {}", hex::encode(fsp_data)),
                    }
                    continue;
                };
                if flags & fsp::FLAG_UNENCRYPTED != 0 {
                    println!("  Unencrypted FSP signal, skipping");
                    continue;
                }
                let mut dec = [0u8; 512];
                match noise::aead_decrypt(&fsp_k_recv, counter, header, encrypted, &mut dec) {
                    Ok(dl) => {
                        if let Some((_timestamp, inner_msg_type, _inner_flags, inner_payload)) =
                            fsp::fsp_strip_inner_header(&dec[..dl])
                        {
                            println!(
                                "  FSP msg_type=0x{:02x}, payload={}B",
                                inner_msg_type,
                                inner_payload.len()
                            );
                            if inner_msg_type == fsp::FSP_MSG_DATA {
                                match decode_response(inner_payload) {
                                    Ok(response) => {
                                        println!("  Service status={}", response.status.as_u16());
                                        match std::str::from_utf8(response.body) {
                                            Ok(s) => println!("{s}"),
                                            Err(_) => {
                                                println!("  hex: {}", hex::encode(response.body))
                                            }
                                        }
                                        println!(
                                            "\nSUCCESS: MCU responded with service data via FSP!"
                                        );
                                    }
                                    Err(_) => {
                                        println!("  hex: {}", hex::encode(inner_payload));
                                        println!("\nSUCCESS: MCU responded with opaque service data via FSP!");
                                    }
                                }
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        println!("  FSP decrypt failed (ctr={counter}): {:?}", e);
                    }
                }
            }
            RecvResult::Heartbeat(ctr) => {
                println!("  Heartbeat (ctr={ctr})");
            }
            RecvResult::Other => continue,
            RecvResult::Timeout => {
                log::error!("TIMEOUT: no service response in 30s");
                std::process::exit(1);
            }
        }
    }
}

enum RecvResult {
    Datagram(Vec<u8>),
    Heartbeat(u64),
    Other,
    Timeout,
}

fn recv_established_datagram(
    sock: &UdpSocket,
    buf: &mut [u8; 4096],
    k_recv: &[u8; 32],
) -> RecvResult {
    match sock.recv_from(buf) {
        Ok((len, _addr)) => {
            let msg = match fmp::parse_message(&buf[..len]) {
                Some(m) => m,
                None => return RecvResult::Other,
            };
            match msg {
                fmp::FmpMessage::Established {
                    counter: rx_ctr,
                    encrypted,
                    ..
                } => {
                    let hdr = &buf[..fmp::ESTABLISHED_HEADER_SIZE];
                    let mut dec = [0u8; 2048];
                    match noise::aead_decrypt(k_recv, rx_ctr, hdr, encrypted, &mut dec) {
                        Ok(dl) => {
                            if dl < fmp::INNER_HEADER_SIZE {
                                return RecvResult::Other;
                            }
                            let msg_type = dec[4];
                            match msg_type {
                                fmp::MSG_HEARTBEAT => RecvResult::Heartbeat(rx_ctr),
                                fmp::MSG_SESSION_DATAGRAM => {
                                    RecvResult::Datagram(dec[fmp::INNER_HEADER_SIZE..dl].to_vec())
                                }
                                _ => RecvResult::Other,
                            }
                        }
                        Err(_) => RecvResult::Other,
                    }
                }
                fmp::FmpMessage::Msg1 { .. } => RecvResult::Other,
                _ => RecvResult::Other,
            }
        }
        Err(_) => RecvResult::Timeout,
    }
}
