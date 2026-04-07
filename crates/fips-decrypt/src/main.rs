use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

use clap::Parser;
use microfips_core::fmp::{
    parse_message, parse_prefix, FmpMessage, COMMON_PREFIX_SIZE, ESTABLISHED_HEADER_SIZE,
    PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use microfips_core::identity::sha256;
use microfips_core::noise::{
    aead_decrypt, ecdh_pubkey, NoiseIkInitiator, NoiseIkResponder, EPOCH_SIZE, PUBKEY_SIZE,
    TAG_SIZE,
};
use pcap_file::pcap::PcapReader;

struct UdpDatagram<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

const DEV_STM32_SECRET: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_stm32"));
const DEV_ESP32_SECRET: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_esp32"));
const DEV_SIM_A_SECRET: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_sim-a"));
const DEV_SIM_B_SECRET: [u8; 32] =
    microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_sim-b"));

#[derive(Debug, Clone)]
struct KeyPair {
    name: String,
    k_send: [u8; 32],
    k_recv: [u8; 32],
}

#[derive(Debug, Parser)]
#[command(name = "fips-decrypt")]
#[command(about = "Read FIPS pcap captures and decode/decrypt FMP frames")]
struct Cli {
    #[arg(
        long = "keys",
        value_name = "HEX:HEX",
        num_args = 1..,
        help = "Space-separated transport key pairs as ksend:krecv (64hex:64hex)"
    )]
    keys: Vec<String>,

    #[arg(
        long = "node",
        value_name = "NAME",
        help = "Use node presets: sim-a, sim-b, stm32, esp32"
    )]
    node: Option<String>,

    #[arg(long, help = "Show raw frame bytes for each decoded frame")]
    verbose: bool,

    #[arg(
        long = "filter",
        value_name = "PHASE",
        help = "Only show frames with this phase (0=established, 1=msg1, 2=msg2)"
    )]
    filter: Option<u8>,

    pcap_file: PathBuf,
}

fn phase_label(phase: u8) -> &'static str {
    match phase {
        PHASE_ESTABLISHED => "ESTABLISHED",
        PHASE_MSG1 => "MSG1",
        PHASE_MSG2 => "MSG2",
        _ => "UNKNOWN",
    }
}

fn msg_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        0x00 => "HEARTBEAT",
        0x01 => "PING",
        0x02 => "PONG",
        0x10 => "SESSION_DATAGRAM",
        _ => "UNKNOWN",
    }
}

fn derive_ik_transport(
    initiator_name: &str,
    initiator_secret: &[u8; 32],
    responder_name: &str,
    responder_secret: &[u8; 32],
) -> Result<KeyPair, Box<dyn Error>> {
    let init_pub = ecdh_pubkey(initiator_secret).map_err(|e| format!("{e:?}"))?;
    let resp_pub = ecdh_pubkey(responder_secret).map_err(|e| format!("{e:?}"))?;

    let init_label = format!("fips-decrypt:init-eph:{initiator_name}->{responder_name}");
    let resp_label = format!("fips-decrypt:resp-eph:{responder_name}<-{initiator_name}");

    let init_eph = sha256(init_label.as_bytes());
    let resp_eph = sha256(resp_label.as_bytes());

    let epoch_i: [u8; EPOCH_SIZE] = [1, 0, 0, 0, 0, 0, 0, 0];
    let epoch_r: [u8; EPOCH_SIZE] = [2, 0, 0, 0, 0, 0, 0, 0];

    let (mut initiator, _) = NoiseIkInitiator::new(&init_eph, initiator_secret, &resp_pub)
        .map_err(|e| format!("{e:?}"))?;
    let mut msg1 = [0u8; 256];
    let msg1_len = initiator
        .write_message1(&init_pub, &epoch_i, &mut msg1)
        .map_err(|e| format!("{e:?}"))?;

    let mut responder = NoiseIkResponder::new(responder_secret, (&msg1[..PUBKEY_SIZE]).try_into()?)
        .map_err(|e| format!("{e:?}"))?;
    let _ = responder
        .read_message1(&msg1[PUBKEY_SIZE..msg1_len])
        .map_err(|e| format!("{e:?}"))?;

    let mut msg2 = [0u8; 128];
    let msg2_len = responder
        .write_message2(&resp_eph, &epoch_r, &mut msg2)
        .map_err(|e| format!("{e:?}"))?;

    let _ = initiator
        .read_message2(&msg2[..msg2_len])
        .map_err(|e| format!("{e:?}"))?;
    let (k_send, k_recv) = initiator.finalize();

    Ok(KeyPair {
        name: format!("{initiator_name}->{responder_name}"),
        k_send,
        k_recv,
    })
}

fn parse_key_pair(spec: &str) -> Result<KeyPair, Box<dyn Error>> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("invalid --keys entry '{spec}', expected ksend_hex:krecv_hex").into());
    }

    let k_send_bytes = hex::decode(parts[0])?;
    let k_recv_bytes = hex::decode(parts[1])?;
    if k_send_bytes.len() != 32 || k_recv_bytes.len() != 32 {
        return Err(format!("invalid key size in '{spec}', each key must be 64 hex chars").into());
    }

    let mut k_send = [0u8; 32];
    let mut k_recv = [0u8; 32];
    k_send.copy_from_slice(&k_send_bytes);
    k_recv.copy_from_slice(&k_recv_bytes);

    Ok(KeyPair {
        name: "custom".to_string(),
        k_send,
        k_recv,
    })
}

fn preset_secret(node: &str) -> Option<[u8; 32]> {
    match node {
        "stm32" => Some(DEV_STM32_SECRET),
        "esp32" => Some(DEV_ESP32_SECRET),
        "sim-a" => Some(DEV_SIM_A_SECRET),
        "sim-b" => Some(DEV_SIM_B_SECRET),
        _ => None,
    }
}

fn build_candidate_keys(cli: &Cli) -> Result<Vec<KeyPair>, Box<dyn Error>> {
    if !cli.keys.is_empty() {
        let mut keys = Vec::with_capacity(cli.keys.len());
        for (idx, spec) in cli.keys.iter().enumerate() {
            let mut pair = parse_key_pair(spec)?;
            pair.name = format!("custom#{idx}");
            keys.push(pair);
        }
        return Ok(keys);
    }

    let nodes = [
        ("stm32", DEV_STM32_SECRET),
        ("esp32", DEV_ESP32_SECRET),
        ("sim-a", DEV_SIM_A_SECRET),
        ("sim-b", DEV_SIM_B_SECRET),
    ];

    if let Some(node) = cli.node.as_deref() {
        let Some(init_secret) = preset_secret(node) else {
            return Err(
                format!("unknown node preset '{node}', expected sim-a|sim-b|stm32|esp32").into(),
            );
        };
        let mut out = Vec::new();
        for (peer_name, peer_secret) in nodes {
            if peer_name == node {
                continue;
            }
            out.push(derive_ik_transport(
                node,
                &init_secret,
                peer_name,
                &peer_secret,
            )?);
        }
        return Ok(out);
    }

    let mut out = Vec::new();
    for (init_name, init_secret) in nodes {
        for (peer_name, peer_secret) in [
            ("stm32", DEV_STM32_SECRET),
            ("esp32", DEV_ESP32_SECRET),
            ("sim-a", DEV_SIM_A_SECRET),
            ("sim-b", DEV_SIM_B_SECRET),
        ] {
            if init_name == peer_name {
                continue;
            }
            out.push(derive_ik_transport(
                init_name,
                &init_secret,
                peer_name,
                &peer_secret,
            )?);
        }
    }
    Ok(out)
}

fn find_fmp_frame(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < COMMON_PREFIX_SIZE {
        return None;
    }
    for start in 0..=(packet.len() - COMMON_PREFIX_SIZE) {
        let candidate = &packet[start..];
        let Some((phase, _, payload_len)) = parse_prefix(candidate) else {
            continue;
        };
        if !matches!(phase, PHASE_ESTABLISHED | PHASE_MSG1 | PHASE_MSG2) {
            continue;
        }
        if payload_len == 0 {
            continue;
        }
        let total = COMMON_PREFIX_SIZE + payload_len as usize;
        if candidate.len() < total {
            continue;
        }
        let frame = &candidate[..total];
        if parse_message(frame).is_none() {
            continue;
        }
        return Some(frame);
    }
    None
}

fn extract_udp_datagram(packet: &[u8]) -> Option<UdpDatagram<'_>> {
    if packet.len() < 20 {
        return None;
    }

    for ip_start in 0..=(packet.len() - 20) {
        let vihl = packet[ip_start];
        if (vihl >> 4) != 4 {
            continue;
        }

        let ihl = ((vihl & 0x0f) as usize) * 4;
        if ihl < 20 || packet.len() < ip_start + ihl {
            continue;
        }

        if packet[ip_start + 9] != 17 {
            continue;
        }

        let total_len = u16::from_be_bytes([packet[ip_start + 2], packet[ip_start + 3]]) as usize;
        if total_len < ihl + 8 {
            continue;
        }

        let ip_end = ip_start + total_len;
        if packet.len() < ip_end {
            continue;
        }

        let udp_start = ip_start + ihl;
        if ip_end < udp_start + 8 {
            continue;
        }

        let src_port = u16::from_be_bytes([packet[udp_start], packet[udp_start + 1]]);
        let dst_port = u16::from_be_bytes([packet[udp_start + 2], packet[udp_start + 3]]);
        let udp_len = u16::from_be_bytes([packet[udp_start + 4], packet[udp_start + 5]]) as usize;
        if udp_len < 8 || udp_start + udp_len > ip_end {
            continue;
        }

        let payload = &packet[udp_start + 8..udp_start + udp_len];
        if payload.len() >= COMMON_PREFIX_SIZE && parse_prefix(payload).is_some() {
            return Some(UdpDatagram {
                src_port,
                dst_port,
                payload,
            });
        }
    }

    None
}

fn decrypt_established(frame: &[u8], candidates: &[KeyPair]) -> Option<String> {
    if frame.len() < ESTABLISHED_HEADER_SIZE + TAG_SIZE {
        return Some("established payload too small".to_string());
    }

    let nonce_ctr = u64::from_le_bytes(frame[8..16].try_into().ok()?);
    let aad = &frame[..ESTABLISHED_HEADER_SIZE];
    let ciphertext = &frame[ESTABLISHED_HEADER_SIZE..];

    for kp in candidates {
        for (label, key) in [("k_send", kp.k_send), ("k_recv", kp.k_recv)] {
            let mut out = vec![0u8; ciphertext.len().saturating_sub(TAG_SIZE)];
            if let Ok(pt_len) = aead_decrypt(&key, nonce_ctr, aad, ciphertext, &mut out) {
                if pt_len < 5 {
                    continue;
                }
                let ts = u32::from_le_bytes(out[..4].try_into().ok()?);
                let msg_type = out[4];
                let payload = &out[5..pt_len];
                return Some(format!(
                    "decrypted by {} ({}) | ts={} msg_type=0x{msg_type:02x}({}) inner_payload={}",
                    kp.name,
                    label,
                    ts,
                    msg_type_name(msg_type),
                    hex::encode(payload)
                ));
            }
        }
    }

    Some("decrypt failed with all key candidates".to_string())
}

fn decode_frame_details(frame: &[u8], keys: &[KeyPair]) -> String {
    match parse_message(frame) {
        Some(FmpMessage::Msg1 {
            sender_idx,
            noise_payload,
        }) => {
            format!(
                "sender_idx={} noise_payload_size={}B",
                sender_idx,
                noise_payload.len()
            )
        }
        Some(FmpMessage::Msg2 {
            sender_idx,
            receiver_idx,
            noise_payload,
        }) => format!(
            "sender_idx={} receiver_idx={} noise_payload_size={}B",
            sender_idx,
            receiver_idx,
            noise_payload.len()
        ),
        Some(FmpMessage::Established {
            receiver_idx,
            counter,
            encrypted,
        }) => {
            let mut line = format!(
                "receiver_idx={} counter={} encrypted_size={}B",
                receiver_idx,
                counter,
                encrypted.len()
            );
            if let Some(decrypt) = decrypt_established(frame, keys) {
                line.push_str(" | ");
                line.push_str(&decrypt);
            }
            line
        }
        None => "failed to parse message body".to_string(),
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let keys = build_candidate_keys(&cli)?;
    eprintln!("Loaded {} key candidate pairs", keys.len());

    let file = File::open(&cli.pcap_file)?;
    let mut reader = PcapReader::new(file)?;

    let mut frame_no = 0usize;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        let Some(udp) = extract_udp_datagram(&pkt.data) else {
            continue;
        };

        let Some(frame) = find_fmp_frame(udp.payload) else {
            continue;
        };

        let Some((phase, flags, payload_len)) = parse_prefix(frame) else {
            continue;
        };
        if cli.filter.is_some() && cli.filter != Some(phase) {
            continue;
        }

        frame_no += 1;
        let dir = if udp.dst_port == 2121 {
            "->"
        } else if udp.src_port == 2121 {
            "<-"
        } else {
            "??"
        };

        let details = decode_frame_details(frame, &keys);
        println!(
            "[frame#{frame_no}] {dir} {} {}B | flags=0x{flags:02x} payload_len={} | {}",
            phase_label(phase),
            frame.len(),
            payload_len,
            details
        );

        if cli.verbose {
            println!("  raw={}", hex::encode(frame));
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        log::error!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microfips_core::fmp::{build_prefix, PHASE_MSG1};
    use microfips_core::noise::aead_encrypt;

    #[test]
    fn parses_known_fmp_prefix() {
        let bytes = build_prefix(PHASE_MSG1, 0x02, 110);
        let parsed = parse_prefix(&bytes).expect("prefix should parse");
        assert_eq!(parsed.0, PHASE_MSG1);
        assert_eq!(parsed.1, 0x02);
        assert_eq!(parsed.2, 110);
    }

    #[test]
    fn aead_decrypt_known_roundtrip_vector() {
        let key = [0x11u8; 32];
        let nonce_ctr = 42u64;
        let aad = b"fmp-aad";
        let plaintext = b"hello-fips";

        let mut ciphertext = [0u8; 64];
        let clen = aead_encrypt(&key, nonce_ctr, aad, plaintext, &mut ciphertext)
            .expect("encrypt should succeed");

        let mut out = [0u8; 64];
        let plen = aead_decrypt(&key, nonce_ctr, aad, &ciphertext[..clen], &mut out)
            .expect("decrypt should succeed");

        assert_eq!(&out[..plen], plaintext);
        assert_eq!(plen, plaintext.len());
    }
}
