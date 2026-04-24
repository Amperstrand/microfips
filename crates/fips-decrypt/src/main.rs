use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

use clap::Parser;
use microfips_core::identity::sha256;
use microfips_core::noise::{
    aead_decrypt, ecdh_pubkey, NoiseIkInitiator, NoiseIkResponder, EPOCH_SIZE, PUBKEY_SIZE,
    TAG_SIZE,
};
use microfips_core::wire::{
    parse_message, parse_prefix, FmpMessage, COMMON_PREFIX_SIZE, ESTABLISHED_HEADER_SIZE,
    PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use pcap_file::pcap::PcapReader;

struct UdpDatagram<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

const DEV_STM32_NSEC: [u8; 32] = microfips_core::hex::hex_bytes_32(env!("DEVICE_NSEC_HEX_stm32"));
const DEV_ESP32_NSEC: [u8; 32] = microfips_core::hex::hex_bytes_32(env!("DEVICE_NSEC_HEX_esp32"));
const DEV_SIM_A_NSEC: [u8; 32] = microfips_core::hex::hex_bytes_32(env!("DEVICE_NSEC_HEX_sim-a"));
const DEV_SIM_B_NSEC: [u8; 32] = microfips_core::hex::hex_bytes_32(env!("DEVICE_NSEC_HEX_sim-b"));

#[derive(Debug, Clone)]
struct KeyPair {
    name: String,
    k_send: [u8; 32],
    k_recv: [u8; 32],
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
        "stm32" => Some(DEV_STM32_NSEC),
        "esp32" => Some(DEV_ESP32_NSEC),
        "sim-a" => Some(DEV_SIM_A_NSEC),
        "sim-b" => Some(DEV_SIM_B_NSEC),
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

    // If --keys-file given, parse JSONL diagnostic dump
    if let Some(ref path) = cli.keys_file {
        return parse_keys_file(path);
    }

    let nodes = [
        ("stm32", DEV_STM32_NSEC),
        ("esp32", DEV_ESP32_NSEC),
        ("sim-a", DEV_SIM_A_NSEC),
        ("sim-b", DEV_SIM_B_NSEC),
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
            ("stm32", DEV_STM32_NSEC),
            ("esp32", DEV_ESP32_NSEC),
            ("sim-a", DEV_SIM_A_NSEC),
            ("sim-b", DEV_SIM_B_NSEC),
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

/// Parse a JSONL diagnostic keys file produced by FIPS `--features diagnostic`.
///
/// Each line looks like:
/// ```json
/// {"fips_diagnostic":"transport_keys","role":"...","remote_static":"hex66","k_send":"hex64","k_recv":"hex64","handshake_hash":"hex64"}
/// ```
fn parse_keys_file(path: &PathBuf) -> Result<Vec<KeyPair>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut keys = Vec::new();

    for (line_no, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let val: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if val.get("fips_diagnostic").and_then(|v| v.as_str()) != Some("transport_keys") {
            continue;
        }

        let k_send_hex = match val.get("k_send").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => continue,
        };
        let k_recv_hex = match val.get("k_recv").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => continue,
        };

        let k_send_bytes = hex::decode(k_send_hex)?;
        let k_recv_bytes = hex::decode(k_recv_hex)?;
        if k_send_bytes.len() != 32 || k_recv_bytes.len() != 32 {
            eprintln!(
                "Warning: keys_file line {} has wrong key length, skipping",
                line_no + 1
            );
            continue;
        }

        let mut k_send = [0u8; 32];
        let mut k_recv = [0u8; 32];
        k_send.copy_from_slice(&k_send_bytes);
        k_recv.copy_from_slice(&k_recv_bytes);

        let role = val
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        keys.push(KeyPair {
            name: format!("keys_file:{role}:{}", &k_send_hex[..8]),
            k_send,
            k_recv,
        });
    }

    if keys.is_empty() {
        return Err(format!("no transport_keys entries found in {}", path.display()).into());
    }

    Ok(keys)
}

#[derive(Debug)]
enum InputFormat {
    Pcap,
    Btsnoop { #[allow(dead_code)] big_endian: bool },
    Unknown,
}

const BTSNOOF_MAGIC_BE: [u8; 8] = [0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00];
const BTSNOOF_MAGIC_LE: [u8; 8] = [0x00, 0x70, 0x6f, 0x6f, 0x6e, 0x73, 0x74, 0x62];
const PCAP_MAGIC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];

fn detect_format(header: &[u8]) -> InputFormat {
    if header.len() < 8 {
        return InputFormat::Unknown;
    }

    if &header[..8] == BTSNOOF_MAGIC_BE {
        return InputFormat::Btsnoop { big_endian: true };
    }
    if &header[..8] == BTSNOOF_MAGIC_LE {
        return InputFormat::Btsnoop {
            big_endian: false,
        };
    }

    if header.len() >= 4 && &header[..4] == PCAP_MAGIC {
        return InputFormat::Pcap;
    }

    InputFormat::Unknown
}

/// btsnoop record header: 24 bytes big-endian
/// (orig_len, incl_len, flags, drops, timestamp_us)
const BTSNOOP_RECORD_HEADER_SIZE: usize = 24;
const BTSNOOP_FILE_HEADER_SIZE: usize = 16;

struct BtsnoopRecord {
    data: Vec<u8>,
    flags: u32,
}

const BTSNOOP_DATALINK_MONITOR: u32 = 2001;

fn read_btsnoop_u32_be(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

fn read_btsnoop_u64_be(data: &[u8]) -> u64 {
    u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

fn parse_btsnoop_records(data: &[u8]) -> Result<(u32, Vec<BtsnoopRecord>), Box<dyn Error>> {
    if data.len() < BTSNOOP_FILE_HEADER_SIZE {
        return Err("btsnoop file too short for header".into());
    }

    let _version = read_btsnoop_u32_be(&data[8..12]);
    let datalink = read_btsnoop_u32_be(&data[12..16]);

    let mut records = Vec::new();
    let mut offset = BTSNOOP_FILE_HEADER_SIZE;

    while offset + BTSNOOP_RECORD_HEADER_SIZE <= data.len() {
        let orig_len = read_btsnoop_u32_be(&data[offset..offset + 4]);
        let incl_len = read_btsnoop_u32_be(&data[offset + 4..offset + 8]);
        let flags = read_btsnoop_u32_be(&data[offset + 8..offset + 12]);
        let _drops = read_btsnoop_u32_be(&data[offset + 12..offset + 16]);
        let _timestamp = read_btsnoop_u64_be(&data[offset + 16..offset + 24]);

        let data_len = incl_len as usize;
        if incl_len != orig_len || offset + BTSNOOP_RECORD_HEADER_SIZE + data_len > data.len() {
            break;
        }

        let record_data = data[offset + BTSNOOP_RECORD_HEADER_SIZE
            ..offset + BTSNOOP_RECORD_HEADER_SIZE + data_len]
            .to_vec();

        records.push(BtsnoopRecord {
            data: record_data,
            flags,
        });

        offset += BTSNOOP_RECORD_HEADER_SIZE + data_len;
    }

    Ok((datalink, records))
}

const HCI_ACL_DATA: u8 = 0x02;
const L2CAP_SIGNALLING_CID: u16 = 0x0001;
const L2CAP_LE_SIGNALLING_CID: u16 = 0x0005;
const L2CAP_CONN_REQ: u8 = 0x02;
const L2CAP_LE_CREDIT_BASED_CONN_REQ: u8 = 0x14;

/// Extract FMP frames from an HCI H4 capture (btsnoop datalink 1001).
/// Tracks L2CAP CoC on PSM 0x0085 to find the FIPS data CID,
/// then strips the 2-byte BE BLE transport framing prefix.
/// Falls back to scanning all ACL payloads for FMP-like data.
fn extract_fmp_from_hci_h4(records: &[BtsnoopRecord], datalink: u32) -> Vec<Vec<u8>> {
    let mut fips_cids: Vec<u16> = Vec::new();
    let mut fmp_frames = Vec::new();

    for record in records {
        let data = &record.data;
        if data.is_empty() {
            continue;
        }

        let acl_data = if datalink == BTSNOOP_DATALINK_MONITOR {
            let pkt_type = (record.flags >> 16) & 0xff;
            if pkt_type != 0x01 {
                continue;
            }
            data.as_slice()
        } else {
            if data[0] != HCI_ACL_DATA {
                continue;
            }
            &data[1..]
        };

        if acl_data.len() < 4 {
            continue;
        }
        let acl_len = u16::from_le_bytes([acl_data[2], acl_data[3]]) as usize;
        if acl_data.len() < 4 + acl_len {
            continue;
        }
        let l2cap_data = &acl_data[4..4 + acl_len];

        if l2cap_data.len() < 4 {
            continue;
        }
        let l2cap_len = u16::from_le_bytes([l2cap_data[0], l2cap_data[1]]) as usize;
        let l2cap_cid = u16::from_le_bytes([l2cap_data[2], l2cap_data[3]]);
        let l2cap_payload = &l2cap_data[4..];
        let l2cap_payload_len = l2cap_len.min(l2cap_payload.len());

        if l2cap_cid == L2CAP_LE_SIGNALLING_CID || l2cap_cid == L2CAP_SIGNALLING_CID {
            let mut sig_offset = 0;
            while sig_offset + 4 <= l2cap_payload_len {
                let code = l2cap_payload[sig_offset];
                let _ident = l2cap_payload[sig_offset + 1];
                let sig_len =
                    u16::from_le_bytes([l2cap_payload[sig_offset + 2], l2cap_payload[sig_offset + 3]])
                        as usize;
                let sig_data_start = sig_offset + 4;

                if code == L2CAP_LE_CREDIT_BASED_CONN_REQ && sig_len >= 6 {
                    let scid = u16::from_le_bytes([
                        l2cap_payload[sig_data_start + 2],
                        l2cap_payload[sig_data_start + 3],
                    ]);
                    if scid > 0x003F && !fips_cids.contains(&scid) {
                        fips_cids.push(scid);
                    }
                }

                if code == L2CAP_CONN_REQ && sig_len >= 4 {
                    let scid = u16::from_le_bytes([
                        l2cap_payload[sig_data_start + 2],
                        l2cap_payload[sig_data_start + 3],
                    ]);
                    if scid > 0x003F && !fips_cids.contains(&scid) {
                        fips_cids.push(scid);
                    }
                }

                sig_offset = sig_data_start + sig_len;
            }
            continue;
        }

        if l2cap_cid <= 0x003F {
            continue;
        }

        let payload = &l2cap_payload[..l2cap_payload_len];
        let is_fips_channel = fips_cids.contains(&l2cap_cid);

        if is_fips_channel {
            extract_fmp_from_l2cap_coc(payload, &mut fmp_frames);
        } else if fips_cids.is_empty() {
            if try_extract_fmp_from_l2cap_coc_check(payload) {
                fips_cids.push(l2cap_cid);
                extract_fmp_from_l2cap_coc(payload, &mut fmp_frames);
            }
        }
    }

    fmp_frames
}

fn try_extract_fmp_from_l2cap_coc_check(payload: &[u8]) -> bool {
    if payload.len() < 2 + 2 + COMMON_PREFIX_SIZE {
        return false;
    }
    let sdu_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if sdu_len == 0 || payload.len() < 2 + sdu_len {
        return false;
    }
    let inner = &payload[2..2 + sdu_len];
    if inner.len() < 2 + COMMON_PREFIX_SIZE {
        return false;
    }
    let fmp_len = u16::from_be_bytes([inner[0], inner[1]]) as usize;
    if fmp_len == 0 || inner.len() < 2 + fmp_len {
        return false;
    }
    let fmp_data = &inner[2..2 + fmp_len];
    if let Some((phase, _, _)) = parse_prefix(fmp_data) {
        return matches!(phase, PHASE_ESTABLISHED | PHASE_MSG1 | PHASE_MSG2);
    }
    false
}

fn extract_fmp_from_l2cap_coc(payload: &[u8], out: &mut Vec<Vec<u8>>) {
    if payload.len() < 2 + COMMON_PREFIX_SIZE {
        return;
    }
    let sdu_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if sdu_len == 0 || payload.len() < 2 + sdu_len {
        return;
    }
    let inner = &payload[2..2 + sdu_len];
    if inner.len() < 2 + COMMON_PREFIX_SIZE {
        return;
    }
    let fmp_len = u16::from_be_bytes([inner[0], inner[1]]) as usize;
    if fmp_len == 0 || inner.len() < 2 + fmp_len {
        return;
    }
    let fmp_data = &inner[2..2 + fmp_len];
    if fmp_data.len() >= COMMON_PREFIX_SIZE && parse_prefix(fmp_data).is_some() {
        out.push(fmp_data.to_vec());
    }
}

struct PcapWriter {
    file: File,
    seq: u16,
}

impl PcapWriter {
    fn create(path: &PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut file = File::create(path)?;
        let header: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        file.write_all(&header)?;
        Ok(Self { file, seq: 0 })
    }

    fn write_udp_packet(&mut self, payload: &[u8], src_port: u16, dst_port: u16) -> Result<(), Box<dyn Error>> {
        let udp_len = 8 + payload.len();
        let ip_total_len = 20 + udp_len;

        let mut pkt = Vec::with_capacity(14 + ip_total_len);

        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
        pkt.extend_from_slice(&self.seq.to_be_bytes());
        self.seq = self.seq.wrapping_add(1);
        pkt.extend_from_slice(&[0x40, 0x00]);
        pkt.push(0x40);
        pkt.push(0x11);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);

        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);

        pkt.extend_from_slice(payload);

        let pkt_len = pkt.len() as u32;
        let rec_header: [u8; 16] = [
            0, 0, 0, 0,
            0, 0, 0, 0,
            (pkt_len & 0xff) as u8,
            ((pkt_len >> 8) & 0xff) as u8,
            ((pkt_len >> 16) & 0xff) as u8,
            ((pkt_len >> 24) & 0xff) as u8,
            (pkt_len & 0xff) as u8,
            ((pkt_len >> 8) & 0xff) as u8,
            ((pkt_len >> 16) & 0xff) as u8,
            ((pkt_len >> 24) & 0xff) as u8,
        ];
        self.file.write_all(&rec_header)?;
        self.file.write_all(&pkt)?;

        Ok(())
    }
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

#[derive(Debug, Parser)]
#[command(name = "fips-decrypt")]
#[command(about = "Read FIPS pcap/btsnoop captures and decode/decrypt FMP frames")]
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

    #[arg(
        long = "keys-file",
        value_name = "PATH",
        help = "Read transport keys from a JSONL diagnostic dump file"
    )]
    keys_file: Option<PathBuf>,

    #[arg(
        long = "output",
        value_name = "PATH",
        help = "Write decrypted output as a pcap file (UDP-encapsulated on port 2121)"
    )]
    output: Option<PathBuf>,

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

fn run_pcap(cli: &Cli, keys: &[KeyPair]) -> Result<(), Box<dyn Error>> {
    let file = File::open(&cli.pcap_file)?;
    let mut reader = PcapReader::new(file)?;

    let mut pcap_writer = match &cli.output {
        Some(path) => Some(PcapWriter::create(path)?),
        None => None,
    };

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

        let details = decode_frame_details(frame, keys);
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

        if let Some(ref mut writer) = pcap_writer {
            write_frame_to_pcap(writer, frame, phase, keys, dir);
        }
    }

    eprintln!("Processed {frame_no} FMP frames from pcap");
    Ok(())
}

fn run_btsnoop(cli: &Cli, keys: &[KeyPair]) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(&cli.pcap_file)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let (datalink, records) = parse_btsnoop_records(&data)?;
    eprintln!("Parsed {} btsnoop records (datalink={})", records.len(), datalink);

    let fmp_frames = extract_fmp_from_hci_h4(&records, datalink);
    eprintln!("Extracted {} FMP frames from HCI capture", fmp_frames.len());

    let mut pcap_writer = match &cli.output {
        Some(path) => Some(PcapWriter::create(path)?),
        None => None,
    };

    let mut frame_no = 0usize;
    for frame in &fmp_frames {
        let Some((phase, flags, payload_len)) = parse_prefix(frame) else {
            continue;
        };
        if cli.filter.is_some() && cli.filter != Some(phase) {
            continue;
        }

        frame_no += 1;
        let dir = "->";

        let details = decode_frame_details(frame, keys);
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

        if let Some(ref mut writer) = pcap_writer {
            write_frame_to_pcap(writer, frame, phase, keys, dir);
        }
    }

    eprintln!("Processed {frame_no} FMP frames from btsnoop");
    Ok(())
}

/// Write a single FMP frame to the output pcap.
/// Always writes the original FMP frame (with FMP header) so the Wireshark
/// dissector can parse it. Decrypted plaintext has no FMP framing and would
/// confuse the dissector.
fn write_frame_to_pcap(writer: &mut PcapWriter, frame: &[u8], _phase: u8, _keys: &[KeyPair], dir: &str) {
    let (src_port, dst_port) = if dir == "<-" {
        (2121u16, 9999u16)
    } else {
        (9999u16, 2121u16)
    };

    let _ = writer.write_udp_packet(frame, src_port, dst_port);
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let keys = build_candidate_keys(&cli)?;
    eprintln!("Loaded {} key candidate pairs", keys.len());

    let mut file = File::open(&cli.pcap_file)?;
    let mut header = [0u8; 16];
    let n = file.read(&mut header)?;
    drop(file);

    if n < 4 {
        return Err("input file too short to detect format".into());
    }

    match detect_format(&header[..n]) {
        InputFormat::Pcap => {
            eprintln!("Detected pcap format");
            run_pcap(&cli, &keys)
        }
        InputFormat::Btsnoop { .. } => {
            eprintln!("Detected btsnoop format");
            run_btsnoop(&cli, &keys)
        }
        InputFormat::Unknown => Err(format!(
            "unknown input format (magic: {})",
            hex::encode(&header[..n.min(8)])
        )
        .into()),
    }
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
    use microfips_core::noise::aead_encrypt;
    use microfips_core::wire::{build_prefix, PHASE_MSG1};

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

    #[test]
    fn btsnoop_detect_magic_be() {
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&BTSNOOF_MAGIC_BE);
        header[8..12].copy_from_slice(&1u32.to_be_bytes());
        header[12..16].copy_from_slice(&1001u32.to_be_bytes());

        match detect_format(&header) {
            InputFormat::Btsnoop { big_endian: true } => {}
            other => panic!("expected Btsnoop BE, got {:?}", format!("{:?}", other).chars().take(40).collect::<String>()),
        }
    }

    #[test]
    fn btsnoop_detect_magic_le() {
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&BTSNOOF_MAGIC_LE);

        match detect_format(&header) {
            InputFormat::Btsnoop { big_endian: false } => {}
            other => panic!("expected Btsnoop LE, got {:?}", format!("{:?}", other).chars().take(40).collect::<String>()),
        }
    }

    #[test]
    fn pcap_detect_magic() {
        let mut header = [0u8; 16];
        header[..4].copy_from_slice(&PCAP_MAGIC);

        match detect_format(&header) {
            InputFormat::Pcap => {}
            other => panic!("expected Pcap, got {:?}", format!("{:?}", other).chars().take(40).collect::<String>()),
        }
    }

    #[test]
    fn btsnoop_parse_empty_file() {
        let mut data = Vec::new();
        data.extend_from_slice(&BTSNOOF_MAGIC_BE);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&1001u32.to_be_bytes());

        let (_datalink, records) = parse_btsnoop_records(&data).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn btsnoop_parse_single_record() {
        let payload = b"hello";
        let mut data = Vec::new();

        data.extend_from_slice(&BTSNOOF_MAGIC_BE);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&1001u32.to_be_bytes());

        let len = payload.len() as u32;
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());

        data.extend_from_slice(payload);

        let (datalink, records) = parse_btsnoop_records(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(&records[0].data, b"hello");
        assert_eq!(datalink, 1001);
    }

    #[test]
    fn keys_file_parse_valid_jsonl() {
        let dir = std::env::temp_dir().join("fips-decrypt-test-keys");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("keys.jsonl");

        let k_send = "1111111111111111111111111111111111111111111111111111111111111111";
        let k_recv = "2222222222222222222222222222222222222222222222222222222222222222";

        let content = format!(
            "{{\"fips_diagnostic\":\"transport_keys\",\"role\":\"initiator\",\"remote_static\":\"{}\",\"k_send\":\"{}\",\"k_recv\":\"{}\",\"handshake_hash\":\"{}\"}}\n",
            "02".to_string() + &"66".repeat(32),
            k_send,
            k_recv,
            "aa".repeat(32)
        );

        std::fs::write(&path, &content).unwrap();

        let keys = parse_keys_file(&path).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].k_send, [0x11u8; 32]);
        assert_eq!(keys[0].k_recv, [0x22u8; 32]);
        assert!(keys[0].name.contains("initiator"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_file_skip_non_transport_lines() {
        let dir = std::env::temp_dir().join("fips-decrypt-test-skip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mixed.jsonl");

        let k_send_hex = "aa".repeat(32);
        let k_recv_hex = "bb".repeat(32);
        let hash_hex = "cc".repeat(32);
        let remote_static = "02".to_string() + &"66".repeat(32);
        let line = format!(
            "{{\"fips_diagnostic\":\"transport_keys\",\"role\":\"responder\",\
             \"remote_static\":\"{}\",\"k_send\":\"{}\",\"k_recv\":\"{}\",\
             \"handshake_hash\":\"{}\"}}",
            remote_static, k_send_hex, k_recv_hex, hash_hex
        );
        let content = format!(
            "{{\"fips_diagnostic\":\"other_event\",\"data\":\"something\"}}\n\
             not json at all\n\
             {}\n",
            line
        );
        std::fs::write(&path, content).unwrap();

        let keys = parse_keys_file(&path).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].name.contains("responder"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_file_empty_produces_error() {
        let dir = std::env::temp_dir().join("fips-decrypt-test-empty");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.jsonl");
        std::fs::write(&path, "").unwrap();

        let result = parse_keys_file(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_fmp_from_acl_with_fallback() {
        let noise_payload = [0xAAu8; 106];
        let mut fmp_frame = [0u8; 256];
        let fmp_len = microfips_core::wire::build_msg1(microfips_core::wire::SessionIndex(0), &noise_payload, &mut fmp_frame).unwrap();

        let mut ble_payload = Vec::new();
        ble_payload.extend_from_slice(&(fmp_len as u16).to_be_bytes());
        ble_payload.extend_from_slice(&fmp_frame[..fmp_len]);

        let sdu_len = ble_payload.len() as u16;
        let mut l2cap_payload = Vec::new();
        l2cap_payload.extend_from_slice(&sdu_len.to_le_bytes());
        l2cap_payload.extend_from_slice(&ble_payload);

        let l2cap_frame_len = l2cap_payload.len() as u16;
        let mut l2cap_frame = Vec::new();
        l2cap_frame.extend_from_slice(&l2cap_frame_len.to_le_bytes());
        l2cap_frame.extend_from_slice(&0x0040u16.to_le_bytes());
        l2cap_frame.extend_from_slice(&l2cap_payload);

        let acl_len = l2cap_frame.len() as u16;
        let mut acl_packet = Vec::new();
        acl_packet.push(HCI_ACL_DATA);
        acl_packet.extend_from_slice(&0x0001u16.to_le_bytes());
        acl_packet.extend_from_slice(&acl_len.to_le_bytes());
        acl_packet.extend_from_slice(&l2cap_frame);

        let mut btsnoop_data = Vec::new();
        btsnoop_data.extend_from_slice(&BTSNOOF_MAGIC_BE);
        btsnoop_data.extend_from_slice(&1u32.to_be_bytes());
        btsnoop_data.extend_from_slice(&1001u32.to_be_bytes());

        let rec_len = acl_packet.len() as u32;
        btsnoop_data.extend_from_slice(&rec_len.to_be_bytes());
        btsnoop_data.extend_from_slice(&rec_len.to_be_bytes());
        btsnoop_data.extend_from_slice(&0u32.to_be_bytes());
        btsnoop_data.extend_from_slice(&0u32.to_be_bytes());
        btsnoop_data.extend_from_slice(&0u64.to_be_bytes());
        btsnoop_data.extend_from_slice(&acl_packet);

        let (_datalink, records) = parse_btsnoop_records(&btsnoop_data).unwrap();
        let fmp_frames = extract_fmp_from_hci_h4(&records, 1001);

        assert_eq!(fmp_frames.len(), 1);
        assert_eq!(&fmp_frames[0], &fmp_frame[..fmp_len]);
    }
}
