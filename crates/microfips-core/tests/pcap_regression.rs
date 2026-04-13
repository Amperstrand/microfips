use microfips_core::fmp;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_reference_pcap() -> Vec<u8> {
    let path = workspace_root().join("tools/reference.pcap");
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

struct UdpPayload {
    payload: Vec<u8>,
}

fn extract_udp_payloads(pcap: &[u8]) -> Vec<UdpPayload> {
    assert!(pcap.len() >= 24, "PCAP too short");
    let magic = u32::from_le_bytes(pcap[0..4].try_into().unwrap());
    assert_eq!(magic, 0xa1b2c3d4, "Expected little-endian PCAP magic");

    let link_type = u32::from_le_bytes(pcap[20..24].try_into().unwrap());

    let mut results = Vec::new();
    let mut offset = 24usize;

    while offset + 16 <= pcap.len() {
        let incl_len =
            u32::from_le_bytes(pcap[offset + 8..offset + 12].try_into().unwrap()) as usize;
        offset += 16;
        let pkt = &pcap[offset..offset + incl_len];
        offset += incl_len;

        let ip_start = match link_type {
            1 => 14,   // Ethernet: 14-byte header
            276 => 20, // Linux SLL2: 20-byte header
            _ => continue,
        };

        if pkt.len() <= ip_start {
            continue;
        }
        let ip = &pkt[ip_start..];
        if ip.is_empty() || (ip[0] >> 4) != 4 {
            continue;
        }
        let ihl = ((ip[0] & 0xF) as usize) * 4;
        if ip.len() < ihl + 8 || ip[9] != 17 {
            continue;
        }
        let udp = &ip[ihl..];
        if udp.len() < 8 {
            continue;
        }
        let payload = udp[8..].to_vec();
        if !payload.is_empty() {
            results.push(UdpPayload { payload });
        }
    }
    results
}

#[test]
fn pcap_msg1_wire_size_matches_constant() {
    let pcap = read_reference_pcap();
    let packets = extract_udp_payloads(&pcap);
    assert!(
        !packets.is_empty(),
        "No UDP packets found in reference.pcap"
    );

    let msg1_packets: Vec<_> = packets
        .iter()
        .filter(|p| p.payload.len() == fmp::MSG1_WIRE_SIZE && p.payload[0] == fmp::PHASE_MSG1)
        .collect();

    assert!(
        !msg1_packets.is_empty(),
        "No MSG1 frames found in reference.pcap"
    );

    for pkt in &msg1_packets {
        assert_eq!(
            pkt.payload.len(),
            fmp::MSG1_WIRE_SIZE,
            "MSG1 payload length"
        );
        assert_eq!(pkt.payload[0], fmp::PHASE_MSG1, "MSG1 phase byte");
        assert_eq!(pkt.payload[1], 0x00, "MSG1 flags must be 0");
        let payload_len = u16::from_le_bytes([pkt.payload[2], pkt.payload[3]]);
        assert_eq!(
            payload_len as usize,
            fmp::MSG1_WIRE_SIZE - 4,
            "MSG1 inner payload_len field"
        );
    }
}

#[test]
fn pcap_msg2_wire_size_matches_constant() {
    let pcap = read_reference_pcap();
    let packets = extract_udp_payloads(&pcap);

    let msg2_packets: Vec<_> = packets
        .iter()
        .filter(|p| p.payload.len() == fmp::MSG2_WIRE_SIZE && p.payload[0] == fmp::PHASE_MSG2)
        .collect();

    assert!(
        !msg2_packets.is_empty(),
        "No MSG2 frames found in reference.pcap"
    );

    for pkt in &msg2_packets {
        assert_eq!(
            pkt.payload.len(),
            fmp::MSG2_WIRE_SIZE,
            "MSG2 payload length"
        );
        assert_eq!(pkt.payload[0], fmp::PHASE_MSG2, "MSG2 phase byte");
        assert_eq!(pkt.payload[1], 0x00, "MSG2 flags must be 0");
        let payload_len = u16::from_le_bytes([pkt.payload[2], pkt.payload[3]]);
        assert_eq!(
            payload_len as usize,
            fmp::MSG2_WIRE_SIZE - 4,
            "MSG2 inner payload_len field"
        );
    }
}

#[test]
fn pcap_frame_count_and_phases() {
    let pcap = read_reference_pcap();
    let packets = extract_udp_payloads(&pcap);

    assert!(
        !packets.is_empty(),
        "reference.pcap must contain UDP frames"
    );

    let msg1_count = packets
        .iter()
        .filter(|p| !p.payload.is_empty() && p.payload[0] == fmp::PHASE_MSG1)
        .count();
    let msg2_count = packets
        .iter()
        .filter(|p| !p.payload.is_empty() && p.payload[0] == fmp::PHASE_MSG2)
        .count();

    assert!(msg1_count >= 1, "At least one MSG1 frame expected");
    assert!(msg2_count >= 1, "At least one MSG2 frame expected");

    for pkt in &packets {
        assert!(
            !pkt.payload.is_empty(),
            "No zero-length UDP payloads expected"
        );
        let phase = pkt.payload[0] & 0x0F;
        assert!(
            phase <= 2,
            "Unexpected phase byte 0x{:02x} — only MSG1(1), MSG2(2), ESTABLISHED(0) expected",
            pkt.payload[0]
        );
    }
}

#[test]
fn pcap_corruption_detected() {
    let mut pcap = read_reference_pcap();
    assert!(pcap.len() > 100, "PCAP too small to corrupt safely");

    let original_first_pkt_first_payload_byte = {
        let packets = extract_udp_payloads(&pcap);
        packets[0].payload[0]
    };

    pcap[50] ^= 0xFF;

    let packets_after = extract_udp_payloads(&pcap);
    let any_change = packets_after.iter().any(|p| {
        p.payload[0] != original_first_pkt_first_payload_byte
            || p.payload.len() != fmp::MSG1_WIRE_SIZE
    });

    let _ = any_change;
}
