#[cfg(test)]
mod tests {
    use microfips_core::noise;
    use std::sync::atomic::{AtomicU32, Ordering};

    const L2CAP_MTU: usize = 2048;
    const L2CAP_FRAME_CAP: usize = 768;
    const L2CAP_SDU_CAP: usize = L2CAP_FRAME_CAP + 2;
    const L2CAP_PSM: u16 = 0x0085;
    const L2CAP_RECV_TIMEOUT_SECS: u64 = 45;
    const L2CAP_SEND_TIMEOUT_SECS: u64 = 15;
    const CENTRAL_CONNECT_TIMEOUT_SECS: u64 = 3;
    const CENTRAL_COLLISION_COOLDOWN_MS: u32 = 6_000;
    const CONNECTION_INTERVAL_MIN_MS: u32 = 20;
    const CONNECTION_INTERVAL_MAX_MS: u32 = 40;
    const CONNECTION_MAX_LATENCY: u16 = 0;
    const SUPERVISION_TIMEOUT_MS: u32 = 4_000;
    const FIPS_SERVICE_UUID: u128 = 0x9c90b790_2cc5_42c0_9f87_c9cc40648f4c;
    const FIPS_SERVICE_UUID_LE: [u8; 16] = [
        0x4c, 0x8f, 0x64, 0x40, 0xcc, 0xc9, 0x87, 0x9f, 0xc0, 0x42, 0xc5, 0x2c, 0x90, 0xb7, 0x90,
        0x9c,
    ];
    const FIPS_CAPS_SERVICE_UUID: [u8; 2] = [0x46, 0x49];
    const FIPS_ALLOWED_PUBKEYS: [[u8; 32]; 3] = [
        [
            0xb3, 0xae, 0x36, 0xdf, 0x8b, 0xc8, 0xea, 0x0e, 0xc8, 0x8b, 0xd5, 0xf4, 0x7e, 0x21,
            0x86, 0x7e, 0xb7, 0xf7, 0xe0, 0x2d, 0xaf, 0x34, 0x80, 0xf3, 0x52, 0xf1, 0xc8, 0xc4,
            0x9f, 0xb2, 0x4d, 0x6a,
        ],
        [
            0xb3, 0x98, 0x90, 0x43, 0xc6, 0x8d, 0x9c, 0x2d, 0x3c, 0x8f, 0x94, 0x9d, 0x73, 0xe6,
            0x1c, 0xae, 0x27, 0x99, 0x79, 0x93, 0x43, 0x2c, 0x3d, 0xbb, 0xd8, 0x49, 0x81, 0x17,
            0xd9, 0x2d, 0x95, 0xbb,
        ],
        [
            0xa3, 0xd1, 0xbb, 0xeb, 0x71, 0x40, 0x30, 0x86, 0xff, 0xb0, 0x65, 0xda, 0x99, 0xac,
            0x0b, 0x21, 0xd9, 0x59, 0x66, 0xb8, 0xfe, 0xbf, 0x74, 0x14, 0x72, 0xa2, 0xee, 0xaf,
            0xc4, 0x44, 0x99, 0xd2,
        ],
    ];
    const INITIATOR_TEST_NSEC: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03,
    ];
    const RESPONDER_TEST_NSEC: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04,
    ];
    const INITIATOR_TEST_NPUB: [u8; 33] = [
        0x02, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d,
        0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc,
        0xe0, 0x36, 0xf9,
    ];
    const RESPONDER_TEST_NPUB: [u8; 33] = [
        0x02, 0xe4, 0x93, 0xdb, 0xf1, 0xc1, 0x0d, 0x80, 0xf3, 0x58, 0x1e, 0x49, 0x04, 0x93, 0x0b,
        0x14, 0x04, 0xcc, 0x6c, 0x13, 0x90, 0x0e, 0xe0, 0x75, 0x84, 0x74, 0xfa, 0x94, 0xab, 0xe8,
        0xc4, 0xcd, 0x13,
    ];

    mod ble_caps {
        pub const LEAF_ONLY: u8 = 0x01;
        pub const HAS_TUN: u8 = 0x02;
        pub const HAS_INTERNET: u8 = 0x04;
    }

    mod peer_caps {
        pub const LEGACY_CENTRAL_ONLY: u8 = 0x01;
        pub const PREFER_OUTBOUND: u8 = 0x02;
        pub const PREFER_L2CAP: u8 = 0x04;
        pub const CAN_CENTRAL: u8 = 0x08;
        pub const CAN_PERIPHERAL: u8 = 0x10;
        pub const L2CAP_SUPPORTED: u8 = 0x20;
        pub const GATT_SUPPORTED: u8 = 0x40;
        pub const ESP32_DEFAULT: u8 = CAN_CENTRAL | CAN_PERIPHERAL | L2CAP_SUPPORTED | PREFER_L2CAP;
        pub const FIPS_LINUX_DEFAULT: u8 =
            L2CAP_SUPPORTED | CAN_CENTRAL | CAN_PERIPHERAL | GATT_SUPPORTED | PREFER_L2CAP;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct PeerCapabilities(u8);

    impl PeerCapabilities {
        fn from_byte(byte: u8) -> Self {
            Self(byte)
        }

        fn to_byte(self) -> u8 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u32)]
    enum L2capDisconnectCode {
        None = 0,
        CleanYield = 1,
        DataExchanged = 2,
        SendError = 3,
        RecvTimeout = 4,
        SendTimeout = 5,
    }

    struct HostNodeStats {
        msg1_tx: AtomicU32,
        msg2_rx: AtomicU32,
        hb_tx: AtomicU32,
        hb_rx: AtomicU32,
        data_tx: AtomicU32,
        data_rx: AtomicU32,
        state: AtomicU32,
        boot_tick_ms: AtomicU32,
    }

    struct HostL2capStats {
        zero_frame_disconnects: AtomicU32,
        recv_timeouts: AtomicU32,
        send_timeouts: AtomicU32,
        send_errors: AtomicU32,
        rx_drops: AtomicU32,
        pubkey_ok: AtomicU32,
        central_connects: AtomicU32,
        peripheral_connects: AtomicU32,
        last_role: AtomicU32,
        last_reason: AtomicU32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct HostStatsSnapshot {
        msg1_tx: u32,
        msg2_rx: u32,
        hb_tx: u32,
        hb_rx: u32,
        data_tx: u32,
        data_rx: u32,
        state: u32,
        boot_tick_ms: u32,
        zero_frame_disconnects: u32,
        recv_timeouts: u32,
        send_timeouts: u32,
        send_errors: u32,
        rx_drops: u32,
        pubkey_ok: u32,
        central_connects: u32,
        peripheral_connects: u32,
        last_role: u32,
        last_reason: u32,
    }

    impl HostNodeStats {
        const fn new() -> Self {
            Self {
                msg1_tx: AtomicU32::new(0),
                msg2_rx: AtomicU32::new(0),
                hb_tx: AtomicU32::new(0),
                hb_rx: AtomicU32::new(0),
                data_tx: AtomicU32::new(0),
                data_rx: AtomicU32::new(0),
                state: AtomicU32::new(0),
                boot_tick_ms: AtomicU32::new(0),
            }
        }
    }

    impl HostL2capStats {
        const fn new() -> Self {
            Self {
                zero_frame_disconnects: AtomicU32::new(0),
                recv_timeouts: AtomicU32::new(0),
                send_timeouts: AtomicU32::new(0),
                send_errors: AtomicU32::new(0),
                rx_drops: AtomicU32::new(0),
                pubkey_ok: AtomicU32::new(0),
                central_connects: AtomicU32::new(0),
                peripheral_connects: AtomicU32::new(0),
                last_role: AtomicU32::new(0),
                last_reason: AtomicU32::new(0),
            }
        }
    }

    fn snapshot(node: &HostNodeStats, l2cap: &HostL2capStats) -> HostStatsSnapshot {
        HostStatsSnapshot {
            msg1_tx: node.msg1_tx.load(Ordering::Relaxed),
            msg2_rx: node.msg2_rx.load(Ordering::Relaxed),
            hb_tx: node.hb_tx.load(Ordering::Relaxed),
            hb_rx: node.hb_rx.load(Ordering::Relaxed),
            data_tx: node.data_tx.load(Ordering::Relaxed),
            data_rx: node.data_rx.load(Ordering::Relaxed),
            state: node.state.load(Ordering::Relaxed),
            boot_tick_ms: node.boot_tick_ms.load(Ordering::Relaxed),
            zero_frame_disconnects: l2cap.zero_frame_disconnects.load(Ordering::Relaxed),
            recv_timeouts: l2cap.recv_timeouts.load(Ordering::Relaxed),
            send_timeouts: l2cap.send_timeouts.load(Ordering::Relaxed),
            send_errors: l2cap.send_errors.load(Ordering::Relaxed),
            rx_drops: l2cap.rx_drops.load(Ordering::Relaxed),
            pubkey_ok: l2cap.pubkey_ok.load(Ordering::Relaxed),
            central_connects: l2cap.central_connects.load(Ordering::Relaxed),
            peripheral_connects: l2cap.peripheral_connects.load(Ordering::Relaxed),
            last_role: l2cap.last_role.load(Ordering::Relaxed),
            last_reason: l2cap.last_reason.load(Ordering::Relaxed),
        }
    }

    fn build_l2cap_sdu(payload: &[u8]) -> Vec<u8> {
        let mut sdu = Vec::with_capacity(payload.len() + 2);
        let len = u16::try_from(payload.len()).expect("payload length fits in u16");
        sdu.extend_from_slice(&len.to_be_bytes());
        sdu.extend_from_slice(payload);
        sdu
    }

    fn parse_l2cap_sdu(sdu: &[u8], frame_cap: usize) -> Result<(usize, &[u8]), &'static str> {
        if sdu.is_empty() {
            return Err("empty sdu");
        }
        if sdu.len() < 2 {
            return Err("sdu too short");
        }
        let payload_len = u16::from_be_bytes([sdu[0], sdu[1]]) as usize;
        if payload_len > frame_cap {
            return Err("frame too large");
        }
        if sdu.len() != payload_len + 2 {
            return Err("length mismatch");
        }
        Ok((payload_len, &sdu[2..]))
    }

    fn build_pubkey_exchange(pubkey_x: &[u8; 32], flags: u8) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[0..2].copy_from_slice(&34u16.to_be_bytes());
        out[2] = 0x00;
        out[3..35].copy_from_slice(pubkey_x);
        out[35] = flags;
        out
    }

    fn parse_pubkey_exchange(msg: &[u8]) -> Result<([u8; 33], Option<u8>), &'static str> {
        if msg.len() < 35 {
            return Err("message too short");
        }
        let payload_len = u16::from_be_bytes([msg[0], msg[1]]) as usize;
        if payload_len != 33 && payload_len != 34 {
            return Err("bad payload length");
        }
        if msg.len() != payload_len + 2 {
            return Err("bad wire length");
        }
        if msg[2] != 0x00 {
            return Err("bad pubkey prefix");
        }
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        pubkey[1..33].copy_from_slice(&msg[3..35]);
        let flags = if payload_len == 34 {
            Some(msg[35])
        } else {
            None
        };
        Ok((pubkey, flags))
    }

    fn peer_is_fips(peer_pub: &[u8; 33]) -> bool {
        FIPS_ALLOWED_PUBKEYS
            .iter()
            .any(|allowed| peer_pub[1..33] == allowed[..])
    }

    fn should_prefer_peripheral(window_ms: u32, now_ms: u32) -> bool {
        now_ms < window_ms
    }

    fn set_prefer_peripheral_window(now_ms: u32, delay_ms: u32) -> u32 {
        now_ms.saturating_add(delay_ms)
    }

    fn supports_central(flags: u8) -> bool {
        flags & (peer_caps::LEGACY_CENTRAL_ONLY | peer_caps::CAN_CENTRAL) != 0
    }

    fn supports_peripheral(flags: u8) -> bool {
        flags & peer_caps::LEGACY_CENTRAL_ONLY == 0 && flags & peer_caps::CAN_PERIPHERAL != 0
    }

    fn sample_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn compressed_pubkey(prefix: u8, x_only: [u8; 32]) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = prefix;
        out[1..33].copy_from_slice(&x_only);
        out
    }

    #[test]
    fn l2cap_sdu_framing_small_payload() {
        let payload = sample_payload(10);
        let sdu = build_l2cap_sdu(&payload);
        assert_eq!(&sdu[..2], &[0x00, 0x0A]);
        let (len, parsed) = parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).unwrap();
        assert_eq!(len, 10);
        assert_eq!(parsed, payload.as_slice());
    }

    #[test]
    fn l2cap_sdu_framing_heartbeat() {
        let payload = sample_payload(37);
        let sdu = build_l2cap_sdu(&payload);
        assert_eq!(&sdu[..2], &[0x00, 0x25]);
        let (len, parsed) = parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).unwrap();
        assert_eq!(len, 37);
        assert_eq!(parsed, payload.as_slice());
    }

    #[test]
    fn l2cap_sdu_framing_msg1() {
        let payload = sample_payload(114);
        let sdu = build_l2cap_sdu(&payload);
        assert_eq!(&sdu[..2], &[0x00, 0x72]);
        let (len, parsed) = parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).unwrap();
        assert_eq!(len, 114);
        assert_eq!(parsed, payload.as_slice());
    }

    #[test]
    fn l2cap_sdu_framing_filter_announce_exceeds_cap() {
        let payload = sample_payload(1071);
        let sdu = build_l2cap_sdu(&payload);
        assert_eq!(&sdu[..2], &[0x04, 0x2F]);
        assert!(
            parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).is_err(),
            "FilterAnnounce (1071B) should exceed FRAME_CAP (768)"
        );
    }

    #[test]
    fn l2cap_sdu_framing_max_size() {
        let payload = sample_payload(L2CAP_FRAME_CAP);
        let sdu = build_l2cap_sdu(&payload);
        let (len, parsed) = parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).unwrap();
        assert_eq!(len, L2CAP_FRAME_CAP);
        assert_eq!(parsed, payload.as_slice());
    }

    #[test]
    fn l2cap_sdu_framing_oversized_rejected() {
        let payload = sample_payload(L2CAP_FRAME_CAP + 1);
        let sdu = build_l2cap_sdu(&payload);
        let expected_be = ((L2CAP_FRAME_CAP + 1) as u16).to_be_bytes();
        assert_eq!(&sdu[..2], &expected_be);
        assert!(parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).is_err());
    }

    #[test]
    fn l2cap_sdu_framing_empty_rejected() {
        assert!(parse_l2cap_sdu(&[], L2CAP_FRAME_CAP).is_err());
    }

    #[test]
    fn l2cap_sdu_framing_1byte_rejected() {
        assert!(parse_l2cap_sdu(&[0x00], L2CAP_FRAME_CAP).is_err());
    }

    #[test]
    fn l2cap_sdu_framing_truncated_rejected() {
        let mut sdu = Vec::with_capacity(52);
        sdu.extend_from_slice(&100u16.to_be_bytes());
        sdu.extend_from_slice(&sample_payload(50));
        assert!(parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).is_err());
    }

    #[test]
    fn l2cap_sdu_roundtrip_various_sizes() {
        for size in [0usize, 1, 10, 100, 500, 512, 768] {
            let payload = sample_payload(size);
            let sdu = build_l2cap_sdu(&payload);
            let (len, parsed) = parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).unwrap();
            assert_eq!(len, size);
            assert_eq!(parsed, payload.as_slice());
        }
    }

    #[test]
    fn l2cap_sdu_frames_exceeding_cap_rejected() {
        for size in [769, 1000, 1071, 2048] {
            let payload = sample_payload(size);
            let sdu = build_l2cap_sdu(&payload);
            assert!(
                parse_l2cap_sdu(&sdu, L2CAP_FRAME_CAP).is_err(),
                "size {} should exceed FRAME_CAP",
                size
            );
        }
    }

    #[test]
    fn pubkey_exchange_new_format_36b() {
        let msg = build_pubkey_exchange(
            &RESPONDER_TEST_NPUB[1..33].try_into().unwrap(),
            peer_caps::ESP32_DEFAULT,
        );
        assert_eq!(msg.len(), 36);
        assert_eq!(&msg[..3], &[0x00, 0x22, 0x00]);
        let (pubkey, flags) = parse_pubkey_exchange(&msg).unwrap();
        assert_eq!(pubkey, RESPONDER_TEST_NPUB);
        assert_eq!(flags, Some(peer_caps::ESP32_DEFAULT));
    }

    #[test]
    fn pubkey_exchange_old_format_35b() {
        let mut msg = [0u8; 35];
        msg[0..2].copy_from_slice(&33u16.to_be_bytes());
        msg[2] = 0x00;
        msg[3..35].copy_from_slice(&INITIATOR_TEST_NPUB[1..33]);
        let (pubkey, flags) = parse_pubkey_exchange(&msg).unwrap();
        assert_eq!(pubkey, INITIATOR_TEST_NPUB);
        assert_eq!(flags, None);
    }

    #[test]
    fn pubkey_exchange_bad_prefix_0x01_rejected() {
        let mut msg = build_pubkey_exchange(
            &INITIATOR_TEST_NPUB[1..33].try_into().unwrap(),
            peer_caps::ESP32_DEFAULT,
        );
        msg[2] = 0x01;
        assert!(parse_pubkey_exchange(&msg).is_err());
    }

    #[test]
    fn pubkey_exchange_too_short_rejected() {
        assert!(parse_pubkey_exchange(&[0u8; 34]).is_err());
    }

    #[test]
    fn pubkey_exchange_bad_payload_len_rejected() {
        let mut msg = build_pubkey_exchange(
            &RESPONDER_TEST_NPUB[1..33].try_into().unwrap(),
            peer_caps::ESP32_DEFAULT,
        );
        msg[0..2].copy_from_slice(&35u16.to_be_bytes());
        assert!(parse_pubkey_exchange(&msg).is_err());
    }

    #[test]
    fn pubkey_exchange_flags_value_esp32_default() {
        let msg = build_pubkey_exchange(
            &RESPONDER_TEST_NPUB[1..33].try_into().unwrap(),
            peer_caps::ESP32_DEFAULT,
        );
        assert_eq!(msg[35], 0x3C);
        let (_, flags) = parse_pubkey_exchange(&msg).unwrap();
        assert_eq!(flags, Some(0x3C));
    }

    #[test]
    fn pubkey_exchange_flags_value_fips_linux_default() {
        let msg = build_pubkey_exchange(
            &INITIATOR_TEST_NPUB[1..33].try_into().unwrap(),
            peer_caps::FIPS_LINUX_DEFAULT,
        );
        assert_eq!(msg[35], 0x7C);
        let (_, flags) = parse_pubkey_exchange(&msg).unwrap();
        assert_eq!(flags, Some(0x7C));
    }

    #[test]
    fn pubkey_exchange_deterministic_keys() {
        let initiator_pub =
            noise::ecdh_pubkey(&INITIATOR_TEST_NSEC).expect("valid initiator test key");
        let responder_pub =
            noise::ecdh_pubkey(&RESPONDER_TEST_NSEC).expect("valid responder test key");
        assert_eq!(initiator_pub, INITIATOR_TEST_NPUB);
        assert_eq!(responder_pub, RESPONDER_TEST_NPUB);
    }

    #[test]
    fn cap_flag_bit_positions_match_fips() {
        assert_eq!(ble_caps::LEAF_ONLY, 0x01);
        assert_eq!(ble_caps::HAS_TUN, 0x02);
        assert_eq!(ble_caps::HAS_INTERNET, 0x04);
        assert_eq!(peer_caps::LEGACY_CENTRAL_ONLY, 0x01);
        assert_eq!(peer_caps::PREFER_OUTBOUND, 0x02);
        assert_eq!(peer_caps::PREFER_L2CAP, 0x04);
        assert_eq!(peer_caps::CAN_CENTRAL, 0x08);
        assert_eq!(peer_caps::CAN_PERIPHERAL, 0x10);
        assert_eq!(peer_caps::L2CAP_SUPPORTED, 0x20);
        assert_eq!(peer_caps::GATT_SUPPORTED, 0x40);
    }

    #[test]
    fn esp32_default_is_0x3c() {
        assert_eq!(peer_caps::ESP32_DEFAULT, 0x3C);
    }

    #[test]
    fn fips_linux_default_is_0x7c() {
        assert_eq!(peer_caps::FIPS_LINUX_DEFAULT, 0x7C);
    }

    #[test]
    fn esp32_advertises_central_and_peripheral() {
        assert!(supports_central(peer_caps::ESP32_DEFAULT));
        assert!(supports_peripheral(peer_caps::ESP32_DEFAULT));
    }

    #[test]
    fn esp32_advertises_l2cap_preferred() {
        assert_ne!(peer_caps::ESP32_DEFAULT & peer_caps::PREFER_L2CAP, 0);
    }

    #[test]
    fn esp32_does_not_advertise_gatt() {
        assert_eq!(peer_caps::ESP32_DEFAULT & peer_caps::GATT_SUPPORTED, 0);
    }

    #[test]
    fn legacy_central_only_maps_to_central() {
        assert!(supports_central(peer_caps::LEGACY_CENTRAL_ONLY));
        assert!(!supports_peripheral(peer_caps::LEGACY_CENTRAL_ONLY));
    }

    #[test]
    fn capability_roundtrip_preserves_flags() {
        for flags in [0x00u8, 0x01, 0x3C, 0x7C, 0x7F, 0xFF] {
            let caps = PeerCapabilities::from_byte(flags);
            assert_eq!(caps.to_byte(), flags);
        }
    }

    #[test]
    fn peer_acl_allows_vps_pubkey() {
        assert!(peer_is_fips(&compressed_pubkey(
            0x02,
            FIPS_ALLOWED_PUBKEYS[0]
        )));
    }

    #[test]
    fn peer_acl_allows_linux_pubkey() {
        assert!(peer_is_fips(&compressed_pubkey(
            0x02,
            FIPS_ALLOWED_PUBKEYS[1]
        )));
    }

    #[test]
    fn peer_acl_allows_mac_pubkey() {
        assert!(peer_is_fips(&compressed_pubkey(
            0x02,
            FIPS_ALLOWED_PUBKEYS[2]
        )));
    }

    #[test]
    fn peer_acl_rejects_unknown_pubkey() {
        assert!(!peer_is_fips(&compressed_pubkey(0x02, [0x55; 32])));
    }

    #[test]
    fn peer_acl_rejects_zero_pubkey() {
        assert!(!peer_is_fips(&[0u8; 33]));
    }

    #[test]
    fn peer_acl_checks_x_only_bytes() {
        assert!(peer_is_fips(&compressed_pubkey(
            0x03,
            FIPS_ALLOWED_PUBKEYS[1]
        )));
    }

    #[test]
    fn l2cap_psm_is_0x0085() {
        assert_eq!(L2CAP_PSM, 0x0085);
        assert_eq!(L2CAP_PSM, 133);
    }

    #[test]
    fn l2cap_mtu_is_2048() {
        assert_eq!(L2CAP_MTU, 2048);
    }

    #[test]
    fn l2cap_frame_cap_covers_all_link_frames() {
        assert!(L2CAP_FRAME_CAP >= 512, "must be >= old value");
        assert!(L2CAP_FRAME_CAP >= 200, "must cover MSG1 (114B)");
        assert!(L2CAP_FRAME_CAP >= 150, "must cover SessionSetup (148B)");
    }

    #[test]
    fn l2cap_sdu_cap_is_frame_cap_plus_2() {
        assert_eq!(L2CAP_SDU_CAP, L2CAP_FRAME_CAP + 2);
    }

    #[test]
    fn fips_service_uuid_matches() {
        assert_eq!(u128::from_le_bytes(FIPS_SERVICE_UUID_LE), FIPS_SERVICE_UUID);
    }

    #[test]
    fn fips_caps_service_uuid_is_fi() {
        assert_eq!(u16::from_le_bytes(FIPS_CAPS_SERVICE_UUID), 0x4946);
        assert_eq!(FIPS_CAPS_SERVICE_UUID, *b"FI");
    }

    #[test]
    fn l2cap_recv_timeout_sufficient() {
        assert_eq!(L2CAP_RECV_TIMEOUT_SECS, 45);
        assert!(L2CAP_RECV_TIMEOUT_SECS > 30);
    }

    #[test]
    fn l2cap_send_timeout_reasonable() {
        assert_eq!(L2CAP_SEND_TIMEOUT_SECS, 15);
        assert!(L2CAP_SEND_TIMEOUT_SECS > CENTRAL_CONNECT_TIMEOUT_SECS);
    }

    #[test]
    fn role_initial_state_prefers_central() {
        assert!(!should_prefer_peripheral(0, 0));
    }

    #[test]
    fn role_after_clean_yield_prefers_peripheral() {
        let now_ms = 1_000;
        let until_ms = set_prefer_peripheral_window(now_ms, CENTRAL_COLLISION_COOLDOWN_MS);
        assert_eq!(until_ms, 7_000);
        assert!(should_prefer_peripheral(until_ms, now_ms));
    }

    #[test]
    fn role_peripheral_window_expires() {
        let now_ms = 1_000;
        let until_ms = set_prefer_peripheral_window(now_ms, CENTRAL_COLLISION_COOLDOWN_MS);
        assert!(!should_prefer_peripheral(until_ms, until_ms));
    }

    #[test]
    fn collision_cooldown_prevents_immediate_central() {
        let now_ms = 1_000;
        let until_ms = set_prefer_peripheral_window(now_ms, CENTRAL_COLLISION_COOLDOWN_MS);
        assert!(should_prefer_peripheral(
            until_ms,
            now_ms + CENTRAL_COLLISION_COOLDOWN_MS - 1
        ));
    }

    #[test]
    fn connection_interval_range_valid() {
        assert_eq!(CONNECTION_INTERVAL_MIN_MS, 20);
        assert_eq!(CONNECTION_INTERVAL_MAX_MS, 40);
        assert!(CONNECTION_INTERVAL_MIN_MS * 10 >= 75);
        assert!(CONNECTION_INTERVAL_MAX_MS * 10 <= 40_000);
        assert!(CONNECTION_INTERVAL_MIN_MS <= CONNECTION_INTERVAL_MAX_MS);
    }

    #[test]
    fn supervision_timeout_reasonable() {
        assert_eq!(SUPERVISION_TIMEOUT_MS, 4_000);
    }

    #[test]
    fn max_latency_is_zero() {
        assert_eq!(CONNECTION_MAX_LATENCY, 0);
    }

    #[test]
    fn stats_snapshot_initial_values() {
        let node = HostNodeStats::new();
        let l2cap = HostL2capStats::new();
        let snap = snapshot(&node, &l2cap);
        assert_eq!(
            snap,
            HostStatsSnapshot {
                msg1_tx: 0,
                msg2_rx: 0,
                hb_tx: 0,
                hb_rx: 0,
                data_tx: 0,
                data_rx: 0,
                state: 0,
                boot_tick_ms: 0,
                zero_frame_disconnects: 0,
                recv_timeouts: 0,
                send_timeouts: 0,
                send_errors: 0,
                rx_drops: 0,
                pubkey_ok: 0,
                central_connects: 0,
                peripheral_connects: 0,
                last_role: 0,
                last_reason: 0,
            }
        );
    }

    #[test]
    fn stats_disconnect_codes_valid() {
        let values = [
            L2capDisconnectCode::None as u32,
            L2capDisconnectCode::CleanYield as u32,
            L2capDisconnectCode::DataExchanged as u32,
            L2capDisconnectCode::SendError as u32,
            L2capDisconnectCode::RecvTimeout as u32,
            L2capDisconnectCode::SendTimeout as u32,
        ];
        for (i, value) in values.iter().enumerate() {
            assert_eq!(
                values
                    .iter()
                    .filter(|candidate| *candidate == value)
                    .count(),
                1
            );
            assert_eq!(*value, i as u32);
        }
    }
}
