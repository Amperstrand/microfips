//! MMP report wire format: SenderReport and ReceiverReport.
//!
//! Serialization and deserialization for the two report types exchanged
//! between link-layer peers. Wire format follows the FIPS upstream layout.

pub const SENDER_REPORT_SIZE: usize = 48;
pub const RECEIVER_REPORT_SIZE: usize = 68;
pub const SENDER_REPORT_BODY_SIZE: usize = 47;
pub const RECEIVER_REPORT_BODY_SIZE: usize = 67;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    pub interval_start_counter: u64,
    pub interval_end_counter: u64,
    pub interval_start_timestamp: u32,
    pub interval_end_timestamp: u32,
    pub interval_bytes_sent: u32,
    pub cumulative_packets_sent: u64,
    pub cumulative_bytes_sent: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    pub highest_counter: u64,
    pub cumulative_packets_recv: u64,
    pub cumulative_bytes_recv: u64,
    pub timestamp_echo: u32,
    pub dwell_time: u16,
    pub max_burst_loss: u16,
    pub mean_burst_loss: u16,
    pub jitter: u32,
    pub ecn_ce_count: u32,
    pub owd_trend: i32,
    pub burst_loss_count: u32,
    pub cumulative_reorder_count: u32,
    pub interval_packets_recv: u32,
    pub interval_bytes_recv: u32,
}

impl SenderReport {
    pub fn encode(&self) -> [u8; SENDER_REPORT_SIZE] {
        let mut buf = [0u8; SENDER_REPORT_SIZE];
        buf[0] = 0x01;
        buf[4..12].copy_from_slice(&self.interval_start_counter.to_le_bytes());
        buf[12..20].copy_from_slice(&self.interval_end_counter.to_le_bytes());
        buf[20..24].copy_from_slice(&self.interval_start_timestamp.to_le_bytes());
        buf[24..28].copy_from_slice(&self.interval_end_timestamp.to_le_bytes());
        buf[28..32].copy_from_slice(&self.interval_bytes_sent.to_le_bytes());
        buf[32..40].copy_from_slice(&self.cumulative_packets_sent.to_le_bytes());
        buf[40..48].copy_from_slice(&self.cumulative_bytes_sent.to_le_bytes());
        buf
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < SENDER_REPORT_BODY_SIZE {
            return None;
        }
        let p = &payload[3..];
        Some(Self {
            interval_start_counter: u64::from_le_bytes(p[0..8].try_into().ok()?),
            interval_end_counter: u64::from_le_bytes(p[8..16].try_into().ok()?),
            interval_start_timestamp: u32::from_le_bytes(p[16..20].try_into().ok()?),
            interval_end_timestamp: u32::from_le_bytes(p[20..24].try_into().ok()?),
            interval_bytes_sent: u32::from_le_bytes(p[24..28].try_into().ok()?),
            cumulative_packets_sent: u64::from_le_bytes(p[28..36].try_into().ok()?),
            cumulative_bytes_sent: u64::from_le_bytes(p[36..44].try_into().ok()?),
        })
    }
}

impl ReceiverReport {
    pub fn encode(&self) -> [u8; RECEIVER_REPORT_SIZE] {
        let mut buf = [0u8; RECEIVER_REPORT_SIZE];
        buf[0] = 0x02;
        buf[4..12].copy_from_slice(&self.highest_counter.to_le_bytes());
        buf[12..20].copy_from_slice(&self.cumulative_packets_recv.to_le_bytes());
        buf[20..28].copy_from_slice(&self.cumulative_bytes_recv.to_le_bytes());
        buf[28..32].copy_from_slice(&self.timestamp_echo.to_le_bytes());
        buf[32..34].copy_from_slice(&self.dwell_time.to_le_bytes());
        buf[34..36].copy_from_slice(&self.max_burst_loss.to_le_bytes());
        buf[36..38].copy_from_slice(&self.mean_burst_loss.to_le_bytes());
        buf[40..44].copy_from_slice(&self.jitter.to_le_bytes());
        buf[44..48].copy_from_slice(&self.ecn_ce_count.to_le_bytes());
        buf[48..52].copy_from_slice(&self.owd_trend.to_le_bytes());
        buf[52..56].copy_from_slice(&self.burst_loss_count.to_le_bytes());
        buf[56..60].copy_from_slice(&self.cumulative_reorder_count.to_le_bytes());
        buf[60..64].copy_from_slice(&self.interval_packets_recv.to_le_bytes());
        buf[64..68].copy_from_slice(&self.interval_bytes_recv.to_le_bytes());
        buf
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < RECEIVER_REPORT_BODY_SIZE {
            return None;
        }
        let p = &payload[3..];
        Some(Self {
            highest_counter: u64::from_le_bytes(p[0..8].try_into().ok()?),
            cumulative_packets_recv: u64::from_le_bytes(p[8..16].try_into().ok()?),
            cumulative_bytes_recv: u64::from_le_bytes(p[16..24].try_into().ok()?),
            timestamp_echo: u32::from_le_bytes(p[24..28].try_into().ok()?),
            dwell_time: u16::from_le_bytes(p[28..30].try_into().ok()?),
            max_burst_loss: u16::from_le_bytes(p[30..32].try_into().ok()?),
            mean_burst_loss: u16::from_le_bytes(p[32..34].try_into().ok()?),
            jitter: u32::from_le_bytes(p[36..40].try_into().ok()?),
            ecn_ce_count: u32::from_le_bytes(p[40..44].try_into().ok()?),
            owd_trend: i32::from_le_bytes(p[44..48].try_into().ok()?),
            burst_loss_count: u32::from_le_bytes(p[48..52].try_into().ok()?),
            cumulative_reorder_count: u32::from_le_bytes(p[52..56].try_into().ok()?),
            interval_packets_recv: u32::from_le_bytes(p[56..60].try_into().ok()?),
            interval_bytes_recv: u32::from_le_bytes(p[60..64].try_into().ok()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sender_report() -> SenderReport {
        SenderReport {
            interval_start_counter: 100,
            interval_end_counter: 200,
            interval_start_timestamp: 5_000,
            interval_end_timestamp: 6_000,
            interval_bytes_sent: 50_000,
            cumulative_packets_sent: 10_000,
            cumulative_bytes_sent: 5_000_000,
        }
    }

    fn sample_receiver_report() -> ReceiverReport {
        ReceiverReport {
            highest_counter: 195,
            cumulative_packets_recv: 9_500,
            cumulative_bytes_recv: 4_750_000,
            timestamp_echo: 5_900,
            dwell_time: 5,
            max_burst_loss: 3,
            mean_burst_loss: 384,
            jitter: 1_200,
            ecn_ce_count: 0,
            owd_trend: -50,
            burst_loss_count: 2,
            cumulative_reorder_count: 10,
            interval_packets_recv: 95,
            interval_bytes_recv: 47_500,
        }
    }

    #[test]
    fn sender_report_encode_size() {
        let encoded = sample_sender_report().encode();
        assert_eq!(encoded.len(), SENDER_REPORT_SIZE);
        assert_eq!(encoded[0], 0x01);
    }

    #[test]
    fn sender_report_roundtrip() {
        let report = sample_sender_report();
        let encoded = report.encode();
        let decoded = SenderReport::decode(&encoded[1..]).unwrap();
        assert_eq!(report, decoded);
    }

    #[test]
    fn sender_report_too_short() {
        assert!(SenderReport::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn sender_report_zero_values_roundtrip() {
        let report = SenderReport {
            interval_start_counter: 0,
            interval_end_counter: 0,
            interval_start_timestamp: 0,
            interval_end_timestamp: 0,
            interval_bytes_sent: 0,
            cumulative_packets_sent: 0,
            cumulative_bytes_sent: 0,
        };
        let encoded = report.encode();
        let decoded = SenderReport::decode(&encoded[1..]).unwrap();
        assert_eq!(report, decoded);
    }

    #[test]
    fn sender_report_wire_layout_matches_fips() {
        let encoded = SenderReport {
            interval_start_counter: 1,
            interval_end_counter: 2,
            interval_start_timestamp: 3,
            interval_end_timestamp: 4,
            interval_bytes_sent: 5,
            cumulative_packets_sent: 6,
            cumulative_bytes_sent: 7,
        }
        .encode();

        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..4], &[0, 0, 0]);
        assert_eq!(u64::from_le_bytes(encoded[4..12].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(encoded[12..20].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(encoded[20..24].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(encoded[24..28].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(encoded[28..32].try_into().unwrap()), 5);
        assert_eq!(u64::from_le_bytes(encoded[32..40].try_into().unwrap()), 6);
        assert_eq!(u64::from_le_bytes(encoded[40..48].try_into().unwrap()), 7);
    }

    #[test]
    fn receiver_report_encode_size() {
        let encoded = sample_receiver_report().encode();
        assert_eq!(encoded.len(), RECEIVER_REPORT_SIZE);
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn receiver_report_roundtrip() {
        let report = sample_receiver_report();
        let encoded = report.encode();
        let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
        assert_eq!(report, decoded);
    }

    #[test]
    fn receiver_report_too_short() {
        assert!(ReceiverReport::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn receiver_report_max_values_roundtrip() {
        let report = ReceiverReport {
            highest_counter: u64::MAX,
            cumulative_packets_recv: u64::MAX,
            cumulative_bytes_recv: u64::MAX,
            timestamp_echo: u32::MAX,
            dwell_time: u16::MAX,
            max_burst_loss: u16::MAX,
            mean_burst_loss: u16::MAX,
            jitter: u32::MAX,
            ecn_ce_count: u32::MAX,
            owd_trend: i32::MAX,
            burst_loss_count: u32::MAX,
            cumulative_reorder_count: u32::MAX,
            interval_packets_recv: u32::MAX,
            interval_bytes_recv: u32::MAX,
        };
        let encoded = report.encode();
        let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
        assert_eq!(report, decoded);
    }

    #[test]
    fn receiver_report_negative_owd_trend_roundtrip() {
        let report = ReceiverReport {
            owd_trend: -12_345,
            ..sample_receiver_report()
        };
        let encoded = report.encode();
        let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.owd_trend, -12_345);
    }

    #[test]
    fn receiver_report_wire_layout_matches_fips() {
        let encoded = ReceiverReport {
            highest_counter: 1,
            cumulative_packets_recv: 2,
            cumulative_bytes_recv: 3,
            timestamp_echo: 4,
            dwell_time: 5,
            max_burst_loss: 6,
            mean_burst_loss: 7,
            jitter: 8,
            ecn_ce_count: 9,
            owd_trend: -10,
            burst_loss_count: 11,
            cumulative_reorder_count: 12,
            interval_packets_recv: 13,
            interval_bytes_recv: 14,
        }
        .encode();

        assert_eq!(encoded[0], 0x02);
        assert_eq!(&encoded[1..4], &[0, 0, 0]);
        assert_eq!(u64::from_le_bytes(encoded[4..12].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(encoded[12..20].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(encoded[20..28].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(encoded[28..32].try_into().unwrap()), 4);
        assert_eq!(u16::from_le_bytes(encoded[32..34].try_into().unwrap()), 5);
        assert_eq!(u16::from_le_bytes(encoded[34..36].try_into().unwrap()), 6);
        assert_eq!(u16::from_le_bytes(encoded[36..38].try_into().unwrap()), 7);
        assert_eq!(&encoded[38..40], &[0, 0]);
        assert_eq!(u32::from_le_bytes(encoded[40..44].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(encoded[44..48].try_into().unwrap()), 9);
        assert_eq!(i32::from_le_bytes(encoded[48..52].try_into().unwrap()), -10);
        assert_eq!(u32::from_le_bytes(encoded[52..56].try_into().unwrap()), 11);
        assert_eq!(u32::from_le_bytes(encoded[56..60].try_into().unwrap()), 12);
        assert_eq!(u32::from_le_bytes(encoded[60..64].try_into().unwrap()), 13);
        assert_eq!(u32::from_le_bytes(encoded[64..68].try_into().unwrap()), 14);
    }
}
