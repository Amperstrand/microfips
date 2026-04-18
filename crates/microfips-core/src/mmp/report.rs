//! MMP report wire format: SenderReport and ReceiverReport.
//!
//! Ported from FIPS upstream: `src/mmp/report.rs`.
//! Wire layout is byte-identical to FIPS for interoperability.

// ============================================================================
// SenderReport (msg_type 0x01, 48 bytes total)
// ============================================================================

/// Link-layer sender report.
///
/// Wire layout (48 bytes total):
/// ```text
/// [0]    msg_type = 0x01
/// [1-3]  reserved (zero)
/// [4-11] interval_start_counter: u64 LE
/// [12-19] interval_end_counter: u64 LE
/// [20-23] interval_start_timestamp: u32 LE
/// [24-27] interval_end_timestamp: u32 LE
/// [28-31] interval_bytes_sent: u32 LE
/// [32-39] cumulative_packets_sent: u64 LE
/// [40-47] cumulative_bytes_sent: u64 LE
/// ```
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

pub const SENDER_REPORT_SIZE: usize = 48;
/// Body size after msg_type byte has been consumed.
pub const SENDER_REPORT_BODY_SIZE: usize = 47;

impl SenderReport {
    /// Encode to wire format (48 bytes: msg_type + 3 reserved + 44 payload).
    pub fn encode(&self) -> [u8; SENDER_REPORT_SIZE] {
        let mut buf = [0u8; SENDER_REPORT_SIZE];
        buf[0] = 0x01; // msg_type
                       // [1-3] reserved (zero)
        buf[4..12].copy_from_slice(&self.interval_start_counter.to_le_bytes());
        buf[12..20].copy_from_slice(&self.interval_end_counter.to_le_bytes());
        buf[20..24].copy_from_slice(&self.interval_start_timestamp.to_le_bytes());
        buf[24..28].copy_from_slice(&self.interval_end_timestamp.to_le_bytes());
        buf[28..32].copy_from_slice(&self.interval_bytes_sent.to_le_bytes());
        buf[32..40].copy_from_slice(&self.cumulative_packets_sent.to_le_bytes());
        buf[40..48].copy_from_slice(&self.cumulative_bytes_sent.to_le_bytes());
        buf
    }

    /// Decode from payload after msg_type byte has been consumed.
    ///
    /// `payload` must be at least 47 bytes (3 reserved + 44 fields).
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < SENDER_REPORT_BODY_SIZE {
            return None;
        }
        let p = &payload[3..]; // skip 3 reserved bytes
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

// ============================================================================
// ReceiverReport (msg_type 0x02, 68 bytes total)
// ============================================================================

/// Link-layer receiver report.
///
/// Wire layout (68 bytes total):
/// ```text
/// [0]    msg_type = 0x02
/// [1-3]  reserved (zero)
/// [4-11] highest_counter: u64 LE
/// [12-19] cumulative_packets_recv: u64 LE
/// [20-27] cumulative_bytes_recv: u64 LE
/// [28-31] timestamp_echo: u32 LE
/// [32-33] dwell_time: u16 LE
/// [34-35] max_burst_loss: u16 LE
/// [36-37] mean_burst_loss: u16 LE (u8.8 fixed-point)
/// [38-39] reserved: u16 LE
/// [40-43] jitter: u32 LE (microseconds)
/// [44-47] ecn_ce_count: u32 LE
/// [48-51] owd_trend: i32 LE (µs/s)
/// [52-55] burst_loss_count: u32 LE
/// [56-59] cumulative_reorder_count: u32 LE
/// [60-63] interval_packets_recv: u32 LE
/// [64-67] interval_bytes_recv: u32 LE
/// ```
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

pub const RECEIVER_REPORT_SIZE: usize = 68;
/// Body size after msg_type byte has been consumed.
pub const RECEIVER_REPORT_BODY_SIZE: usize = 67;

impl ReceiverReport {
    /// Encode to wire format (68 bytes: msg_type + 3 reserved + 64 payload).
    pub fn encode(&self) -> [u8; RECEIVER_REPORT_SIZE] {
        let mut buf = [0u8; RECEIVER_REPORT_SIZE];
        buf[0] = 0x02; // msg_type
                       // [1-3] reserved (zero)
        buf[4..12].copy_from_slice(&self.highest_counter.to_le_bytes());
        buf[12..20].copy_from_slice(&self.cumulative_packets_recv.to_le_bytes());
        buf[20..28].copy_from_slice(&self.cumulative_bytes_recv.to_le_bytes());
        buf[28..32].copy_from_slice(&self.timestamp_echo.to_le_bytes());
        buf[32..34].copy_from_slice(&self.dwell_time.to_le_bytes());
        buf[34..36].copy_from_slice(&self.max_burst_loss.to_le_bytes());
        buf[36..38].copy_from_slice(&self.mean_burst_loss.to_le_bytes());
        // [38-39] reserved (zero)
        buf[40..44].copy_from_slice(&self.jitter.to_le_bytes());
        buf[44..48].copy_from_slice(&self.ecn_ce_count.to_le_bytes());
        buf[48..52].copy_from_slice(&self.owd_trend.to_le_bytes());
        buf[52..56].copy_from_slice(&self.burst_loss_count.to_le_bytes());
        buf[56..60].copy_from_slice(&self.cumulative_reorder_count.to_le_bytes());
        buf[60..64].copy_from_slice(&self.interval_packets_recv.to_le_bytes());
        buf[64..68].copy_from_slice(&self.interval_bytes_recv.to_le_bytes());
        buf
    }

    /// Decode from payload after msg_type byte has been consumed.
    ///
    /// `payload` must be at least 67 bytes (3 reserved + 64 fields).
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < RECEIVER_REPORT_BODY_SIZE {
            return None;
        }
        let p = &payload[3..]; // skip 3 reserved bytes
        Some(Self {
            highest_counter: u64::from_le_bytes(p[0..8].try_into().ok()?),
            cumulative_packets_recv: u64::from_le_bytes(p[8..16].try_into().ok()?),
            cumulative_bytes_recv: u64::from_le_bytes(p[16..24].try_into().ok()?),
            timestamp_echo: u32::from_le_bytes(p[24..28].try_into().ok()?),
            dwell_time: u16::from_le_bytes(p[28..30].try_into().ok()?),
            max_burst_loss: u16::from_le_bytes(p[30..32].try_into().ok()?),
            mean_burst_loss: u16::from_le_bytes(p[32..34].try_into().ok()?),
            // skip 2 reserved bytes at p[34..36]
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_report_encode_size() {
        let sr = SenderReport {
            interval_start_counter: 100,
            interval_end_counter: 200,
            interval_start_timestamp: 5000,
            interval_end_timestamp: 6000,
            interval_bytes_sent: 50_000,
            cumulative_packets_sent: 10_000,
            cumulative_bytes_sent: 5_000_000,
        };
        let encoded = sr.encode();
        assert_eq!(encoded.len(), 48);
        assert_eq!(encoded[0], 0x01);
    }

    #[test]
    fn test_sender_report_roundtrip() {
        let sr = SenderReport {
            interval_start_counter: 100,
            interval_end_counter: 200,
            interval_start_timestamp: 5000,
            interval_end_timestamp: 6000,
            interval_bytes_sent: 50_000,
            cumulative_packets_sent: 10_000,
            cumulative_bytes_sent: 5_000_000,
        };
        let encoded = sr.encode();
        // decode expects payload after msg_type
        let decoded = SenderReport::decode(&encoded[1..]).unwrap();
        assert_eq!(sr, decoded);
    }

    #[test]
    fn test_sender_report_too_short() {
        assert!(SenderReport::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_sender_report_zero_values() {
        let sr = SenderReport {
            interval_start_counter: 0,
            interval_end_counter: 0,
            interval_start_timestamp: 0,
            interval_end_timestamp: 0,
            interval_bytes_sent: 0,
            cumulative_packets_sent: 0,
            cumulative_bytes_sent: 0,
        };
        let encoded = sr.encode();
        let decoded = SenderReport::decode(&encoded[1..]).unwrap();
        assert_eq!(sr, decoded);
    }

    #[test]
    fn test_receiver_report_encode_size() {
        let rr = ReceiverReport {
            highest_counter: 195,
            cumulative_packets_recv: 9_500,
            cumulative_bytes_recv: 4_750_000,
            timestamp_echo: 5900,
            dwell_time: 5,
            max_burst_loss: 3,
            mean_burst_loss: 384,
            jitter: 1200,
            ecn_ce_count: 0,
            owd_trend: -50,
            burst_loss_count: 2,
            cumulative_reorder_count: 10,
            interval_packets_recv: 95,
            interval_bytes_recv: 47_500,
        };
        let encoded = rr.encode();
        assert_eq!(encoded.len(), 68);
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn test_receiver_report_roundtrip() {
        let rr = ReceiverReport {
            highest_counter: 195,
            cumulative_packets_recv: 9_500,
            cumulative_bytes_recv: 4_750_000,
            timestamp_echo: 5900,
            dwell_time: 5,
            max_burst_loss: 3,
            mean_burst_loss: 384,
            jitter: 1200,
            ecn_ce_count: 0,
            owd_trend: -50,
            burst_loss_count: 2,
            cumulative_reorder_count: 10,
            interval_packets_recv: 95,
            interval_bytes_recv: 47_500,
        };
        let encoded = rr.encode();
        let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
        assert_eq!(rr, decoded);
    }

    #[test]
    fn test_receiver_report_too_short() {
        assert!(ReceiverReport::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_receiver_report_max_values() {
        let rr = ReceiverReport {
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
        let encoded = rr.encode();
        let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
        assert_eq!(rr, decoded);
    }

    #[test]
    fn test_receiver_report_negative_owd_trend() {
        let rr = ReceiverReport {
            owd_trend: -12345,
            ..ReceiverReport {
                highest_counter: 0,
                cumulative_packets_recv: 0,
                cumulative_bytes_recv: 0,
                timestamp_echo: 0,
                dwell_time: 0,
                max_burst_loss: 0,
                mean_burst_loss: 0,
                jitter: 0,
                ecn_ce_count: 0,
                owd_trend: 0,
                burst_loss_count: 0,
                cumulative_reorder_count: 0,
                interval_packets_recv: 0,
                interval_bytes_recv: 0,
            }
        };
        let encoded = rr.encode();
        let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.owd_trend, -12345);
    }

    #[test]
    fn test_sender_report_fips_wire_compat() {
        // Verify byte layout matches FIPS src/mmp/report.rs encode()
        let sr = SenderReport {
            interval_start_counter: 1,
            interval_end_counter: 2,
            interval_start_timestamp: 3,
            interval_end_timestamp: 4,
            interval_bytes_sent: 5,
            cumulative_packets_sent: 6,
            cumulative_bytes_sent: 7,
        };
        let enc = sr.encode();
        assert_eq!(enc[0], 0x01); // msg_type
        assert_eq!(&enc[1..4], &[0, 0, 0]); // reserved
        assert_eq!(u64::from_le_bytes(enc[4..12].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(enc[12..20].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(enc[20..24].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(enc[24..28].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(enc[28..32].try_into().unwrap()), 5);
        assert_eq!(u64::from_le_bytes(enc[32..40].try_into().unwrap()), 6);
        assert_eq!(u64::from_le_bytes(enc[40..48].try_into().unwrap()), 7);
    }
}
