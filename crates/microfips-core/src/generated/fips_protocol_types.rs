// GENERATED from jmcorgan/fips v0.4.0 (d5ee526). Do not hand-edit.
// Regenerate via hackathon-tooling/protocol-gen/generate.py

//! FIPS protocol wire-format types and constants.
//!
//! Generated from jmcorgan/fips v0.4.0 (d5ee526).
//!
//! This module collects the wire-format constants, enums, and struct
//! layouts from the FIPS source tree so that external tooling
//! (dissectors, fuzzers, test harnesses, documentation generators)
//! can reference a single authoritative definition without depending
//! on the full `fips` crate.
//!
//! Source files (all paths relative to the fips repository root):
//!   - `src/protocol/mod.rs` — top-level protocol version
//!   - `src/noise/mod.rs` — Noise protocol constants (IK + XK)
//!   - `src/node/wire.rs` — FMP (FIPS Messaging Protocol) framing
//!   - `src/protocol/link.rs` — Link-layer message types
//!   - `src/mmp/mod.rs` — MMP timing/config constants
//!   - `src/mmp/report.rs` — MMP SenderReport / ReceiverReport layouts

// ============================================================================
// Type aliases for fips newtypes (simplified for standalone use)
// ============================================================================

/// Session index — wraps `u32` in fips (`SessionIndex`).
pub type SessionIndex = u32;

/// Node address — 16 bytes in fips (`NodeAddr`).
pub type NodeAddr = [u8; 16];

// ============================================================================
// Source: src/protocol/mod.rs
// ============================================================================

/// Protocol version for message compatibility.
pub const PROTOCOL_VERSION: u8 = 1;

// ============================================================================
// Source: src/noise/mod.rs — Noise protocol constants
// ============================================================================
//
// Constants are placed before wire.rs because FMP framing sizes depend
// on Noise handshake message sizes.

/// Protocol name for Noise IK with secp256k1 (link layer).
pub const PROTOCOL_NAME_IK: &[u8] = b"Noise_IK_secp256k1_ChaChaPoly_SHA256";

/// Protocol name for Noise XK with secp256k1 (session layer).
pub const PROTOCOL_NAME_XK: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";

/// Maximum message size for noise transport messages.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of the AEAD tag.
pub const TAG_SIZE: usize = 16;

/// Size of a public key (compressed secp256k1).
pub const PUBKEY_SIZE: usize = 33;

/// Size of the startup epoch (random bytes for restart detection).
pub const EPOCH_SIZE: usize = 8;

/// Size of encrypted epoch (epoch + AEAD tag).
pub const EPOCH_ENCRYPTED_SIZE: usize = EPOCH_SIZE + TAG_SIZE; // 24

/// Size of IK handshake message 1: ephemeral (33) + encrypted static (33 + 16 tag) + encrypted epoch (8 + 16 tag).
pub const HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE + PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE; // 106

/// Size of IK handshake message 2: ephemeral (33) + encrypted epoch (8 + 16 tag).
pub const HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE + EPOCH_ENCRYPTED_SIZE; // 57

/// XK msg1: ephemeral only (33 bytes).
pub const XK_HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE; // 33

/// XK msg2: ephemeral (33) + encrypted epoch (8 + 16 tag) = 57 bytes.
pub const XK_HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE + EPOCH_ENCRYPTED_SIZE; // 57

/// XK msg3: encrypted static (33 + 16 tag) + encrypted epoch (8 + 16 tag) = 73 bytes.
pub const XK_HANDSHAKE_MSG3_SIZE: usize = PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE; // 73

/// Replay window size in packets (matching WireGuard).
pub const REPLAY_WINDOW_SIZE: usize = 2048;

/// Role in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// We initiated the connection.
    Initiator,
    /// They initiated the connection.
    Responder,
}

/// Which Noise pattern is being used for this handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoisePattern {
    /// Noise IK: two-message handshake (link layer).
    Ik,
    /// Noise XK: three-message handshake (session layer).
    Xk,
}

/// Handshake state machine states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeProgress {
    /// Initial state, ready to send/receive message 1.
    Initial,
    /// Message 1 sent/received, ready for message 2.
    Message1Done,
    /// Message 2 sent/received, ready for message 3 (XK only).
    Message2Done,
    /// Handshake complete, ready for transport.
    Complete,
}

// ============================================================================
// Source: src/node/wire.rs — FMP (FIPS Messaging Protocol) framing
// ============================================================================

/// FMP protocol version (4 high bits of byte 0).
pub const FMP_VERSION: u8 = 0;

/// Phase value for established (encrypted) frames.
pub const PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for Noise IK message 1 (handshake initiation).
pub const PHASE_MSG1: u8 = 0x1;

/// Phase value for Noise IK message 2 (handshake response).
pub const PHASE_MSG2: u8 = 0x2;

/// Size of the common packet prefix (all packet types).
pub const COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full established frame header (prefix + receiver_idx + counter).
pub const ESTABLISHED_HEADER_SIZE: usize = 16;

/// Size of Noise IK message 1 wire packet: prefix + sender_idx + noise_msg1.
pub const MSG1_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + HANDSHAKE_MSG1_SIZE; // 114 bytes

/// Size of Noise IK message 2 wire packet: prefix + sender_idx + receiver_idx + noise_msg2.
pub const MSG2_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + 4 + HANDSHAKE_MSG2_SIZE; // 69 bytes

/// Minimum size for encrypted frame: header + tag (no plaintext).
pub const ENCRYPTED_MIN_SIZE: usize = ESTABLISHED_HEADER_SIZE + TAG_SIZE; // 32 bytes

/// Size of the encrypted inner header (timestamp + message type).
pub const INNER_HEADER_SIZE: usize = 5;

/// Key epoch flag — selects active key during rekeying.
pub const FLAG_KEY_EPOCH: u8 = 0x01;

/// Congestion Experienced echo flag.
pub const FLAG_CE: u8 = 0x02;

/// Spin bit for RTT measurement.
pub const FLAG_SP: u8 = 0x04;

/// Parsed common packet prefix (first 4 bytes of every FMP packet).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct CommonPrefix {
    /// Protocol version (high nibble of byte 0).
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-packet signal flags (meaningful only for phase 0x0).
    pub flags: u8,
    /// Length of payload following the phase-specific header (excludes AEAD tag).
    pub payload_len: u16,
}

/// Parsed established frame header (phase 0x0).
///
/// Wire format (16 bytes):
/// ```text
/// [ver+phase:1][flags:1][payload_len:2 LE][receiver_idx:4 LE][counter:8 LE]
/// ```
///
/// The full 16-byte header is used as AAD for the AEAD construction.
#[derive(Clone, Debug)]
pub struct EncryptedHeader {
    /// Per-packet flags (K, CE, SP).
    pub flags: u8,
    /// Length of encrypted payload (excluding AEAD tag).
    pub payload_len: u16,
    /// Session index chosen by the receiver (for O(1) lookup).
    pub receiver_idx: SessionIndex,
    /// Monotonic counter used as AEAD nonce.
    pub counter: u64,
    /// Raw 16-byte header for use as AEAD AAD.
    pub header_bytes: [u8; ESTABLISHED_HEADER_SIZE],
}

/// Parsed Noise IK message 1 header (phase 0x1).
///
/// Wire format (114 bytes):
/// ```text
/// [0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:106]
/// ```
#[derive(Clone, Debug)]
pub struct Msg1Header {
    /// Session index chosen by the sender (becomes receiver_idx for responses).
    pub sender_idx: SessionIndex,
    /// Offset where Noise msg1 payload begins.
    pub noise_msg1_offset: usize,
}

/// Parsed Noise IK message 2 header (phase 0x2).
///
/// Wire format (69 bytes):
/// ```text
/// [0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:57]
/// ```
#[derive(Clone, Debug)]
pub struct Msg2Header {
    /// Session index chosen by the responder.
    pub sender_idx: SessionIndex,
    /// Echo of the initiator's sender_idx from msg1.
    pub receiver_idx: SessionIndex,
    /// Offset where Noise msg2 payload begins.
    pub noise_msg2_offset: usize,
}

// ============================================================================
// Source: src/protocol/link.rs — Link-layer message types
// ============================================================================

/// Handshake message type identifiers.
///
/// These messages are exchanged during Noise IK handshake before link
/// encryption is established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeMessageType {
    /// Noise IK message 1: initiator sends ephemeral + encrypted static.
    NoiseIKMsg1 = 0x01,
    /// Noise IK message 2: responder sends ephemeral.
    NoiseIKMsg2 = 0x02,
}

/// Link-layer message type identifiers.
///
/// These messages are exchanged between directly connected peers over
/// Noise-encrypted links. All payloads are encrypted with session keys
/// established during the Noise IK handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkMessageType {
    /// Encapsulated session-layer datagram for forwarding.
    SessionDatagram = 0x00,

    /// Sender-side MMP report.
    SenderReport = 0x01,
    /// Receiver-side MMP report.
    ReceiverReport = 0x02,

    /// Spanning tree state announcement.
    TreeAnnounce = 0x10,

    /// Bloom filter reachability update.
    FilterAnnounce = 0x20,

    /// Request to discover a node's coordinates.
    LookupRequest = 0x30,
    /// Response with target's coordinates.
    LookupResponse = 0x31,

    /// Orderly disconnect notification before link closure.
    Disconnect = 0x50,
    /// Periodic heartbeat for link liveness detection.
    Heartbeat = 0x51,
}

/// Reason for an orderly disconnect notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    /// Normal shutdown (operator requested).
    Shutdown = 0x00,
    /// Restarting (may reconnect soon).
    Restart = 0x01,
    /// Protocol error encountered.
    ProtocolError = 0x02,
    /// Transport failure.
    TransportFailure = 0x03,
    /// Resource exhaustion (memory, connections).
    ResourceExhaustion = 0x04,
    /// Authentication or security policy violation.
    SecurityViolation = 0x05,
    /// Configuration change (peer removed from config).
    ConfigurationChange = 0x06,
    /// Timeout or keepalive failure.
    Timeout = 0x07,
    /// Unspecified reason.
    Other = 0xFF,
}

/// Orderly disconnect notification sent before closing a peer link.
///
/// Wire format:
/// | Offset | Field    | Size   | Notes                  |
/// |--------|----------|--------|------------------------|
/// | 0      | msg_type | 1 byte | 0x50                   |
/// | 1      | reason   | 1 byte | DisconnectReason value |
#[derive(Clone, Debug)]
pub struct Disconnect {
    /// Reason for disconnection.
    pub reason: DisconnectReason,
}

/// SessionDatagram fixed header size: msg_type(1) + ttl(1) + path_mtu(2) + src_addr(16) + dest_addr(16).
pub const SESSION_DATAGRAM_HEADER_SIZE: usize = 36;

/// Encapsulated session-layer datagram for multi-hop forwarding.
///
/// Wire format (36-byte fixed header):
/// | Offset | Field     | Size     | Description                         |
/// |--------|-----------|----------|-------------------------------------|
/// | 0      | msg_type  | 1 byte   | 0x00                                |
/// | 1      | ttl       | 1 byte   | Decremented each hop                |
/// | 2      | path_mtu  | 2 bytes  | Path MTU (LE), min'd at each hop    |
/// | 4      | src_addr  | 16 bytes | Source node_addr                    |
/// | 20     | dest_addr | 16 bytes | Destination node_addr               |
/// | 36     | payload   | variable | Session-layer message               |
#[derive(Clone, Debug)]
pub struct SessionDatagram<'a> {
    /// Source node address (originator of this datagram).
    pub src_addr: NodeAddr,
    /// Destination node address (for routing decisions).
    pub dest_addr: NodeAddr,
    /// Time-to-live (decremented at each hop, dropped at zero).
    pub ttl: u8,
    /// Path MTU: minimum link MTU along the path so far.
    pub path_mtu: u16,
    /// Session-layer payload (e2e encrypted or plaintext error signal).
    pub payload: &'a [u8],
}

/// Borrowed view of a session datagram payload.
#[derive(Clone, Copy, Debug)]
pub struct SessionDatagramRef<'a> {
    pub src_addr: NodeAddr,
    pub dest_addr: NodeAddr,
    pub ttl: u8,
    pub path_mtu: u16,
    pub payload: &'a [u8],
}

// ============================================================================
// Source: src/mmp/mod.rs — MMP timing and configuration constants
// ============================================================================

/// SenderReport body size (after msg_type byte): 3 reserved + 44 payload = 47.
pub const SENDER_REPORT_BODY_SIZE: usize = 47;

/// ReceiverReport body size (after msg_type byte): 3 reserved + 64 payload = 67.
pub const RECEIVER_REPORT_BODY_SIZE: usize = 67;

/// SenderReport total wire size including inner header: 5 + 47 = 52.
pub const SENDER_REPORT_WIRE_SIZE: usize = 52;

/// ReceiverReport total wire size including inner header: 5 + 67 = 72.
pub const RECEIVER_REPORT_WIRE_SIZE: usize = 72;

/// Jitter EWMA: alpha = 1/16 (RFC 3550 S6.4.1).
pub const JITTER_ALPHA_SHIFT: u32 = 4;

/// SRTT: alpha = 1/8 (Jacobson, RFC 6298).
pub const SRTT_ALPHA_SHIFT: u32 = 3;

/// RTTVAR: beta = 1/4 (Jacobson, RFC 6298).
pub const RTTVAR_BETA_SHIFT: u32 = 2;

/// Dual EWMA short-term: alpha = 1/4.
pub const EWMA_SHORT_ALPHA: f64 = 0.25;

/// Dual EWMA long-term: alpha = 1/32.
pub const EWMA_LONG_ALPHA: f64 = 1.0 / 32.0;

/// Default report interval before SRTT is available (cold start).
pub const DEFAULT_COLD_START_INTERVAL_MS: u64 = 200;

/// Minimum report interval (SRTT clamp floor).
pub const MIN_REPORT_INTERVAL_MS: u64 = 1_000;

/// Maximum report interval (SRTT clamp ceiling).
pub const MAX_REPORT_INTERVAL_MS: u64 = 5_000;

/// Number of SRTT samples before transitioning from cold-start to normal floor.
pub const COLD_START_SAMPLES: u32 = 5;

/// Default OWD ring buffer capacity.
pub const DEFAULT_OWD_WINDOW_SIZE: usize = 32;

/// Default operator log interval in seconds.
pub const DEFAULT_LOG_INTERVAL_SECS: u64 = 30;

/// Session-layer minimum report interval.
pub const MIN_SESSION_REPORT_INTERVAL_MS: u64 = 500;

/// Session-layer maximum report interval.
pub const MAX_SESSION_REPORT_INTERVAL_MS: u64 = 10_000;

/// Session-layer cold-start report interval (before SRTT is available).
pub const SESSION_COLD_START_INTERVAL_MS: u64 = 1_000;

/// MMP operating mode.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MmpMode {
    /// Sender + receiver reports at RTT-adaptive intervals. Maximum fidelity.
    #[default]
    Full,
    /// Receiver reports only. Loss inferred from counter gaps.
    Lightweight,
    /// Spin bit + CE echo only. No reports exchanged.
    Minimal,
}

// ============================================================================
// Source: src/mmp/report.rs — MMP report wire format
// ============================================================================

/// Link-layer sender report.
///
/// Wire layout (48 bytes total, sent as link message):
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

/// Link-layer receiver report.
///
/// Wire layout (68 bytes total, sent as link message):
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
/// [48-51] owd_trend: i32 LE (us/s)
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
