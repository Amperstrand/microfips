/// Protocol-level errors.
///
/// ⚠ FIPS GAP [FIPS-140-3 §9.9]: On any cryptographic error (e.g.,
/// `DecryptFailed`), FIPS 140-3 requires the module to enter a critical error
/// state: zeroize all Sensitive Security Parameters (SSPs), cease all
/// cryptographic operations, and indicate the error condition. Currently these
/// errors propagate as `Result::Err` with no SSP zeroization or module halt.
/// Required: Implement a critical error state handler per ISO 19790 §9.9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Disconnected,
    Timeout,
    InvalidFrame,
    InvalidMessage,
    DecryptFailed,
    PeerDisconnected,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disconnected => f.write_str("disconnected"),
            Self::Timeout => f.write_str("timeout"),
            Self::InvalidFrame => f.write_str("invalid frame"),
            Self::InvalidMessage => f.write_str("invalid message"),
            Self::DecryptFailed => f.write_str("decrypt failed"),
            Self::PeerDisconnected => f.write_str("peer disconnected"),
        }
    }
}

impl core::error::Error for ProtocolError {}
