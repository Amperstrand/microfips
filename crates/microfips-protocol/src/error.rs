//! Ported from fips v0.4.0: `src/protocol/error.rs` (simplified subset for no_std).
//!
//! Subset only: transport/disconnect/decrypt errors. Upstream has richer error taxonomy.

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

impl From<microfips_core::noise::NoiseError> for ProtocolError {
    fn from(e: microfips_core::noise::NoiseError) -> Self {
        match e {
            microfips_core::noise::NoiseError::DecryptionFailed => Self::DecryptFailed,
            _ => Self::InvalidMessage,
        }
    }
}
