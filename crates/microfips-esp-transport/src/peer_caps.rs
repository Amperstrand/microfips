//! BLE peer capability negotiation for ESP32 L2CAP.
//!
//! Ported from fips src/transport/ble/capabilities.rs.
//! Capability flags are exchanged during the initial pubkey handshake
//! as a single byte appended to the pubkey frame.

#![cfg(feature = "l2cap")]

// Ported from fips PeerCapabilities constants (src/transport/ble/capabilities.rs)
pub const LEGACY_CENTRAL_ONLY: u8 = 0x01;
pub const PREFER_OUTBOUND: u8 = 0x02;
pub const PREFER_PERIPHERAL: u8 = 0x04; // microfips-specific
pub const CAN_CENTRAL: u8 = 0x08;
pub const CAN_PERIPHERAL: u8 = 0x10;
pub const L2CAP_SUPPORTED: u8 = 0x20;
pub const GATT_SUPPORTED: u8 = 0x40;

/// ESP32-D0WD as peripheral-only L2CAP device.
pub const ESP32_DEFAULT: u8 = CAN_PERIPHERAL | L2CAP_SUPPORTED;

/// Check if peer prefers to initiate connections.
// Ported from fips PeerCapabilities::prefers_outbound()
pub fn peer_prefers_outbound(flags: u8) -> bool {
    flags & PREFER_OUTBOUND != 0
}

/// Check if peer can accept inbound connections.
/// `flags == 0` means legacy unrestricted (all roles allowed).
// Ported from fips PeerCapabilities::can_accept_inbound()
pub fn peer_can_peripheral(flags: u8) -> bool {
    flags == 0 || flags & CAN_PERIPHERAL != 0
}
