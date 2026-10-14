//! ESP32-S3 (TiLDAGON) firmware: chip-specific run functions and binary entry points.

#![no_std]

pub mod run;
pub use microfips_esp_transport::{handler, node_info};

pub use microfips_esp_transport::{led, rng, stats, uart_transport};

#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
pub use microfips_esp_transport::control;
// Not feature-gated: the radio-less `uart`/`usb` binaries need `logger::init()`
// too (the transport dep enables its `log` feature unconditionally, see
// Cargo.toml), and the gated re-export was the stale half of the same gap the
// C3 crate had.
pub use microfips_esp_transport::logger;

#[cfg(feature = "ble")]
pub use microfips_esp_transport::ble_transport;

#[cfg(feature = "l2cap")]
pub use microfips_esp_transport::l2cap_transport;
