#![no_std]

pub mod config;
pub mod handler;
pub mod node_info;

pub use microfips_esp_transport::{led, rng, stats, uart_transport};

#[cfg(feature = "wifi")]
pub mod wifi_transport;

#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
pub use microfips_esp_transport::logger;
#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
pub mod control;

#[cfg(feature = "ble")]
pub mod ble_host;
#[cfg(feature = "ble")]
pub mod ble_transport;

#[cfg(feature = "l2cap")]
pub mod l2cap_host;
#[cfg(feature = "l2cap")]
pub mod l2cap_transport;
