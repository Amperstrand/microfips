//! Shared ESP32 transport implementations: UART, USB CDC, BLE GATT, BLE L2CAP, WiFi, and common hardware abstractions.

#![no_std]

extern crate alloc;

#[cfg(all(
    feature = "esp32",
    feature = "esp32s3",
    any(target_arch = "xtensa", target_arch = "riscv32")
))]
compile_error!("features \"esp32\" and \"esp32s3\" are mutually exclusive");

pub mod config;
pub mod gpio_helpers;
pub mod handler;
pub mod heap;
pub mod led;
pub mod macros;
pub mod node_info;
pub mod rng;
pub mod runner;
pub mod run_tasks;
pub mod stats;
pub mod uart_transport;

#[cfg(feature = "esp32s3")]
pub mod usb_transport;

#[cfg(feature = "wifi")]
pub mod wifi_transport;

#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
pub mod control;
#[cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]
pub mod logger;

#[cfg(feature = "ble")]
pub mod ble_host;
#[cfg(feature = "ble")]
pub mod ble_transport;

#[cfg(feature = "l2cap")]
pub mod backoff;
#[cfg(feature = "l2cap")]
pub mod l2cap_host;
#[cfg(feature = "l2cap")]
pub mod l2cap_transport;
#[cfg(feature = "l2cap")]
pub mod peer_caps;
