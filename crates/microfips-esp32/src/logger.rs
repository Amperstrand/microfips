//! Structured logging backend for ESP32 BLE/L2CAP firmware.
//! Uses esp_println for UART0 TX output. Init before any log macros are used.

#![cfg(any(feature = "ble", feature = "l2cap"))]

use log::{Level, LevelFilter, Log, Metadata, Record};

struct UartLogger;

static LOGGER: UartLogger = UartLogger;

impl Log for UartLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Format: [LEVEL module_path] message
            // Matches FIPS structured logging style
            esp_println::println!(
                "[{} {}] {}",
                record.level(),
                record.module_path().unwrap_or("?"),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

/// Initialize the global logger. Call once at startup, before any log macros.
pub fn init() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);
}
