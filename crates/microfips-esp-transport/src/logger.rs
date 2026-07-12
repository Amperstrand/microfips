#![cfg(any(feature = "ble", feature = "l2cap", feature = "wifi", feature = "espnow"))]

use log::{Level, LevelFilter, Log, Metadata, Record};

struct UartLogger;

static LOGGER: UartLogger = UartLogger;

impl Log for UartLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
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

pub fn init() {
    // SAFETY: We call init() exactly once during boot, before any other logging
    // occurs. No concurrent access to the logger state is possible at this point.
    // The _racy variants are required on riscv32imc targets which lack native
    // atomic pointer operations (no 'a' extension on the C3).
    unsafe {
        log::set_logger_racy(&LOGGER).unwrap();
        log::set_max_level_racy(LevelFilter::Info);
    }
}
