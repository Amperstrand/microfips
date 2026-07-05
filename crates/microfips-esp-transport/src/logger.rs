#![cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]

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
    #[cfg(not(target_arch = "riscv32"))]
    log::set_logger(&LOGGER).unwrap();
    #[cfg(not(target_arch = "riscv32"))]
    #[cfg(not(target_arch = "riscv32"))]
    log::set_max_level(LevelFilter::Info);
}
