//! Per-chip constants for ESP32 variants.
//!
//! Single source of truth for register addresses, memory layouts, and device
//! identifiers. Adding a new chip = add one `impl ChipConfig for NewChip` block.

/// Trait providing chip-specific constants.
///
/// Each ESP32 variant implements this to supply its register addresses,
/// device name, and linker script path. Consumers use the trait methods
/// instead of raw `#[cfg]` blocks scattered across files.
pub trait ChipConfig {
    const DEVICE_NAME: &'static str;
    const DEVICE_NSEC_ENV: &'static str;
    const RESET_REGISTER: usize;
    const USB_SERIAL_JTAG_BASE: usize;
    const GPIO_OUT_W1TS_FIELD: GpioField;
    const GPIO_OUT_W1TC_FIELD: GpioField;
    const HAS_HARDWARE_ATOMICS: bool;
}

pub enum GpioField {
    OutDataW1ts,
    OutW1ts,
}

pub struct Esp32;
pub struct Esp32s3;
pub struct Esp32c3;

impl ChipConfig for Esp32 {
    const DEVICE_NAME: &'static str = "microfips-esp32";
    const DEVICE_NSEC_ENV: &'static str = "DEVICE_NSEC_HEX_esp32";
    const RESET_REGISTER: usize = 0x3FF4_8000;
    const USB_SERIAL_JTAG_BASE: usize = 0; // ESP32 has no USB Serial JTAG
    const GPIO_OUT_W1TS_FIELD: GpioField = GpioField::OutDataW1ts;
    const GPIO_OUT_W1TC_FIELD: GpioField = GpioField::OutDataW1ts;
    const HAS_HARDWARE_ATOMICS: bool = true; // Xtensa LX6
}

impl ChipConfig for Esp32s3 {
    const DEVICE_NAME: &'static str = "microfips-esp32s3";
    const DEVICE_NSEC_ENV: &'static str = "DEVICE_NSEC_HEX_esp32s3";
    const RESET_REGISTER: usize = 0x6000_8000;
    const USB_SERIAL_JTAG_BASE: usize = 0x6003_8000;
    const GPIO_OUT_W1TS_FIELD: GpioField = GpioField::OutW1ts;
    const GPIO_OUT_W1TC_FIELD: GpioField = GpioField::OutW1ts;
    const HAS_HARDWARE_ATOMICS: bool = true; // Xtensa LX7
}

impl ChipConfig for Esp32c3 {
    const DEVICE_NAME: &'static str = "microfips-esp32c3";
    const DEVICE_NSEC_ENV: &'static str = "DEVICE_NSEC_HEX_esp32c3";
    const RESET_REGISTER: usize = 0x6000_8000;
    const USB_SERIAL_JTAG_BASE: usize = 0x6004_3000;
    const GPIO_OUT_W1TS_FIELD: GpioField = GpioField::OutW1ts;
    const GPIO_OUT_W1TC_FIELD: GpioField = GpioField::OutW1ts;
    const HAS_HARDWARE_ATOMICS: bool = false; // RISC-V RV32IMC, no A extension
}
