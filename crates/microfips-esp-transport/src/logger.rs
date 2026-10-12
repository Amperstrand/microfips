#![cfg(all(
    feature = "log",
    any(feature = "esp32", feature = "esp32s3", feature = "esp32c3")
))]

//! Global log backend for the ESP firmware images.
//!
//! The module is compiled whenever the crate has both the `log` crate (`log`
//! feature) and the esp-println printer (each chip feature enables
//! `esp-println/<chip>`). The previous gate was `any(ble, l2cap, wifi, esp-now)`,
//! which excluded the radio-less `uart`/`usb` binaries; this one compiles there
//! too. That relation to the old gate holds only *under this crate's feature
//! invariant*, which is worth naming rather than assuming: each radio feature
//! (`ble`, `l2cap`, `wifi`, `esp-now`) names `log` in its own feature list in
//! `Cargo.toml`, and any build that selects a radio feature also selects a chip
//! feature (the chip features are mutually exclusive, enforced in `lib.rs`). Drop
//! the first half and the radio gate is no longer implied by the new one; drop the
//! second and a radio build loses this module entirely, failing loudly at its
//! `logger::init()` call site instead of silently discarding records.

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

/// Installs the global log backend for this image.
///
/// `log::set_logger` / `log::set_max_level` are gated in `log` 0.4 behind
/// `target_has_atomic = "ptr"`, which is **false** for
/// `riscv32imc-unknown-none-elf` (RV32IMC has no compare-and-swap). Gating the whole
/// function on that cfg made it an empty no-op on the ESP32-C3, so every
/// `log::info!` / `log::error!` in the C3 firmware (`microfips-protocol` alone has
/// 47 sites) was discarded at runtime.
///
/// The CAS-less branch installs through `log`'s racy API (`set_logger_racy` /
/// `set_max_level_racy`): ungated in `log` 0.4, available on every target, and
/// backed by a `Cell`-wrapped `AtomicUsize` where pointer-width atomics do not
/// exist. That is the *same* mechanism `esp-println`'s own `log-04` backend uses
/// (`esp-println-0.18.0/src/logger.rs::init_logger` calls exactly these two
/// functions), so nothing here is hand-rolled and the `log` contract is unchanged.
///
/// # Why the racy install is sound here (CAS-less targets)
///
/// `set_logger_racy` must not race another installer, i.e. interrupts must be
/// disabled around it *or* no interrupt may install a logger. The precondition
/// would not hold on a target where logging is installed from an interrupt, but
/// it holds here: `init` is the only installer in the image (nothing else calls
/// `set_logger`/`set_logger_racy`, and `esp-println`'s own `log-04` backend is not
/// enabled), so while interrupts may well be enabled, none of them can install
/// one. Each caller is a single firmware entry point (`run_uart_node`,
/// `run_wifi_node`, `run_esp_now_node`, …) reached once from `main` before any
/// other task runs, and no entry point calls another, so two installers can never
/// overlap. An interrupt that *logs* in the window between the `LOGGER` store and
/// the `STATE` store sees `STATE == UNINITIALIZED` (and a max level of `Off`) and
/// is dropped, so a partially-initialised logger is never observed.
#[cfg(target_has_atomic = "ptr")]
pub fn init() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);
}

#[cfg(not(target_has_atomic = "ptr"))]
pub fn init() {
    // SAFETY: single installer per image, called once from the entry point before
    // any other task exists; see the doc comment above.
    unsafe {
        log::set_logger_racy(&LOGGER).unwrap();
        log::set_max_level_racy(LevelFilter::Info);
    }
}

/// Compile-time witness that the *installing* path is the one compiled for this
/// target: `set_logger_racy` is the ungated alternative to the
/// `target_has_atomic = "ptr"`-gated `set_logger`, so this static only resolves if
/// that API still exists on `riscv32imc-unknown-none-elf`. In other words it pins
/// the *availability* of the racy API (fails the C3 build if it is gated away
/// again), and `#[used]` keeps the pointer in the object file so the C3 image can
/// be inspected as evidence (`llvm-nm`/`llvm-objdump`) that a real installer is
/// linked in. It does **not** prove the installer is called: an `init()` body
/// emptied to `{}` still compiles with this static present (that empty body was
/// built as the control on card t_2ac11284: exit 0, witness still linked).
///
/// What does show the install happening is the disassembly of `init` itself — the
/// racy installer called first, its `Result` unwrapped, then the level store. Every
/// stretch this excerpt drops is marked, so it can be diffed against a fresh dump
/// without unexplained holes; the nine quoted instructions plus the three marked
/// spans are all 29 instructions `llvm-objdump` prints for `init`:
///
/// ```text
///         ...                     # init's prologue: addi sp, sp, -0x10; sw ra, 0xc(sp)
/// 4203bdc4: lui   a0, 0x3c008
/// 4203bdc8: addi  a0, a0, -0x68   # &LOGGER — lui+addi is the whole address
/// 4203bdcc: lui   a1, 0x3c008
/// 4203bdd0: addi  a1, a1, -0x90   # &(dyn Log vtable of UartLogger) — likewise
/// 4203bdd4: auipc ra, 0x32
/// 4203bdd8: jalr  0x302(ra)       # log::set_logger_racy
///         ...                     # 15 instructions: the unwrap() of that Result — on the
///                                 # fast path only sb/lbu/andi/beqz, and that beqz (at
///                                 # 4203bde6) branches to 4203be12; the 11 instructions
///                                 # that follow it are the cold path (skipped on success):
///                                 # the branch to core::result::unwrap_failed and that
///                                 # call's setup
/// 4203be12: li    a0, 0x3         # LevelFilter::Info
/// 4203be14: auipc ra, 0x0
/// 4203be18: jalr  -0x1c0(ra)      # log::set_max_level_racy
///         ...                     # epilogue: lw ra, 0xc(sp); addi sp, sp, 0x10; ret
/// ```
///
/// Those addresses are from the C3 `uart` image; the full `llvm-objdump -d` dumps
/// behind this excerpt are the `disasm_{base,after}.txt` pair in the kanban
/// evidence bundle for card t_2ac11284, not in this tree.
#[cfg(not(target_has_atomic = "ptr"))]
#[used]
static RACY_INSTALL_WITNESS: unsafe fn(&'static dyn Log) -> Result<(), log::SetLoggerError> =
    log::set_logger_racy;
