# ESP32-C3 (RISC-V) Build Target — Feasibility Assessment

Status: **Proposed** · Date: 2026-07-04 · Branch: `feat/noise-xx-handshake`

## 1. Summary

This document assesses adding the **ESP32-C3** (Espressif RISC-V) as a first-class
microFIPS build target alongside the existing Xtensa-based ESP32 boards. The
conclusion is a **LOW-risk, ~2–4 hour** change that should be scheduled **after**
the Noise-XX interop work is locked down.

## 2. Current Build Targets

| Target | Architecture | Crate | Toolchain | Notes |
|---|---|---|---|---|
| ESP32-D0WD | Xtensa LX6 | `microfips-esp32` | `xtensa-esp32-none-elf` (espup) | 520 KB SRAM, classic BT + BLE + WiFi |
| ESP32-S3 | Xtensa LX7 | `microfips-esp32s3` | `xtensa-esp32s3-none-elf` (espup) | 512 KB SRAM, BLE + WiFi (USB JTAG serial) |
| STM32F4/F7 | ARM Cortex-M4F/M7F | *(lab/hardware only — no Rust crate)* | `thumbv7em-none-eabihf` | Driven via labgrid (`flash_stm32.sh`, `flash_stm32f746.sh`, `stm32-f469.yaml`); ADR-0001 selected `embassy` over `stm32f4xx-hal`. No `microfips-stm32*` crate exists in the workspace today. |

Shared ESP transport code lives in `microfips-esp-transport`, which exposes
per-chip feature flags `esp32` and `esp32s3`. The workspace pins:

- `esp-hal = "1.1.0"` (resolved `1.1.1` in `Cargo.lock`)
- `esp-radio = "0.18.0"`
- `esp-rtos = "0.3.0"`, `esp-bootloader-esp-idf = "0.5"`, `esp-println = "0.17.0"`
- `rust-toolchain.toml` currently lists only `thumbv7em-none-eabihf` under
  `targets` (the Xtensa targets are managed out-of-band via `espup`).

## 3. What Changes for the ESP32-C3

| Dimension | ESP32 / S3 (Xtensa) | ESP32-C3 (this proposal) |
|---|---|---|
| CPU core | Xtensa LX6 / LX7 | **RISC-V RV32IMC** (single core) |
| Target triple | `xtensa-esp*-none-elf` | **`riscv32imc-esp-none-elf`** |
| Toolchain source | `espup` (forked Xtensa LLVM) | **Upstream `rustup` target** — no `espup` needed for the C3 alone |
| esp-hal feature | `esp32` / `esp32s3` | **`esp32c3`** |
| SRAM | 520 KB / 512 KB | **400 KB** (~23 % less than D0WD) |
| Bluetooth | Classic BT + BLE | **BLE only — no Classic Bluetooth** |
| WiFi | Yes | Yes (C3 has WiFi; only Classic BT is absent) |
| Debug print | UART / JTAG-serial | UART (no built-in JTAG-serial on most modules) |

Net effect: the protocol stack (`microfips-core`, `microfips-protocol`,
`microfips-service`) is architecture-independent and unchanged. Only the
board-support glue (HAL init, radio init, allocator sizing, print backend)
needs a C3 variant.

## 4. Required Changes

1. **New crate `crates/microfips-esp32c3`** — clone of `microfips-esp32`
   with:
   - `esp-hal` features `["esp32c3", "unstable"]`
   - `esp-rtos` / `esp-bootloader-esp-idf` / `esp-radio` / `esp-println`
     feature `esp32c3`
   - `microfips-esp-transport` feature `esp32c3` (see item 3)
   - Drop the `l2cap`-over-classic-BT bin target — C3 has no Classic BT.
     Keep `ble`, `wifi`, and `uart` bin targets.
   - Reduce static buffer/heap reservations to fit 400 KB SRAM (audit
     `esp_alloc::HEAP` size and any `static_cell` pools).
2. **Workspace `Cargo.toml`** — add `crates/microfips-esp32c3` to `members`.
3. **`microfips-esp-transport/Cargo.toml`** — add an `esp32c3` feature
   mirroring the existing `esp32` / `esp32s3` entries:
   ```toml
   esp32c3 = ["esp-hal/esp32c3", "esp-radio/esp32c3", "esp-println/esp32c3", "esp-println/auto"]
   ```
4. **`rust-toolchain.toml`** — add `"riscv32imc-esp-none-elf"` to `targets`
   (and `rustup target add riscv32imc-esp-none-elf` locally).
5. **Build test** — `cargo build -p microfips-esp32c3` for each of
   `--no-default-features`, `--features ble`, `--features wifi`.
6. **BLE + WiFi verification on hardware** — flash a C3 devkit, run the BLE
   handshake (Noise XX, `FMP_VERSION=1`) against an existing ESP32/S3 peer,
   and confirm a WiFi over-the-air session. This is the only step that
   needs physical hardware and is the main schedule risk.

## 5. Risk Assessment

**Overall risk: LOW.**

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| esp-hal / esp-radio lack C3 support | Very unlikely — both 1.1.x / 0.18 explicitly ship `esp32c3` features; C3 is one of the most-used esp-rs targets | High | Already verified feature exists in pinned versions; bump only if needed |
| 400 KB SRAM insufficient for current buffer pools | Low — protocol frames are small; main consumer is the BLE/WIFI packet pool | Medium | Shrink `esp_alloc` heap and `trouble-host` packet pool; benchmark before/after |
| No Classic BT breaks an assumed transport | Low — microFIPS uses BLE (trouble-host) and WiFi, not Classic BT | Low | C3 crate simply omits the `l2cap`/classic-BT bin target |
| Toolchain/CI churn from mixing Xtensa and RISC-V | Low — RISC-V target comes from upstream rustup, so it is *simpler* than the Xtensa path | Low | Add the target to `rust-toolchain.toml`; CI already invokes espup for Xtensa |
| Protocol behaviour differs on RV32 | Very unlikely — `microfips-core` is `no_std`, arch-neutral, already tested on Cortex-M and Xtensa | High if it occurred | Re-run `microfips-core` unit tests on the C3 target; they are host-run and arch-independent |

No cryptographic, framing, or Noise-XX changes are required — the C3 is
purely another board-support target.

## 6. Recommendation

**Proceed, but AFTER the Noise-XX interop is locked down.**

- Sequencing: do **not** land this while the handshake/interop matrix is still
  in motion. A new target multiplies the interop test surface (C3 ↔ D0WD,
  C3 ↔ S3, …) and should be added to a frozen protocol baseline.
- Effort estimate: **2–4 hours** of engineering work (crate scaffold +
  workspace/transport wiring + cross-compile), plus one hardware session for
  BLE+WiFi bring-up. The software side is mechanical; the hardware day is the
  dominant unknown.
- Deliverable checklist: `microfips-esp32c3` crate, workspace member,
  `esp32c3` transport feature, toolchain target, green `cargo build`, and at
  least one logged C3 ↔ ESP32 BLE handshake.

## 7. Open Questions

- Do we want a single `microfips-esp` umbrella crate with chip features
  (`--features esp32c3`) instead of one crate per chip? Out of scope here, but
  worth raising before the C3 lands — the per-chip-crate pattern is already
  established (`microfips-esp32`, `microfips-esp32s3`), so matching it is the
  low-friction choice.
- Should the STM32 lab targets be promoted to real workspace crates at the
  same time? That is a separate, larger effort and is explicitly out of scope
  for this assessment.
