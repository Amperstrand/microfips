# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Minimal FIPS (Free Internetworking Peering System) leaf-node firmware in Rust (Embassy, no_std) for STM32F469/F746 and ESP32 (D0WD, S3, C3), plus host-side simulators and Python bridges. Both MCU families run the same protocol stack (Noise_IK/XK handshake, FMP link framing, FSP session protocol) and reach a FIPS daemon over serial/BLE/WiFi transports.

**`AGENTS.md` is the authoritative operational reference** — read it before any hardware work. It covers flashing, VPS access, transport test procedures, LED state machines, pin maps, known keys, and upstream FIPS compatibility. This file is a summary; when they disagree, trust AGENTS.md. Note: AGENTS.md writes `/home/ubuntu/export-esp.sh`, but on this machine the ESP toolchain env script is `/home/andre/export-esp.sh`.

## Commands

Toolchain is nightly (rust-toolchain.toml). ESP32 builds additionally need the Espressif toolchain: `. ~/export-esp.sh && RUSTUP_TOOLCHAIN=esp ...`.

```bash
# Unit tests (no hardware)
cargo test -p microfips-core                                       # Noise, FMP, FSP, identity
cargo test -p microfips-protocol --features std -- --test-threads=1  # framing, transport, Node, ScriptedPeer
cargo test -p microfips-core noise::tests::test_name               # single test: filter by path

# Lint (CI runs these on host crates: core, protocol, link, sim, http-test)
cargo clippy
cargo fmt --check

# STM32 firmware
cargo build -p microfips --release --target thumbv7em-none-eabi                                        # F469 (default)
cargo build -p microfips --release --target thumbv7em-none-eabi --no-default-features --features board-f746  # F746

# ESP32-D0WD firmware (one binary per transport feature: default=UART, ble, l2cap, wifi)
. ~/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release \
  --target xtensa-esp32-none-elf -Zbuild-std=core,alloc [--features ble|l2cap|wifi]

# ESP32-S3 (WiFi default, or --features l2cap)
. ~/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32s3 --release \
  --target xtensa-esp32s3-none-elf -Zbuild-std=core,alloc

# WiFi builds need credentials from .env (gitignored): export $(grep -v '^#' .env | xargs)

# Host-side handshake against the VPS (no MCU needed)
cargo run -p microfips-link

# Hardware tests (labgrid + pytest, see Makefile)
make test-host / test-esp32-uart / test-esp32-l2cap / test-esp32-ble / test-stm32
```

Host tools require identity via env: `FIPS_NSEC` (64 hex) and `FIPS_PEER_NPUB` (66 hex); they panic if unset. Device keys live in `device-registry.json`. After changing `device-registry.json` or identity code, `cargo clean -p <esp crate>` before rebuilding — keys are compiled in.

## Architecture

Layering, from portable to hardware-specific:

1. **Extracted protocol crates** (no_std, portable, candidate for upstreaming to FIPS):
   - `fips-noise` — Noise IK/XK/XX state machines, crypto (secp256k1 ECDH, ChaChaPoly, SHA256)
   - `fips-fmp` — FMP link-layer wire format (framing, MSG1/2/3)
   - `fips-identity` — NodeAddr, FipsAddress, key derivation
2. **`microfips-core`** — re-exports the above plus FSP session protocol, MMP metrics, device constants
3. **`microfips-protocol`** — `Node` (the whole runtime: handshake, heartbeats, dual FSP sessions), the transport trait, and the `ScriptedPeer` test harness. `--features std` enables host tests; `noise-xx` cfg-gates IK vs XX.
4. **`microfips-service`** — transport-neutral byte-oriented request/response layer above the protocol; HTTP stays out of it (demo-only `microfips-http-demo`)
5. **Composition roots** — thin binaries wiring a transport into `Node`: `microfips` (STM32, USB CDC/UART), `microfips-esp32`/`-esp32s3`/`-esp32c3`, `microfips-sim` (host UDP simulator), `microfips-link` (host handshake tester)
6. **Shared ESP32 layers** — `microfips-esp-common` (chip-agnostic: DNS, config, stats, UDP/WiFi transport) and `microfips-esp-transport` (runner `run_node()`, LED, TRNG, handlers). Only WiFi init stays per-chip (TRNG borrow constraints). BLE/L2CAP/WiFi are feature-gated transport plumbing, not separate stacks.

Wire formats: serial transports use **2-byte LE length-prefixed frames**; FIPS UDP uses **raw frames**; BLE L2CAP uses **2-byte BE length prefix** (matches FIPS `BluerStream`). Noise details intentionally deviate from the spec to match FIPS (empty AAD, IK `se` ordering, x-only ECDH) — see "Noise Protocol Design Choices" in AGENTS.md; do not "fix" them.

Host bridges in `tools/` (`serial_udp_bridge.py`, `ble_udp_bridge.py`) translate MCU frames to UDP toward the FIPS daemon; the L2CAP and WiFi variants connect without a bridge.

## Hardware rules (violating these bricks boards or wedges the host)

- **Never use probe-rs while USB CDC is active** on STM32 — periodic CPU halts break USB transfers. Flash with `st-flash --connect-under-reset`, test via pyserial.
- **Never run `probe-rs erase --chip STM32F469NIHx`** — corrupts flash/option bytes.
- **Never use `esptool --no-stub` on ESP32-S3** — overwrites the partition table. Use `espflash`.
- **Never write to `/sys/bus/usb/.../unbind`/`bind` or `usb1/remove`** — corrupts the kernel TTY layer; recovery requires reboot.
- **Never `pkill -f` during hardware tests** — it kills the test's own SSH session. Kill specific PIDs.
- **Never hardcode `/dev/ttyUSB*`/`ttyACM*` numbers** — multiple devices enumerate unstably. Always detect by VID:PID (detection snippets in AGENTS.md): STM32 CDC `c0de:cafe`, ST-Link `0483:374b`, ESP32-D0WD CP210x `10c4:ea60`, ESP32-S3 `303a:1001`; an unrelated M5 Stack (`0403:6001`) is also attached — never flash it.
- Pipeline order matters for STM32 tests: start the serial proxy (asserts DTR) before resetting the MCU; never `st-flash reset` mid-test. Prefer `scripts/test_hw_handshake.sh`.

## Gotchas

- `RawRestoreStateInner defined multiple times` build error → stale Cargo feature-unification cache; run `cargo clean`.
- `defmt_rtt` in the binary breaks STM32 USB CDC enumeration even when unused.
- Each ESP32 feature variant produces its own binary (`microfips-esp32[-ble|-l2cap|-wifi]`); flashing the wrong one is a common failure.
- Secrets (VPS credentials, WiFi) come from env/`.env`, never committed. Never put a default device identity in code.
