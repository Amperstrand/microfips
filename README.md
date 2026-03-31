# microfips

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO and ESP32-D0WD.

A Rust embedded firmware that implements leaf-only FIPS nodes using Embassy for async
HAL, Noise_IK/XK handshakes, FMP link framing, FSP session protocol, and a no_std
FIPS protocol stack. Both MCUs connect to a FIPS VPS via serial-to-UDP bridges.

## Current Status

**M8 DONE — Sim-to-MCU FSP ping proven end-to-end (2026-03-31)**

A software simulator (SIM-B) successfully sent an encrypted FSP PING to the physical
STM32 through the live FIPS VPS and received a PONG back. The full path is:

```
SIM-B (host) → UDP → FIPS (VPS) → UDP → serial bridge → STM32 (hardware)
                                                    ← PONG ←
```

**What works:**
- 169 unit tests pass (90 core + 21 error injection + 22 compatibility + 17 wire format + 13 FSP edge cases + 6 FSP integration + 46 protocol)
- **Sim-to-sim FSP ping through FIPS** — SIM-B → FIPS → SIM-A, full XK handshake + PING/PONG
- **Sim-to-MCU FSP ping through FIPS** — SIM-B → FIPS → physical STM32, proven on hardware
- **Dual-MCU simultaneous handshake** — both MCUs sustain heartbeat with VPS concurrently
- Sim-to-MCU ping test passes with `--test-ping` flag (exit 0 on PONG received)
- Host-side handshake test (`microfips-link`) proven against live VPS
- USB CDC ACM enumeration with upstream embassy crates.io v0.6.0
- **STM32 completes IK handshake with live VPS** — MSG1 sent, MSG2 received, heartbeat sustained
- **ESP32 completes IK handshake with live VPS** — UART transport via CP210x USB-serial
- FIPS forwards SessionDatagrams between any two authenticated peers (no tree_peer needed)
- 4-LED state machine on STM32 for visual debugging, single LED on ESP32
- FIPS cross-reference annotations normalized to canonical format (`// FIPS: bd08505 ...`)
- Structured logging with `[SIM-A → FIPS]` labels in simulator and link tools
- CI: unit tests, lint, firmware cross-build, sim-ping E2E test, FIPS integration

**What doesn't work yet:**

| Issue | Description | Root Cause |
|-------|-------------|------------|
| USB timing | STM32 sends 5 MSG1 retries before handshake succeeds | Bridge must open serial port before MCU `wait_connection()` returns |

**Key bugs found and fixed across all sessions:**

| # | Bug | Impact | Fix |
|---|-----|--------|-----|
| 1 | recv_frame infinite loop | STM32 hung forever on MSG2 | Fall through to read, never `continue` without I/O |
| 2 | Handshake discarded non-Msg2 | Stale FIPS data killed session | Loop recv_frame until Msg2 |
| 3 | `fmp_raw_frame_size()` truncation | All FIPS-originated frames truncated | Use full UDP datagram for established frames |
| 4 | SIM-B k_send/k_recv swap | Initiator couldn't decrypt responses | Use k_recv for decryption |
| 5 | ESP32 k_send/k_recv swap | Same as #4 on ESP32 | Same fix |
| 6 | AwaitingMsg3 no timeout | FSP responder stuck forever on stale state | Reset session on InvalidState, retry |
| 7 | Bridge thread race | Two readers split TCP data on reconnect | Stop both threads before reconnect |
| 8 | Bridge CPU spin | GIL starvation under Python | `time.sleep(0.001)` in idle path |
| 9 | Stale ESP32 NodeAddr constants | ESP32 targeted wrong MCU | Updated to match current deterministic keys |
| 10 | Sim hardcoded wrong FSP target pubkey | Sim used SIM-A pubkey for STM32 target | Added NodeAddr-to-pubkey mapping |

**Fork issue resolved (2026-03-28):**
The `Amperstrand/embassy` fork (commit `c0289d7a8`) breaks USB enumeration on STM32F469.
Switching all embassy deps to upstream crates.io v0.6.0 fixed it immediately.

## Architecture

```
  STM32F469I-DISCO          Host (Linux)               VPS
  +----------------+    +-------------------+    +------------------+
  | microfips fw   |    | serial_udp_bridge |    | FIPS daemon      |
  | FIPS protocol  |CDC | (single-hop,      |UDP | port 2121        |
  | Noise_IK/XK    |<-->|  auto-detect MCU) |<-->|                  |
  | FMP + FSP      |    | serial <-> UDP    |    | forwards between |
  | Heartbeats     |    +-------------------+    | all authenticated |
  +----------------+                             | peers            |
                                                   +------------------+
  ESP32-D0WD
  +----------------+    +-------------------+
  | microfips-esp32|    | serial_udp_bridge |
  | FIPS protocol  |UART| (single-hop,      |UDP --+
  | Noise_IK       |<-->|  auto-detect MCU) |<-->   |
  | FMP + FSP      |    +-------------------+       |
  | (hand-rolled)  |                                  |
  +----------------+                                  v
                                              +------------------+
  Simulator (host)                             | FIPS daemon      |
  +----------------+    +-------------------+  | port 2121        |
  | microfips-sim   |    | (none needed)     |  |                  |
  | uses Node from  |UDP | direct UDP        |->|                  |
  | microfips-proto |<-->|                   |  +------------------+
  +----------------+    +-------------------+
```

Two transport options:
- **Single-hop bridge** (recommended): `serial_udp_bridge.py` sends UDP directly to FIPS
  from the host. No SSH tunnel or VPS-side bridge needed.
- **Legacy 3-hop** (deprecated): serial → TCP proxy → SSH tunnel → VPS bridge → FIPS

All serial data uses **length-prefixed frames**: `[2-byte LE length][payload]`.
FIPS UDP transport uses **raw frames** (no length prefix).

## Node Identities (deterministic pattern keys)

All keys are deterministic: 31 zero bytes + last byte N (secp256k1 generator * N).

| Node | Secret (last byte) | Pubkey prefix | npub prefix | NodeAddr prefix |
|------|--------------------|---------------|-------------|-----------------|
| STM32 | `...0001` | `0279be667ef9dcbb` | `npub10xlxvlh...` | `132f39a9...` |
| ESP32 | `...0002` | `02c6047f9441ed7d` | `npub1ccz8l9z...` | `0135da2f...` |
| SIM-A | `...0003` | `02f9308a019258c3` | `npub1lycg5qv...` | `7c79f307...` |
| SIM-B | `...0004` | `02eeb19fd1768397` | `npub1a6cel5t...` | `36be1ea4...` |
| VPS | (real key) | `020e7a0da01a255` | `npub1wwsqf76...` | `73a004fb...` |

## Testing

### Unit tests (no hardware)

```sh
cargo test -p microfips-core                    # 123 tests: Noise, FMP, FSP, identity, error injection, compatibility
cargo test -p microfips-core -- --nocapture     # verbose output
cargo test -p microfips-protocol --features std -- --test-threads=1  # 46 tests: framing, transport, node
```

### Key generation

```sh
cargo run -p microfips-link -- --keygen
# Output:
#   FIPS_SECRET=<64 hex chars>
#   FIPS_PUB=<66 hex chars>
```

### Host-side VPS handshake (no hardware, raw UDP)

```sh
cargo run -p microfips-link                     # sends MSG1 to VPS via UDP (default keys)

# With custom keys (override via environment):
FIPS_SECRET=<hex> FIPS_PEER_PUB=<hex> cargo run -p microfips-link -- 127.0.0.1:2121
# Exit 0 = success, 1 = timeout (expected from unconfigured IP), 2 = error
```

## Observability

### Wireshark Dissector

A Lua dissector for FMP frames is available at `tools/fips_dissector.lua`:

```sh
tshark -r capture.pcap -X lua_script:tools/fips_dissector.lua -V
tshark -r capture.pcap -X lua_script:tools/fips_dissector.lua -Y 'fips.phase == 1'
```

### PCAP Capture

Capture FIPS traffic with tcpdump:

```sh
./tools/capture_fips.sh capture.pcap 100
```

A reference capture from a sim-to-sim test is at `tools/reference.pcap`.

### Sim-to-sim FSP ping through FIPS (no hardware)

Requires both sims to connect to the live FIPS VPS. SIM-A acts as FSP responder,
SIM-B as initiator. FIPS forwards SessionDatagrams between them.

```sh
# Terminal 1: SIM-A (responder)
cargo run -p microfips-sim --release -- --udp orangeclaw.dns4sats.xyz:2121 --sim-a

# Terminal 2: SIM-B (initiator, targets SIM-A, exits on PONG)
cargo run -p microfips-sim --release -- --udp orangeclaw.dns4sats.xyz:2121 --sim-b --test-ping
# Expected: "FSP ACK received" → "FSP established! Sending MSG3" → "*** PONG received from target! ***"
```

### Sim-to-MCU FSP ping through FIPS (hardware: STM32 required)

The simulator sends an encrypted FSP PING to the physical STM32 through FIPS.
STM32 must be connected via serial bridge (see AGENTS.md for hardware setup).

```sh
# 1. Flash and reset STM32, wait for USB enumeration
st-flash --connect-under-reset reset
sleep 8

# 2. Start serial bridge (auto-detects MCU by VID:PID c0de:cafe)
python3 tools/serial_udp_bridge.py --serial /dev/ttyACM1 --udp-host orangeclaw.dns4sats.xyz &

# 3. Run SIM-B targeting STM32's NodeAddr (exit 0 on PONG)
FIPS_SECRET=0303030303030303030303030303030303030303030303030303030303030303 \
  cargo run -p microfips-sim --release -- \
  --udp orangeclaw.dns4sats.xyz:2121 \
  --initiator --target 132f39a98c31baaddba6525f5d43f295 \
  --test-ping
# Expected: "*** PONG received from target! ***" (exit 0)
```

### Host-side simulator (general)

```sh
# Responder mode (default)
cargo run -p microfips-sim --release -- --udp orangeclaw.dns4sats.xyz:2121 --sim-a

# Initiator mode with custom identity and target
FIPS_SECRET=<hex> cargo run -p microfips-sim --release -- \
  --udp orangeclaw.dns4sats.xyz:2121 --initiator --target <16-byte-hex-nodeaddr>

# Enable debug logging from core crates
RUST_LOG=debug cargo run -p microfips-sim --release -- --udp orangeclaw.dns4sats.xyz:2121 --sim-a
```

### Hardware (STM32F469)

See AGENTS.md for the full hardware test procedure and LED state machine.

```sh
# Flash (use st-flash, NOT probe-rs — see AGENTS.md)
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
st-flash --connect-under-reset write microfips.bin 0x08000000
```

### Hardware (ESP32)

```sh
# Kill stale processes holding serial port
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1

# Flash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  espflash flash -p /dev/ttyUSB0 --chip esp32 \
  target/xtensa-esp32-none-elf/release/microfips-esp32
```

## Build

Requires nightly Rust. See AGENTS.md for full toolchain setup.

### STM32F469

```sh
cargo build -p microfips --release --target thumbv7em-none-eabi
# Output: target/thumbv7em-none-eabi/release/microfips
```

### ESP32-D0WD

Requires Espressif Rust toolchain (installed via `espup`, activated with `RUSTUP_TOOLCHAIN=esp`):

```sh
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc
# Output: target/xtensa-esp32-none-elf/release/microfips-esp32
```

## CI

GitHub Actions runs on push/PR to main, all on `ubuntu-latest`:
- **Unit Tests** — 90 tests in `microfips-core`, 46 tests in `microfips-protocol`
- **Error Injection** — 21 tests in `microfips-core`
- **Compatibility** — 22 FIPS comparison tests in `microfips-core`
- **Wire Format Tests** — 17 FMP format tests in `microfips-core`
- **FSP Integration** — 6 FSP session tests in `microfips-core`
- **FSP Edge Cases** — 13 FSP protocol edge cases in `microfips-core`
- **Build Host Tools** — `microfips-link` + `microfips-sim` + `microfips-http-test` release binaries
- **Lint & Format** — clippy + rustfmt on all host crates
- **Sim Ping E2E** — SIM-B → FIPS → SIM-A FSP PING/PONG test (must pass)
- **FIPS Handshake Integration** — local Noise IK handshake (must pass) + public VPS (best-effort)
- **Build Firmware** — STM32 (`thumbv7em-none-eabi`) + ESP32 (`xtensa-esp32-none-elf`)
- **Summary** — aggregate status table

### Environment variables for key override

All host tools accept key overrides via environment variables:

| Variable | Format | Used by | Purpose |
|----------|--------|---------|---------|
| `FIPS_SECRET` | 64 hex chars (32B secret) | fips-handshake, microfips-sim, microfips-http-test | Override identity secret key |
| `FIPS_PEER_PUB` | 66 hex chars (33B compressed pubkey) | fips-handshake, microfips-sim | Override peer's public key |

When not set, tools fall back to hardcoded defaults (MCU dev identity / VPS pubkey).

## Hardware

### STM32F469I-DISCO
- **MCU:** STM32F469NI (Cortex-M4F, 180 MHz, 1 MB Flash, 384 KB SRAM)
- **USB OTG FS:** PA11 (DM), PA12 (DP) — CDC ACM
- **LEDs:** PG6 (green), PD4 (orange), PD5 (red), PK3 (blue) — active high
- **RNG:** HASH_RNG interrupt — hardware TRNG
- **Debug:** ST-LINK/V2.1 (PA13 SWDIO, PA14 SWCLK)
- **Clocks:** HSI 16 MHz + PLL → 168 MHz sys, 48 MHz USB (HSE bypass hangs)
- **USB VID:PID:** `c0de:cafe` (CDC ACM, detected as `/dev/ttyACM*`)
- **Flash:** `st-flash --connect-under-reset write` (NOT probe-rs during USB testing)

### ESP32-D0WD
- **MCU:** ESP32-D0WD (Xtensa LX6, 240 MHz, 4 MB Flash)
- **UART:** GPIO1 (TX), GPIO3 (RX) — CP210x USB-serial
- **LED:** GPIO2 (blue onboard, active high)
- **USB VID:PID:** `10c4:ea60` (Silicon Labs CP210x, detected as `/dev/ttyUSB*`)
- **Flash:** `espflash flash -p /dev/ttyUSB0 --chip esp32` (NOT probe-rs)
- **Note:** ESP32 uses hand-rolled protocol code (not `microfips-protocol::Node`). Can only
  act as FSP initiator (no responder code for incoming SessionSetups).

## Milestones

| Milestone | Description | Status |
|-----------|-------------|--------|
| M0 | Environment, repo, scaffold | Done |
| M1 | USB CDC ACM enumeration + echo | Done |
| M2 | Length-prefixed framing over CDC | Done |
| M3 | Host-side handshake test (`microfips-link`) | Done |
| M4 | MCU handshake with live VPS | Done |
| M5 | Host-side full lifecycle simulator (`microfips-sim`) | Done |
| M6 | MCU full lifecycle (handshake + heartbeat exchange) | Done |
| M7 | FSP session protocol (XK handshake + encrypted data) | Done |
| M8 | Sim-to-MCU FSP ping through FIPS | **Done** — SIM-B → FIPS → physical STM32 PING/PONG |
| M9 | MCU-to-MCU ping (STM32 ↔ ESP32 through FIPS) | **Done** — MCU-to-MCU FSP PING/PONG + HTTP through FIPS proven on hardware (2026-04-01) |
| M10 | FIPS DNS resolution (`.fips` names) | Future |

### M8 sub-milestones (all done)

| ID | Description | Status |
|----|-------------|--------|
| M8.1 | Sim-to-sim FSP handshake through FIPS | Done |
| M8.2 | Sim-to-sim FSP PING/PONG through FIPS | Done |
| M8.3 | Sim-to-STM32 FSP handshake through FIPS | Done |
| M8.4 | Sim-to-STM32 FSP PING/PONG through FIPS | Done |
| M8.5 | FIPS forwards SessionDatagrams between authenticated peers | Verified — no tree_peer needed |

### M9 blockers (resolved)

All blockers are resolved:
- STM32 now uses `FspDualHandler::new_dual()` targeting ESP32 (dual mode: initiator + responder)
- ESP32 already uses `FspDualHandler::new_dual()` targeting STM32 (since commit `c7da1c2`)
- FIPS routes SessionDatagrams between direct peers via `find_next_hop()` — no `tree_peer` needed

### M9 sub-milestones

| ID | Description | Status |
|----|-------------|--------|
| M9.1 | STM32 FSP dual mode (initiator+responder targeting ESP32) | Done |
| M9.2 | ESP32 FSP dual mode (already done, commit c7da1c2) | Done |
| M9.3 | Sim-to-MCU HTTP-over-FSP test | Done |
| M9.4 | MCU-to-MCU FSP PING/PONG through FIPS (hardware E2E) | Done |

## Project Layout

```
microfips/
  Cargo.toml                    # Workspace: core, link, sim, protocol, esp32 (firmware excluded for CI)
  AGENTS.md                     # Build/flash/test/debug reference (authoritative)
  rust-toolchain.toml           # Nightly Rust (no pinned date)
  crates/
    microfips/                  # STM32 firmware (package name: microfips)
      build.rs                  # Linker flags: --nmagic, -Tlink.x
      .cargo/config.toml        # probe-rs runner config (local debug only)
      src/main.rs               # FIPS leaf node firmware (4-LED state machine, uses Node)
    microfips-esp32/            # ESP32 firmware (package name: microfips-esp32)
      src/main.rs               # FIPS leaf node (hand-rolled protocol, 1-LED, UART transport)
    microfips-core/             # no_std FIPS protocol: Noise IK/XK, FMP, FSP, identity
    microfips-link/             # Host-side handshake test (UDP, --keygen, env var keys)
    microfips-sim/              # Host-side simulator using Node from microfips-protocol
    microfips-http-test/        # FIPS responder for integration tests (UDP, env var keys)
    microfips-protocol/         # no_std FIPS protocol state machine: Transport trait, framing, Node
  tools/
    serial_udp_bridge.py        # Single-hop serial↔UDP bridge (recommended)
    serial_tcp_proxy.py         # Serial↔TCP proxy (legacy 3-hop pipeline)
    fips_bridge.py              # TCP↔UDP bridge (runs on VPS, legacy)
  scripts/
    test_hw_handshake.sh        # Automated hardware test with cleanup + assertions
  docs/
    architecture.md             # Protocol and transport details
    milestones.md               # M0-M10 tracking
    adr/                        # Architecture decision records
```

## License

MIT OR Apache-2.0
