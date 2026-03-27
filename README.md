# microfips

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO.

A Rust embedded firmware that implements a leaf-only FIPS node on an STM32F469 board
using Embassy for async HAL, USB CDC ACM for serial transport, length-prefixed
framing, Noise_IK handshake, and a no_std FIPS protocol stack.

## Current Status

**What works:**
- 55 unit tests pass for protocol logic (Noise, FMP, FSP, identity)
- Host-side handshake test (`microfips-link`) proven against live VPS, returns proper exit codes
- Host-side simulator (`microfips-sim`) proven 70+ seconds sustained heartbeat against live VPS
- USB CDC ACM enumeration and bidirectional data transfer
- Firmware builds for `thumbv7em-none-eabi` (207 KB, CI verified with .text validation)
- CI pipeline: 5 jobs all green (test, build-host, lint, sim-smoke, build-firmware, summary)

**Current blocker:**
- Hardware heartbeat exchange: EPENA gets stuck after first `write_packet()` (MSG1).
  EPENA recovery code is in the embassy fork but not yet proven on hardware.

## Architecture

```
  STM32F469I-DISCO          Host (Linux)               VPS
  +----------------+    +-------------------+    +------------------+
  | microfips fw   |    | serial_tcp_proxy  |    | fips_bridge.py   |
  |                |CDC | (auto-detect MCU) |TCP | --tcp localhost  |
  | FIPS protocol  |<-->|                   |<-->|                  |
  | Noise_IK       |    | serial <-> TCP    |SSH | UDP <-> TCP      |
  | FMP framing    |    |                   |-R  |                  |
  | Heartbeats     |    +-------------------+    +--------+---------+
  +----------------+                                     |
         ^                                              | UDP
         | USB OTG FS                                   v
    /dev/ttyACM*                                  +------------------+
                                                   | FIPS daemon     |
                                                   | port 2121       |
                                                   +------------------+
```

The bridge **must** run on the VPS because FIPS replies to the UDP packet's source
address. A local bridge would cause FIPS to reply to our public IP (unreachable).
When the bridge runs on the VPS, FIPS sees the source as `127.0.0.1:31337`,
which matches the configured peer address, so replies route correctly through
the SSH tunnel.

All data over CDC ACM uses **length-prefixed frames**: `[2-byte LE length][payload]`.

## MCU Identity

```
Secret:  ac68af89462e7ed26ff670c186b4eeb53c4e82d72c8ef6cec4e676c7843f832e
Pubkey:  02633860dc5f7ccb68df79362c9edf35e35e616d7ae86fcee268a2f749452b6842
npub:    npub1vdtfdhzl0n9k3hmexckfahe4ud0xzmt6aphuacng5tm5j3ftdppqj0ujhf
```

## Testing

### Unit tests (no hardware)

```sh
cargo test -p microfips-core                    # 55 tests: Noise, FMP, FSP, identity
cargo test -p microfips-core -- --nocapture     # verbose output
```

### Host-side VPS handshake (no hardware, raw UDP)

```sh
cargo run -p microfips-link                     # sends MSG1 to VPS via UDP
# Exit 0 = success, 1 = timeout (expected from unconfigured IP), 2 = error
```

### Host-side simulator (no hardware)

```sh
cargo run -p microfips-sim -- --listen 45679    # TCP server mode
cargo run -p microfips-sim 127.0.0.1:45679      # TCP client mode
cargo run -p microfips-sim                      # stdio mode
```

### Hardware (STM32F469)

See AGENTS.md for the full hardware test procedure.

```sh
# Flash (use st-flash, NOT probe-rs — see AGENTS.md)
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
st-flash --connect-under-reset write microfips.bin 0x08000000
```

## Build

Requires nightly Rust, `thumbv7em-none-eabi` target, and `arm-none-eabi-objcopy`.

```sh
# Add firmware to workspace members first (excluded by default for CI)
# In Cargo.toml: members = [..., "crates/microfips"]
cargo build -p microfips --release --target thumbv7em-none-eabi
```

## CI

GitHub Actions runs on push/PR to main, all on `ubuntu-latest`:
- **Unit Tests** — 55 tests in `microfips-core`
- **Build Host Tools** — `microfips-link` + `microfips-sim` release binaries + artifacts
- **Lint & Format** — clippy + rustfmt on core, link, sim
- **Simulator Smoke** — verify sim starts and exits cleanly on EOF
- **Build Firmware** — clones embassy fork, cross-builds for `thumbv7em-none-eabi`, validates .text size
- **Summary** — aggregate status table

## Hardware

- **Board:** STM32F469I-DISCO
- **MCU:** STM32F469NI (Cortex-M4F, 180 MHz, 1 MB Flash, 384 KB SRAM)
- **USB OTG FS:** PA11 (DM), PA12 (DP) — CDC ACM
- **LED:** PG6 (active high, user LED)
- **RNG:** HASH_RNG interrupt — hardware TRNG
- **Debug:** ST-LINK/V2.1 (PA13 SWDIO, PA14 SWCLK)
- **Clocks:** HSI 16 MHz + PLL → 168 MHz sys, 48 MHz USB (HSE bypass hangs)

## Milestones

| Milestone | Description | Status |
|-----------|-------------|--------|
| M0 | Environment, repo, scaffold | Done |
| M1 | USB CDC ACM enumeration + echo | Done |
| M2 | Length-prefixed framing over CDC | Done |
| M3 | Host-side handshake test (`microfips-link`) | Done |
| M4 | MCU handshake with live VPS | Done (MSG1 sent, MSG2 received, keys derived) |
| M5 | Host-side full lifecycle simulator (`microfips-sim`) | Done (proven 70+ seconds) |
| M6 | MCU full lifecycle (handshake + heartbeat exchange) | In Progress (EPENA stuck bug) |
| M7 | HTTP status page over FIPS session | Planned |

## Project Layout

```
microfips/
  Cargo.toml                    # Workspace: core, link, sim (firmware excluded for CI)
  AGENTS.md                     # Build/flash/test/debug reference
  rust-toolchain.toml           # Nightly Rust (no pinned date)
  crates/
    microfips/                  # MCU firmware (package name: microfips)
      build.rs                  # Linker flags: --nmagic, -Tlink.x, -Tdefmt.x
      .cargo/config.toml        # probe-rs runner config (local debug only)
      src/main.rs               # FIPS leaf node firmware
    microfips-core/             # no_std FIPS protocol: Noise, FMP, FSP, identity
    microfips-link/             # Host-side handshake test (UDP, exit codes)
    microfips-sim/              # Host-side full lifecycle simulator (framing over stdio/TCP)
  tools/
    fips_bridge.py              # CDC/TCP <-> UDP bridge (runs on VPS)
    serial_tcp_proxy.py         # Serial <-> TCP proxy (runs on host)
    test_sim_vps.sh             # VPS integration test for microfips-sim
  docs/
    architecture.md             # Protocol and transport details
    milestones.md               # M0-M7 tracking
    adr/                        # Architecture decision records
```

## License

MIT OR Apache-2.0
