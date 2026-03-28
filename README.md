# microfips

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO.

A Rust embedded firmware that implements a leaf-only FIPS node on an STM32F469 board
using Embassy for async HAL, USB CDC ACM for serial transport, length-prefixed
framing, Noise_IK handshake, and a no_std FIPS protocol stack.

## Current Status

**What works:**
- 71 unit tests pass for protocol logic (Noise IK, Noise XK, FMP, FSP, identity)
- 10 unit tests pass for protocol crate (framing, transport, node)
- Host-side handshake test (`microfips-link`) proven against live VPS, returns proper exit codes
- Host-side simulator (`microfips-sim`) proven 45+ seconds sustained heartbeat against live VPS
- USB CDC ACM enumeration with upstream embassy crates.io v0.6.0
- Firmware builds for `thumbv7em-none-eabi` (110 KB, CI verified)
- CI pipeline: all jobs green
- Full-chain data flow proven: MCU sends MSG1 (114B) through CDC → proxy → SSH tunnel → bridge → FIPS
- VPS confirms "Connection promoted to active peer" and responds with MSG2 (69B)
- 4-LED state machine for visual debugging (boot, usb_ready, msg1_sent, handshake_ok, hb_tx, hb_rx, err, disconnected)

**Fork issue resolved (2026-03-28):**
The `Amperstrand/embassy` fork (commit `c0289d7a8`) breaks USB enumeration on STM32F469.
Switching all embassy deps to upstream crates.io v0.6.0 fixed it immediately.
Only `embassy-usb-synopsys-otg/src/lib.rs` was modified in the fork (4 patches).

**Framing bug found and fixed (2026-03-28):**
`recv_frame()` discarded the frame header when the body was incomplete (setting `rpos = rlen`
for "not enough data yet"). This is the root cause of the MCU MSG2 drop (#6). The 71-byte
MSG2 frame (2B header + 69B payload) arriving across USB 64-byte packet boundaries would
trigger the incomplete-frame path, losing the header. Fix: only skip invalid frames
(ml==0, ml>MAX_FRAME); wait for more data when the frame is simply incomplete.
The fix is in `microfips-protocol` and needs to be backported to the firmware `main.rs`.

**Known infrastructure issues:**
- `serial_tcp_proxy.py` takes 5-10s to open serial port (pyserial delay), causing it to miss
  the MCU's first MSG1. Workaround: start proxy immediately after MCU reset via `--reset` flag.
- Proxy cannot survive USB device resets (dies on ENODEV when MCU resets mid-session).
- CI firmware build job still clones the broken embassy fork instead of using crates.io.
- See [issues](https://github.com/Amperstrand/microfips/issues) for details (#6 MSG2 bug, #7 transport trait, #8 proxy, #9 CI).

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
cargo test -p microfips-core                    # 71 tests: Noise, FMP, FSP, identity
cargo test -p microfips-core -- --nocapture     # verbose output
cargo test -p microfips-protocol --features std -- --test-threads=1  # 10 tests: framing, transport, node
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

See AGENTS.md for the full hardware test procedure and LED state machine.

```sh
# Flash (use st-flash, NOT probe-rs — see AGENTS.md)
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
st-flash --connect-under-reset write microfips.bin 0x08000000
```

### Hardware handshake test (automated)

```sh
# Set VPS credentials in environment first
export VPS_HOST=orangeclaw.dns4sats.xyz VPS_USER=routstr VPS_PASS=<password>
bash scripts/test_hw_handshake.sh
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
- **Unit Tests** — 71 tests in `microfips-core`
- **Build Host Tools** — `microfips-link` + `microfips-sim` release binaries + artifacts
- **Lint & Format** — clippy + rustfmt on core, link, sim
- **Simulator Smoke** — verify sim starts and exits cleanly on EOF
- **Build Firmware** — clones embassy fork, cross-builds for `thumbv7em-none-eabi`, validates .text size
- **Summary** — aggregate status table

## Hardware

- **Board:** STM32F469I-DISCO
- **MCU:** STM32F469NI (Cortex-M4F, 180 MHz, 1 MB Flash, 384 KB SRAM)
- **USB OTG FS:** PA11 (DM), PA12 (DP) — CDC ACM
- **LEDs:** PG6 (green), PD4 (orange), PD5 (red), PK3 (blue) — active high
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
| M5 | Host-side full lifecycle simulator (`microfips-sim`) | Done (proven 45+ seconds sustained heartbeat) |
| M6 | MCU full lifecycle (handshake + heartbeat exchange) | **Unblocked** — framing bug found and fixed in protocol crate, needs firmware backport |
| M6.5 | Host-side transport trait for firmware protocol testing | Done — `microfips-protocol` crate with Transport trait, MockTransport, 10 tests |
| M7 | HTTP status page over FIPS session | Planned |

## Project Layout

```
microfips/
  Cargo.toml                    # Workspace: core, link, sim, protocol (firmware excluded for CI)
  AGENTS.md                     # Build/flash/test/debug reference
  rust-toolchain.toml           # Nightly Rust (no pinned date)
  crates/
    microfips/                  # MCU firmware (package name: microfips)
      build.rs                  # Linker flags: --nmagic, -Tlink.x
      .cargo/config.toml        # probe-rs runner config (local debug only)
      src/main.rs               # FIPS leaf node firmware (4-LED state machine)
    microfips-core/             # no_std FIPS protocol: Noise, FMP, FSP, identity
    microfips-link/             # Host-side handshake test (UDP, exit codes)
    microfips-sim/              # Host-side full lifecycle simulator (framing over stdio/TCP)
    microfips-protocol/         # no_std FIPS protocol state machine: Transport trait, framing, Node
  tools/
    fips_bridge.py              # CDC/TCP <-> UDP bridge (runs on VPS)
    serial_tcp_proxy.py         # Serial <-> TCP proxy (runs on host)
    test_sim_vps.sh             # VPS integration test for microfips-sim
  scripts/
    test_hw_handshake.sh        # Automated hardware test with cleanup + assertions
  docs/
    architecture.md             # Protocol and transport details
    milestones.md               # M0-M7 tracking
    adr/                        # Architecture decision records
```

## License

MIT OR Apache-2.0
