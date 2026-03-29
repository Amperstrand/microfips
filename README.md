# microfips

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO.

A Rust embedded firmware that implements a leaf-only FIPS node on an STM32F469 board
using Embassy for async HAL, USB CDC ACM for serial transport, length-prefixed
framing, Noise_IK handshake, and a no_std FIPS protocol stack.

## Current Status

**M6 DONE — MCU full lifecycle proven on hardware (2026-03-28)**

The MCU completes an IK handshake with the live VPS and sustains heartbeat exchange
every ~10 seconds. Five bugs were found and fixed to get here (see below).

**What works:**
- 83 unit tests pass for protocol logic (Noise IK, Noise XK, FMP, FSP, identity)
- 26 unit tests pass for protocol crate (framing, transport, node)
- Host-side handshake test (`microfips-link`) proven against live VPS
- Host-side simulator (`microfips-sim`) proven 45+ seconds sustained heartbeat against live VPS
- USB CDC ACM enumeration with upstream embassy crates.io v0.6.0
- Firmware builds for `thumbv7em-none-eabi` (110 KB, CI verified)
- **MCU completes IK handshake with live VPS** — MSG1 sent, MSG2 received, keys derived
- **MCU sends heartbeats every ~10s** — proven on hardware, sustained 3+ minutes
- **Bridge forwards MCU heartbeats to FIPS** — no link dead timeout
- 4-LED state machine for visual debugging
- Embassy crates at latest upstream (all v0.6.0, published 2026-03-20)

**Bugs found and fixed this session:**

| # | Bug | Root Cause | Fix |
|---|-----|-----------|-----|
| 1 | recv_frame infinite loop | `continue` skipped `read_packet` on incomplete frames | Fall through to read always |
| 2 | Handshake discarded non-Msg2 | Stale FIPS data caused Err(Invalid) | Loop until Msg2 |
| 3 | steady() framing same pattern | Used `continue` in while loop | Used `break` |
| 4 | Bridge thread race | Old thread survived reconnect, two readers split TCP | Stop both before reconnect |
| 5 | Bridge CPU spin | No sleep in idle loop, GIL starvation | `time.sleep(0.001)` |

**Open issues:** #8 (proxy reconnection)

**Fork issue resolved (2026-03-28):**
The `Amperstrand/embassy` fork (commit `c0289d7a8`) breaks USB enumeration on STM32F469.
Switching all embassy deps to upstream crates.io v0.6.0 fixed it immediately.

**Key lessons:**
- `loop + continue` in async framing parsers: every code path must either return or await I/O
- Python threading: always join ALL threads before creating new ones on reconnect
- `pkill -f` kills the test's own SSH session — use PID-based kills
- SWD reset kills USB device — sequence operations: reset → enum → proxy → tunnel → bridge
- Infrastructure bugs look like firmware bugs — instrument all layers

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
cargo test -p microfips-core                    # 83 tests: Noise, FMP, FSP, identity
cargo test -p microfips-core -- --nocapture     # verbose output
cargo test -p microfips-protocol --features std -- --test-threads=1  # 26 tests: framing, transport, node
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
- **Unit Tests** — 83 tests in `microfips-core`
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
| M4 | MCU handshake with live VPS | Done |
| M5 | Host-side full lifecycle simulator (`microfips-sim`) | Done |
| M6 | MCU full lifecycle (handshake + heartbeat exchange) | **Done** — sustained 3+ min on hardware |
| M7 | HTTP status page over FIPS session | In progress |

### M6 sub-milestones (all done)

| ID | Description | Status |
|----|-------------|--------|
| M6.1 | MCU MSG1 reaches FIPS through full chain | Done |
| M6.2 | FIPS promotes MCU to active peer | Done |
| M6.3 | MSG2 returns through full chain to MCU | Done |
| M6.4 | MCU recv_frame handles multi-packet MSG2 | Done |
| M6.5 | MCU handshake completes (Noise IK finalize) | Done |
| M6.6 | MCU sends heartbeats every 10s | Done |
| M6.7 | Sustained heartbeat exchange (3+ min) | Done |

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
