# microfips

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO and ESP32-D0WD.

A Rust embedded firmware that implements leaf FIPS nodes using Embassy for async HAL,
Noise_IK/XK handshakes, FMP link framing, FSP session protocol, and a no_std FIPS
protocol stack. Both MCUs use `microfips-protocol::Node`, can participate in dual FSP
mode, and can expose application request/response traffic through the transport-neutral
`microfips-service` layer. Both MCUs connect to a FIPS VPS via host bridges (serial or BLE).
ESP32 also supports direct BLE L2CAP connection to a local FIPS daemon.

## Current Status

All core milestones (M0 through M9, M11) are complete. The project has proven end-to-end
encrypted communication across every supported transport: USB CDC serial, BLE GATT,
BLE L2CAP, WiFi, and host-side UDP simulators.

### Build Matrix (all compile-tested)

| Transport | ESP32-D0WD | ESP32-S3 | Hardware verified |
|-----------|-----------|----------|-------------------|
| UART | ✅ | ✅ | STM32 UART verified |
| BLE GATT | ✅ | ✅ | D0WD BLE bridge verified |
| BLE L2CAP | ✅ | ✅ | Both→FIPS verified |
| WiFi | ✅ | ✅ | Both verified |

Capabilities:
- **Noise_IK/XK handshakes** with live FIPS VPS on both STM32 and ESP32
- **FSP session protocol** with encrypted PING/PONG between any two peers (sim-to-sim, sim-to-MCU, MCU-to-MCU)
- **Dual FSP mode** on both MCUs (initiator + responder targeting each other)
- **ESP32 BLE GATT transport** (Python bridge, feature-gated behind `--features ble`)
- **ESP32 BLE L2CAP transport** (direct to local FIPS daemon, PSM 133, feature-gated behind `--features l2cap`)
- **ESP32 WiFi transport** (direct UDP to FIPS, feature-gated behind `--features wifi`)
- **Bridge auto-reconnect** on serial port failure for both STM32 (USB CDC) and ESP32 (CP210x)
- **ESP32 control interface** over UART0 (BLE/L2CAP/WiFi variants) with `show_status`, `show_peers`, `show_stats`, `help`, `version`, `reset`
- **Shared ESP32 crates** (`microfips-esp-common` + `microfips-esp-transport`) eliminate code duplication between D0WD and S3
- **Both ESP32s hardware-verified** over L2CAP to local FIPS daemon (D0WD via peripheral, S3 via central)
- **CI pipeline** with unit tests, lint, firmware cross-build, sim-to-sim ping E2E, FIPS integration, and ESP32 builds

### Known Issues
- ESP32-D0WD L2CAP scan does not find Linux FIPS daemon (connects via peripheral path instead — FIPS scans and connects to D0WD)
- ESP32-S3 WiFi steady state: connects but heartbeat cycle fails (link-dead after 30s)
- Embassy task files (ble_host, l2cap_host, control) still duplicated between chip crates (~2400 lines remaining)

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
  | FIPS protocol  |UART| (single-hop)      |UDP --+
  | Noise_IK       |<-->|                   |<-->   |
  | FMP + FSP      |    +-------------------+       |
  +----------------+    +-------------------+       |
  | microfips-esp32|    | ble_udp_bridge    |       |
  | FIPS protocol  |BLE | (single-hop)      |UDP --+
  | Noise_IK       |<-->|                   |<-->   |
  | FMP + FSP      |    +-------------------+       |
  +----------------+                                  v
                                                +------------------+
  ESP32-D0WD (L2CAP)                            | FIPS daemon      |
  +----------------+                            | port 2121        |
  | microfips-esp32|                            |                  |
  | FIPS protocol  |BLE                         +------------------+
  | Noise_IK       |L2CAP  FIPS daemon (local)
  | FMP + FSP      |<----> PSM 133
  +----------------+

  ESP32-D0WD / ESP32-S3 (WiFi)
  +----------------+
  | microfips-esp32|     WiFi STA ----+
  | FIPS protocol  |     DHCP + DNS   |
  | Noise_IK       |<------------------ UDP ---> FIPS VPS (port 2121)
  | FMP + FSP      |
  +----------------+

  Simulator (host)                             | FIPS daemon      |
  +----------------+    +-------------------+  | port 2121        |
  | microfips-sim   |    | (none needed)     |  |                  |
  | uses Node from  |UDP | direct UDP        |->|                  |
  | microfips-proto |<-->|                   |  +------------------+
  +----------------+    +-------------------+
```

Transport options:
- **Serial bridge** (recommended): `serial_udp_bridge.py` sends UDP directly to FIPS
  from the host. No SSH tunnel or VPS-side bridge needed.
- **ESP32 WiFi** (direct): ESP32 connects directly to FIPS VPS via WiFi + UDP. Feature-gated
  behind `--features wifi`. Requires external antenna on D0WD. See AGENTS.md for full WiFi instructions.
- **ESP32 BLE bridge**: `ble_udp_bridge.py` bridges ESP32 BLE GATT to UDP. Feature-gated
  behind `--features ble`. See AGENTS.md for full BLE instructions.
- **ESP32 L2CAP direct**: ESP32 connects directly to local FIPS daemon via BLE L2CAP CoC.
  Feature-gated behind `--features l2cap`. No bridge needed. See AGENTS.md for full L2CAP instructions.
- **Legacy 3-hop** (deprecated): serial -> TCP proxy -> SSH tunnel -> VPS bridge -> FIPS

Each MCU runs the same FIPS stack (Noise_IK/XK, FMP, FSP) and connects through a
single-hop bridge. ESP32 additionally supports BLE GATT (`ble_udp_bridge`), BLE L2CAP
direct, and WiFi (direct UDP) transports.
Host-side simulators connect via direct UDP with no bridge at all.

Above the protocol/runtime crates, `microfips-service` provides a compact byte-oriented
request/response boundary for downstream apps. HTTP stays optional in the separate
`microfips-http-demo` crate.

All serial data uses **length-prefixed frames**: `[2-byte LE length][payload]`.
FIPS UDP transport uses **raw frames** (no length prefix).

### Bridge auto-reconnect

Both `serial_udp_bridge.py` and `serial_tcp_proxy.py` reconnect automatically on serial
port failure. The ESP32's CP210x USB-serial chip stays enumerated during CPU resets,
so the bridge survives transparently and continues forwarding once the ESP32 finishes
booting. STM32's USB CDC disappears on reset; the bridge detects ENODEV and reconnects
when the STM32 re-enumerates.

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
cargo test -p microfips-core                    # core protocol tests
cargo test -p microfips-core -- --nocapture     # verbose output
cargo test -p microfips-protocol --features std -- --test-threads=1  # protocol tests
cargo test -p microfips-service                 # service layer tests
cargo test -p microfips-http-demo --features http  # HTTP demo tests
```

### Key generation and VPS handshake (no hardware)

```sh
cargo run -p microfips-link -- --keygen              # generate keys
FIPS_SECRET=<hex> FIPS_PEER_PUB=<hex> cargo run -p microfips-link
FIPS_SECRET=<hex> FIPS_PEER_PUB=<hex> cargo run -p microfips-link -- 127.0.0.1:2121
# Exit 0 = success, 1 = timeout, 2 = error
```

### Sim-to-sim FSP ping through FIPS (no hardware)

Requires both sims to connect to the live FIPS VPS. SIM-A acts as FSP responder,
SIM-B as initiator. FIPS forwards SessionDatagrams between them.

```sh
# Terminal 1: SIM-A (responder)
cargo run -p microfips-sim --release -- --udp orangeclaw.dns4sats.xyz:2121 --sim-a

# Terminal 2: SIM-B (initiator, exits on PONG)
cargo run -p microfips-sim --release -- --udp orangeclaw.dns4sats.xyz:2121 --sim-b --test-ping
```

### Sim-to-MCU FSP ping (hardware: STM32 required)

STM32 must be connected via serial bridge (see AGENTS.md for hardware setup).

```sh
st-flash --connect-under-reset reset && sleep 8
python3 tools/serial_udp_bridge.py --serial /dev/ttyACM1 --udp-host orangeclaw.dns4sats.xyz &

FIPS_SECRET=0303030303030303030303030303030303030303030303030303030303030303 \
  cargo run -p microfips-sim --release -- \
  --udp orangeclaw.dns4sats.xyz:2121 --initiator --target 132f39a98c31baaddba6525f5d43f295 --test-ping
# Expected: "*** PONG received from target! ***" (exit 0)
```

### Hardware tests

See AGENTS.md for full hardware test procedures, flash commands, and the LED state machine.

```sh
# STM32 flash
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
st-flash --connect-under-reset write microfips.bin 0x08000000

# ESP32 flash (UART variant)
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  espflash flash -p /dev/ttyUSB0 --chip esp32 \
  target/xtensa-esp32-none-elf/release/microfips-esp32

# ESP32 BLE variant
espflash flash -p /dev/ttyUSB0 --chip esp32 \
  target/xtensa-esp32-none-elf/release/microfips-esp32-ble

# ESP32 L2CAP variant
espflash flash -p /dev/ttyUSB0 --chip esp32 \
  target/xtensa-esp32-none-elf/release/microfips-esp32-l2cap
```

## ESP32 Control Interface (BLE and L2CAP variants)

When BLE or L2CAP transport is active, UART0 exposes a FIPS-compatible control interface
for runtime inspection. Send line-delimited commands, receive JSON responses.

| Command | Description |
|---------|-------------|
| `show_status` | Node address, npub, connection state, uptime, transport type |
| `show_peers` | Peer node address and pubkey (error if no peer) |
| `show_stats` | Protocol counters: msg1_tx, msg2_rx, hb_tx, hb_rx, data_tx, data_rx |
| `help` | List of available commands |
| `version` | Firmware version string |
| `reset` | Software reset via RTC_CNTL SW_SYS_RST |

Response format: `{"status":"ok","data":{...}}` or `{"status":"error","message":"..."}`.
See `tools/test_control.py` for automated testing and AGENTS.md for full details.

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

### ESP32 Structured Logging (BLE/L2CAP variants)

BLE and L2CAP firmware variants use the `log` crate with FIPS-compatible format on UART0:
`[LEVEL module_path] message`. Log output is interleaved with control interface responses.

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
# UART variant (default) -> microfips-esp32
# BLE variant (--features ble) -> microfips-esp32-ble
# L2CAP variant (--features l2cap) -> microfips-esp32-l2cap
# WiFi variant (--features wifi) -> microfips-esp32-wifi
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc
# Add --features ble, --features l2cap, or --features wifi for alternate transports
```

Each variant outputs to its own binary. No build order dependency between variants.

## CI

GitHub Actions runs on push/PR to main. See `.github/workflows/ci.yml` for full job definitions.

- **Unit Tests** -- `cargo test` across core, protocol, service, and http-demo crates
- **Golden Vectors** -- drift check against upstream FIPS reference + `cargo test --test golden_vectors`
- **Noise Compliance** -- deviation documentation checks, specific protocol tests, 10-round stability checks for IK/XK transport keys and FSP handshakes
- **Build Host Tools** -- `microfips-link`, `microfips-sim`, `microfips-http-test`, `microfips-http-demo` release binaries
- **Lint & Format** -- clippy + rustfmt on all host crates
- **Sim Smoke** -- verify simulator starts and exits cleanly on EOF
- **Sim-to-Sim Ping** -- SIM-B -> FIPS -> SIM-A FSP PING/PONG (must pass)
- **FIPS Handshake Integration** -- local Noise IK handshake (must pass) + public VPS (continue-on-error)
- **Build Firmware** -- STM32 (`thumbv7em-none-eabi`) + ESP32 UART + ESP32 BLE variants
- **Summary** -- aggregate status table

### Environment variables for key override

All host tools accept key overrides via environment variables:

| Variable | Format | Used by | Purpose |
|----------|--------|---------|---------|
| `FIPS_SECRET` | 64 hex chars (32B secret) | fips-handshake, microfips-sim, microfips-http-test | Override identity secret key |
| `FIPS_PEER_PUB` | 66 hex chars (33B compressed pubkey) | fips-handshake, microfips-sim | Override peer's public key |

Host tools do not fall back to hardcoded identities anymore. Set both variables explicitly.

## Hardware

### STM32F469I-DISCO
- **MCU:** STM32F469NI (Cortex-M4F, 180 MHz, 1 MB Flash, 384 KB SRAM)
- **USB OTG FS:** PA11 (DM), PA12 (DP) -- CDC ACM
- **LEDs:** PG6 (green), PD4 (orange), PD5 (red), PK3 (blue) -- active high
- **RNG:** HASH_RNG interrupt -- hardware TRNG
- **Debug:** ST-LINK/V2.1 (PA13 SWDIO, PA14 SWCLK)
- **Clocks:** HSI 16 MHz + PLL -> 168 MHz sys, 48 MHz USB (HSE bypass hangs)
- **USB VID:PID:** `c0de:cafe` (CDC ACM, detected as `/dev/ttyACM*`)
- **Flash:** `st-flash --connect-under-reset write` (NOT probe-rs during USB testing)

### ESP32-D0WD
- **MCU:** ESP32-D0WD (Xtensa LX6, 240 MHz, 4 MB Flash)
- **UART:** GPIO1 (TX), GPIO3 (RX) -- CP210x USB-serial
- **WiFi:** 802.11 b/g/n 2.4 GHz (requires external antenna)
- **BLE:** Internal esp-radio BLE controller (antenna on-board)
- **LED:** GPIO2 (blue onboard, active high)
- **USB VID:PID:** `10c4:ea60` (Silicon Labs CP210x, detected as `/dev/ttyUSB*`)
- **Flash:** `espflash flash -p /dev/ttyUSB0 --chip esp32` (NOT probe-rs)
- Runs the same FIPS protocol stack as STM32 (Noise_IK, FMP, FSP dual mode).

### ESP32-S3 (TiLDAGON)
- **MCU:** ESP32-S3, 8 MB Flash
- **WiFi:** 802.11 b/g/n 2.4 GHz (requires external antenna)
- **Serial:** USB Serial JTAG (VID:PID `303a:1001`, detected as `/dev/ttyACM*`)
- **Flash:** `espflash flash -p /dev/ttyACM<N> --chip esp32s3` (NOT esptool --no-stub)
- Uses `microfips-esp32` crate with shared `microfips-esp-common` (DNS, config, stats)
- Separate node identity from D0WD (secret `0x05` vs `0x02`)

### Shared ESP32 code
- **`microfips-esp-common`** — chip-agnostic shared crate: DNS resolver, config constants,
  stats counters, node info (no esp-hal dependency)
- Both `microfips-esp32` (D0WD) and `microfips-esp32s3` (S3) depend on it

## Known Issues

| Issue | Description | Status |
|-------|-------------|--------|
| ESP32-S3 steady state | WiFi connects and DNS resolves, but `HandshakeOk` → `Disconnected` cycle. S3 never sends heartbeats back to FIPS. FIPS drops link after 30s. Under investigation — likely a timing or transport issue in the steady-state loop. | Open |
| WiFi control interface | Control interface (`show_status` etc.) not responding on WiFi variant. Logger and control share UART0 TX — RX path may need separate initialization. | Open |

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
| M8 | Sim-to-MCU FSP ping through FIPS | Done |
| M9 | MCU-to-MCU ping (STM32 <-> ESP32 through FIPS) | Done |
| M10 | FIPS DNS resolution (`.fips` names) | Future |
| M11 | ESP32 L2CAP direct transport to FIPS daemon | Done |

## Project Layout

```
microfips/
  Cargo.toml                    # Workspace: core, protocol, service, link, sim, esp32, etc.
  AGENTS.md                     # Build/flash/test/debug reference (authoritative)
  rust-toolchain.toml           # Nightly Rust (no pinned date)
  crates/
    microfips/                  # STM32 firmware (package name: microfips)
      build.rs                  # Linker flags: --nmagic, -Tlink.x
      .cargo/config.toml        # probe-rs runner config (local debug only)
      src/main.rs               # FIPS leaf node firmware (4-LED state machine, uses Node)
    microfips-esp32/            # ESP32-D0WD firmware (package name: microfips-esp32)
      src/lib.rs                # Re-exports from esp-transport + chip-specific config/tasks
      src/config.rs             # D0WD secret, register addresses, BLE/L2CAP constants
      src/{ble,l2cap}_host.rs   # Embassy tasks (chip-specific statics + secret refs)
      src/control.rs            # UART control interface (chip-specific register addresses)
      src/bin/{uart,ble,l2cap,wifi}.rs  # Binary entry points (chip-specific GPIO/pins)
    microfips-esp32s3/          # ESP32-S3 variant (package name: microfips-esp32s3)
    microfips-esp-transport/    # Shared ESP32 transport code (led, rng, stats, handlers, etc.)
    microfips-esp-common/       # Chip-agnostic ESP32 code (DNS, config, UDP transport)
    microfips-core/             # no_std FIPS protocol: Noise IK/XK, FMP, FSP, identity
    microfips-protocol/         # no_std FIPS protocol state machine: Transport trait, framing, Node
    microfips-service/          # Transport-neutral request/response layer
    microfips-http-demo/        # Optional HTTP adapter and demo service
    microfips-link/             # Host-side handshake test (UDP, --keygen, env var keys)
    microfips-sim/              # Host-side simulator using Node from microfips-protocol
    microfips-http-test/        # FIPS responder for integration tests (UDP, env var keys)
    fips-decrypt/               # FIPS decrypt tool
  tools/
    serial_udp_bridge.py        # Single-hop serial<->UDP bridge (recommended)
    ble_udp_bridge.py           # Single-hop BLE<->UDP bridge (ESP32, feature-gated)
    serial_tcp_proxy.py         # Serial<->TCP proxy (legacy 3-hop pipeline)
    fips_bridge.py              # TCP<->UDP bridge (runs on VPS, legacy)
    fips_dissector.lua          # Wireshark Lua dissector for FMP frames
    capture_fips.sh             # PCAP capture helper
    reference.pcap              # Reference capture from sim-to-sim FSP PING test
    test_control.py             # ESP32 control interface test tool
    test_ble_bridge.py          # BLE bridge test tool
    test_sim_vps.sh             # Sim-to-VPS test helper
  scripts/
    test_hw_handshake.sh        # Automated hardware handshake test
    test_mcu_to_mcu_fsp.sh      # MCU-to-MCU FSP E2E test
    test_dual_mcu.sh            # Dual-MCU simultaneous test
    setup-vps-peer.sh           # VPS peer configuration
    install-fips-service.sh     # FIPS systemd service installation
    start-fips.sh               # FIPS daemon startup helper
    ci-fips-node.sh             # CI FIPS node setup
  docs/
    architecture.md             # Protocol and transport details
    milestones.md               # M0-M11 tracking
    adr/                        # Architecture decision records
```

## License

MIT OR Apache-2.0
