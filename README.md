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
- 87 unit tests pass for protocol logic (Noise IK, Noise XK, FMP, FSP, identity)
- 26 unit tests pass for protocol crate (framing, transport, node)
- Host-side handshake test (`microfips-link`) proven against live VPS
- Host-side simulator (`microfips-sim`) uses `Node` from `microfips-protocol` (no duplicated protocol logic)
- **CI integration test** — fresh key pairs per run, local Noise IK handshake verified
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
  [ESP32 WiFi mode]                                         VPS
  ESP32 --WiFi--------------------------------------------------> FIPS daemon
            UDP port 2121 (raw FMP frames, no bridge)              port 2121

  [Serial mode -- STM32 or ESP32]
  MCU                    Host (Linux)               VPS
  +----------------+  +--------------------+  +------------------+
  | microfips fw   |  | serial_udp_bridge  |  |                  |
  |                |<>| (auto-detect MCU)  |<>| FIPS daemon      |
  | FIPS protocol  |  | serial <-> UDP     |  | port 2121        |
  | Noise_IK       |  +--------------------+  +------------------+
  | FMP framing    |
  +----------------+
```

**ESP32 (WiFi mode):** Connects directly to the FIPS VPS via UDP over WiFi -- no bridge
or host PC needed. Each UDP datagram = one raw FMP frame.

**ESP32/STM32 (serial mode):** Length-prefixed CDC/UART frames forwarded by
`serial_udp_bridge.py` on the host. Required when WiFi is unavailable or not configured.

### ESP32 credential setup (`secrets.rs`)

All device-specific credentials live in a gitignored file:
`crates/microfips-esp32/src/secrets.rs`

```sh
cp crates/microfips-esp32/src/secrets.rs.example \
   crates/microfips-esp32/src/secrets.rs
# then edit the file with your values:
$EDITOR crates/microfips-esp32/src/secrets.rs
```

| Constant | Description | Example |
|----------|-------------|---------|
| `WIFI_SSID` | WiFi network name. **Leave empty `""` to skip WiFi and use serial UART.** | `"MyNetwork"` |
| `WIFI_PASS` | WPA2 password | `"hunter2"` |
| `FIPS_HOST` | FIPS VPS IP address (dotted-quad -- DNS not yet implemented) | `"165.22.195.26"` |
| `FIPS_PORT` | FIPS VPS UDP port | `2121` |
| `DEVICE_SECRET` | 32-byte identity secret key (generate with `--keygen`, see below) | `[0x00, ..., 0x02]` |
| `MY_NODE_ADDR` | 16-byte node address derived from `DEVICE_SECRET` | `[0x01, 0x35, ...]` |
| `PEER_PUB` | 33-byte compressed pubkey of the peer (STM32) | `[0x02, 0x79, ...]` |
| `PEER_NODE_ADDR` | 16-byte node address of the peer (STM32) | `[0x13, 0x2f, ...]` |
| `DEVICE_ALIAS` | Friendly name printed at boot | `"esp32-leaf"` |

**Boot sequence:**
1. If `WIFI_SSID` is non-empty -- attempt WiFi (15s association timeout + 20s DHCP timeout)
2. If WiFi succeeds -- run FIPS over UDP directly to VPS (no bridge/host needed)
3. If WiFi fails or `WIFI_SSID` is empty -- fall back to serial UART + `serial_udp_bridge.py`

## MCU Identities (deterministic pattern keys)

| MCU | Secret (last byte) | npub | node_addr |
|-----|-------------------|------|-----------|
| STM32 (`DEFAULT_SECRET`) | `...0x01` | `npub10xlxvlhemwtlxywh66s5xdtsgnfzqsvqkxnkjrfp2q5tml4dhmaqpj9tnz` | `132f39a98c31baaddba6525f5d43f295` |
| ESP32 (`DEVICE_SECRET` in `secrets.rs`) | `...0x02` | `npub1ccz8l9zpa47k6vz9gphftsrumpw80rjt3nhnefat4symjhrsnmjs38mnyd` | `0135da2f8acf7b9e3090939432e47684` |
| SIM-A | `...0x03` | `npub1lycg5qvsknxwrrrhlmdyxz0lwnge7w36lj7hm5n56grnz4p6fdsswcekyz` | `7c79f3071e28344e8153bf6c73c294eb` |
| SIM-B | `...0x04` | `npub1ujfahuwpn0fpf5j0jzm33fzs78g5jxdxelp5vms4qkd0w4uq3j6s7dtujw` | `36be1ea4d814af2888b895065a0b2538` |
| VPS | (DEFAULT_PEER_PUB) | `npub1wwsqf76nzh9jfm96jhxw3rge7yvwdj3vgzxcwt2lrn5wre52w80qhf8xt0` | `73a004fb58cb41616c2b5ef4bd801a9b` |

All keys use the secp256k1 generator point multiplied by N (1..5). Verified by
`audit_all_hardcoded_keys` test in `microfips-core`. To use custom keys see
`Key generation` below and set `DEVICE_SECRET` in `secrets.rs`.

## Testing

### Unit tests (no hardware)

```sh
cargo test -p microfips-core                    # 87 tests: Noise, FMP, FSP, identity
cargo test -p microfips-core -- --nocapture     # verbose output
cargo test -p microfips-protocol --features std -- --test-threads=1  # 26 tests: framing, transport, node
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

### Local handshake test (no hardware, no VPS)

```sh
# Generate fresh key pairs
NODE_KEYS=$(cargo run -p microfips-link -- --keygen)
NODE_SECRET=$(echo "$NODE_KEYS" | sed -n 's/^FIPS_SECRET=//p')
NODE_PUB=$(echo "$NODE_KEYS" | sed -n 's/^FIPS_PUB=//p')

LEAF_KEYS=$(cargo run -p microfips-link -- --keygen)
LEAF_SECRET=$(echo "$LEAF_KEYS" | sed -n 's/^FIPS_SECRET=//p')

# Start responder (background)
FIPS_SECRET=$NODE_SECRET cargo run -p microfips-http-test -- 127.0.0.1:31338 &

# Run initiator handshake
FIPS_SECRET=$LEAF_SECRET FIPS_PEER_PUB=$NODE_PUB \
  cargo run -p microfips-link -- 127.0.0.1:31338
# Expect: "SUCCESS: FIPS handshake completed!"
```

### Host-side simulator (no hardware)

```sh
cargo run -p microfips-sim -- --listen 45679    # TCP server mode
cargo run -p microfips-sim 127.0.0.1:45679      # TCP client mode
cargo run -p microfips-sim                      # stdio mode

# With custom keys:
FIPS_SECRET=<hex> FIPS_PEER_PUB=<hex> cargo run -p microfips-sim -- --listen 45679
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
- **Unit Tests** — 87 tests in `microfips-core`, 26 tests in `microfips-protocol`
- **Build Host Tools** — `microfips-link` + `microfips-sim` + `microfips-http-test` release binaries
- **Lint & Format** — clippy + rustfmt on all host crates
- **Simulator Smoke** — verify sim starts and exits cleanly on EOF
- **FIPS Handshake Integration** — two tests per run:
  1. **Local**: generates fresh key pairs, starts http-test as responder, runs leaf handshake (must pass)
  2. **Public**: attempts handshake with `orangeclaw.dns4sats.xyz:2121` using default MCU identity (best-effort, VPS may be unreachable)
- **Build Firmware** — cross-builds for `thumbv7em-none-eabi`, validates .text size
- **Summary** — aggregate status table

### Environment variables for key override

All host tools accept key overrides via environment variables:

| Variable | Format | Used by | Purpose |
|----------|--------|---------|---------|
| `FIPS_SECRET` | 64 hex chars (32B secret) | fips-handshake, microfips-sim, microfips-http-test | Override identity secret key |
| `FIPS_PEER_PUB` | 66 hex chars (33B compressed pubkey) | fips-handshake, microfips-sim | Override peer's public key |

When not set, tools fall back to hardcoded defaults (MCU dev identity / VPS pubkey).

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
    microfips/                  # STM32F469 firmware (USB CDC ACM transport)
      build.rs                  # Linker flags: --nmagic, -Tlink.x
      .cargo/config.toml        # probe-rs runner config (local debug only)
      src/main.rs               # FIPS leaf node firmware (4-LED state machine)
    microfips-esp32/            # ESP32 firmware (WiFi UDP or UART serial transport)
      src/main.rs               # FIPS leaf node firmware (WiFi-first, UART fallback)
      src/secrets.rs.example    # Credential template -- copy to secrets.rs (gitignored)
      src/secrets.rs            # [gitignored] WIFI_SSID, WIFI_PASS, FIPS_HOST, keys
    microfips-core/             # no_std FIPS protocol: Noise, FMP, FSP, identity
    microfips-link/             # Host-side handshake test (UDP, --keygen, env var keys)
    microfips-sim/              # Host-side simulator using Node from microfips-protocol
    microfips-http-test/        # FIPS responder for integration tests (UDP, env var keys)
    microfips-protocol/         # no_std FIPS protocol state machine: Transport trait, framing, Node
  tools/
    fips_bridge.py              # CDC/TCP <-> UDP bridge (runs on VPS)
    serial_tcp_proxy.py         # Serial <-> TCP proxy (runs on host)
    test_sim_vps.sh             # VPS integration test for microfips-sim
  scripts/
    test_hw_handshake.sh        # Automated hardware test with cleanup + assertions
    ci-fips-node.sh             # Build and run full FIPS node for CI (future use)
  docs/
    architecture.md             # Protocol and transport details
    milestones.md               # M0-M7 tracking
    adr/                        # Architecture decision records
```

## License

MIT OR Apache-2.0
