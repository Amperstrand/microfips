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
| `FIPS_PUB` | 33-byte compressed pubkey of the FIPS node (IK peer). Default: VPS pubkey. For local testing: set to the sim/test node's pubkey. | `[0x02, 0x0e, ...]` |
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

### Testing ESP32 over WiFi with a local simulator (no VPS needed)

This test verifies the full WiFi→UDP→Noise IK→heartbeat path using a laptop as
the FIPS node. No VPS or serial bridge required — the ESP32 talks directly to
`microfips-http-test` over your local WiFi network.

**1. Choose keys.** Use the deterministic pattern keys for simplicity:

| Role | Secret (last byte) | Pubkey (hex) |
|------|-------------------|--------------|
| Laptop (FIPS node) | `...0x03` (SIM-A) | `02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9` |
| ESP32 | `...0x02` (default) | `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` |

**2. Configure ESP32 `secrets.rs`.** Copy the template and edit:

```sh
cp crates/microfips-esp32/src/secrets.rs.example \
   crates/microfips-esp32/src/secrets.rs
```

Set these values in `secrets.rs`:

```rust
pub const WIFI_SSID: &str = "YourWiFiNetwork";   // your WiFi SSID
pub const WIFI_PASS: &str = "YourWiFiPassword";  // your WiFi password
pub const FIPS_HOST: &str = "192.168.1.100";      // your laptop's LAN IP
pub const FIPS_PORT: u16 = 2121;

// SIM-A pubkey (the laptop's identity):
pub const FIPS_PUB: [u8; 33] = [
    0x02, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3,
    0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52,
    0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99,
    0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36,
    0xf9,
];
```

Leave `DEVICE_SECRET` as the default (`...0x02`).

**3. Build and flash the ESP32:**

```sh
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc
espflash flash -p /dev/ttyUSB0 --chip esp32 \
  target/xtensa-esp32-none-elf/release/microfips-esp32
```

**4. Start the FIPS responder on your laptop:**

```sh
# SIM-A secret (0x03), ESP32 pubkey as peer:
FIPS_SECRET=0000000000000000000000000000000000000000000000000000000000000003 \
FIPS_PEER_PUB=02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 \
  cargo run -p microfips-http-test -- 0.0.0.0:2121
```

**5. Expected output:**

On the laptop (microfips-http-test):
```
Received 114 bytes from 192.168.1.42:xxxxx
  MSG1: sender_idx=0, noise_payload=110B
  Sending MSG2: 69 bytes
  Heartbeat (ctr=0)
  Heartbeat (ctr=1)
  ...
```

On the ESP32 serial monitor:
```
microfips-esp32 (esp32-leaf) booting
WiFi: connecting to "YourWiFiNetwork"...
WiFi: link up
WiFi: IP 192.168.1.42
TRANSPORT: WiFi UDP -> 192.168.1.100:2121
```

The ESP32 LED turns on when MSG1 is sent and stays on after handshake completes.
Heartbeats continue every 10 seconds.

**Troubleshooting:**
- Verify laptop IP: `ip addr show` or `ifconfig` (use the WiFi interface address)
- Firewall: ensure UDP port 2121 is open (`sudo ufw allow 2121/udp`)
- If ESP32 falls back to serial: check WIFI_SSID spelling and WPA password
- DNS not supported: `FIPS_HOST` must be a dotted-quad IP, not a hostname

## BLE Gateway (research)

**Goal:** Add BLE (Bluetooth Low Energy) as a third transport option, parallel to
WiFi (direct UDP) and serial UART (via `serial_udp_bridge.py`). A host-side BLE
gateway would bridge BLE↔UDP, analogous to how `serial_udp_bridge.py` bridges
serial↔UDP today.

### Architecture

```
  [BLE mode]
  ESP32                    Host (Linux/macOS)              VPS
  +----------------+  +------------------------+  +------------------+
  | microfips fw   |  | ble_udp_bridge.py      |  |                  |
  |                |~~| BLE GATT <-> UDP       |~~| FIPS daemon      |
  | FIPS protocol  |  | (length-prefixed FMP)  |  | port 2121        |
  | Noise_IK       |  +------------------------+  +------------------+
  | BLE GATT server|
  +----------------+
```

### Transport design

| Aspect | Serial bridge (`serial_udp_bridge.py`) | BLE bridge (`ble_udp_bridge.py`) |
|--------|---------------------------------------|----------------------------------|
| MCU side | UART TX/RX (115200 baud) | BLE GATT server: one NOTIFY characteristic (MCU→host) + one WRITE characteristic (host→MCU) |
| Host side | `/dev/ttyUSB0` via pyserial | `bleak` Python library (cross-platform BLE) |
| Framing | 2-byte LE length prefix | 2-byte LE length prefix (same as serial) |
| MTU | 256 bytes per UART read | 20–512 bytes per BLE write (negotiate via MTU exchange) |
| Fragmentation | Handled by reassembly buffer | Needed: BLE ATT MTU < FMP frame size. Fragment with sequence numbers or rely on L2CAP segmentation |
| Throughput | ~11.5 KB/s at 115200 baud | ~2–10 KB/s typical (BLE 4.2 with DLE) |
| Range | USB cable | ~10–30m indoor |
| Power | USB-powered | Battery-friendly (BLE sleep between intervals) |

### ESP32 firmware changes

1. **BLE peripheral initialization** — use `esp-radio` or `esp-idf-svc` BLE APIs
   to create a GATT server with a custom service:
   - Service UUID: `c0de0001-...` (custom)
   - TX characteristic (NOTIFY): MCU writes FMP frames here → host receives
   - RX characteristic (WRITE): host writes FMP frames here → MCU receives
2. **BleTransport struct** — implements the same send/recv interface as UartTransport
3. **Boot sequence** — try WiFi → try BLE → fall back to UART serial
4. **Framing** — same 2-byte LE length prefix as UART (the bridge strips it and
   sends raw FMP over UDP, exactly like `serial_udp_bridge.py`)

### Host-side BLE gateway (`ble_udp_bridge.py`)

```python
# Conceptual structure (uses `bleak` for cross-platform BLE):
import asyncio, struct
from bleak import BleakClient, BleakScanner
import socket

FIPS_SERVICE = "c0de0001-..."
TX_CHAR = "c0de0002-..."  # NOTIFY: MCU -> host
RX_CHAR = "c0de0003-..."  # WRITE:  host -> MCU

async def main():
    device = await BleakScanner.find_device_by_name("microfips-esp32")
    async with BleakClient(device) as client:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # BLE NOTIFY → strip length prefix → UDP to FIPS
        # UDP recv → add length prefix → BLE WRITE to MCU
```

### Key considerations

- **MTU negotiation:** BLE default ATT MTU is 23 bytes (20 usable). FMP MSG1 is
  114 bytes. Must negotiate higher MTU (≥256) or implement fragmentation.
  ESP32 BLE supports MTU up to 517. `bleak` handles MTU negotiation automatically.
- **Fragmentation:** If MTU < frame size, fragment FMP frames at the bridge level.
  Each fragment gets a 1-byte header: `[seq_num | LAST_FLAG]`. Reassemble on both sides.
- **Connection interval:** Default 30ms. For heartbeat-only traffic (~10s interval),
  a longer connection interval (100–500ms) saves power.
- **Security:** BLE link-layer encryption (LE Secure Connections / LESC) is optional.
  The FIPS Noise IK handshake already provides end-to-end encryption, so BLE-level
  encryption is defense-in-depth, not required.
- **`bleak` library:** Pure-Python, works on Linux (BlueZ), macOS (CoreBluetooth),
  and Windows (WinRT). No C extensions needed. Well-maintained.
- **esp-radio BLE:** The `esp-radio` crate (already a dependency) supports BLE on ESP32.
  Check `esp-radio = { features = ["esp32", "wifi", "ble"] }` for BLE support.

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
