# microfips — Agent Reference

## Project

**RULE: do NOT post issues, comments, PRs, or any other content to external
projects** (anything outside the Amperstrand org — upstream repos like
esp-rs/esp-hal, embassy-rs, jmcorgan/fips, rustyrussell/*). Draft the text,
park it in an Amperstrand issue labeled for the maintainer's review, and let
a human decide whether and where to post. Learned 2026-08-30: our
esp-rs/esp-hal#6243 was closed as a duplicate of #6220 — posting it cost an
upstream maintainer triage time to re-derive what a 2-minute search of their
open issues would have found. Research and reference external issues freely;
just never write to them without explicit maintainer approval. (Same policy
as the greatspectations line below: "upstream conversations only after the
dogfood proves value" — and then still through a human.)

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO and ESP32.
Both MCUs use length-prefixed framing → host bridge → UDP → VPS running stock FIPS.
- **STM32F469I-DISCO:** USB CDC ACM transport → serial_udp_bridge.py (primary target)
- **STM32F746G-DISCO:** USB CDC ACM transport → serial_udp_bridge.py (tested, hardware-verified 2026-05-04: FIPS Noise IK handshake + heartbeat with VPS passes. Separate build target `--features board-f746`. Only 1 user LED on PI1; orange/red/blue pins are Arduino header GPIOs with no physical LEDs.)
- **ESP32-D0WD:** UART transport (CP210x USB-serial) → serial_udp_bridge.py, OR BLE transport → ble_udp_bridge.py (feature-gated), OR WiFi transport → direct UDP to FIPS (feature-gated, requires external antenna)
- **ESP32-S3 Walter (QuickSpot):** WiFi transport → direct UDP to a LAN FIPS daemon found via mDNS discovery, with fallback to the VPS (hardware-verified 2026-08-18: handshake, heartbeats, mDNS pinned+open discovery, re-discovery on link death, WiFi re-association on AP loss. See "ESP32-S3 Walter" and "mDNS LAN Discovery" sections.) OR ESP-NOW transport → second Walter as gateway → daemon (no IP stack on the node; gateway is either standalone WiFi/UDP or radio↔USB + serial_udp_bridge.py; hardware-verified 2026-08-19 incl. channel sweep, see "ESP-NOW Transport" section.) OR **FIPS relay AP**: open `!FIPS` access point with DHCP + mDNS advert + UDP relay to the daemon, chainable Router→Extender (hardware-verified 2026-08-20), optionally also a FIPS peer itself (`relay-ap-peer`, verified 2026-08-22; see "FIPS Relay Access Point" section.)

## Workspace architecture

**Extracted protocol crates (no_std, portable, can be consumed by upstream FIPS):**
- `fips-noise`: Noise IK/XK/XX state machines, crypto helpers (secp256k1 ECDH, ChaChaPoly, SHA256)
- `fips-fmp`: FMP link-layer wire format (framing, message parsing, build_msg1/2/3)
- `fips-identity`: NodeAddr, FipsAddress, key derivation, hex utilities

**Application crates:**
- `microfips-core`: device constants + re-exports from fips-noise/fips-fmp/fips-identity, FSP session protocol, MMP metrics
- `microfips-protocol`: `Node`, transport trait, FSP runtime, `ScriptedPeer` test harness (cfg-gated IK vs XX via `noise-xx` feature)
- `microfips-service`: transport-neutral request/response layer above protocol
- `microfips-http-demo`: optional demo-only HTTP adapter and demo service
- `microfips-esp-transport`: shared ESP32 transport code (runner, LED, RNG, handlers, WiFi config)
- `microfips-esp-common`: chip-agnostic ESP32 code (DNS, config, stats, UDP transport)

STM32, ESP32, simulator, and host demo binaries are composition roots over those layers.
ESP32 D0WD and S3 share a `runner` module (`run_node()`, `make_led()`, `init_trng()`)
from `microfips-esp-transport`; only WiFi stays per-chip due to TRNG borrow constraints.
BLE is feature-gated transport plumbing, not a separate protocol stack.

## VPS Access

VPS credentials are stored in environment variables (or a `.env` file, never committed):

```bash
export VPS_HOST=orangeclaw.dns4sats.xyz
export VPS_USER=routstr
export VPS_PASS=<password>

# Shorthand:
vssh() { sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" "$@"; }
vscp() { sshpass -p "$VPS_PASS" scp -o StrictHostKeyChecking=no "$1" "$VPS_USER@$VPS_HOST:$2"; }
```

VPS FIPS binds `0.0.0.0:2121`, MCU peers configured at `127.0.0.1:31337` (STM32) and `127.0.0.1:31338` (ESP32).
FIPS logs: `vssh "echo $VPS_PASS | sudo -S journalctl -u fips --no-pager -n 30 --since '5 min ago'"`

**orangeclaw status (2026-09-02, #190):** host is alive (DNS + ICMP green) but the
daemon is silent — a pinned-key MSG1 gets zero reply (daemon down or key rotated;
indistinguishable without creds, so the registry `vps` entry is left untouched).
For VPS-path testing until creds return, use a throwaway SHC VPS:

```bash
# Build the daemon in a WORKTREE — building in /home/ubuntu/src/fips refreshes
# the system daemon binary (Restart=on-failure picks it up):
git -C /home/ubuntu/src/fips worktree add --detach /tmp/opencode/fips-build fork/main
cd /tmp/opencode/fips-build && cargo build --release

# JIT VPS (shc toolkit; ~$0.24/day, cancel when done — --reap is the safety net).
# FACILITY GOTCHA: Cherryvale (all ssd-*/dev-* lines) is unreachable from EU —
# order hdd-*/nvme-* (Katy, TX) instead:
shc order --hostname fips-e2e --size hdd-1c-4gb --template debian13-cloud \
  --ssh-key ~/.ssh/id_ed25519.pub --reap 6h --tag <work> --pay

# Deploy (config: lab template with bind 0.0.0.0:2121, lan-mdns off, fresh
# lab_keygen N identity), then verify from the workstation:
scp target/release/fips target/release/fipsctl <vm>:/home/debian/
FIPS_NSEC=<sim nsec> FIPS_PEER_NPUB=<daemon npub> \
  ./target/release/fips-handshake <vm-ip>:2121   # expect SUCCESS
# Daemon-side: ~/fipsctl -s /run/user/1000/fips/control.sock show peers
# (IK sessions do NOT appear in the daemon's INFO log — use fipsctl).
```
Verified green 2026-09-02 (handshake ×2 + peer `connected` via fipsctl); see #190.

## Build

### STM32F469

```bash
cargo build -p microfips --release --target thumbv7em-none-eabi
# Output: target/thumbv7em-none-eabi/release/microfips

# Display build (LCD debug output, #113 — adds BSP + embedded-graphics, ~186 KB .text):
cargo build -p microfips --release --target thumbv7em-none-eabi --features display
```

Display output hardware-verified 2026-09-02 (#113): IK handshake + sustained
heartbeats vs the local daemon with the display task running (ETX 1.0, 0% loss),
soft-reset re-enumeration intact; LCD rendering (title, npub, state, counters,
per-line redraw without flicker) visually confirmed on the physical screen.

### STM32F746

```bash
cargo build -p microfips --release --target thumbv7em-none-eabi --no-default-features --features board-f746
# Output: target/thumbv7em-none-eabi/release/microfips
```

Same firmware crate, different `board-*` feature. The default build targets F469.

### ESP32-D0WD

Requires the Espressif Rust toolchain (installed via `espup`, activated with `RUSTUP_TOOLCHAIN=esp`):

```bash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc
# Output: target/xtensa-esp32-none-elf/release/microfips-esp32
```

### ESP32-D0WD (BLE variant)

Same toolchain. Feature flag `ble` enables BLE transport instead of UART:

```bash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features ble
# Output: target/xtensa-esp32-none-elf/release/microfips-esp32-ble
```

Default build (no `--features ble`) produces UART transport firmware. The BLE variant uses
UART0 for structured logging (`log` crate) and control interface instead of FIPS traffic.

Each variant outputs to its own binary — no build order dependency between variants.

### ESP32 (WiFi variant)

Requires an ESP32 variant with WiFi hardware and an external antenna (e.g. ESP32-S3,
ESP32-WROOM-32, ESP32-D0WD). Feature flag `wifi`
enables WiFi transport instead of UART:

```bash
# Set credentials in .env (gitignored, never committed):
#   WIFI_SSID=MyNetwork
#   WIFI_PASSWORD=MyPass
export $(grep -v '^#' .env | xargs) \
  && . /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features wifi
# Output: target/xtensa-esp32-none-elf/release/microfips-esp32-wifi
```

The ESP32-D0WD has WiFi hardware (802.11 b/g/n). However, WiFi requires an
external antenna — most D0WD dev boards include one, but verify before use. Credentials
are set via `WIFI_SSID` and `WIFI_PASSWORD` env vars at build time (from `.env`).
No secrets in source.

## Flash and Run

### CRITICAL: Do NOT use probe-rs during USB testing (STM32)

probe-rs halts the CPU periodically for RTT reads. When the CPU is halted mid-USB-transfer,
the USB connection drops. This manifests as device disappearing from lsusb, /dev/ttyACM*
not appearing, and corrupted register reads (EPENA stuck, EPTYP wrong).

This was misdiagnosed as an embassy USB bug (PR #5738, since closed). The real root cause
is probe-rs + USB coexistence. A completely separate firmware using usb-device (NOT embassy)
also fails enumeration with probe-rs attached.

**Correct deployment: use st-flash, then test via pyserial.**

```bash
# Flash
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
st-flash --connect-under-reset write microfips.bin 0x08000000

# Reset
st-flash --connect-under-reset reset
```

### USB OTG FS PHY reset (automatic)

The firmware performs an explicit USB PHY reset after `embassy_stm32::init()` to ensure
reliable re-enumeration after `st-flash` soft resets (SYSRESETREQ without NRST). Without
this, the USB PHY can retain stale state and the device won't appear as `/dev/ttyACM*`.

No manual RESET button press is needed after flashing.

### When probe-rs IS acceptable

- Initial bringup (no USB active yet)
- Reading/writing flash option bytes (carefully — see warnings below)
- `probe-rs download --chip STM32F469NIHx --connect-under-reset` (flashing only, then detach immediately)

### defmt_rtt breaks USB CDC (confirmed cross-project)

`defmt_rtt` (even when unused via `use defmt_rtt as _`) prevents USB OTG FS enumeration on this board. Root cause unknown — possibly SWD/ITM resource contention. This is distinct from the probe-rs issue above; even with `st-flash` and no probe-rs attached, `defmt_rtt` in the binary prevents enumeration.

**Evidence**: Confirmed in gm65-scanner project via controlled A/B test on identical firmware — same code with `defmt_rtt` removed enumerates, with it present does not. The BSP's HAL unconditionally compiles with `defmt` feature enabled.

**Current microfips status**: `use defmt_rtt as _;` is imported in `crates/microfips/src/main.rs:7`. The firmware appears to work with USB CDC based on test procedures, but no `defmt!` macros are actually called. If USB issues arise, try building without `defmt_rtt` and `panic_probe`.

### SWD recovery when USB is active (STM32)

```bash
st-flash --connect-under-reset reset
```

### ESP32 BLE Transport

The ESP32 firmware supports BLE as an alternative to UART serial. Feature-gated behind
`--features ble`. When active, UART0 is repurposed for `esp_println!` debug output instead
of FIPS traffic.

**BLE stack:** trouble v0.6.0 + esp-radio v0.17.0 (pure Rust, no_std, Embassy-native)
**Host bridge:** `tools/ble_udp_bridge.py` using `bleak` (Python async BLE library)

**GATT service UUIDs (firmware ↔ bridge must match):**

| Characteristic | UUID | Direction |
|---------------|------|-----------|
| Service | `6f696670-7300-4265-8001-000000000001` | — |
| RX (write) | `6f696670-7300-4265-8002-000000000002` | Host → ESP32 |
| TX (notify) | `6f696670-7300-4265-8003-000000000003` | ESP32 → Host |

**Build BLE firmware:**
```bash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features ble
```

**Flash:**
```bash
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 target/xtensa-esp32-none-elf/release/microfips-esp32-ble
```

**Verify BLE advertising:**
```bash
python3 -c "
import asyncio
from bleak import BleakScanner
async def scan():
    devices = await BleakScanner.discover(timeout=10)
    found = [d for d in devices if d.name and 'microfips' in d.name.lower()]
    if found:
        print(f'Found: {found[0].name} ({found[0].address})')
    else:
        print('Not found')
asyncio.run(scan())
"
```

**Run BLE bridge to VPS:**
```bash
python3 tools/ble_udp_bridge.py --ble-name "microfips-esp32" --udp-host orangeclaw.dns4sats.xyz --verbose
```

**Expected:** `>> BLE->UDP: frame#1 114B` (MSG1), `<< UDP->BLE: frame#1 69B` (MSG2),
then heartbeat frames every ~10s.

**UART debug output:**
While BLE is active, UART0 outputs debug via `esp_println!`. Read with:
```bash
python3 -c "
import serial, time
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=2)
deadline = time.time() + 20
while time.time() < deadline:
    line = s.readline().decode(errors='replace').strip()
    if line: print(line, flush=True)
s.close()
"
```

**Dependencies:**
```bash
pip install bleak
```

**Troubleshooting:**
- **No BLE device found in scan:** ESP32 may still be booting (wait 10s, retry). Check BLE adapter: `hciconfig hci0` (must show UP RUNNING).
- **Bridge connects but no frames:** Check UART debug output for errors. Verify VPS is reachable.
- **Bridge can't open serial for debug:** BLE bridge uses D-Bus/BlueZ, not the serial port. They can coexist.
- **Default UART build broken after BLE work:** Both builds are tested. Run `cargo clean` if Cargo feature cache causes issues.

### ESP32 L2CAP Transport

The ESP32 firmware can connect directly to a local FIPS daemon via BLE L2CAP
Connection-Oriented Channels (CoC). No Python bridge, no UDP hop. Feature-gated
behind `--features l2cap`. When active, UART0 is repurposed for structured logging
(`log` crate) and control interface instead of FIPS traffic.

**BLE stack:** trouble-host v0.6.0 + esp-radio v0.17.0 (pure Rust, no_std, Embassy-native)
Same stack as BLE GATT but uses L2CAP CoC API instead of GATT characteristics.

**L2CAP constants:**

| Item | Value |
|------|-------|
| PSM | `0x0085` (133 decimal) |
| FIPS Service UUID | `9c90b790-2cc5-42c0-9f87-c9cc40648f4c` |
| L2CAP MTU | 2048 bytes |
| PacketPool MTU | 2054 bytes (configured via `.cargo/config.toml`) |
| Pre-handshake format | **fips master dialect (2026-08-29):** raw 33B SDU `[0x00][32B x-only secp256k1 pubkey]`, no capability byte. Legacy branch dialect `[0x00][x-only 32][1B flags]` (34B payload, 36B wire, 2B BE prefix) is still parsed on RX for old daemons. |
| Framing | **fips master:** one FMP frame per L2CAP SDU, no prefix (dialect selected by the exchange form: flags-less 33B exchange ⇒ raw SDUs). Legacy peers: 2-byte BE length prefix inside each SDU. |
| Capability byte | `0x3C` — legacy dialect only; master has no caps/role negotiation, so `peer_sent_first=false` (the leaf always initiates Noise; `true` deadlocks both sides until recv timeout) |
| FRAME_CAP | 768 bytes (application-level frame buffer; MTU stays 2048) |
| BLE address | Random static (`02:00:00:00:00:FF`) — deterministic from `ESP32_NSEC[27..32]` + `0xFF` prefix, MSB-first. FIPS master dials with the **learned** LE address type since commit `1422117e` (a hardcoded LePublic dial to a Random peer fails in the kernel at mgmt level with NO HCI command and no socket error — the dialer only ever sees its own timeout) |
| Advertising name | `microfips-l2cap` |
| Extra allowlist key | `FIPS_EXTRA_ALLOWED_XONLY_HEX=<64 hex>` build knob accepts a lab/test daemon key beyond the production 4-entry `FIPS_ALLOWED_PUBKEYS` (registered in the microfips-build KNOBS tracker) |

**Build L2CAP firmware:**
```bash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features l2cap
```

**Flash:**
```bash
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 target/xtensa-esp32-none-elf/release/microfips-esp32-l2cap
```

**Test procedure (local FIPS daemon, no VPS needed):**

1. Start local FIPS daemon with BLE:
   ```bash
   pkill -f "target/release/fips" 2>/dev/null; sleep 2
   RUST_LOG=debug /home/ubuntu/src2/fips/target/release/fips --config /tmp/fips-local-ble.yaml > /tmp/fips-local.log 2>&1 &
   ```

2. FIPS config for BLE transport:
   ```yaml
   transports:
     ble:
       adapter: hci0
   ```
   Role negotiation is handled via capability flags in the BLE pubkey exchange
   (FIPS commit `8c388cf`). No manual tiebreaker configuration needed.

3. Flash ESP32:
   ```bash
   kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
   . /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features l2cap
   . /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 target/xtensa-esp32-none-elf/release/microfips-esp32-l2cap
   ```

4. Wait 15s for BLE scan + connection, then check FIPS logs:
   ```bash
   tail -30 /tmp/fips-local.log
   ```

**Expected in FIPS log:** `BLE scanner: FIPS peer found`, `BLE connection established`,
`Sent msg2 response`, `Connection promoted to active peer`. No `bad prefix 0x01` errors.
Sustained heartbeats continue indefinitely after promotion.

**Connection modes:**

The ESP32 supports both central (scan + outbound connect) and peripheral (advertise +
accept) roles. Central role is attempted first (3s BLE scan for FIPS service UUID),
then falls back to peripheral advertising if no FIPS peer is found.

**UART debug output + control interface:**
While L2CAP or BLE is active, UART0 outputs structured logs via the `log` crate
(format: `[LEVEL module_path] message`, matching FIPS style). UART0 also accepts
line-delimited control commands. Read logs and send commands with:

```bash
# Read structured log output
python3 -c "
import serial, time
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=2)
deadline = time.time() + 20
while time.time() < deadline:
    line = s.readline().decode(errors='replace').strip()
    if line: print(line, flush=True)
s.close()
"

# Send control commands (JSON responses)
python3 tools/test_control.py
```

**Control commands:**

| Command | Response | Description |
|---------|----------|-------------|
| `show_status` | JSON with node_addr, npub, state, uptime_secs, transport_type | Node overview |
| `show_peers` | JSON with peer's node_addr and pubkey | Peer info (error if no peer) |
| `show_stats` | JSON with msg1_tx, msg2_rx, hb_tx, hb_rx, data_tx, data_rx | Protocol counters |
| `help` | Plain text list of commands | Command reference |
| `version` | `microfips-esp32 <version>` | Firmware version |
| `reset` | JSON `{"status":"ok"}`, then reboot | Software reset via RTC_CNTL SW_SYS_RST |

Response format matches FIPS control protocol: `{"status":"ok","data":{...}}` or
`{"status":"error","message":"..."}`.

**Troubleshooting:**
- **No FIPS connection:** Check BLE adapter: `hciconfig hci0` (must show UP RUNNING).
  Restart FIPS daemon. Role negotiation is automatic via capability flags.
- **`bad prefix 0x01` in FIPS logs:** Stale L2CAP channels from previous connection.
  ESP32 drains channels on reconnect (fixed in commit `8ed21cb`).
- **`BLE probe connect timeout`:** Check BLE address type — FIPS must use `LeRandom` for
  ESP32's random static address (fixed in FIPS commit `9779672`).
- **Wrong firmware flashed:** Each variant has its own binary: `microfips-esp32` (UART),
  `microfips-esp32-ble` (BLE), `microfips-esp32-l2cap` (L2CAP). No build order dependency.
- **Tie-breaker deadlock:** Both sides try to be central simultaneously. Resolved via
  capability-based role negotiation (FIPS commit `8c388cf`). No manual config needed.

**Key differences from BLE GATT:**
- No Python bridge needed — ESP32 talks to FIPS daemon directly over BLE L2CAP
- No UDP hop — pure BLE L2CAP connection to local FIPS daemon
- No GATT characteristics — uses L2CAP CoC channel on PSM 0x0085
- 2-byte BE length prefix on all L2CAP frames (matches FIPS `BluerStream` framing — applies to pubkey exchange AND all subsequent data)

### ESP32 WiFi Transport

WiFi transport for ESP32 variants with WiFi hardware (e.g. ESP32-S3, ESP32-WROOM-32).
Feature-gated behind `--features wifi`, outputs `microfips-esp32-wifi` binary.

**Build:**
```bash
# Set credentials in .env (gitignored, never committed):
#   WIFI_SSID=MyNetwork
#   WIFI_PASSWORD=MyPass
export $(grep -v '^#' .env | xargs) \
  && . /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf \
  -Zbuild-std=core,alloc --features wifi
```

Credentials are set via `WIFI_SSID` and `WIFI_PASSWORD` environment variables at build
time (from `.env`, which is gitignored). No secrets in source.

**Flash:**
```bash
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 \
  target/xtensa-esp32-none-elf/release/microfips-esp32-wifi
```

The ESP32-D0WD has WiFi hardware (802.11 b/g/n) but requires an external antenna.
Most dev boards include one. WiFi works on all standard ESP32 variants.

**Features:**
- WiFi STA via DHCP with 30s timeout (panic on failure)
- DNS A-record resolution for VPS hostname (manual UDP DNS query, no new deps)
- Raw framing mode for direct UDP to FIPS (`set_raw_framing(true)`)
- Mutually exclusive with `ble` and `l2cap` features
- Separate binary: `microfips-esp32-wifi` (UART/BLE/L2CAP use `microfips-esp32`)

**Architecture:**
- `wifi_transport.rs` — Transport trait impl over embassy-net UDP socket (shared via `microfips-esp-common`)
- `bin/wifi.rs` — WiFi composition-root binary
- Config: `WIFI_SSID`, `WIFI_PASSWORD` (env vars), `VPS_HOST`, `VPS_PORT`
- Retains `WifiController` for transport lifetime (prevents WiFi disconnect)
- Both D0WD and S3 use `WifiTransport` from `microfips-esp-common`

**Test:**
```bash
# Build
export $(grep -v '^#' .env | xargs) \
  && . /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf \
  -Zbuild-std=core,alloc --features wifi

# Flash (D0WD via CP210x)
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 \
  target/xtensa-esp32-none-elf/release/microfips-esp32-wifi

# Monitor serial output
python3 -c "
import serial, time
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=2)
deadline = time.time() + 45
while time.time() < deadline:
    line = s.readline().decode(errors='replace').strip()
    if line: print(line, flush=True)
s.close()
"
```

**Expected:** WiFi connects, DNS resolves VPS hostname, FIPS handshake (MSG1 sent,
MSG2 received), sustained heartbeats.

**Troubleshooting:**
- **WiFi doesn't connect:** Verify `WIFI_SSID` and `WIFI_PASSWORD` are correct at build time.
  The firmware panics after 30s DHCP timeout. Verify the target board has an external
  antenna connected.
- **DNS resolution fails:** The firmware uses manual UDP DNS queries (port 53). Ensure the
  WiFi network allows DNS to external resolvers. The VPS hostname must have an A record.
- **Handshake fails:** Verify VPS FIPS is running and reachable from the WiFi network. Check
  `VPS_HOST` and `VPS_PORT` config values.
- **Wrong firmware flashed:** Each variant has its own binary: `microfips-esp32` (UART),
  `microfips-esp32-ble` (BLE), `microfips-esp32-l2cap` (L2CAP), `microfips-esp32-wifi` (WiFi).
  No build order dependency.

### ESP32-S3 (TiLDAGON)

The ESP32-S3 TiLDAGON supports WiFi and BLE L2CAP transports via `microfips-esp32s3` crate
with shared `microfips-esp-common` for DNS, config, and stats.

**Build (WiFi):**
```bash
export $(grep -v '^#' .env | xargs) \
  && . /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  cargo build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf \
  -Zbuild-std=core,alloc
# Output: target/xtensa-esp32s3-none-elf/release/microfips-esp32s3
```

**Build (BLE L2CAP):**
```bash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  cargo build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf \
  -Zbuild-std=core,alloc --features l2cap
# Output: target/xtensa-esp32s3-none-elf/release/microfips-esp32s3-l2cap
```

**IMPORTANT:** After any change to `device-registry.json` or identity code, MUST run
`cargo clean -p microfips-esp32s3` before rebuild to avoid stale compiled-in keys.

**Flash:**
```bash
# Detect S3 port (currently /dev/ttyACM1)
for p in /dev/ttyACM*; do vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2); [ "$vid" = "303a/1001/101" ] && echo "S3 on $p"; done

# Flash WiFi variant
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyACM<N> --chip esp32s3 \
  target/xtensa-esp32s3-none-elf/release/microfips-esp32s3

# Flash L2CAP variant
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyACM<N> --chip esp32s3 \
  target/xtensa-esp32s3-none-elf/release/microfips-esp32s3-l2cap
```

**Serial port:** USB Serial JTAG (VID:PID `303a:1001`, `/dev/ttyACM*`), NOT CP210x.
Auto-reset works via DTR/RTS, no button pressing needed.
**Current mapping:** `/dev/ttyACM1` (detect at runtime — never hardcode).

**Monitor serial output:**
```bash
python3 -c "
import serial, time
s = serial.Serial('/dev/ttyACM1', 115200, timeout=2)
deadline = time.time() + 30
while time.time() < deadline:
    line = s.readline().decode(errors='replace').strip()
    if line: print(line, flush=True)
s.close()
"
```

**CRITICAL: Do NOT use `esptool --no-stub`** — it overwrites the partition table and bricks
the board. Always use `espflash`.

**Serial logging note:** `esp-println` on S3 outputs to UART0 (GPIO43/44) by default, NOT the
USB JTAG serial port (`/dev/ttyACM*`). To see logs through USB JTAG, add `"jtag-serial"` feature
to `esp-println` in `crates/microfips-esp32s3/Cargo.toml`:
```toml
esp-println = { version = "0.16.1", default-features = false, features = ["esp32s3", "jtag-serial"], optional = true }
```
Without `jtag-serial`, use `espflash flash --monitor` to see bootloader output only (no app logs).

**BLE status (2026-04-19):** S3 L2CAP firmware boots successfully with `esp-radio` BLE init,
advertises as peripheral, and connects to FIPS via central role. The 0-frame disconnect
(tie-breaker yield) and peripheral fallback both work correctly. FIPS must have a free BLE
connection slot — the Mac peer can occupy the slot and block S3 connections.

**TiLDAGON USB device mapping:** Serial `64:E8:33:72:01:24`, always verify with `lsusb` or
the detection script above. The M5 Stack (`0403:6001`, `/dev/ttyUSB0`) is a separate device.

**Recovery from bricked state:**
1. Hold boop (back button) while plugging USB
2. Hold for 3 seconds, then release
3. `espflash erase-flash --chip esp32s3`
4. `espflash flash --chip esp32s3` with the firmware binary

### ESP32-S3 Walter (QuickSpot)

The [Walter](https://www.quickspot.io/) (DPTechnics) is an ESP32-S3-WROOM-1-N16R2 board:
16 MB flash, 2 MB PSRAM, chip rev v0.2, onboard Sequans GM02SP LTE-M/NB-IoT modem
(unused by microfips). It runs the standard `microfips-esp32s3` crate with the `esp32s3`
identity from `device-registry.json` — no board-specific code needed.
Hardware-verified 2026-08-18: WiFi transport, Noise IK handshake with local
fips 0.5.0-dev daemon, sustained heartbeats (0% loss, ETX 1.0), mDNS discovery,
re-discovery on link death, and WiFi re-association on AP loss.

**Serial port:** native USB Serial JTAG (VID:PID `303a:1001`, `/dev/ttyACM*`), same
detection as the TiLDAGON — always detect by VID:PID, never hardcode the tty number.
This machine has two Walters: #1 MAC `cc:8d:a2:2c:91:98` (identity `esp32s3`,
generator*5), #2 MAC `cc:8d:a2:2c:94:08` (identity `esp32s3b`, generator*7 —
apply via `DEVICE_NSEC_HEX_esp32s3` build override). They share VID:PID, so always
disambiguate by serial number (`udevadm info -q property /dev/ttyACM<N> | grep
ID_SERIAL_SHORT` — the serial IS the MAC). espflash auto-reset works via
DTR/RTS, no button pressing. Firmware logs appear on the same USB JTAG port
(`esp-println` with `jtag-serial`).
**pyserial DTR/RTS hazard:** opening the port with default control-line handling can
reset the chip — a wrong DTR/RTS sequence resets it into DOWNLOAD mode (`waiting for
download`, firmware not running). To open without touching the chip: construct
`serial.Serial()` unopened, set `.dtr = False; .rts = False`, then `.open()`. Recover a
download-mode board with `espflash reset -p /dev/ttyACM<N>`.

**LED:** the firmware drives GPIO2 as the status LED; on the Walter that is an exposed
header pin with no onboard LED — wire one externally for LED state visibility.

**Build (WiFi, LAN daemon via mDNS pinned discovery):**
```bash
# .env (gitignored): WIFI_SSID=..., WIFI_PASSWORD=... (2.4 GHz only)
. ~/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  WIFI_SSID="<ssid>" WIFI_PASSWORD="<pass>" \
  DEVICE_NPUB_HEX_vps="<local daemon npub_hex, see device-registry.json 'linux' entry>" \
  cargo build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf -Zbuild-std=core,alloc
# Output: target/xtensa-esp32s3-none-elf/release/microfips-esp32s3
```
The `DEVICE_NPUB_HEX_vps` env override (see "Build-time identity overrides" below) pins
the peer to the LAN daemon's key; mDNS discovery then finds its address at boot, so no
`FIPS_TARGET_HOST` or hardcoded IP is needed. Omit the override to target the VPS.

**Flash + monitor:**
```bash
fuser -k /dev/ttyACM<N> 2>/dev/null
espflash flash -p /dev/ttyACM<N> --chip esp32s3 target/xtensa-esp32s3-none-elf/release/microfips-esp32s3
python3 -c "
import serial, time
s = serial.Serial('/dev/ttyACM<N>', 115200, timeout=2)
deadline = time.time() + 45
while time.time() < deadline:
    line = s.readline().decode(errors='replace').strip()
    if line: print(line, flush=True)
s.close()"
```
**Expected boot log:** `WiFi connected` → `IP: ...` → `mDNS: pinned FIPS peer discovered
at <ip>:2121` → `session: handshake ok, entering steady` → heartbeats every ~10 s.
Verify on the daemon: `fipsctl show peers` lists node_addr `6bef476b...` as connected.

### mDNS LAN Discovery (WiFi transports)

WiFi builds (D0WD and S3) discover the FIPS daemon on the local network via mDNS-SD
(RFC 6762/6763) instead of relying only on the compiled-in target host. Requires a
FIPS daemon with `lan-mdns` (verified against fips 0.5.0-dev), which advertises
`_fips._udp.local.` with TXT keys `npub=<bech32>`, `scope=<mesh name>`, `v=1`
automatically — no daemon configuration needed.

**Mechanism:** one-shot PTR queries from an ephemeral UDP port, so responders answer
by **unicast** (RFC 6762 §6.7 legacy queries) — multicast TX only, no group join, no
dependence on lossy WiFi multicast RX. 3 attempts × 1.5 s window, then fallback to the
static target (DNS resolve of `VPS_HOST`). The advert is a **routing hint, never
identity** — the Noise IK handshake against the discovered endpoint proves the key.

**Pinned mode (default):** only an advert whose TXT npub bech32-decodes to the
compiled-in peer key (`DEVICE_NPUB_HEX_vps`) supplies the endpoint. Other daemons on
the LAN are ignored. A spoofed advert can at worst redirect to an endpoint that must
still prove the pinned key.

**Open mode (`--features mdns-open`):** the first scope- and version-compatible advert
supplies endpoint AND peer npub (trust-on-first-advert — use only on LANs the operator
controls). Optional `FIPS_DISCOVERY_SCOPE` env at build time restricts matching to one
mesh scope (e.g. `fips-overlay-v1`); empty accepts any scope. With multiple same-scope
daemons on the LAN, the fastest responder wins.

**Self-healing (both modes):** the transport re-runs on every reconnect attempt after
the first session ends, in order: re-associate WiFi if the AP dropped us (esp-radio
does not auto-reconnect) → re-acquire DHCP → re-discover the bound peer key via mDNS
(follows daemon IP changes) → handshake. Re-discovery always pins to the key bound at
boot, so a different daemon appearing mid-run can never hijack the link. Verified
recovery time: ~1 s after daemon disconnect, ~2 s after WiFi disassociation.

**Implementation:** parser + `discover_fips()` in `microfips-esp-common/src/mdns.rs`
(host-tested against a captured fips 0.5.0-dev response fixture), bech32 npub decode in
`fips-identity/src/bech32.rs`, transport wiring in
`microfips-esp-transport/src/wifi_transport.rs::wait_ready`. A diagnostic spike binary
(`microfips-esp32s3-mdns-spike`) verifies multicast TX/RX + unicast responses on
hardware. Host-side advert check: `avahi-browse -rt _fips._udp`.

### ESP-NOW Transport (radio-only, no IP)

FIPS over raw ESP-NOW (802.11 vendor action frames): the node needs no AP, no
DHCP, no IP stack. Hardware-verified 2026-08-19 Walter↔Walter: Noise IK handshake,
heartbeats, FSP sessions, 1071-byte FilterAnnounce frames, ETX 1.0, 0% loss.

**Hybrid node (`microfips-esp32s3-hybrid`, preferred for leaf boards):** one binary
that uses direct WiFi/UDP when the AP and daemon are reachable and falls back to
ESP-NOW via a gateway otherwise — same pinned npub and end-to-end Noise IK on both
paths, so switching changes the route, never the trust model. Switching happens at
session boundaries: boot tries WiFi twice then starts on ESP-NOW; in WiFi mode, 2
consecutive failed connection attempts fall back to ESP-NOW; in ESP-NOW mode an
SSID-filtered scan (no association) runs every `HYBRID_WIFI_PROBE_SECS` (default 300)
and only a visible AP *plus* fresh mDNS confirmation of the daemon triggers the switch
back — a reachable AP with an unreachable daemon keeps the working ESP-NOW link.
Build with `--features esp-now,wifi --bin microfips-esp32s3-hybrid` (needs WiFi creds
AND the npub override). Chaos knob for testing: `HYBRID_TEST_WIFI_DOWN_SECS=<n>`
forces the WiFi path down for the first n seconds of uptime (hardware-verified:
boots onto ESP-NOW via gateway, then switches to WiFi in ~2 s once the window ends).

**Single-transport topologies** (node = `microfips-esp32s3-espnow`, a full FIPS node;
both gateways are single-peer relays that unicast to whichever node's frame they saw
last):
1. **Standalone (preferred):** node ↔ ESP-NOW ↔ `microfips-esp32s3-espnow-wifi-gw`
   (joins the AP as station, mDNS-discovers the pinned daemon, relays straight to its
   UDP port; runs on any power brick — no host machine in the data path). Hardware-
   verified 2026-08-19.
2. **USB-bridged:** node ↔ ESP-NOW ↔ `microfips-esp32s3-espnow-gw` (radio↔USB relay on
   host USB) ↔ `serial_udp_bridge.py` ↔ daemon UDP. Useful when a host is attached
   anyway — the bridge's frame log is handy for debugging.

**Build + flash (standalone gateway + node):**
```bash
. ~/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  WIFI_SSID="<ssid>" WIFI_PASSWORD="<pass>" \
  DEVICE_NPUB_HEX_vps="<daemon npub_hex, device-registry.json 'linux' entry for the local daemon>" \
  cargo build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf \
  -Zbuild-std=core,alloc --no-default-features --features esp-now,wifi \
  --bin microfips-esp32s3-espnow --bin microfips-esp32s3-espnow-wifi-gw
espflash flash -p /dev/ttyACM<gw>   --chip esp32s3 target/xtensa-esp32s3-none-elf/release/microfips-esp32s3-espnow-wifi-gw
espflash flash -p /dev/ttyACM<node> --chip esp32s3 target/xtensa-esp32s3-none-elf/release/microfips-esp32s3-espnow
```
(For the USB-bridged variant, build `--features esp-now --bin microfips-esp32s3-espnow-gw`
and run `python3 -u tools/serial_udp_bridge.py --serial /dev/ttyACM<gw> --udp-host
127.0.0.1 --udp-port 2121`.)

**Channels:** the standalone gateway is pinned to the AP's channel by its station
association; the node cannot know it in advance, so it **sweeps channels 1–13** during
broadcast discovery (2 broadcasts per channel, stops on peer lock, resumes on session
death — verified: node started on ch 5, swept to the AP's ch 1, locked, handshaked).
`ESP_NOW_CHANNEL` (default 1) is only the sweep's starting channel; for the USB-bridged
gateway (unassociated) it is that gateway's fixed channel. Since #167 (commit 9bdf60c)
the last-known-good channel is retained in `.rtc_slow.persistent` (survives soft
resets, cold-boot-zeroed): boot lingers on the retained channel before sweeping, and
explicit `ESP_NOW_CHANNEL` builds are exempt (deliberate pins win). **Pitfall: use
`.rtc_slow.persistent`, never `.rtc_slow.data` — the latter is LOAD-typed and startup
reloads it from flash every boot, silently wiping retention** (verified the hard way).

**Wire format:** ESP-NOW caps payloads at 250 bytes; FMP frames go up to 2048. Each
frame is chunked with a 2-byte header (msg id, last-flag|fragment index), reassembled
strictly in order; any gap/interleave drops the message and the protocol layers retry
(codec: `microfips-esp-common/src/espnow_frag.rs`, host-tested). Gateway↔host framing
is the standard 2-byte LE length prefix.

**Peer discovery / self-healing:** the node broadcasts its handshake, locks onto the
first responding MAC for unicast (MAC-level ACK+retry), and reverts to broadcast when
a session ends. The MAC is a routing hint only — Noise IK against the pinned npub
(`DEVICE_NPUB_HEX_vps`) proves identity, same trust model as mDNS discovery.
Because sends keep succeeding at MAC level while the daemon is unreachable (the
gateway ACKs), daemon loss is detected by the Node's RX-silence link-death timeout
(`link_dead_timeout_secs`, 30 s): verified cycle = bridge killed → `steady: link dead,
31s without valid frames` → broadcast re-discovery → re-handshake ~5 s after the
bridge returns. The gateway drops radio→host frames after a 500 ms USB write timeout
when nothing drains USB, so a stopped bridge cannot wedge it.

**Console:** the node and the standalone WiFi gateway log on their USB JTAG ports as
usual (the WiFi gateway logs association, mDNS discovery, and `node locked <mac>`).
Only the USB-bridged gateway never initializes the logger — its USB channel carries
frames, and log text would corrupt the stream (only ROM boot text and panics appear
there; the bridge's length-prefix resync skips that noise).

**Pitfalls:**
- When testing bridge outages, kill the bridge's *python* PID, not the wrapping shell —
  an orphaned bridge keeps the port open and both processes steal bytes from each other
  (pyserial then reports "device reports readiness to read but returned no data /
  multiple access on port").
- Bridge reconnection pins to the board's USB serial number; with two Walters attached
  this prevents re-attaching to the node's console (VID:PID alone is ambiguous).
- ESP-NOW node ↔ WiFi node identity collision: both Walters must not run with the same
  `device-registry.json` identity against one daemon — use the `esp32s3b` entry for the second
  board.

### FIPS Relay Access Point (`!FIPS` Router / Extender)

`microfips-esp32s3-relay-ap` turns a Walter into a **FIPS-blind relay AP**: radio in
AP+STA mode, open access point (default SSID `!FIPS`, 192.168.4.1/24) for clients, station
uplink toward the daemon's network. Clients get **FIPS connectivity only** — embassy-net has
no IP forwarding/NAT, so no internet or LAN access through `!FIPS`. Noise IK runs end-to-end
between client and daemon; the relay cannot read or forge traffic, so the open AP exposes no
more than the daemon's default-open LAN ACL already does. Hardware-verified 2026-08-20.

**What the AP side provides:** DHCP server (8-address pool from .10, MAC-keyed leases),
mDNS responder advertising `_fips._udp.local.` with the *upstream daemon's* npub/scope and
the relay's own address (instance `fips-relay-<last 2 MAC bytes>`), and a per-client UDP
relay (4 concurrent flows → own uplink socket each, idle slots recycled after 120 s).
Because the advert carries the daemon's npub, clients' **pinned** discovery accepts the
relay with no configuration change — zero-touch peering. Clients see the AP and get DHCP
before the uplink is up; the advert appears once the daemon is found.

**Roles are uplink config only** (same binary):
```bash
# Router: uplink = the daemon's LAN (defaults to WIFI_SSID/WIFI_PASSWORD)
. ~/export-esp.sh && RUSTUP_TOOLCHAIN=esp \
  WIFI_SSID="<home ssid>" WIFI_PASSWORD="<home pass>" \
  DEVICE_NPUB_HEX_vps="<daemon npub_hex>" \
  cargo build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf \
  -Zbuild-std=core,alloc --no-default-features --features relay-ap --bin microfips-esp32s3-relay-ap
# Extender: uplink = another relay's !FIPS; re-advertises what it discovers upstream
RELAY_UPLINK_SSID='!FIPS' RELAY_UPLINK_PASSWORD='' <same build command>
# Client node for the !FIPS network (any WiFi node firmware):
WIFI_SSID='!FIPS' WIFI_PASSWORD='' DEVICE_NPUB_HEX_vps="<daemon npub_hex>" cargo build -p microfips-esp32s3 ...
```
`RELAY_AP_SSID` overrides the offered SSID. **Run `cargo clean -p microfips-esp-transport -p
microfips-esp32s3` between builds with different env values** (compiled-in, see the identity
pitfall). Extender and Router share the SSID; the uplink scan picks the strongest BSSID that
is not the board's own AP MAC, so an Extender never chains to itself. In AP+STA mode the AP
follows the uplink's channel. Each hop uses 192.168.4.0/24 on both its AP and STA side —
fine, because the two stacks are independent and nothing routes between them.

**Verified chain:** Router (Walter #2) → daemon; client node joined `!FIPS`, got .10 by
DHCP, discovered the relay via pinned mDNS, handshaked through it (ETX 1.0, 0% loss both
directions, ~50 kbit/s goodput — same as direct). Extender (Walter #1) joined the Router
(own BSSID excluded), took a lease, adopted the Router's advert as upstream and re-advertises.
Not yet verified: a client on the Extender's segment (3-hop) — needs a third device; the
daemon host itself cannot be the client because it is the uplink target.

**Open-AP pitfall (fixed):** esp-radio's default station auth threshold is WPA2; joining an
open network failed with `NoAccessPointFoundInAuthmodeThreshold`. All station paths now use
`wifi_transport::station_config()`, which selects open auth for an empty password.

**Logs:** `relay: DHCP reply to <mac> -> <ip> (<n> leases)`, `relay: uplink '<ssid>' via
<bssid>`, `relay: upstream FIPS endpoint <ip:port>`; LED = upstream known. The relay logs
only state changes — a silent console after boot is a settled, healthy relay.

**Peer variant (`microfips-esp32s3-relay-ap-peer`, hardware-verified 2026-08-22):** same
relay plus a full FIPS `Node` with the compiled-in device identity (`DEVICE_NSEC_HEX_esp32s3`)
over the same uplink. `RelayPeerTransport` is one more UDP flow on the station stack toward
whatever `uplink_task` published as upstream — the daemon on a Router, the upstream relay on
an Extender — so a peering Extender runs Noise IK through the Router like any client. Raw
framing (FIPS UDP). Each node session waits for/re-reads the upstream, so it follows daemon
moves without owning the WiFi controller. Relay path stays FIPS-blind. In peer mode the LED
shows the **node session** (not the uplink). Build = relay build + `--bin
microfips-esp32s3-relay-ap-peer`. Verified Router+peer: mDNS-pinned upstream 192.168.1.97:2121,
`handshake ok, entering steady`, heartbeats both ways, 1071-byte FilterAnnounce frames.
Cost: +~12 KB RAM (socket buffers + node), +~180 KB flash.

**Verified chain 2026-08-22 (both peers):** Walter #2 Router+peer (`esp32s3b`, 192.168.1.80)
→ daemon; Walter #1 Extender+peer (`esp32s3`, 192.168.4.10 behind #2) → daemon through #2.
`fipsctl show peers` lists both (`npub1tj7l…jus6` = #2 `fdcd:9177:582b:93ca:2144:ee27:a0ec:f197`,
`npub1979a…zcrp` = #1 `fd6b:ef47:6b39:1177:c1d5:87c4:344:ddca`), `has_bloom_filter: false,
has_tree_position: false` (leaf). `ping <fips-addr>` from the daemon host: 5/5 both, min
10.5 ms (#2) / 14.7 ms (#1, two radio hops); first reply ~0.7 s (FSP session setup).

**ICMPv6 echo over the IPv6 shim (added 2026-08-22):** the daemon delivers `ping` as an FSP
DataPacket to port 256 (`[src_port:2 LE][dst_port:2 LE][format 0x00][ver_tc_flow:4]
[next_header][hop_limit][ICMPv6…]`, current FIPS `upper/ipv6_shim.rs` — note the older
6-byte `fsp::Ipv6Shim` in microfips-core has no format byte). Before this the request was
handed to the demo request dispatcher, which answered with a text error, so nodes were
unpingable. `microfips_core::ipv6_shim::icmpv6_echo_reply` now answers in
`FspDualHandler::handle_responder` before the app sees the message; the checksum is updated
incrementally (only the type byte changes; the swapped pseudo-header addresses are
sum-invariant), so no address reconstruction is needed. The handler also logs every inbound
session datagram (`fsp: datagram in len=… fsp_type=… src=… -> …`) at INFO.

**Host tooling:** `fipsctl show {peers,links,sessions,routing,tree,bloom,…}` talks to
`/tmp/fips-control.sock` (JSON; root-owned — `sudo -n fipsctl -s /tmp/fips-control.sock show
peers`. fipsctl's default `/run/user/1000/fips/control.sock` does not exist on this machine,
corrected 2026-09-02) — use it to confirm a Walter's link from the daemon side
(IK sessions are not in the daemon's INFO log). `fipstop` is the live monitor.

**Silent-console pitfall (CP210x atoms/D0WD):** a "dead" UART logger is usually an
UNREAD one. The USB-serial chip/driver buffers TX with no reader attached, so logs
stop appearing (and the buffer stays full) until something opens the port and drains
the backlog — then hours of logs flush at once. The 2026-08-29 L2CAP session
misread this as "logger wedged after boot": the console answered JSON the whole
time (raw `os.open`+termios, no TIOCM), and steady-state logs appeared the moment
a reader attached. Rule: before diagnosing a silent logger, attach a reader and
wait for the backlog; check the control interface separately — tasks can be alive
and working while "invisible".

**Console-tap pitfall:** opening the Walter's USB-Serial-JTAG port with pyserial resets the
board even with `dtr=False; rts=False` set before `open()`. Keep one long-lived reader per
board in the background (`nohup python3 tap.py 900 > tap.out &`, anchored `pgrep -f
"^python3 tap.py"` to stop it — an unanchored `pkill -f` matches and kills the calling
shell) and wait for `handshake ok` before measuring. `cargo clean -p …` without `--release
--target xtensa-esp32s3-none-elf` removes 0 files and the next build silently reuses the
previous identity/uplink env — always clean with profile and target when env changes.

**Pinned-key pitfall (bit again 2026-08-22):** building without `DEVICE_NPUB_HEX_vps=<local
daemon npub_hex>` pins the firmware to the real VPS key. Symptom on a relay: the uplink
receives and parses the daemon's mDNS advert but the pinned filter rejects it, so it falls
through to DNS and announces the VPS (`upstream FIPS endpoint 91.99.211.197:2121`), and a
peer node then fails its handshake with `Timeout`. Also: `export $(grep -v '^#' .env | xargs)`
splits `WIFI_SSID` values containing spaces — load `.env` line-wise
(`while IFS='=' read -r k v; do export "$k=$v"; done < .env`).

### Build-time identity overrides

`microfips-build` lets a same-named env var override any `device-registry.json` value at build
time, without editing the file:

```bash
DEVICE_NPUB_HEX_vps=02...   # repoint the firmware's peer key (e.g. at the local daemon)
DEVICE_NSEC_HEX_esp32s3=... # override a device secret
FIPS_TARGET_HOST=host-or-ip # override the static target (IPv4 literals skip DNS)
FIPS_DISCOVERY_SCOPE=name   # open-mode mDNS scope filter
REKEY_AFTER_SECS=<secs>     # self-initiated rekey cadence (0 = off, default; scenario-verified fips-lab test_rekey_self_initiated)
```

The registry is public-only (issue #134): vector devices carry `vector_key.generator_mul`
(the scalar is derived at build time, never stored), host secrets are `RETRIEVE_FROM_*`
markers, and `esp32c3` has NO default identity — build it with
`DEVICE_NSEC_HEX_esp32c3=<64 hex>` (CI injects a throwaway value). See `.env.example`
for the full env shape, including `FIPS_PEER_ALLOWLIST` (WireGuard-style responder
allowlist, `fips-identity::load_peer_allowlist`).

The local Linux daemon's current npub lives in `/etc/fips/fips.pub` and is mirrored in
the `device-registry.json` `linux` entry. **If handshakes are silently ignored, check for a stale
peer key first** — fips logs all MSG1 rejections at `debug` level or not at all, so a
wrong responder key produces no daemon log output at the default INFO level
(re-run with `RUST_LOG=debug` to see `Failed to process msg1` / `Invalid msg1 header`).

### ESP32 flash and monitor

Do NOT use probe-rs with ESP32. Use `espflash` from the Espressif toolchain.
If `espflash` fails to connect, kill stale processes holding the serial port first.

```bash
# Kill stale processes (e.g., leftover serial_tcp_proxy)
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null
sleep 1

# Flash (primary)
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 target/xtensa-esp32-none-elf/release/microfips-esp32

# Flash (fallback if espflash fails — uses esptool v5.2.0, already installed)
esptool --chip esp32 --port /dev/ttyUSB0 --before default-reset -b 460800 write-flash 0x0 target/xtensa-esp32-none-elf/release/microfips-esp32

# Monitor (optional, after flash)
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash monitor -p /dev/ttyUSB0 --chip esp32
```

 **ESP32 serial port:** CP210x USB-serial (VID:PID `10c4:ea60`), detect with the script above — do NOT hardcode `/dev/ttyUSB*`.
Always detect by VID:PID `10c4:ea60` (Silicon Labs CP210x):

```bash
for p in /dev/ttyUSB*; do
    vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$vid" = "10c4/ea60/100" ] && echo "ESP32 on $p"
done
```

## Testing

### Test graduation & token discipline (POLICY — read before any test work)

**Every interactive test eventually becomes a unit or e2e test.** Interactive
verification is for NEW hypotheses only; once a behavior is understood, the
finding graduates into `cargo test` / `cargo nextest` (software) or a fips-lab
pytest scenario (hardware, see the Bench Testing Playbook) in the SAME session
that found it. Re-verifying known behavior interactively is a bug in process.
Template: fips-lab #5 (`test_rekey_soak`, from the 2026-09-01 session).

**Token discipline DURING interactive tests** (the loop is sometimes
unavoidable — make it cheap):
1. Plan the assertions BEFORE touching hardware (what string, which log,
   how many occurrences). Absence-signatures count (e.g. rekey is silent at
   INFO on the daemon — assert on the SecurityViolation cycle instead).
2. Verify compiled-in env by scanning the binary BEFORE flashing (SSID
   string, pinned npub bytes, nsec tail) — never debug a stale pin on hardware.
3. Batch the waiting: one long sleep + one evidence sweep beats N short
   sleep-and-check round-trips. Each round-trip costs a full context reload.
4. Capture artifacts once (console tap + daemon log slice) and analyze from
   the files, not from live tails.
5. Timebox: if the hypothesis hasn't resolved in 2-3 cycles, stop and write
   the failing case as a test instead — the test outlives the session.
6. Close the loop: file the scenario issue (or the test) before ending the
   session. An undocumented interactive test will be repeated by hand.

### Unit tests (no hardware)
```bash
cargo test -p microfips-core          # 234 tests: Noise, FMP, FSP, identity
cargo test -p microfips-core -- --nocapture  # verbose output
cargo test -p microfips-protocol --features std -- --test-threads=1  # 135 tests: framing, transport, node, ScriptedPeer (IK wire)
cargo test -p microfips-protocol --features std,noise-xx -- --test-threads=1  # same suite on the XX wire (134 pass; the 1 cfg'd-out IK-only tiebreaker variant has an uncfg'd XX equivalent)
cargo nextest run -p microfips-protocol --features std --test-threads=1  # same, but a hung test FAILS instead of hanging the suite (see .config/nextest.toml)
```

**Hang rule:** `cargo test --test-threads=1` never prints a summary if a test
wedges — two noise-xx hangs were invisible in a "11 failures" scorecard until
the 2026-08-31 session. When quoting test counts, run under `cargo nextest`
(slow-timeout terminates wedged tests) or wrap in `timeout(1)` first.

### Host-side VPS handshake test (no MCU)
```bash
cargo run -p microfips-link            # sends MSG1 to VPS via UDP, expects MSG2
```

### USB CDC frame check (hardware, no FIPS)

The M1/M2-era echo mode no longer exists in firmware. Current firmware, once the
port opens with DTR asserted (`wait_connection()` resolves), sends a FIPS MSG1
(114 B, FMP prefix `0x0100`) within ~0.5 s (retried every ~3 s, full cycle ~33.5 s):

```bash
python3 -c "
import serial, struct, time
s = serial.Serial('/dev/ttyACM<N>', 115200, timeout=2)  # detect by VID:PID c0de:cafe
deadline = time.time() + 40
while time.time() < deadline:
    hdr = s.read(2)
    if len(hdr) == 2:
        n = struct.unpack('<H', hdr)[0]
        payload = s.read(n)
        if n == 114 and payload[:2] == b'\x01\x00':
            print('MSG1 received — USB CDC OK'); break
s.close()
"
```

For a full handshake, run `tools/serial_udp_bridge.py` against a daemon instead
(see the bridge test sections).

### Bridge + MCU + VPS handshake test (hardware — simplified single-hop)

The `serial_udp_bridge.py` tool replaces the old 3-hop pipeline. No SSH tunnel or
VPS-side bridge needed — it sends UDP directly from the host to FIPS.

```bash
# STM32 (auto-detect by VID:PID, reset first)
st-flash --connect-under-reset reset
sleep 8  # wait for USB enumeration
python3 tools/serial_udp_bridge.py --serial /dev/ttyACM<N> --udp-host orangeclaw.dns4sats.xyz

# ESP32 (auto-detect by VID:PID)
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
python3 tools/serial_udp_bridge.py --serial /dev/ttyUSB0 --udp-host orangeclaw.dns4sats.xyz

# Both MCUs simultaneously (use different bind ports)
python3 tools/serial_udp_bridge.py --serial /dev/ttyACM<N> --bind-port 45679 &
python3 tools/serial_udp_bridge.py --serial /dev/ttyUSB0 --bind-port 45680 &
```

**Expected:** `>> CDC->UDP: frame#1 114B` (MSG1), `<< UDP->CDC: frame#1 69B` (MSG2),
then heartbeat frames every ~10s.

### Bridge + MCU + VPS handshake test (hardware — legacy 3-hop)

See `scripts/test_hw_handshake.sh` for the full automated procedure. The manual steps are:

```bash
# 0. CLEANUP — kill stale processes by PID (NOT pkill -f — kills test's own SSH)
# If you have saved PIDs from a previous run:
kill $PROXY_PID $TUNNEL_PID 2>/dev/null
fuser -k 45679/tcp 2>/dev/null  # local port cleanup
vssh 'pkill -f fips_bridge 2>/dev/null; echo $VPS_PASS | sudo -S fuser -k 45679/tcp 2>/dev/null'
vssh "echo $VPS_PASS | sudo -S systemctl restart fips"

# 1. Verify USB (after MCU reset + 7s enumeration wait)
lsusb | grep -E "c0de|0483"
# Find the MCU port (NOT ttyACM0 — that's ST-Link):
for p in /dev/ttyACM*; do
    prod=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$prod" = "c0de/cafe/10" ] && echo "MCU on $p"
done

# 2. Start serial TCP proxy on host
python3 tools/serial_tcp_proxy.py --serial /dev/ttyACM<N> --port 45679 &

# 3. SSH reverse tunnel: VPS:45679 → host:45679
sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no -fN \
  -R 45679:127.0.0.1:45679 -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
  $VPS_USER@$VPS_HOST

# 4. Upload and start bridge on VPS
vscp tools/fips_bridge.py :/tmp/fips_bridge.py
vssh 'nohup python3 /tmp/fips_bridge.py --tcp 127.0.0.1:45679 > /tmp/bridge_hw.log 2>&1 &'

# 5. Check results (after ~10s)
vssh 'cat /tmp/bridge_hw.log'
vssh "echo $VPS_PASS | sudo -S journalctl -u fips --no-pager -n 10 --since '1 min ago'"
```

**Expected in bridge log:** `CDC->UDP: frame#1 114B` (MSG1), `UDP->CDC: frame#1 69B` (MSG2)
**Expected in VPS journal:** `Connection promoted to active peer`, no `link dead timeout`
**Bridge has diagnostic alive logs:** `>> alive, buf=0B, frames=N, rx=NB` every 10s

### Bridge + ESP32 + VPS handshake test (hardware)

Manual steps for ESP32 (uses port 45680, VPS peer port 31338):

```bash
# 0. CLEANUP — kill stale processes
kill $PROXY_PID $TUNNEL_PID 2>/dev/null
fuser -k 45680/tcp 2>/dev/null
vssh 'pkill -f fips_bridge 2>/dev/null; echo $VPS_PASS | sudo -S fuser -k 45680/tcp 2>/dev/null'
vssh "echo $VPS_PASS | sudo -S systemctl restart fips"

# 1. Verify ESP32 serial port (CP210x, NOT ttyACM*)
for p in /dev/ttyUSB*; do
    vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$vid" = "10c4/ea60/100" ] && echo "ESP32 on $p"
done

# 2. Start serial TCP proxy on host
python3 tools/serial_tcp_proxy.py --serial /dev/ttyUSB0 --port 45680 &

# 3. SSH reverse tunnel: VPS:45680 → host:45680
sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no -fN \
  -R 45680:127.0.0.1:45680 -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
  $VPS_USER@$VPS_HOST

# 4. Upload and start bridge on VPS (ESP32 uses --local-port 31338)
vscp tools/fips_bridge.py :/tmp/fips_bridge.py
vssh 'nohup python3 /tmp/fips_bridge.py --tcp 127.0.0.1:45680 --local-port 31338 > /tmp/bridge_esp32.log 2>&1 &'

# 5. Check results (after ~10s)
vssh 'cat /tmp/bridge_esp32.log'
vssh "echo $VPS_PASS | sudo -S journalctl -u fips --no-pager -n 10 --since '1 min ago'"
```

**Note:** ESP32 does not use USB CDC, so there is no DTR-based `wait_connection()` blocking.
The proxy can be started at any time; the ESP32 immediately begins sending MSG1 once booted.

### BLE bridge + ESP32 + VPS handshake test (hardware)

Requires BLE firmware flashed and `bleak` installed (`pip install bleak`).

```bash
# 1. Flash BLE firmware (if not already)
kill $(fuser /dev/ttyUSB0 2>/dev/null) 2>/dev/null; sleep 1
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 target/xtensa-esp32-none-elf/release/microfips-esp32-ble

# 2. Verify BLE advertising (wait 8s after flash for boot)
sleep 8
python3 -c "
import asyncio
from bleak import BleakScanner
async def scan():
    devices = await BleakScanner.discover(timeout=10)
    found = [d for d in devices if d.name and 'microfips' in d.name.lower()]
    assert found, 'microfips-esp32 not found'
    print(f'Found: {found[0].name} ({found[0].address})')
asyncio.run(scan())
"

# 3. Start BLE bridge
python3 tools/ble_udp_bridge.py --ble-name "microfips-esp32" --udp-host orangeclaw.dns4sats.xyz --verbose &

# 4. Wait for handshake (~30s)
sleep 30

# 5. Check results
# Expected in bridge output: "BLE->UDP: frame#1" (MSG1), "UDP->BLE: frame#1" (MSG2)
# Check VPS: vssh "echo $VPS_PASS | sudo -S journalctl -u fips --no-pager -n 5 --since '1 min ago'"
```

**Note:** BLE bridge uses BlueZ D-Bus API, not the serial port. No DTR-based `wait_connection()`
blocking. The ESP32 advertises immediately on boot and the bridge connects within seconds.

### MCU-to-MCU FSP test (both MCUs required)

Both STM32 and ESP32 must be connected. The automated script handles setup, bridge startup, IK handshake waiting, and FSP frame detection. Supports `--flash` to build and flash both MCUs first.

```bash
# Full E2E test (build + flash + run)
bash scripts/test_mcu_to_mcu_fsp.sh --flash

# Run only (MCUs already flashed)
bash scripts/test_mcu_to_mcu_fsp.sh
```

**Expected:** FSP SessionSetup (148B) and SessionAck frames in bridge logs, heartbeat sustained for both MCUs.
See `.sisyphus/evidence/task-8-mcu-fsp-setup.txt` for reference output.

### PCAP Capture & Wireshark Analysis

FIPS traffic (UDP port 2121) can be captured with standard tools:

```sh
# Capture FIPS traffic
./tools/capture_fips.sh capture.pcap 100

# Analyze with tshark + Lua dissector
tshark -r capture.pcap -X lua_script:tools/fips_dissector.lua -V
tshark -r capture.pcap -X lua_script:tools/fips_dissector.lua -T fields -e fips.phase -e fips.payload_length
tshark -r capture.pcap -X lua_script:tools/fips_dissector.lua -Y 'fips.phase == 1'
```

A reference capture from a sim-to-sim FSP PING test is at `tools/reference.pcap`.
The dissector (`tools/fips_dissector.lua`) parses FMP prefix, MSG1, MSG2, and established frames.
Encrypted payloads are shown as opaque hex — no key material needed.

### Process management for hardware tests

**CRITICAL: Do NOT use `pkill -f` patterns.** They kill the current SSH session running
the test. Only use `kill $SPECIFIC_PID`. Use `disown` on background SSH sessions.

### Hardware testing procedure (CRITICAL — read before every hardware test)

**Pipeline startup order matters.** The MCU's `wait_connection()` blocks until a USB
serial port is opened with DTR asserted. If the proxy isn't running, the MCU sits in
`wait_connection()` forever and never sends MSG1.

**Correct order:**
1. Clean all stale processes (proxy, tunnel, bridge, FIPS restart)
2. Start serial TCP proxy (this opens the serial port → asserts DTR → MCU proceeds)
3. Start SSH reverse tunnel
4. Upload and start bridge on VPS
5. Wait for handshake results (MCU sends MSG1 ~0.5s after proxy opens port)

**WRONG order — do NOT do this:**
- Resetting MCU before proxy is running → MCU enters `wait_connection()`, no DTR, blocks
- Using `st-flash reset` while proxy/tunnel/bridge are active → kills USB, proxy gets
  `[Errno 5] Input/output error`, bridge gets BrokenPipe, cascade failure
- Starting pipeline, resetting MCU, then checking — USB re-enumerates on different
  ttyACM number, proxy holds stale fd

**Never use `st-flash reset` during a live test.** It halts the CPU via SWD, kills the
USB device, and the proxy/bridge lose their connections. Only reset BEFORE starting
the pipeline, or not at all (the MCU's `run()` loop handles retries automatically).

**MCU retry timing:** CONNECT_DELAY (500ms) + RECV_TIMEOUT (30s) + RETRY_SECS (3s) =
~33.5s per handshake cycle. If you miss MSG1, wait ~34s for the next attempt.

**Use the test script.** `scripts/test_hw_handshake.sh` handles cleanup, enumeration,
pipeline startup, and result checking in the correct order. Prefer it over manual setup.

**Bridge reconnect bug (known):** When one of the bridge's two threads dies (e.g.,
`serial_to_udp` gets BrokenPipe), the reconnect loop only triggers when BOTH threads
die. If only one dies, the bridge hangs. Workaround: kill and restart the entire bridge
process instead of relying on reconnect.

**probe-rs and USB coexistence:** `probe-rs read --connect-under-reset` halts the CPU
to read memory. This is safe for post-mortem debugging (CPU is in reset). But do NOT
attach probe-rs/RTT while USB CDC traffic is active — the periodic CPU halts break
USB transfers.

## LED State Machine

The STM32F469I-DISCO has 4 user LEDs for debug feedback (no debugger needed):

| LED | Pin | Color |
|-----|-----|-------|
| LD1 | PG6 | Green |
| LD2 | PD4 | Orange |
| LD3 | PD5 | Red |
| LD4 | PK3 | Blue |

| State | Green | Orange | Red | Blue | Meaning |
|-------|:-----:|:------:|:---:|:----:|---------|
| Boot | blink | off | off | off | Firmware running, crypto init |
| USB ready | on | off | off | off | `wait_connection()` resolved |
| Handshake | on | on | off | off | MSG1 sent, waiting MSG2 |
| ESTABLISHED | on | on | off | on | Handshake OK, entering steady |
| HB sent | on | on | off | flash | Heartbeat transmitted |
| HB received | on | on | on | on | Heartbeat received from peer |
| Error | off | off | on | off | Handshake failed |
| Disconnected | off | off | off | off | USB disconnected, retrying |

Post-mortem state can be read via `probe-rs read` with CPU in reset (not live):
```bash
probe-rs read --chip STM32F469NIHx --connect-under-reset b32 <STAT_STATE_addr> 1
# STAT_STATE values: 0=boot, 1=usb_ready, 2=msg1_sent, 3=handshake_ok, 4=hb_tx, 5=hb_rx, 6=err, 7=disconnected
```

### ESP32 LED State Machine

The ESP32 has a single user LED on GPIO2 (blue onboard LED). State visibility is
more limited than STM32's 4-LED display. Behavior is identical for UART, BLE, L2CAP, and WiFi transports.

### STM32F746 LED State Machine

The STM32F746G-DISCO has only 1 physical user LED on PI1 (Arduino D13).
The firmware assigns PI1 as green, with PI2/PI3/PG6 as orange/red/blue (no physical LEDs on those pins).
The state machine runs identically to F469 but only the green LED (PI1) is visible.

| State | GPIO2 (Blue) | Meaning |
|-------|:------------:|---------|
| Boot / Disconnected | off | Firmware running or USB disconnected |
| MSG1 sent (handshake in progress) | on | MSG1 sent, waiting MSG2 |
| Handshake OK (entering steady) | on | Handshake succeeded |
| HB sent / HB received | unchanged | Counter-only update, LED stays on |

States 4 (HB sent) and 5 (HB received) do not change the LED — only the atomic
counters are updated. This is because ESP32's steady-state loop runs in a single
`select()` branch (UART recv always wins over timer), and changing the LED in the
recv hot path adds latency with no visual benefit (the LED is already on from state 3).

## Debugging Best Practices

1. **Never read hardware registers while probe-rs has the CPU halted.** The state is
   undefined mid-transfer. Register captures under these conditions are artifacts,
   not evidence of firmware bugs.

2. **Use LED patterns for state visibility.** No debugger can be attached during USB
   traffic. The 4 LEDs encode the full state machine (see table above).

3. **Use atomic counters for post-mortem debugging.** `STAT_MSG1_TX`, `STAT_MSG2_RX`,
   `STAT_HB_TX`, `STAT_HB_RX`, `STAT_USB_ERR`, `STAT_STATE`, `STAT_RECV_PKT`,
   `STAT_RECV_FRAME` can be read after reset via probe-rs (not live — only in reset/halt).

4. **Isolate variables before escalating.** If USB fails, first test without probe-rs.
   Only blame firmware after eliminating external variables.

5. **Minimal, separated changes.** One concern per PR. Don't bundle cleanup, errata
   workarounds, and speculative recovery paths.

6. **Stale Cargo cache breaks critical-section**: If `cargo build` fails with
   `RawRestoreStateInner defined multiple times` in critical-section, run `cargo clean`
   before rebuilding. This is a Cargo feature unification cache issue, not a nightly
   or crate version incompatibility.

7. **BLE address type must match remote device.** When constructing a targeted BLE
   connect (e.g. trouble-host `Central::connect()` with `filter_accept_list`), the
   address kind (PUBLIC vs RANDOM) must match what the remote device actually advertises.
   `Address::random(bytes)` hardcodes `AddrKind::RANDOM` -- if the target has a PUBLIC
   address (check with `hciconfig hci0`), use `AddrKind::PUBLIC` explicitly. A mismatch
   causes silent connect failure. See issue #81.

8. **BLE disconnect settle delay.** After a BLE L2CAP disconnect, the HCI controller
   needs time to clean up before accepting a new connection. The firmware uses a
   500ms settle delay (`BLE_DISCONNECT_SETTLE_MS`) between disconnect and the next
   connect attempt. Reducing this risks "Connection Already Exists" errors from the
   controller.

## DANGER: Do NOT erase flash via probe-rs

```bash
# NEVER RUN THIS — corrupts STM32F469 flash/option bytes:
probe-rs erase --chip STM32F469NIHx --connect-under-reset
```

## DANGER: Do NOT manipulate USB sysfs paths directly

**Never run these commands:**
```bash
echo "1-6" > /sys/bus/usb/drivers/usb/unbind
echo "1-6" > /sys/bus/usb/drivers/usb/bind
```

Unbinding a CDC ACM device from the `usb` driver corrupts the kernel TTY layer.
`open(/dev/ttyACM*)` hangs at kernel level with no recovery except reboot.

**Recovery (in order of preference):**
1. Rebind unbound PCI controller
2. PCI-level reset
3. Physical USB cable disconnect/reconnect
4. Host reboot

**Safe USB reset:** `st-flash --connect-under-reset reset` (goes through SWD, not USB bus).

### USB recovery via uhubctl (IMPORTANT)

When ST-Link USB gets stuck (LIBUSB_ERROR_PIPE after repeated SWD operations):

```bash
sudo uhubctl -l 1 -a cycle -f -d 5 -r 2
```

- `-r 2` (repeat=2) is the key — some devices need two off cycles to actually power down
- After cycle, wait 8-10s for full re-enumeration
- Check with `lsusb | grep "0483"` AND the VID:PID detection loop — sometimes `lsusb` shows device but sysfs is broken from earlier `usb1 remove`
- **Do NOT use `echo 1 > /sys/bus/usb/devices/usb1/remove`** — corrupts USB device tree, `lsusb` stops working even though devices are present

## Known Pins

### STM32F469

| Peripheral | Pins | Notes |
|------------|------|-------|
| USB OTG FS | PA11 (DM), PA12 (DP) | CDC ACM |
| LED green | PG6 | Active high |
| LED orange | PD4 | Active high |
| LED red | PD5 | Active high |
| LED blue | PK3 | Active high |
| RNG | HASH_RNG interrupt | Hardware TRNG |
| ST-Link | PA13 (SWDIO), PA14 (SWCLK) | Debug probe |

### STM32F746G-DISCO

Separate build target (`--features board-f746`). Same firmware crate, same protocol stack.
USB OTG FS and RNG peripherals are register-compatible. FIPS handshake + heartbeat hardware-verified 2026-05-04.
Runs at 216 MHz (vs 168 MHz on F469). Only 1 physical user LED on this board.

| Peripheral | Pins | Notes |
|------------|------|-------|
| USB OTG FS | PA11 (DM), PA12 (DP) | Register-compatible with F469 |
| LED green | PI1 | Arduino D13, only user LED on this board |
| LED orange | PI2 | Arduino D8, no physical LED |
| LED red | PI3 | Arduino D7, no physical LED |
| LED blue | PG6 | Arduino D2, no physical LED |
| RNG | `RNG` interrupt | Different interrupt name from F469 (`HASH_RNG`) |
| HSE | 25 MHz (X2) | Firmware uses HSI (16 MHz) instead |
| Flash | 1 MB (1024 KiB) | |
| SRAM | 320 KiB | |
| ST-Link | SWD on PA13/PA14 | |
| Clock | 216 MHz sys, 48 MHz USB | HSI/8 * 216 /2 = 216 MHz, /9 = 48 MHz |

### ESP32-D0WD

| Peripheral | Pins | Notes |
|------------|------|-------|
| UART TX | GPIO1 | Connected to CP210x RX |
| UART RX | GPIO3 | Connected to CP210x TX |
| BLE | Internal | esp-radio BLE controller (antenna on-board) |
| LED (blue) | GPIO2 | Active high, onboard |
| Flash | GPIO6–GPIO11 | SPI flash (do not use) |

## Clock Config

### STM32F469

Default (no display):
```
HSI (16 MHz) → PLL → 168 MHz sysclk
                   → 48 MHz USB (PLL_Q, Clk48sel)
                   → 42 MHz APB1
                   → 84 MHz APB2
```

With `--features display` (uses BSP `config_180()` preset):
```
HSE (8 MHz oscillator) → PLL1 → 180 MHz sysclk
                             → 48 MHz USB/RNG (PLLSAI1_Q, Clk48sel — NOT PLL1_Q)
                        → PLLSAI → 54.86 MHz LTDC pixel clock (PLLSAI_R)
                   → 45 MHz APB1, 90 MHz APB2
```

The "HSE bypass hangs" warning applies to `HseMode::Bypass`, NOT `HseMode::Oscillator`.
The board has an 8 MHz crystal — `HseMode::Oscillator` works fine (proven in gm65-scanner, micronuts).

Note: DCKCFGR2 does NOT exist on STM32F469 (Amperstrand/embassy-stm32f469i-disco#27).
embassy writes CK48MSEL to DCKCFGR, which is correct for this MCU. No DCKCFGR2 workaround needed.

### STM32F746

```
HSI (16 MHz) → PLL → 216 MHz sysclk
                   → 48 MHz USB (PLL_Q, Clk48sel)
                   → 54 MHz APB1
                   → 108 MHz APB2
```

HSE is 25 MHz on F746G-DISCO but firmware uses HSI for consistency with F469.

### ESP32-D0WD

ESP32 uses internal PLL from 40 MHz crystal. Clock config is handled by esp-hal.
No manual clock configuration needed — `esp_hal::init()` sets up 240 MHz CPU clock.

## USB Serial Port

The MCU appears as a CDC ACM device with VID:PID `c0de:cafe`. The ttyACM number varies
— it is NOT always ttyACM1 (ttyACM0 is usually ST-Link). Always detect by VID/PID:

```bash
for p in /dev/ttyACM*; do
    prod=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$prod" = "c0de/cafe/10" ] && echo "MCU on $p"
done
```

## ESP32 Serial Ports (D0WD + S3)

**WARNING: tty numbers are NOT stable.** USB enumeration order changes across reboots, cable replugs, and hub power cycles. A device that was `ttyUSB1` may appear as `ttyUSB0` next boot. **Always detect by VID:PID, never hardcode tty numbers.** An M5 Stack (FTDI FT232, VID:PID `0403:6001`) is also connected and appears as `/dev/ttyUSB*` — do not flash or open that device.

Two ESP32 devices are connected simultaneously, plus an M5 Stack on FTDI. All three appear as `/dev/ttyUSB*`. **Never assume a fixed tty number** — always detect by VID/PID.

### ESP32-D0WD (CP210x UART)

VID:PID `10c4:ea60`, appears as `/dev/ttyUSB*`:

```bash
for p in /dev/ttyUSB*; do
    vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$vid" = "10c4/ea60/100" ] && echo "ESP32-D0WD on $p"
done
```

### ESP32-S3 TiLDAGON (USB Serial JTAG)

VID:PID `303a:1001`, appears as `/dev/ttyACM*` (NOT ttyUSB). Uses Espressif USB JTAG/serial, NOT CP210x:

```bash
for p in /dev/ttyACM*; do
    vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$vid" = "303a/1001/101" ] && echo "ESP32-S3 on $p"
done
```

**IMPORTANT:** The S3's `/dev/ttyACM*` port is distinct from the STM32's ST-Link (`0483:374b`) and the MCU CDC (`c0de:cafe`). All three appear as ttyACM — always match by VID/PID.

### Quick detection script (all devices)

```bash
echo "=== STM32 ST-Link ==="
for p in /dev/ttyACM*; do vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2); [ "$vid" = "483/374b/100" ] && echo "  ST-Link on $p"; done
echo "=== STM32 MCU (c0de:cafe) ==="
for p in /dev/ttyACM*; do prod=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2); [ "$prod" = "c0de/cafe/10" ] && echo "  MCU on $p"; done
echo "=== ESP32-D0WD (CP210x) ==="
for p in /dev/ttyUSB*; do vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2); [ "$vid" = "10c4/ea60/100" ] && echo "  D0WD on $p"; done
echo "=== ESP32-S3 (USB JTAG) ==="
for p in /dev/ttyACM*; do vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2); [ "$vid" = "303a/1001/101" ] && echo "  S3 on $p"; done
```

## Toolchain

Host crates and STM32 firmware build on **stable** (verified 2026-08-30: core
tests, protocol suite 135/135, thumbv7em release build — embassy has needed no
nightly features since async-fn-in-trait stabilized in Rust 1.75). No
`rust-toolchain.toml`: repos ride the machine default (stable) per
hackathon-tooling's rust-toolchain policy. ESP32/xtensa builds explicitly set
`RUSTUP_TOOLCHAIN=esp` (env override beats any toolchain file — that fork of
nightly is required for `-Zbuild-std`). CI jobs pin their own toolchains via
`dtolnay/rust-toolchain@v1` independent of local files.

## Actual MCU Keys (verified 2026-03-30)

| MCU | Source | Pubkey (x-only, hex) | npub | NodeAddr |
|-----|--------|----------------------|------|-----------|
| STM32 | `device-registry.json` stm32, nsec=`...01` | `79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` | `npub10xlxvlh...` | `132f39a9...` |
| ESP32-D0WD | `device-registry.json` esp32, nsec=`...02` | `c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` | `npub1ccz8l9z...` | `0135da2f...` |
| ESP32-S3 | `device-registry.json` esp32s3, nsec=`...05` | `2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4` | `npub1lycg5qv...` | `6bef476b...` |
| VPS | `/etc/fips/fips.pub` on VPS | `0e7a0da01a255cde106a202ef4f573676ef9e24f1c8176d03ae83a2a3a037d21` | `npub1peaqmgq6y4wduyr2yqh0fatnvah0ncj0rjqhd5p6aqaz5wsr05ssu0cnha` | — |
| Linux FIPS | `/etc/fips/fips.pub` on this machine | `b3989043c68d9c2d3c8f949d73e61cae27997993432c3dbbd8498117d92d95bb` | `npub1979azcrp...` | `8b5844e7...` |

All MCU keys are deterministic (secp256k1 generator × N); the registry stores only the
multiplier (`vector_key.generator_mul`), never the scalar — microfips-build derives
`nsec = BE32(N)` at build time (issue #134). `crates/microfips-core/tests/device_registry.rs`
CI-enforces the public-only schema and greps the tree for retired literals.
ESP32-D0WD pubkey verified via FIPS peer authentication log.
ESP32-S3 pubkey from `device-registry.json` (verified 2026-04-10, NodeAddr `6bef476b391177c1d587c40344ddcab1`).

## CI Pipeline

GitHub Actions (`.github/workflows/ci.yml`) runs on push/PR to main:
- **test**: `cargo test -p microfips-core` (234 tests) + `cargo test -p microfips-protocol --features std` (135 tests) + `cargo test -p microfips-protocol --features std,noise-xx` (XX wire) + `cargo test -p fips-noise --features noise-xx` (37 XX crypto tests)
- **build-host**: `cargo build -p microfips-link -p microfips-sim -p microfips-http-test --release` + upload artifacts
- **lint**: `cargo clippy` + `cargo fmt --check` on all host crates (core, protocol, link, sim, http-test)
- **sim-smoke**: verify `microfips-sim` starts and exits cleanly on EOF
- **build-firmware**: STM32 F469 `cargo build -p microfips --release --target thumbv7em-none-eabi` + STM32 F746 `--no-default-features --features board-f746` + ESP32 `. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc` (UART default) + ESP32 BLE `. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features ble` + ESP32 WiFi `. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp WIFI_SSID=ci WIFI_PASSWORD=ci cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features wifi` + ESP32-S3 `. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp WIFI_SSID=ci WIFI_PASSWORD=ci cargo build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf -Zbuild-std=core,alloc` using upstream crates.io embassy v0.6.0
- **fips-integration**: local keygen + Noise IK handshake test (must pass), public VPS handshake (continue-on-error)
- **summary**: aggregate status table

A second workflow, `.github/workflows/xx-interop.yml` (#195, 2026-09-03), gates the
XX/FMP-v1 wire on push/PR paths touching the protocol crates: it builds upstream
jmcorgan/fips at a PINNED ref (`NEXT_REF`, currently `f1ff410f` — bump deliberately,
never track a branch; #180 lesson) and runs `fips-handshake --features noise-xx`
(one-shot handshake) plus `microfips-sim --features noise-xx` (60 s heartbeat session)
against it on loopback. Failure policy: our XX regression = fail/block; pinned ref
vanished upstream = warn+skip (golden-vectors precedent). CI identity discipline:
daemon G·20, sim G·21, link probe G·23 — never share an identity between the two
clients in one run (the next daemon discards the second session as a simultaneous-init
collision, leaving the sim silent). Bench XX daemon stays G·22.

### Environment variables for CI key override

All host tools accept `FIPS_NSEC` (64 hex chars) to override the identity secret key.
`FIPS_PEER_NPUB` (66 hex chars) overrides the peer's public key (used by `fips-handshake` and `microfips-sim`).
`FIPS_SECRET` and `FIPS_PEER_PUB` are accepted as deprecated fallbacks (with a warning printed to stderr).
When not set, tools panic — no default device identity is allowed.

## Open Issues

| # | Title | Severity | Notes |
|---|-------|----------|-------|
| #12 | M7: HTTP status page over FIPS | feature | Firmware has HTTP handler; needs E2E test |
| #14 | X25519 DH discussion | discussion | Requires FIPS maintainer decision |
| #81 | BLE address type mismatch pitfall | pitfall | `Address::random()` hardcodes RANDOM kind — must match target. Current code correct. |
| #90 | L2CAP RX channel capacity overflow | bug | Fixed: RX channel increased 5→16 slots (commit `dcf3dc8`). Needs hardware verification. |
| #88 | FRAME_CAP vs FIPS MTU RAM tradeoff | analysis | Resolved: FRAME_CAP=768 (max that links on ESP32-D0WD DRAM budget). MTU stays 2048. |
| #77 | Firmware DoS hardening | security | Reconnect limits, memory protection. See also FIPS #57 (packet loss degradation on ESP32-S3). |
| #91 | ESP32-S3 STA WiFi power-save latency spikes | fixed (STA) | Pure-STA path fixed via init-config PS=None (commit `07bbdcf`, min ~9 ms across a 5-min soak). Relay AP+STA must keep default power save — disabling it regresses to 180–830 ms. See "ESP32-S3 WiFi Power-Save Latency" below. |

### FIPS Issues Affecting microfips

Tracking upstream FIPS GitHub issues (Amperstrand/fips) that affect microfips:

| FIPS # | Title | State | microfips Impact |
|--------|-------|-------|------------------|
| #57 | Monotonic packet loss degradation on ESP32-S3 | OPEN | **Monitor** — WiFi/BLE coexistence issue on S3. May affect D0WD. |
| #58 | microfips compatibility vs 0.4.0-dev | OPEN | **P0 future** — Noise IK→XX, FMP v0→v1, version negotiation. Breaking changes. microfips prep: `noise-xx` feature complete and CI-enforced on both wires (2026-08-31, #178); FMP v1 negotiation remains (#179). |
| #73 | Privacy: cleartext pubkeys enable device tracking | OPEN | **Consider** — Ephemeral introduction keys for BLE pubkey exchange. |
| #79 | PeerBackoff auto-denies legitimate ESP32 peers | CLOSED | **Verified fixed** — FIPS no longer counts tie-breaker yields as failures. |
| #82 | FilterAnnounce exceeds L2CAP MTU | CLOSED | **Accepted** — Leaf nodes skip bloom filters. FRAME_CAP=768 < 1071B FilterAnnounce. |
| #56 | 0-byte frame fatal disconnect | CLOSED | **Verified fixed** — FIPS now handles gracefully. ESP32 never sends 0-byte frames. |
| #66 | ESP32-S3 MTU limitation and bloom filter skip | CLOSED | **Verified** — FIPS skips FilterAnnounce to MTU-limited peers. |
| #55 | Dual-role tie-breaker deadlock | CLOSED | **Verified fixed** — FIPS adds disconnect+settle delay after yield. |

## ESP32-S3 WiFi Power-Save Latency (Issue #91)

**Symptom.** Ping to an ESP32-S3 WiFi node (any `!FIPS` client, an Extender, or a plain
STA on the home router) is a healthy ~10 ms for the first ~30 s after association, then
degrades into intermittent episodes of **170–800 ms RTT with bunched replies** (`ping`
reports `pipe 2–5`). During an episode even the *minimum* RTT rises to a beacon-multiple
floor — every packet is delayed, not just some. Between episodes it returns to ~10 ms. It
is **not** a constant tax; it is periodic bursts on a fast baseline.

**Root cause (investigated 2026-08-22).** STA-side WiFi modem-sleep / DTIM buffering. The
esp-radio blob defaults to `WIFI_PS_MIN_MODEM`; after the link goes idle the station parks
its receiver between the AP's DTIM beacons, so the AP buffers downlink and releases it in
bursts. Confirmed by elimination — each test isolates one variable:

| Test | Result | Rules out |
|------|--------|-----------|
| Idle-yield probe during a spike | executor polled 140k/s → **116/s** | raw CPU load (core is starved of *wakeups*, not busy) |
| Heap sampled through spikes | flat 50–53 KB | memory leak / allocator stall |
| Slow with **no USB reader** attached | still slow | serial-JTAG logging FIFO |
| **Pure STA** build (no peer-node, no relay) | still slow | the `relay-ap-peer` code |
| **1 ping/s vs 5 ping/s** | both hit the same floor | throughput/backlog — it is per-packet *latency* |
| Phone confirmed on the home AP, not `!FIPS` | spikes persist | a sleeping client on our softAP |
| **Bare STA on the home router, no softAP** | still spikes, ~30 s onset | AP+STA single-radio coexistence |

The last row is decisive: a plain station with no softAP and no hop chain still spikes, so
the buffering is the station's own sleep against the upstream AP.

**FIX for the pure-STA path (verified, committed `07bbdcf`).** Disable STA power save via
esp-radio's *init-config*, not a post-`set_config` call. `esp_radio::wifi::new()` runs
`set_power_saving(None)` and then `set_config(initial_config)` as one init with a single
`esp_wifi_start`, so passing the station config as `ControllerConfig::default()
.with_initial_config(Config::Station(...))` keeps PS=None from being clobbered:

```rust
let controller_config = esp_radio::wifi::ControllerConfig::default()
    .with_initial_config(WifiConfig::Station(station_config(ssid, password)));
let (mut wifi_controller, interfaces) = esp_radio::wifi::new(wifi, controller_config)?;
// ...no separate set_config; connect_async() directly.
```

Verified A/B on one board/identity (bare STA on the home router): before, min RTT jumped to
170 ms in ~30 s-onset episodes (windows 170–850 ms); after, **min holds ~9 ms across a 5-min
soak**, only sporadic single-packet jitter to ~180 ms. Applies to `wifi_transport.rs`
(plain WiFi / hybrid leaf node).

**Do NOT call `set_power_saving(None)` yourself after a separate `set_config` on the pure-STA
path** — that applies cleanly (logs `Ok`, Noise link handshakes) but the build then answers
**0 pings** (link `connected`, FSP datagrams stall), reproducible across a hard reset. Use
the init-config form above instead.

**Do NOT disable STA power save on the relay (AP+STA) path — it REGRESSES latency.** In
AP+STA the default `WIFI_PS_MIN_MODEM` is the *good* config. Head-to-head, same instant:
a Router with `set_power_saving(None)` added to `apply_config` ran a **uniform 180–830 ms**
(every window, no fast samples), while the unmodified committed Router beside it held
**9–22 ms**. Forcing the station awake breaks the single-radio AP+STA time-sharing. The
relay's own latency is intermittent spikes on a ~9 ms baseline (a milder, separate
coexistence effect, related to upstream FIPS #57) and is **not** helped by any PS change;
leave the relay on the default. If a relay-side fix is ever needed, the lever is softAP
DTIM/beacon tuning in `AccessPointConfig`, not STA power save.

**Testing caveat (bit me repeatedly).** Reflashing the *same* device identity many times in
a row leaves stale link/session state on the daemon for that node address, which produces
flaky ICMP (link `connected` in `fipsctl show links` but 0 % echo) that is easy to mistake
for a firmware regression. When validating a fix, flash a *fresh* identity, or restart the
daemon, and confirm against `fipsctl show links` / `show peers` before trusting a ping
result. Measure with `ping -c10 -i0.2` and read the **min** (baseline health) separately
from avg/max (episode severity); a single 5-ping burst is too short to catch the ~30 s
onset.

## BLE Address Type Pitfall (Issue #81)

When constructing a targeted BLE connect (e.g. trouble-host `Central::connect()` with
`filter_accept_list`), the address kind (PUBLIC vs RANDOM) must match what the remote
device actually advertises. A mismatch causes silent connect failure.

- ESP32-D0WD and ESP32-S3 both use random static BLE addresses (`USE_PUBLIC_BLE_ADDRESS = false`)
- The FIPS Linux daemon has a PUBLIC address on hci0
- Current code uses `AddrKind::PUBLIC` in the filter_accept_list for FIPS — correct
- FIPS (commit 9c6507e) uses `resolve_addr_type()` to dynamically detect remote address type
- **NEVER use `Address::random(bytes)` for the FIPS target** — it hardcodes `AddrKind::RANDOM`

## Upstream FIPS Compatibility

**Upstream FIPS source:** `/home/ubuntu/src/fips` (NOT `/home/ubuntu/src2/fips.rm` which is stale/abandoned).
Use `/home/ubuntu/src/fips` for any FIPS source code reference, diff, or API lookup.

### Current State (as of 2026-05-02)

- **FIPS master** has merged macOS BLE (bluest crate) and Windows ports
- **`ble-transport-reliability`** branch (based on master at `cbc7809`) adds: Linux drain task with adaptive rate limiting, macOS BLE transport, GATT PSM re-discovery on reconnect, BLE config validation, TCP window clamping for BLE-tunneled TCP. **Wire protocol unchanged** — ESP32 needs no changes.
- **`linux-ble-stability-v2`** branch (our previous test branch) has been superseded by `ble-transport-reliability`. All leaf-proxy and BLE framing fixes are now in the newer branch.
- **`next` branch** (0.4.0-dev, jmcorgan/next) contains breaking changes: Noise IK/XK → XX, FMP v0 → v1, version negotiation, profile negotiation
- microfips needs to **rebase off latest master** before next development cycle

### FIPS `ble-transport-reliability` Branch (audited 2026-05-02)

23 commits since branch-off from master. Key changes relevant to microfips:

**No wire protocol changes.** All changes are Linux/macOS daemon-side implementation details transparent to an ESP32 L2CAP peer.

**Linux drain task architecture:**
- Each BLE connection has a background drain task that mediates all rate-limited sends
- `send()` enqueues to a 32-slot channel, drain task applies rate limiting before L2CAP write
- `send_urgent()` bypasses drain queue — used for MSG2 handshake responses and rekey MSG2
- Rate limiter uses BBR-inspired AIMD: 15–80 Kbps, RTT <200ms → probe up, RTT >500ms → drain down
- ESP32 observation: inbound frame timing is spaced by rate limiter, no backpressure signaling
- **ESP32 doesn't need drain/pacer** — it writes directly to BLE at controller speed

**macOS BLE transport:**
- New `io_macos.rs` using bluest (central) and CoreBluetooth (peripheral)
- Identical wire protocol to Linux: same PSM (0x0085), MTU (2048), framing (2-byte BE length prefix), pubkey exchange format
- ESP32 works with both macOS and Linux FIPS daemons without modification

**GATT PSM re-discovery (Linux + macOS):**
- Retries GATT PSM characteristic read after 200ms on first failure
- macOS: uses `discover_services_with_uuid()` to bypass stale cache
- ESP32 impact: none — ESP32 advertises PSM, doesn't discover it

**BLE config validation:**
- `BleConfig::validate()` resets invalid fields to defaults instead of erroring
- Defaults: PSM=0x0085, MTU=2048, max_connections=7, connect_timeout=10s, send_burst=2048
- ESP32 impact: none — ESP32 uses compile-time constants

**Key FIPS BLE constants:**
| Constant | Value | Purpose |
|----------|-------|---------|
| `BLE_LINUX_QUEUE_DEPTH` | 32 | Drain queue capacity (frames) |
| `BLE_SEND_TIMEOUT` | 15s | L2CAP write timeout |
| `MIN_RATE_BPS` | 15,000 | Minimum send rate (AIMD) |
| `MAX_RATE_BPS` | 80,000 | Maximum send rate (AIMD) |
| `RTT_LOW_MS` | 200 | Uncongested threshold |
| `RTT_HIGH_MS` | 500 | Congested threshold |
| `PUBKEY_EXCHANGE_TIMEOUT_SECS` | 5 | Pubkey exchange timeout |

**Pubkey exchange format (verified compatible):**
- FIPS sends 34 bytes raw through `BleStream`, which adds 2-byte BE length prefix on the wire
- microfips sends 36 bytes (2B prefix + 34B payload) matching the same format
- Both sides agree: `[0x00][32B x-only pubkey][1B capabilities]` (34B payload)
- `BluerStream::recv()` strips the 2-byte prefix before passing to `pubkey_exchange()`

### Noise Protocol Design Choices

FIPS implements Noise directly (not via a spec-compliant Noise library), following only the
cryptographic primitives and ordering from the Noise spec. Custom payloads (startup epoch,
capability flags, negotiation) are attached to handshake messages. Same approach as Lightning Network.

Confirmed by FIPS maintainer (2026-04-11): these are deliberate design choices, not bugs.

| # | Choice | Description | Rationale |
|---|--------|-------------|-----------|
| D1 | Empty AAD during handshake | `AEAD_ENCRYPT(k, n, b"", plaintext)` instead of passing `h` as AAD | Custom Noise implementation with own payloads; transport keys bind via `ck` |
| D2 | IK `se` token ordering | Initiator computes `DH(e,rs)` not `DH(s,re)` | Part of custom IK. Eliminated in 0.4.0-dev by switching to Noise XX. |
| D3 | x-only ECDH | `SHA256(x_coordinate)` instead of raw ECDH shared secret | Required for Nostr npub compatibility. Same technique as BIP-340. |

microfips matches all three for interoperability. Golden vectors (FIPS issue #1) validate cross-implementation compatibility.

### ESPHome Integration

NOTE (2026-08-31): `leaf_proxies` no longer exists in the fips we track — a full
source scan of fork/main (v0.5.0) finds no `leaf_proxies`/ESPHome code. It existed
in an older daemon generation (documented then as `SHA256("esphome:fips_ble:" +
identity_seed)` → secp256k1 keypair, a FIPS-side TCP-proxy pattern). microfips's
approach is unchanged and unaffected: direct BLE L2CAP from ESP32 to FIPS,
implementing the FIPS protocol stack natively. See issue #76 for integration paths.

### Upcoming Breaking Changes (0.4.0-dev)

When the `next` branch ships, microfips will need:

1. **Noise XX migration** — rewrite `microfips-core/src/noise.rs` for 3-message XX handshake (both link and session layers)
2. **FMP v1 wire format** — new msg3 header, version negotiation payload
3. **Version negotiation** — min/max version range, 64-bit feature bitfield, TLV extensions
4. **Profile negotiation** — new concept, requirements TBD
5. **Golden vector regeneration** — XX handshake vectors needed for validation

## Lab Bench Test Rig (added 2026-08-29)

Physical bench for hardware-testing PRs (mDNS/ESP-NOW/hybrid/link-death, e.g. PR #156).
Tooling: `tools/lab_keygen.py`, `tools/fips-lab.yaml`, `scripts/run_lab_daemon.sh`,
`tools/detect_lab_ports.sh`. Migration target: fips-lab (labgrid) — see bottom.

**Protocol dialect on the bench:** the lab daemon (and every deployed fips we
interop with) speaks the **IK / v0.5.0 wire** — all bench nodes are built with
default features. The Noise XX wire (FIPS next forward-compat) is
**suite-, host-interop-, AND bench-hardware-verified** (2026-09-02, #179/#193):
the protocol suite runs green under `--features std,noise-xx` (CI-enforced),
the firmware crates forward `noise-xx`, `microfips-sim --features noise-xx`
completed a full FMP v1 negotiation + heartbeat session against a next-branch
daemon (0.6.0-dev `f1ff410f`, built in a WORKTREE — never in
`/home/ubuntu/src/fips`, whose target/ refreshes the system daemon), and the
bench S3 ran the same wire against a next daemon end-to-end (pinned mDNS
discovery, FMP v1 agreed, one sustained session, daemon-initiated rekey
followed over XX). Bench XX recipe: `BenchXxDaemon` in fips-lab (G·22 identity
on :21214, `node.rendezvous.lan.enabled: true` — LAN mDNS is OPT-IN on next,
unlike 0.5.0), binary from a `/tmp/opencode/fips-next` worktree via
`FIPS_NEXT_BIN` (disposable — rebuild per the `tools/fips-xx-cross-example.rs`
header recipe when gone); scenario `test_bench_xx` guards it (two greens
2026-09-02). MMP report interop fixed 2026-09-03 (#196, sim-verified): the
"Malformed SenderReport" noise was our 0.5.0-era report bodies (double
type byte) hitting next's `[format_version][total_length]` decoder, and the
forever-200ms report interval was us sending SenderReports a Leaf was never
supposed to send. On the XX wire report sends are now gated on the
negotiated provides/wants bits (Leaf: ReceiverReports only, data-gated to
the heartbeat cadence) and use next's slim layouts — the daemon parses
every report and measures real RTT/loss/jitter. The bench XX session
also found the silent-peer policy bug (healthy link torn down every
~link_dead_timeout when no FSP flows; fixed by feeding the policy from the
direct send paths — regression-guarded in `test_bench_xx`). Opt-in cross test
via `FIPS_NEXT_CROSS_BIN=<upstream xx_cross example> cargo test -p fips-noise
--features std`.

### Current bench inventory

| Board | Chip | Identity (device-registry.json) | USB | Port |
|-------|------|----------------------|-----|------|
| lab workstation | — | `lab-daemon` G·8 | — | runs the FIPS lab daemon |
| S3 board `F4:12:FA:CF:03:84` | ESP32-S3 16MB | `s3-lab` G·9 | USB-JTAG | ttyACM by-id Espressif serial |
| CYD | ESP32-D0WD-V3 | `cyd` G·10 | CH340 | ttyUSB by-path (CH340 has no serial) |
| M5 Atom `81528A13B6` | ESP32-PICO-D4 | `atom-a` G·11 | FTDI | ttyUSB by-id |
| M5 Atom `9D529068B4` | ESP32-PICO-D4 | `atom-b` G·12 | FTDI | ttyUSB by-id |
| M5 Stack `Hades2001` | — | — | FTDI | **OFF-LIMITS — other project** |

Identity assignment rule: **one deterministic key per physical board (MAC/serial
labeled), never per-role**. `tools/lab_keygen.py N` derives nsec/npub/node_addr
(generator·N, node_addr = SHA256(x)[..16]) with a self-check; write the entry into
device-registry.json and override at build time (`DEVICE_NSEC_HEX_esp32s3=...` etc. — the
microfips-build env-override feature). The daemon peers pin via
`DEVICE_NPUB_HEX_vps=<lab-daemon npub>`.

### Lab daemon security checklist (run before exposing any test daemon)

1. Isolated `--config` with explicit deterministic nsec — NEVER the workstation's
   persistent `/etc/fips/fips.key`, and never reuse `vps`/`linux` identities.
2. `bind_addr` scoped to the lab AP interface, not `0.0.0.0` — the workstation has
   NO host firewall (ufw inactive) and sits on multiple interfaces (LAN,
   docker bridges; NetBird is NOT running on this machine as of 2026-08-30 —
   older docs said otherwise. Autodetect: `ip link | grep -E "wt|nb"` and
   `systemctl is-active netbird` before reasoning about overlay exposure).
3. Dedicated UDP port (21213 in use; system daemon keeps 2121 — they coexist).
4. Know the mDNS exposure: `rendezvous.lan` joins multicast on ALL interfaces
   (mdns-sd has no interface filter). Advert data is public-key-only; fine on the
   lab LAN, do not enable where untrusted L2 exists.
5. Audit with `ss -tulnp` after start; expect exactly one v4 UDP bind on the AP IP.

### Lessons learned (2026-08-29 session)

- **nohup is not enough.** A `nohup cmd &` launched from a tool shell dies when the
  shell times out — the SIGTERM hits the whole process group. Use
  `setsid cmd > log 2>&1 < /dev/null &` (see `scripts/run_lab_daemon.sh`). Symptom
  seen: daemon silently dead 2 min after "successful" start; every later probe
  (mDNS browse, bridge) mysteriously timed out against a corpse.
- **pkill -f self-match** (hit AGAIN despite the warning above): the pattern
  `fips --config /tmp/opencode/fips-lab` matched the invoking shell's own command
  line and killed it. Kill by exact PID resolved via `pgrep -f "<config path>"`.
- **"mdns broken" was a dead daemon.** Verify the service is alive (fresh log
  lines, PID check) before debugging the protocol. `zeroconf` (pip) is the fastest
  independent advert check: browse `_fips._udp.local.` for ~4s.
- **Binary path sharing:** the systemd `fips.service` runs
  `/home/ubuntu/src/fips/target/release/fips` — a `cargo build` there silently
  refreshes the system daemon binary (Restart=on-failure picks it up). Build in a
  worktree if you don't want that.
- **espflash flash syntax:** `espflash flash -p PORT --chip CHIP IMAGE` — this
  version has no `--no-monitor` flag; run monitors separately (pyserial).
- **Board ports are unstable; CH340 (CYD) exposes no USB serial number** — pin by
  `/dev/serial/by-path/` for the CYD, by-id for FTDI atoms and the S3 USB-JTAG.

### Orchestration roadmap (fips-lab migration)

**Status 2026-09-01:** the fips-lab pytest environment is REPAIRED (fips-lab
`148e269`, issue #4 closed — 91 tests collect cleanly). The cross-project
**Bench Testing Playbook** now lives at fips-lab `docs/bench-testing-playbook.md`
(graduation principle, bench patterns, scenario backlog) — read it before
running interactive hardware tests. First scenario LIVE: `test_rekey_soak`
(fips-lab #5, closed done — green in 96s, RED proven against pre-rekey firmware).

Phase 1 — labgrid targets for the bench (S3 via espflash USB-JTAG; CYD/atoms via
esptool), port pinning from `detect_lab_ports.sh` semantics, and a
`LabFipsServiceDriver` (isolated config/port/identity + the security checklist).
Phase 2 — scenario suites: `test_rekey_soak.py` (#5), `test_link_death.py`,
`test_mdns_pinned.py` (rogue-advert), `test_rekey_self_initiated.py` (node-driven,
validates the REKEY_AFTER_SECS knob), `test_mcu_to_mcu_mesh.py` (STM32 CDC + S3 WiFi
dual-peer; asserts S3 FSP auto-initiation both directions — the initiator was always
armed; the old zero-count was a missing send-log line, fixed 2026-09-02 #188), and
`test_rekey_bidirectional.py` (node AND daemon rotate in one session — cadences must
overlap: daemon=120 starves under ~33s node rotations, daemon=20 sits under the 30s
dampening; daemon=32 is the working point) — all LIVE and green; the reusable bench
fixtures live in fips_lab/bench.py (build matrix + binary verification + daemon
lifecycle + tap + artifacts). The mesh scenario was promoted 2026-09-02 (queue
item 2) to FULL FSP session-content assertions: SessionSetup→ACK, msg3, then
PING/PONG round-trips — PINGs identified by size (len=73/frame=110B, a 4-byte
payload: 35B body + AEAD), PONGs by the inbound log's src prefix (STM32 registry
NodeAddr `132f39a9…f295` → `src=132f..f295`, fsp_type 0x00; the SessionAck is
len=135 fsp_type=0x02), 3/3/1 across two consecutive greens. Also LIVE:
`test_l2cap_bringup.py` (#188 candidate 4,
graduated 2026-09-02 — atom-a D0WD ↔ lab daemon over BLE L2CAP via the bench D0WD
tier; two consecutive greens with identical verdicts; the bench-era
`test_esp32_l2cap.py` retired). D0WD bench facts it encoded: L2CAP firmware pins the
peer ONLY via `FIPS_EXTRA_ALLOWED_XONLY_HEX` (embedded as ASCII hex, not bytes —
`DEVICE_NPUB_HEX_vps` is not compiled into this transport); the system daemon holds
the hci0 advert slot so the lab daemon never advertises (link forms via its scanner
probing the atom's peripheral advert); the atom's FTDI port asserts DTR on open and
resets the board (deterministic fresh boot); raw-termios taps stop receiving live
bytes on FTDI after draining the backlog — `fips_lab/ftdi_tap.py` (pyserial) is the
FTDI tap, `raw_tap.py` stays USB-JTAG-only. Also LIVE:
`test_rekey_soak_long.py` (known unknown 1 closed 2026-09-02 — the hour-scale
interleave soak at the bidirectional working point; first full 1800s run green
in 30:31: 49 node + 21 daemon rotations, 56 cutovers/drains, 319 heartbeats,
ONE session throughout — zero rebuilds across 70 rotations — zero disconnects/
SecurityViolations. Floors scale with the window via REKEY_SOAK_SECS so the
same file smoke-runs at 120s; the daemon's FIRST rotation is a tail event at
short windows — only asserted at ≥360s, modeled from the V ∈ [17,47]s
per-rotation redraw). Remaining:
`test_espnow_gw.py`, `test_hybrid_switch.py` (daemon stop/start
via the driver = RX-silence test; both blocked on a second S3), and the soak
cron/nightly wiring (hackathon-tooling bench-nightly job — the scenario exists
and is marked slow; scheduling is tooling work),
with keygen→cargo-env wiring automated in fixtures
(the build matrix + binary verification from the playbook).
Phase 3 — port router-automation patterns: per-board file locks, `results/<run_id>/`
reporting, SHC cloud-lab WAN-daemon job for internet-path scenarios.

Cross-project — micronuts FIPS integration (ADRed 2026-09-02, micronuts
`docs/FIPS-INTEGRATION-ADR.md`): ESP32-sidecar topology (wallet UART →
microfips-esp32 leaf → daemon → responder → mint). The service envelopes already
match — spike verdict in micronuts `docs/FIPS-SERVICE-INTERFACE-SPIKE.md` (gate 3 ✅,
~50-line mechanical adapter; one open sizing item: Cashu RPC payloads vs the 2048 B
FMP frame cap). Gates before wiring: (1) our #179 (FMP v1 + noise-xx firmware
forwarding), (2) micronuts security review. #113 display output closed 2026-09-02
(hardware + visual verified; see the Build section).

### Lessons (2026-09-02: #113 display close-out)

- **Registry entries carrying the same key in ≥2 encodings drift silently.** The
  `linux` entry's `npub_hex` had drifted from its own bech32 `npub` field after a
  daemon key rotation — every MSG1 dropped with zero daemon logs (bad-key rejections
  live below INFO). Guard: layer 4 in
  `crates/microfips-core/tests/device_registry.rs` (cross-encoding recompute,
  RED-proven against the stale entry); generalized in hackathon-tooling
  `checklists/key-registry-consistency.md`.
- **embassy-executor 0.10: task constructors return `Result<SpawnToken, SpawnError>`;
  `Spawner::spawn` takes the token and returns `()`.** The `.expect()` belongs on the
  constructor call, not around `spawn` — the #113 research brief had this inverted
  (verified in embassy-executor-macros 0.8.0 `task.rs`).
- **Concurrent sessions on one worktree can commit each other's dirty files.** A
  parallel session's 16:04 commit (6652549) swept this session's dirty AGENTS.md into
  its own docs commit — content benign, history interleaved. When a second session is
  live on the same repo, check `git show --stat` after committing. Worse variant
  (2026-09-02 evening): the parallel session REBASED main mid-session, orphaning this
  session's just-made commit; their follow-up `add -A` then landed the (still-present
  worktree) content inside their own commits. A local commit hash is NOT durable while
  another session is live — after any surprise history change, re-verify by CONTENT
  (`git log -S "<marker>"`, grep the tree), not by hash, and keep the durable record
  in the issue close-out + regression tests, not the commit id.

### More lessons (same session, hybrid-switch testing)

- **`option_env!` env knobs are invisible to cargo's change detection.**
  `HYBRID_TEST_WIFI_DOWN_SECS` / `HYBRID_WIFI_PROBE_SECS` / `ESP_NOW_CHANNEL` have no
  `rerun-if-env-changed` — setting OR clearing them silently keeps stale values in the
  binary. Always `touch crates/microfips-esp-transport/src/config.rs` (or `cargo clean -p`)
  when changing these, and verify the knob landed via its boot log line before drawing
  conclusions. Fix tracked in the hybrid return-to-WiFi issue.
- **Build-equivalence claims need `cmp`, not reasoning (bit 2026-09-02, #113).** After
  a build sequence with env overrides, a source edit in between makes cargo recompile —
  with whatever env is (not) exported at that moment. A flashed local-pinned binary and
  a later "final" rebuild silently differed (registry vps key vs local daemon key), and
  "the edit is codegen-neutral" was the wrong proof. `cmp` the two artifacts, or
  re-verify the pinned constant in the binary, before calling builds equivalent.
- **Opening `/dev/ttyACM*` (USB-JTAG) resets the board** — pyserial asserts DTR on open.
  For observation without disturbance use raw `os.open` + `termios` (no TIOCM touches;
  see /tmp/opencode/raw_logger.py pattern), or keep one persistent owner.
- **Never let two processes drive the same serial port** (logger + esptool DTR/RTS dance
  knocked an S3 into download mode). One owner; reboot via the firmware console `reset`
  command or via esptool while nothing else holds the port.
- **Verify which path actually carries traffic** before debugging protocol code: node logs
  look identical across transports. Use `ip neigh` (ARP presence), daemon-side mDNS bursts,
  and `tcpdump 'udp port 5353 or host <node-ip>'` as ground truth.

### Lessons (2026-08-31: noise-xx dual-wire + CI unblock)

- **Hangs are invisible to failure counts.** The #178 scorecard said 11 failing
  tests; reality was 11 failures + 2 HANGS — and under `--test-threads=1` a hang
  means the suite never prints any summary. Quote counts only from a run with
  per-test termination (`cargo nextest`, now wired into CI + `.config/nextest.toml`).
- **`curl -sL` without `-f` turns upstream 404s into false "drift".** The
  golden-vectors job compared our vectors against a "404: Not Found" body for 25
  minutes before anyone read the log. Fetch failures must be distinguishable from
  content mismatches (fixed: skip-with-warning + #180).
- **Pins die when upstream rewrites history.** Two CI contracts broke in one day
  (golden-vectors branch deleted; pinned FIPS_REF commit vanished from the clone).
  Vendor references you depend on (the specquotes `.pin` pattern), don't fetch
  them from refs you don't control at CI time.
- **Red main hides new breakage.** Five distinct failures (secret literal in a
  script, fmt drift, a new clippy lint, two dead upstream refs) had accumulated
  since morning unnoticed. Before diagnosing YOUR change, check the last green
  run on main — and read the *first failing step* of a failed job, not the job name.
- **Test harnesses must not hardcode wire sizes.** The IK-era tests hardcoded
  106/57/69-byte messages; under `noise-xx` the fips-fmp constants switch to
  33/106/118 and the tests broke in ways unrelated to the feature. Always use
  `wire::HANDSHAKE_MSG*_SIZE` / `wire::MSG*_WIRE_SIZE` (they are feature-gated
  correctly).
- **Fixtures coupled to RNG draw order are brittle by design.** The XX
  ScriptedPeer fixture only matches the Node's msg1 byte-for-byte because both
  draw (ephemeral, then sender-index) in the same order — reordering draws in
  `handshake_xx` breaks the fixture silently-in-intent (tests fail loudly, at
  least). Documented in the fixture; do not "clean up" the draw order casually.

### Lessons (2026-09-01: rekey soak — interactive hardware session)

Full write-up: **fips-lab `docs/bench-testing-playbook.md`** (the cross-project
playbook; PRta/tollgate-lab/fips-lab contributions and the scenario backlog
live there). The short version of that session:

- **Every interactive finding is a scenario not yet written.** The rekey soak
  cost ~25 agent tool-calls + ~20 min of sleeps to prove once; as
  `test_rekey_soak` (fips-lab #5) it costs one pytest command forever. The
  interactive loop finds new knowledge; scenarios guard it. If you grep the
  same log for the same string in two different sessions, that grep belongs
  in `tests/`.
- **Verify compiled-in env by scanning the binary.** `option_env!` is
  invisible to cargo change detection — after an env-pinned build, grep the
  binary for the SSID (ASCII), the pinned npub (`bytes.fromhex`), and the
  G·N nsec tail. Catches the stale-pin trap in seconds.
- **Port kill order: reader first, then fuser, then flash.** A stuck
  espflash timeout is a stale console reader; check `pgrep` before retrying.
- **The daemon is silent about rekey at INFO** — assert on the *absence
  signature* (the SecurityViolation disconnect cycle) plus the node console,
  not on daemon rekey lines.
- **The soak found a real bug the suite couldn't**: duplicate msg1 resends
  drew two different msg2s (fresh ephemeral each answer) → key divergence →
  SecurityViolation blip. Fixed in bbfa864 with a TDD idempotence test. Bench
  time is the only place this class of timing/loss bug shows up — which is
  exactly why scenarios must be cheap to rerun.

### Lessons (2026-09-02: #179 XX interop — raw-framing truncation)

- **The test transport can mask wire bugs the real surface exposes.** The XX
  negotiation extra was silently truncated by `fmp_raw_frame_size` (fixed
  `MSG2_WIRE_SIZE`) in raw-UDP mode; every ScriptedPeer test passed because
  the test harness uses length-prefixed framing, which never consults that
  code. The bug only surfaced as a daemon-side "msg3 decryption failed" in a
  live sim↔next-daemon run — with matching keys, matching counters on paper,
  and identical ciphertext bytes. When a framing change lands, drive the real
  transport mode (raw UDP for FIPS), not just the scripted harness.
- **Bisect cross-implementation crypto failures with key/nonce dumps, not
  code-reading.** Reading both state machines top-down three times "proved"
  they matched; one `mix_key` trace on each side + the attempted-nonce log
  pinpointed the divergence (our n=1 vs their n=2) in a single round-trip.
  The upstream worktree is disposable — instrument it with eprintln probes
  freely, never commit it.
- **A self-consistent implementation pair proves nothing about interop.** Our
  XX stack was green on both self-tests AND upstream's own self-tests before
  the live run failed. The only decisive artifacts are cross-implementation:
  the `xx_cross` example (their responder driven over stdio by our initiator)
  and the live daemon run. Keep the cross test env-gated
  (`FIPS_NEXT_CROSS_BIN`) so it runs wherever an upstream checkout exists.

### Lessons (2026-09-02: FSP observability + rekey interleave)

- **Validate the probe before trusting a zero.** The mesh scenario counted
  `"type=0x00"` on the S3 console — a string that can only appear in *inbound*
  datagram log lines, impossible in that topology. Its zero was guaranteed and
  proved nothing; a whole session nearly concluded "the WiFi path never
  initiates FSP" from it. A soft metric that has never observed a positive is
  not evidence of absence: derive probe strings from the emitting code (grep
  the exact format string in the firmware source), and never hardcode a
  guessed frame size (the `149B` probe; the real SessionSetup frame is 148B —
  record a size histogram instead).
- **Presence signatures: every send path needs its log line.** The absence-
  signature doctrine has a counterpart: a scenario asserting that something
  DID happen needs firmware evidence that the thing emits. `Node::
  send_session_datagram` logged nothing on success while link-message sends
  logged — so FSP initiator activity was invisible on every transport, and
  the console silence was misread as a dead initiator. Fixed in b2094de
  (`steady: sending session datagram type=… len=… frame=…B`). New send paths
  follow this convention, symmetric with `send_link_message`.
- **Model BOTH sides' timers from source before bench-tuning cadences.** The
  bidirectional rekey working point cost 3 bench runs (2 failures) because
  the fips daemon's jitter mechanism — per-session uniform ±15s draw,
  `fips/src/node/mod.rs` REKEY_JITTER_SECS — was one grep away and predicts
  every outcome. What matters: BOTH sides reset their rekey timer on every
  rotation (node: `session_started` resets on own cutover AND peer-follow
  promote; daemon: per-session `after_secs` restarts when the node's rotation
  replaces the session), plus the node's 30s self-init dampening. Hardware-
  verified starvation bounds: daemon=120 starves (V never under the ~33s node
  cycle); daemon=20 mostly suppresses the node (most V draws under 30s).
  Working point daemon=32. Bench runs then only confirm — they don't explore.
- **Rekey interleave is safe on hardware**: node AND daemon rotating in one
  session — 2 consecutive greens (`test_rekey_bidirectional`), one session
  throughout (zero rebuilds), zero SecurityViolations. The dampening +
  idempotent-msg1 machinery held under real interleaving.

### Spec quotes (greatspectations dogfood, 2026-08-29)

We pin verbatim spec quotes in source comments and CI-check them against vendored
spec documents, using our experimental fork `Amperstrand/greatspectations`
(default branch `ai-experimental-slop` — clearly labeled as our AI-experiment
branch; upstream conversations only after the dogfood proves value).

- `specquotes.toml` + `specs/` (vendored at a pinned upstream ref, see
  `specs/*.pin`) define the sources; the CI job `Spec Quotes` enforces them.
- Quote syntax: `// BIP #173: <verbatim spec text>`; `// Note:` lines are
  comment-asides (dropped from the match) used to record accepted deviations
  with rationale, directly adjacent to the spec line they deviate from.
- FIPS wire invariants (#176, 2026-09-03): six quotes pin our wire format to
  the daemon implementation we interop with — sources `FIPS-AEAD`/`FIPS-ECDH`
  (D1 empty-AAD, D3 x-only ECDH), `FIPS-FMP` (4-byte common prefix),
  `FIPS-BLE` (L2CAP `[0x00][pubkey:32]` pre-handshake exchange), `FIPS-FSP`
  (SessionSetup dispatched by the phase nibble), `FIPS-MDNS` (TXT `npub=`
  routing-hint trust model). Vendored under `specs/fips/` from Amperstrand/fips
  fork/main `0aef8ea2` (the same ref the CI daemon builds use) with leading
  rust comment markers stripped (`//!`, `///`, `//`) so multi-line quotes
  match across lines. Placement rule learned the hard way: a quote block
  continues through ANY following `//`-family comment — always place quotes
  LAST in a comment run, directly above the code they pin.
- First use: `crates/fips-identity/src/bech32.rs` pins BIP-173's encoder-
  lowercase MUST (we comply) and the mixed-case MUST NOT (documented deviation
  from the PR #156 review — harmless because the decoded key is only a routing
  hint authenticated by Noise IK).
- Local run:
  `uvx --from /home/ubuntu/src/greatspectations greatspectate check --config specquotes.toml --comment-start "// " --comment-continue "//" --comment-aside "// Note:" <files>`
- Drift is caught with file:line precision plus a "closest match (NN%)"
  hint — tamper-test verified 2026-08-29.

### CYD radio: not dead, just slow (2026-08-29 correction)

The CYD was misdiagnosed as radio-dead from `NoAccessPointFound` (rssi -128) inside
a ~60s window while an Atom associated from the same desk. Reflash + a longer
patience window: it associates fine, DHCPs, and completed an mdns-open
trust-on-first-advert discovery + IK handshake against the lab daemon. Rule: give
a board's WiFi retry loop at least 2-3 minutes (5 attempts) before concluding
hardware faults — and prefer cross-checking (another board on the same AP) over
attributing to the radio early.
