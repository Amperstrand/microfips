# microfips — Agent Reference

## Project

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO.
USB CDC ACM → length-prefixed framing → Python bridge (serial↔UDP) → VPS running stock FIPS.

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

VPS FIPS binds `0.0.0.0:2121`, MCU peer configured at `127.0.0.1:31337`.
FIPS logs: `vssh "echo $VPS_PASS | sudo -S journalctl -u fips --no-pager -n 30 --since '5 min ago'"`

## Build

```bash
cargo build --release --target thumbv7em-none-eabi
# Output: target/thumbv7em-none-eabi/release/microfips
```

## Flash and Run

### CRITICAL: Do NOT use probe-rs during USB testing

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

### When probe-rs IS acceptable

- Initial bringup (no USB active yet)
- Reading/writing flash option bytes (carefully — see warnings below)
- `probe-rs download --chip STM32F469NIHx --connect-under-reset` (flashing only, then detach immediately)

### SWD recovery when USB is active

```bash
st-flash --connect-under-reset reset
```

## Testing

### Unit tests (no hardware)
```bash
cargo test -p microfips-core          # 71 tests: Noise, FMP, FSP, identity
cargo test -p microfips-core -- --nocapture  # verbose output
```

### Host-side VPS handshake test (no MCU)
```bash
cargo run -p microfips-link            # sends MSG1 to VPS via UDP, expects MSG2
```

### USB CDC echo test (hardware, no FIPS)
```bash
python3 -c "
import serial, struct, time
s = serial.Serial('/dev/ttyACM1', 115200, timeout=1)
for n in [1, 16, 63, 64, 100]:
    payload = bytes(range(n))
    s.write(struct.pack('<H', len(payload)) + payload)
    time.sleep(0.05)
    hdr = s.read(2)
    resp = s.read(struct.unpack('<H', hdr)[0])
    assert resp == payload, f'echo failed for {n}B'
    print(f'echo {n}B OK')
print('all pass')
"
```

### Bridge + MCU + VPS handshake test (hardware)

See `scripts/test_hw_handshake.sh` for the full automated procedure. The manual steps are:

```bash
# 0. CLEANUP — kill all stale processes
pkill -9 -f serial_tcp_proxy 2>/dev/null
pkill -9 -f "ssh.*45679" 2>/dev/null
vssh 'pkill -9 -f fips_bridge 2>/dev/null; echo $VPS_PASS | sudo -S fuser -k 45679/tcp 2>/dev/null'
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

## Embassy Fork Status

**CRITICAL FINDING (2026-03-28):** The `Amperstrand/embassy` fork commit `c0289d7a8` breaks USB
enumeration on STM32F469. Only `embassy-usb-synopsys-otg/src/lib.rs` was modified (4 patches).
Switching all embassy deps to upstream crates.io v0.6.0 fixed enumeration immediately.

**Current firmware uses upstream crates.io embassy** — NOT the fork. See `crates/microfips/Cargo.toml`.

The 4 fork patches were:
1. Remove SNAK from `configure_endpoints()` IN path — cosmetic
2. Add AHBIDL wait before FIFO flush (STM32F4 errata ES0321 §2.16.1) — safe
3. Add EPENA recovery in `write()` — **RISKY**, can abort in-flight transfers
4. Add proper disable sequence in `endpoint_set_enabled()` IN path — safe

See GitHub issue #6 for investigation details.

## Debugging Best Practices

1. **Never read hardware registers while probe-rs has the CPU halted.** The state is
   undefined mid-transfer. Register captures under these conditions are artifacts,
   not evidence of firmware bugs.

2. **Use LED patterns for state visibility.** No debugger can be attached during USB
   traffic. The 4 LEDs encode the full state machine (see table above).

3. **Use atomic counters for post-mortem debugging.** `STAT_MSG1_TX`, `STAT_MSG2_RX`,
   `STAT_HB_TX`, `STAT_HB_RX`, `STAT_USB_ERR`, `STAT_STATE` can be read after reset
   via probe-rs (not live — only in reset/halt).

4. **Isolate variables before escalating.** If USB fails, first test without probe-rs.
   Only blame firmware after eliminating external variables.

5. **Minimal, separated changes.** One concern per PR. Don't bundle cleanup, errata
   workarounds, and speculative recovery paths.

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

## Known Pins

| Peripheral | Pins | Notes |
|------------|------|-------|
| USB OTG FS | PA11 (DM), PA12 (DP) | CDC ACM |
| LED green | PG6 | Active high |
| LED orange | PD4 | Active high |
| LED red | PD5 | Active high |
| LED blue | PK3 | Active high |
| RNG | HASH_RNG interrupt | Hardware TRNG |
| ST-Link | PA13 (SWDIO), PA14 (SWCLK) | Debug probe |

## Clock Config

```
HSI (16 MHz) → PLL → 168 MHz sysclk
                   → 48 MHz USB (PLL_Q, Clk48sel)
                   → 42 MHz APB1
                   → 84 MHz APB2
```

HSE bypass hangs on this board. Do NOT use HSE.

## USB Serial Port

The MCU appears as a CDC ACM device with VID:PID `c0de:cafe`. The ttyACM number varies
— it is NOT always ttyACM1 (ttyACM0 is usually ST-Link). Always detect by VID/PID:

```bash
for p in /dev/ttyACM*; do
    prod=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$prod" = "c0de/cafe/10" ] && echo "MCU on $p"
done
```

## Nightly Toolchain

Uses `nightly` (latest). No pinned date. CI uses `dtolnay/rust-toolchain@v1` with `toolchain: nightly`.

## Known Bugs

### MCU silently drops MSG2 (critical, #9)

The MCU sends MSG1 (114B) through the full chain and FIPS responds with MSG2 (69B),
but the MCU never processes it. The MCU retries MSG1 every ~33s indefinitely.

**Evidence:**
- Bridge log confirms CDC→UDP (MSG1) and UDP→CDC (MSG2) bidirectional flow
- VPS journal confirms "Connection promoted to active peer"
- Proxy log confirms SERIAL TX of MSG2 data to MCU
- MCU post-mortem counters show STAT_MSG1_TX=0, STAT_MSG2_RX=0 (counters are in BSS,
  reset to 0 by startup code — read during reset shows last run's values only if not
  power-cycled; probe-rs `read --connect-under-reset` may not capture running state)
- MCU does NOT panic (no LED error pattern observed)
- Host-side simulator works perfectly with same protocol code

**Hypothesis:** The firmware's `recv_frame()` (main.rs:366) fails to reassemble the
length-prefixed MSG2 across USB 64-byte packet boundaries. The MSG2 frame is 71B
(2B header + 69B payload) spanning two USB packets (64B + 7B). Possible causes:
1. `read_packet()` returns data that doesn't align with framing protocol expectations
2. The buffer state (`rpos`/`rlen`) from handshake MSG1 send leaks into recv_frame
3. `fmp::parse_message()` fails on the actual FIPS wire format (different from test vectors)
4. USB endpoint FIFO gets corrupted by the rapid data flood from FIPS after MSG2

**Debug approach:**
1. Extract protocol logic behind a `Transport` trait (see #10) to test framing on host
2. Add a known-good echo mode to firmware that echoes received frames back (verify USB RX works)
3. Use `STAT_STATE` (if not optimized out) or LED patterns to narrow down where MSG2 is lost
4. Capture the exact bytes the MCU receives via a pass-through logging mode

### Proxy serial port open is slow

`serial.Serial()` takes 5-10 seconds to open `/dev/ttyACM*`. The MCU sends MSG1 ~0.5s
after enumeration. If the proxy isn't open yet, MSG1 is lost. Workaround: use the proxy's
`--reset` flag which resets the MCU then auto-detects and opens the port.

### Proxy cannot survive USB device reset

When the MCU resets (SWD or power), the USB device disappears. The proxy gets ENODEV on
serial write and the serial reader thread dies. The proxy needs reconnection logic.

## CI Pipeline

GitHub Actions (`.github/workflows/ci.yml`) runs on push/PR to main:
- **test**: `cargo test -p microfips-core` (71 tests)
- **build-host**: `cargo build -p microfips-link --release` + upload artifact
- **lint**: `cargo clippy` + `cargo fmt --check` on host crates
- **build-firmware**: clones `Amperstrand/embassy` fork, builds for `thumbv7em-none-eabi` (BROKEN — fork breaks USB, needs update to use crates.io)
- **fips-integration**: runs `fips-handshake` against VPS (continue-on-error)
