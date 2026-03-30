# microfips — Agent Reference

## Project

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO and ESP32.
Both MCUs use length-prefixed framing → Python bridge (serial↔UDP) → VPS running stock FIPS.
- **STM32F469I-DISCO:** USB CDC ACM transport
- **ESP32-D0WD:** UART transport (CP210x USB-serial)

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

## Build

### STM32F469

```bash
cargo build --release --target thumbv7em-none-eabi
# Output: target/thumbv7em-none-eabi/release/microfips
```

### ESP32-D0WD

Requires the Espressif Rust toolchain (installed via `espup`, activated with `RUSTUP_TOOLCHAIN=esp`):

```bash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc
# Output: target/xtensa-esp32-none-elf/release/microfips-esp32
```

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

### When probe-rs IS acceptable

- Initial bringup (no USB active yet)
- Reading/writing flash option bytes (carefully — see warnings below)
- `probe-rs download --chip STM32F469NIHx --connect-under-reset` (flashing only, then detach immediately)

### SWD recovery when USB is active (STM32)

```bash
st-flash --connect-under-reset reset
```

### ESP32 flash and monitor

Do NOT use probe-rs with ESP32. Use `espflash` from the Espressif toolchain.

```bash
# Flash
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 target/xtensa-esp32-none-elf/release/microfips-esp32

# Monitor (optional, after flash)
. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash monitor -p /dev/ttyUSB0 --chip esp32
```

**ESP32 serial port:** `/dev/ttyUSB0` (CP210x USB-serial), NOT `/dev/ttyACM*`.
Always detect by VID:PID `10c4:ea60` (Silicon Labs CP210x):

```bash
for p in /dev/ttyUSB*; do
    vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$vid" = "10c4/ea60/100" ] && echo "ESP32 on $p"
done
```

## Testing

### Unit tests (no hardware)
```bash
cargo test -p microfips-core          # 83 tests: Noise, FMP, FSP, identity
cargo test -p microfips-core -- --nocapture  # verbose output
cargo test -p microfips-protocol --features std -- --test-threads=1  # 26 tests: framing, transport, node
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
more limited than STM32's 4-LED display:

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
   `STAT_HB_TX`, `STAT_HB_RX`, `STAT_USB_ERR`, `STAT_STATE`, `STAT_RECV_PKT`,
   `STAT_RECV_FRAME` can be read after reset via probe-rs (not live — only in reset/halt).

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

### ESP32-D0WD

| Peripheral | Pins | Notes |
|------------|------|-------|
| UART TX | GPIO1 | Connected to CP210x RX |
| UART RX | GPIO3 | Connected to CP210x TX |
| LED (blue) | GPIO2 | Active high, onboard |
| Flash | GPIO6–GPIO11 | SPI flash (do not use) |

## Clock Config

### STM32F469

```
HSI (16 MHz) → PLL → 168 MHz sysclk
                   → 48 MHz USB (PLL_Q, Clk48sel)
                   → 42 MHz APB1
                   → 84 MHz APB2
```

HSE bypass hangs on this board. Do NOT use HSE.

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

## ESP32 Serial Port

The ESP32 connects via CP210x USB-serial with VID:PID `10c4:ea60`. The ttyUSB number varies.
Always detect by VID/PID:

```bash
for p in /dev/ttyUSB*; do
    vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$vid" = "10c4/ea60/100" ] && echo "ESP32 on $p"
done
```

## Nightly Toolchain

Uses `nightly` (latest). No pinned date. CI uses `dtolnay/rust-toolchain@v1` with `toolchain: nightly`.

## Known Bugs

### RESOLVED: MCU silently drops MSG2 (#6, closed)

**Root cause was THREE bugs, not one:**

1. **recv_frame infinite loop (critical):** The framing "fix" (7f4d093) introduced an infinite
   loop where `continue` skipped `read_packet` on incomplete multi-packet frames. MSG2 (71B)
   arrives as 64B+7B USB packets. The incomplete-frame case did `compact + continue` which
   looped back without ever calling `read_packet`. The MCU spun forever, 30s timeout never
   fired. **Fix (bb97936):** restructure to always fall through to `read_packet` when more
   data is needed. No code path loops back without either returning or awaiting I/O.

2. **Handshake loop discarded non-Msg2 (7f4d093):** Stale FIPS data (heartbeat retransmits
   from previous sessions) arriving before MSG2 caused immediate `Err(Invalid)` return.
   **Fix:** loop `recv_frame` until Msg2 received, skip other message types.

3. **steady() inline framing had same pattern (7f4d093):** Used `continue` in a `while` loop
   instead of `break`. Fixed with `break`.

### RESOLVED: Bridge stops forwarding CDC->UDP (#11, closed)

**Root cause:** Two bugs in the Python bridge.

1. **Thread race on reconnect:** When one thread died, the bridge started new threads while
   the old surviving thread was still running. Two `serial_to_udp` threads reading from the
   same TCP socket split data between them, corrupting frames. **Fix (a76156e):** set
   `state['stop']=True` and join BOTH threads with generous timeouts before reconnecting.

2. **CPU spinning:** `serial_to_udp` looped with no sleep when idle, starving `udp_to_serial`
   under Python GIL contention. **Fix:** `time.sleep(0.001)` in the idle path.

### Proxy serial port open is slow (#8, open)

`serial.Serial()` takes 5-10 seconds to open `/dev/ttyACM*`. The MCU sends MSG1 ~0.5s
after enumeration. If the proxy isn't open yet, MSG1 is lost. The MCU's retry loop (500ms
CONNECT_DELAY + 30s RECV_TIMEOUT + 3s RETRY_SECS = ~33.5s per cycle) handles this, but
the first attempt always misses. Fix: add reconnection logic to proxy or use a control
byte to trigger handshake start.

### Proxy cannot survive USB device reset (#8, open)

When the MCU resets (SWD or power), the USB device disappears. The proxy gets ENODEV on
serial write and the serial reader thread dies. The proxy needs reconnection logic.

### RESOLVED: Noise finalize bug on ESP32

`noise_st.finalize()` was called on the pre-read_message2 state instead of the clone
after `read_message2()`. The handshake appeared to succeed but transport keys were wrong.
**Fix:** use `st.finalize()` (the state after `read_message2()`), not `noise_st.finalize()`.

### RESOLVED: UART recv error handling on ESP32

`transport.recv()` returning `Err` in the steady-state loop caused immediate session failure.
Any transient UART glitch killed the entire session. **Fix:** `continue` with 100ms delay
on recv errors instead of returning `Err`.

### RESOLVED: Timer starvation on ESP32

ESP32 UART delivers data continuously, causing `select()` to always pick the recv branch
and starving the heartbeat timer. The heartbeat check inside the recv branch
(`if Instant::now() >= next_hb`) handles this, matching the STM32's approach.

## CI Pipeline

GitHub Actions (`.github/workflows/ci.yml`) runs on push/PR to main:
- **test**: `cargo test -p microfips-core` (83 tests) + `cargo test -p microfips-protocol --features std` (26 tests)
- **build-host**: `cargo build -p microfips-link -p microfips-sim -p microfips-http-test --release` + upload artifacts
- **lint**: `cargo clippy` + `cargo fmt --check` on all host crates (core, protocol, link, sim, http-test)
- **sim-smoke**: verify `microfips-sim` starts and exits cleanly on EOF
- **build-firmware**: STM32 `cargo build -p microfips --release --target thumbv7em-none-eabi` + ESP32 `. /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc` using upstream crates.io embassy v0.6.0
- **fips-integration**: local keygen + Noise IK handshake test (must pass), public VPS handshake (continue-on-error)
- **summary**: aggregate status table

### Environment variables for CI key override

All host tools accept `FIPS_SECRET` (64 hex chars) to override the identity secret key.
`FIPS_PEER_PUB` (66 hex chars) overrides the peer's public key (used by `fips-handshake` and `microfips-sim`).
When not set, tools fall back to hardcoded defaults (MCU dev identity / VPS pubkey).

## Open Issues

| # | Title | Severity | Notes |
|---|-------|----------|-------|
| #8 | serial_tcp_proxy: slow open + no reconnection on USB reset | infrastructure | MCU retry loop compensates |
| #12 | M7: HTTP status page over FIPS | feature | Firmware has HTTP handler; needs E2E test |
| #13 | Noise crate audit: snow not viable | resolved | Hand-rolled Noise is working, tested (113 tests) |
| #14 | X25519 DH discussion | discussion | Requires FIPS maintainer decision |
| #15 | IK responder transport keys mismatch | low | MCU is always initiator; untested code path |
