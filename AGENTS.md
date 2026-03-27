# microfips — Agent Reference

## Project

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO.
USB CDC ACM → length-prefixed framing → Python bridge (serial↔UDP) → VPS running stock FIPS.

## Build

```bash
cargo build --release --target thumbv7em-none-eabi
# Output: target/thumbv7em-none-eabi/release/microfips
```

## Flash and Run

### CRITICAL: Do NOT use probe-rs during USB testing

probe-rs halts the CPU periodically for RTT reads. When the CPU is halted mid-USB-transfer,
the USB connection drops. This manifests as device disappearing from lsusb, /dev/ttyACM1
not appearing, and corrupted register reads (EPENA stuck, EPTYP wrong).

This was misdiagnosed as an embassy USB bug (PR #5738, since closed). The real root cause
is probe-rs + USB coexistence. A completely separate firmware using usb-device (NOT embassy)
also fails enumeration with probe-rs attached. See Amperstrand/micronuts#19.

**Correct deployment: use st-flash, then test via pyserial.**

```bash
# Flash
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
st-flash --connect-under-reset write microfips.bin 0x08000000

# Reset
st-flash --connect-under-reset reset

# Wait ~5s for boot + 2s CDC delay, then run bridge
sleep 7
python3 tools/fips_bridge.py
```

### When probe-rs IS acceptable

- Initial bringup (no USB active yet)
- Reading/writing flash option bytes (carefully — see warnings below)
- Attaching RTT for non-USB debugging (e.g., clock config, RNG, crypto)
- `probe-rs download --chip STM32F469NIHx --connect-under-reset` (flashing only, then detach immediately)

### SWD recovery when USB is active

```bash
# Option 1: st-flash can connect under reset when probe-rs cannot
st-flash --connect-under-reset reset

# Option 2: Full power cycle
# Unplug ALL USB cables from board, press+hold NRST, plug ST-LINK USB, release NRST
```

## Testing

### Unit tests (no hardware)
```bash
cargo test -p microfips-core          # 71 tests: Noise, FMP, FSP, SLIP, identity
cargo test -p microfips-core -- --nocapture  # verbose output
```

### Host-side VPS handshake test (no MCU)
```bash
cargo run -p microfips-link            # sends MSG1 to VPS via UDP, expects MSG2
```

### USB CDC echo test (hardware, no FIPS)
```bash
# Flash echo firmware, then:
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

Firmware is already flashed and proven correct via sim. After a fresh reboot:

```bash
# 1. Verify USB
lsusb | grep -E "c0de|0483"   # should show microfips (c0de:cafe) and ST-Link (0483:374b)
cat /sys/class/tty/ttyACM1/device/../uevent | grep PRODUCT  # should be c0de/cafe

# 2. Upload latest bridge to VPS
sshpass -p 'Elci9quadAd' scp -o StrictHostKeyChecking=no \
  tools/fips_bridge.py routstr@orangeclaw.dns4sats.xyz:/tmp/fips_bridge.py

# 3. Restart FIPS to clear stale sessions
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  "echo Elci9quadAd | sudo -S systemctl restart fips"

# 4. Reset MCU and wait for USB enumeration
st-flash --connect-under-reset reset && sleep 7

# 5. Start serial TCP proxy on host (listens on port 45679)
python3 tools/serial_tcp_proxy.py --serial /dev/ttyACM1 --port 45679 &

# 6. SSH reverse tunnel: VPS:45679 → host:45679
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no -fN \
  -R 45679:127.0.0.1:45679 -o ServerAliveInterval=30 \
  routstr@orangeclaw.dns4sats.xyz

# 7. Start bridge on VPS (connects to VPS:45679 → tunnel → proxy → MCU)
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  'nohup python3 /tmp/fips_bridge.py --tcp 127.0.0.1:45679 > /tmp/bridge_hw.log 2>&1 &'

# 8. Wait 30s, check results
sleep 30
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  'cat /tmp/bridge_hw.log'
# Should show: CDC->UDP: 114B (MSG1), UDP->CDC: 69B (MSG2), then heartbeat exchanges

sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  "echo Elci9quadAd | sudo -S journalctl -u fips --no-pager -n 10 --since '2 min ago'"
# Should show: promoted to active peer, no "link dead timeout"

# Cleanup
pkill -f serial_tcp_proxy
pkill -f "ssh.*45679"
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  'pkill -f fips_bridge'
```

## Debugging Best Practices

1. **Never read hardware registers while probe-rs has the CPU halted.** The state is
   undefined mid-transfer. Register captures under these conditions are artifacts,
   not evidence of firmware bugs.

2. **Isolate variables before escalating.** If USB fails, first test without probe-rs.
   Only blame firmware after eliminating external variables.

3. **One board with probe-rs is not evidence.** A systematic bug affecting all STM32 chips
   would have multiple reporters. If you're the only one seeing it, check your test setup.

4. **File issues on our repo first.** Only escalate upstream after reproducing with
   correct methodology and getting independent confirmation.

5. **Minimal, separated changes.** One concern per PR. Don't bundle cleanup, errata
   workarounds, and speculative recovery paths.

## Embassy Fork Status

Forked to `Amperstrand/embassy` with 4 changes to `embassy-usb-synopsys-otg`:
1. Remove SNAK from `configure_endpoints()` IN path
2. Add AHBIDL wait before FIFO flush (STM32F4 errata ES0321 §2.16.1)
3. Add EPENA recovery in `write()` (RISKY — can abort in-flight transfers)
4. Add proper disable sequence in `endpoint_set_enabled()` IN path

**Assessment**: SNAK removal is cosmetic (every other DWC2 driver skips it). AHBIDL waits
are safe errata workarounds. EPENA recovery in `write()` is risky — micronuts tested
1200 commands on upstream without it ever firing. Consider reverting to upstream if
st-flash deployment resolves USB issues.

PR: https://github.com/embassy-rs/embassy/pull/5738 (closed)

## DANGER: Do NOT erase flash via probe-rs

```bash
# NEVER RUN THIS — corrupts STM32F469 flash/option bytes:
probe-rs erase --chip STM32F469NIHx --connect-under-reset
```

## Known Pins

| Peripheral | Pins | Notes |
|------------|------|-------|
| USB OTG FS | PA11 (DM), PA12 (DP) | CDC ACM |
| LED | PG6 | Active high (user LED) |
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

The MCU appears as `/dev/ttyACM1` (NOT ttyACM0 — that's the ST-Link).
Verify with: `cat /sys/class/tty/ttyACM1/device/../uevent | grep PRODUCT`
Expected: `PRODUCT=c0de/cafe`

### DANGER: Do NOT manipulate USB sysfs paths directly

**Never run these commands:**
```bash
# NEVER — causes permanent TTY hang requiring physical USB disconnect or reboot:
echo "1-6" > /sys/bus/usb/drivers/usb/unbind
echo "1-6" > /sys/bus/usb/drivers/usb/bind
```

Unbinding a CDC ACM device from the `usb` driver and rebinding it corrupts the kernel
TTY layer. The `/dev/ttyACM*` node may reappear but `open()` hangs at kernel level with no
process holding it. This was discovered the hard way on 2026-03-27.

**Recovery attempts that DO NOT work:**
1. **xhci_hcd unbind/bind** — resets USB bus but TTY zombie persists
2. **USB device unbind + st-flash re-enumerate** — device re-enumerates fresh but TTY zombie persists
3. **cdc_acm module reload** (`modprobe -r cdc_acm && modprobe cdc_acm`) — driver reloads but TTY core zombie persists
4. **USBDEVFS_RESET ioctl** on `/dev/bus/usb/...` — hangs and further degrades USB subsystem
5. **`uhubctl`** — no compatible hub controller on this machine for port power cycling
6. **authorized toggle** — this is what causes the problem in the first place
7. **probe-rs** — cannot help; once USB bus is degraded, ST-Link is also invisible
8. **PCI-level reset** (`/sys/bus/pci/devices/.../reset`) — works ONCE to restore USB bus after
   xhci_hcd damage, but TTY zombie survives; after USBDEVFS_RESET damage, PCI reset also hangs
9. **Removing stale /dev node + udev trigger** — sysfs TTY entry already gone, but cdc_acm bind
   hangs trying to re-register the TTY (kernel TTY core slot 1 is permanently stuck)
10. **Signal-interrupted open() from C** — child in D-state, open() is not interruptible

**CRITICAL: Do NOT cascade recovery attempts.** Each failed attempt further degrades the kernel.
The recovery order should be: (1) PCI reset to restore USB bus, (2) if TTY still stuck, just reboot.
Do NOT attempt USBDEVFS_RESET or cdc_acm bind after a TTY hang — they will cascade into
PCI-level hangs requiring a reboot anyway.

**Recovery that WORKS (in order of preference):**
1. **Rebind unbound PCI controller** — if `0000:02:00.0` disappeared from
   `/sys/bus/pci/drivers/xhci_hcd/`, rebinding it (`echo "0000:02:00.0" | sudo tee .../bind`)
   restores the USB bus and all devices. This works when the controller was cleanly unbound
   (not stuck in D-state).
2. **PCI-level reset** (`echo 1 > /sys/bus/pci/devices/0000:XX:XX.X/reset` after unbinding from
   xhci_hcd) — restores USB bus if only xhci_hcd was damaged, does NOT fix TTY zombie
3. Physical USB cable disconnect/reconnect (of the MCU USB cable, not ST-Link)
4. Host reboot (only thing that clears a TTY zombie)

**Safe USB reset via st-flash** (does NOT affect TTY layer):
```bash
st-flash --connect-under-reset reset
```

This resets the MCU CPU but does NOT cause USB re-enumeration issues because it goes
through the ST-Link SWD interface, not the USB bus.

**If you need to reset the USB connection**, use `st-flash --connect-under-reset reset` or
physically disconnect/reconnect the cable. Never touch `/sys/bus/usb/drivers/usb/`.

## Nightly Toolchain

Pinned to `nightly-2025-09-01` (1.91). Required by smoltcp 0.13 and cortex-m compatibility.

## VPS Access

```bash
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz
# FIPS logs:
echo 'Elci9quadAd' | sudo -S journalctl -u fips --no-pager -n 30 --since '5 min ago'
```

VPS FIPS binds `0.0.0.0:2121`, MCU peer configured at `127.0.0.1:31337`.
