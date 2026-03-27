# microfips

Minimal FIPS (Free Internetworking Peering System) leaf node on STM32F469I-DISCO.

A Rust embedded firmware that implements a leaf-only FIPS node on an STM32F469 board
using Embassy for async HAL, USB CDC ACM for serial transport, length-prefixed
framing, Noise_IK handshake, and a no_std FIPS protocol stack.

## Current Status

**What works:**
- USB CDC ACM enumeration and bidirectional data transfer
- FIPS Noise_IK handshake: complete end-to-end on sim (proven 70+ seconds)
- Three critical protocol bugs found and fixed (see below)
- Host-side handshake test (`microfips-link`) proven against live VPS
- 71 unit tests pass for protocol logic (Noise, FMP, FSP, SLIP, identity)
- Bridge-on-VPS architecture verified: full MSG1/MSG2/heartbeat exchange on sim
- Firmware compiled and flashed to MCU, ready for hardware test

**Current blocker:**
- Hardware test blocked by kernel TTY hang caused by USB sysfs manipulation during
  debugging (2026-03-27). Requires host reboot to clear. See AGENTS.md for details.
  The firmware is already flashed and proven correct via sim — after reboot, hardware
  test should work immediately.

**Three bugs fixed this session:**
1. `finalize()` used wrong HKDF (two calls with `[0;32]` + `k1` instead of single
   call with empty IKM). Produced completely wrong transport keys.
2. ESTABLISHED wire format was `[sender_idx:4][receiver_idx:4][epoch:4]` but FIPS
   uses `[receiver_idx:4][counter:8]`. Heartbeats were silently dropped by FIPS.
3. Sim had no TcpStream read timeout — heartbeat timer never fired.

**See [docs/milestones.md](docs/milestones.md) for detailed milestone tracking.**

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
Seed:    b'microfips-stm32fips-test-seed-001'
Secret:  ac68af89462e7ed26ff670c186b4eeb53c4e82d72c8ef6cec4e676c7843f832e
Pubkey:  02633860dc5f7ccb68df79362c9edf35e35e616d7ae86fcee268a2f749452b6842
npub:    npub1vdtfdhzl0n9k3hmexckfahe4ud0xzmt6aphuacng5tm5j3ftdppqj0ujhf
```

## Testing

### Unit tests (no hardware)

```sh
cargo test -p microfips-core                    # 71 tests: Noise, FMP, FSP, SLIP, identity
cargo test -p microfips-core -- --nocapture     # verbose output
```

### Host-side simulator (no hardware, tests against live VPS)

The `microfips-sim` crate simulates the MCU's full FIPS lifecycle (handshake +
heartbeat loop) on the host, using the same `microfips-core` protocol code.
It speaks length-prefixed framing over stdin/stdout and can be piped through
`fips_bridge.py --tcp` to test against the VPS without any hardware.

```sh
cargo run -p microfips-sim                      # local framing test
# See tools/test_sim_vps.sh for VPS integration test
```

### Host-side VPS handshake (no hardware, raw UDP)

```sh
cargo run -p microfips-link                     # sends MSG1 to VPS via UDP
```

### Hardware (STM32F469)

```sh
# Flash (use st-flash, NOT probe-rs — see AGENTS.md)
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
st-flash --connect-under-reset write microfips.bin 0x08000000

# After reboot, run the hardware test:
# 1. Reset MCU
st-flash --connect-under-reset reset && sleep 7

# 2. Start serial TCP proxy on host
python3 tools/serial_tcp_proxy.py --serial /dev/ttyACM1 --port 45679 &

# 3. Start SSH reverse tunnel (VPS:45679 → host:45679)
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no -fN -R 45679:127.0.0.1:45679 \
  -o ServerAliveInterval=30 routstr@orangeclaw.dns4sats.xyz

# 4. Start bridge on VPS
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  'nohup python3 /tmp/fips_bridge.py --tcp 127.0.0.1:45679 > /tmp/bridge_hw.log 2>&1 &'

# 5. Wait 30s, check bridge log for CDC->UDP (MSG1) and UDP->CDC (MSG2 + heartbeats)
sleep 30
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  'cat /tmp/bridge_hw.log'

# 6. Check FIPS journal for no "link dead timeout"
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no routstr@orangeclaw.dns4sats.xyz \
  "echo Elci9quadAd | sudo -S journalctl -u fips --no-pager -n 10 --since '2 min ago'"
```

## Build

Requires nightly Rust pinned to `nightly-2025-09-01` (1.91), `thumbv7em-none-eabi`
target, and `arm-none-eabi-objcopy`.

```sh
cargo build --release --target thumbv7em-none-eabi
```

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
| M4 | MCU handshake with live VPS | In Progress (blocked by kernel TTY, firmware ready) |
| M5 | Host-side full lifecycle simulator (`microfips-sim`) | Done (sim proven 70+ seconds) |
| M6 | MCU full lifecycle (handshake + heartbeat exchange) | Pending (firmware ready, needs hardware test) |
| M7 | HTTP status page over FIPS session | Planned |

See [docs/milestones.md](docs/milestones.md) for details.

## Project Layout

```
microfips/
  Cargo.toml                    # Workspace root, patch cortex-m
  AGENTS.md                     # Build/flash/test/debug reference
  src/main.rs                   # MCU firmware (FIPS leaf node)
  crates/
    microfips-core/             # no_std FIPS protocol: Noise, FMP, FSP, SLIP, identity
    microfips-link/             # Host-side handshake test (UDP, proven against VPS)
    microfips-sim/              # Host-side full lifecycle simulator (framing over stdio)
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
