# Milestones

## M0: Environment & Workspace

- [x] Confirm board (STM32F469I-DISCO) and tooling
- [x] Create git repo and GitHub remote
- [x] Create project scaffold and documentation
**Success signal:** `cargo build --target thumbv7em-none-eabi` succeeds.

## M1: USB CDC ACM + Echo

- [x] Embassy firmware with clock config (HSI 16 MHz, 168 MHz sys, 48 MHz USB)
- [x] USB OTG FS enumeration with CDC ACM class (VID:PID = c0de:cafe)
- [x] LED on PG6 during active connection
- [x] Bidirectional CDC echo (multiple packet sizes including 64B + ZLP)
- [x] USB enumeration works with st-flash (probe-rs breaks USB — see AGENTS.md)
- [x] Embassy fork fully reverted to upstream (4 USB "fixes" were misdiagnosis)

**Success signal:** `ls /dev/ttyACM*` shows device; echo test passes.

## M2: Length-Prefixed Framing

- [x] `cdc_send_frame()`: 2-byte LE header + payload + ZLP handling
- [x] `recv_frame()`: reassembly from 64B USB packets with timeout
- [x] Buffer compaction for partial reads
- [x] EP_OUT buffer increased from 256B to 1024B (StaticCell, matches micronuts)

**Success signal:** Multi-packet frames sent and received correctly over CDC.

## M3: Host-Side Handshake Test

- [x] `microfips-link` crate: Noise IK handshake over raw UDP
- [x] Proven against live VPS: sends MSG1, receives MSG2 (69B)
- [x] VPS promotes MCU identity to active peer
- [x] Transport keys derived correctly

**Success signal:** `cargo run -p microfips-link <vps-host>:2121` completes handshake.

## M4: MCU Handshake with Live VPS

- [x] MCU sends MSG1 (114B) through USB → proxy → tunnel → bridge → FIPS
- [x] Bridge receives MSG2 (69B) from FIPS, writes to tunnel → proxy → CDC
- [x] MCU does NOT panic (PANIC_LINE = 0)
- [x] `finalize()` fixed to match FIPS `split()` — single HKDF with empty IKM
- [x] ESTABLISHED format fixed to match FIPS wire format: `[receiver_idx:4][counter:8]`
- [x] Receive path uses `counter` from header (not local counter) for AEAD nonce
- [x] Non-ESTABLISHED messages ignored in steady state (other peers through bridge)
- [x] Firmware compiled and flashed to MCU
- [ ] Hardware test: MCU completes handshake with live VPS (blocked by kernel TTY hang)

**Current blocker:** Kernel TTY hang from USB sysfs manipulation (2026-03-27).
Firmware is ready — needs host reboot to clear TTY zombie, then hardware test
should work immediately (sim proved protocol correct for 70+ seconds).

**Success signal:** VPS journalctl shows "Connection promoted to active peer"
followed by sustained heartbeat exchange (no "link dead timeout").

## M5: Host-Side Full Lifecycle Simulator

- [x] `microfips-sim` crate: simulates MCU FIPS lifecycle on host (std, no embassy)
- [x] Uses same `microfips-core` protocol code as firmware
- [x] Length-prefixed framing over stdin/stdout and TCP
- [x] `--listen PORT` mode for direct TCP bridge testing
- [x] Full lifecycle: handshake → heartbeat loop → reconnection
- [x] Sustained heartbeat exchange proven for 70+ seconds against live VPS
- [x] Non-ESTABLISHED messages from other peers ignored gracefully
- [x] Read timeout set on TcpStream so heartbeat timer fires

**Success signal:** `cargo run -p microfips-sim --listen 45679` completes handshake and
maintains heartbeat exchange when connected through SSH tunnel + VPS bridge.

**Status: DONE — sim is a proven FIPS leaf node.**

## M6: MCU Full Lifecycle

- [x] Firmware compiled with all protocol fixes (finalize, ESTABLISHED format, counter)
- [x] Firmware flashed to MCU
- [ ] MCU completes handshake with live VPS (blocked by kernel TTY, needs reboot)
- [ ] MCU sends heartbeats every 10s, VPS responds
- [ ] MCU processes incoming ESTABLISHED messages (heartbeat, disconnect)
- [ ] Reconnection after USB disconnect
- [ ] Long-running stability (10+ minutes sustained)

**Status: Firmware ready, awaiting hardware test after reboot.**

## M7: HTTP Status Page

- [ ] Tiny HTTP/1.1 server over FIPS session
- [ ] Serve status page with node info (uptime, peer state, address)
- [ ] End-to-end test: request from another FIPS peer

**Success signal:** `curl http://<fips-addr>` from VPS returns status page.
