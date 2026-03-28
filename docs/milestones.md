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
- [x] MSG1 reaches FIPS through full chain (CDC → proxy → tunnel → bridge → UDP)
- [x] VPS promotes MCU to active peer ("Connection promoted to active peer" in journal)
- [x] FIPS responds with MSG2 (69B) back through chain
- [x] Bridge logs confirm bidirectional flow: CDC→UDP (MSG1) and UDP→CDC (MSG2)
- [ ] **BUG: MCU does not process MSG2** — retries MSG1 every ~33s indefinitely
- [ ] MCU sends heartbeats every 10s, VPS responds
- [ ] MCU processes incoming ESTABLISHED messages (heartbeat, disconnect)
- [ ] Reconnection after USB disconnect
- [ ] Long-running stability (10+ minutes sustained)

**Status: BLOCKED by MSG2 processing bug (#6).**

The host-side simulator (`microfips-sim`) completes the full lifecycle successfully
(70+ seconds heartbeat exchange), proving the protocol logic is correct. The bug is
in the firmware's USB packet → frame reassembly layer, not in Noise/FMP.

**Hypothesis:** `recv_frame()` fails to reassemble the 2-byte length prefix + MSG2
payload across USB 64-byte packet boundaries. The MSG2 frame (71B = 2B header + 69B)
spans two USB packets (64B + 7B), but something in the framing logic causes it to be
dropped. Possible causes:
1. `recv_frame()` returns a frame with wrong offset due to leftover data in buffer
2. `read_packet()` returns data that doesn't align with the framing protocol
3. The MCU receives FIPS's MSG2 but `fmp::parse_message()` fails to match it

**Success signal:** MCU LEDs show ESTABLISHED (green+orange+blue), heartbeat exchange
sustained for 10+ minutes, no MSG1 retries.

## M6.5: Host-Side Transport Trait

- [ ] Extract protocol state machine from `main.rs` into `microfips-core`
- [ ] Define `Transport` trait: `send_frame()`, `recv_frame()`, `wait_ready()`
- [ ] Implement `CdcAcmTransport` for firmware (wraps `CdcAcmClass`)
- [ ] Implement `TcpTransport` for host testing (wraps `TcpStream`)
- [ ] Implement `MockTransport` for unit testing (in-memory channels)
- [ ] Protocol logic tests run with `MockTransport` (no hardware, no network)
- [ ] Full handshake + heartbeat test runs on host in <1 second

**Status: PLANNED. See issue #7.**

Research shows that mocking embassy-usb directly is impractical (would require implementing
5 traits including full USB enumeration sequence). The recommended approach is to abstract
the FIPS protocol behind a `Transport` trait, keeping all testable logic in `microfips-core`
(which supports `std`). The firmware `main.rs` becomes a thin wrapper. Embassy already has
`embassy-executor/platform-std` and `embassy-sync` has a `std` feature, making this feasible.

**Success signal:** `cargo test -p microfips-core` covers the full FIPS lifecycle including
framing, handshake, heartbeat, and reconnection — all without hardware.

## M7: HTTP Status Page

- [ ] Tiny HTTP/1.1 server over FIPS session
- [ ] Serve status page with node info (uptime, peer state, address)
- [ ] End-to-end test: request from another FIPS peer

**Success signal:** `curl http://<fips-addr>` from VPS returns status page.
