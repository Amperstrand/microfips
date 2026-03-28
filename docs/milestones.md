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
- [x] **Framing bug found and fixed** — `recv_frame()` discarded header on incomplete frames
- [x] **Protocol crate proven** — `microfips-protocol` with Transport trait, 10 passing tests
- [x] **Full software proof** — host sim completes handshake + 45s sustained heartbeat vs live VPS
- [ ] Backport framing fix to firmware `main.rs` and reflash
- [ ] MCU completes handshake with live VPS (MSG1 sent, MSG2 processed, keys derived)
- [ ] MCU sends heartbeats every 10s, VPS responds
- [ ] MCU processes incoming ESTABLISHED messages (heartbeat, disconnect)
- [ ] Reconnection after USB disconnect
- [ ] Long-running stability (10+ minutes sustained)

**Status: UNBLOCKED. Framing bug root cause identified in `microfips-protocol` tests.
Needs firmware backport + reflash + hardware test.**

The host-side simulator (`microfips-sim`) completes the full lifecycle successfully
(45+ seconds heartbeat exchange), and the `microfips-protocol` crate's framing tests
prove the recv_frame fix. The firmware `main.rs` has the same bug and needs the same fix.

**Success signal:** MCU LEDs show ESTABLISHED (green+orange+blue), heartbeat exchange
sustained for 10+ minutes, no MSG1 retries.

## M6.5: Host-Side Transport Trait

- [x] `microfips-protocol` crate: `#![no_std]` Transport trait with `wait_ready()`, `send()`, `recv()`
- [x] `FrameWriter` and `FrameReader`: length-prefixed framing over any Transport
- [x] `Node<T: Transport, R: CryptoRng>`: handshake, steady-state, heartbeat
- [x] `MockTransport` for unit testing (loopback mode, reset per test)
- [x] 10 passing tests: roundtrip, 71B frame, 128B frame, sequential, timeout, large frame (1400B), node send/recv
- [x] Embassy-executor v0.10.0 `block_on()` pattern (Box::leak + pool_size=64 task)
- [x] Full software proof: `microfips-sim` completes handshake + 45s sustained heartbeat vs live VPS
- [x] Framing bug found: `recv_frame()` discarded header on incomplete frames — fixed in protocol crate
- [ ] `CdcTransport` implementation for firmware (wraps embassy USB CDC ACM)
- [ ] Firmware `main.rs` slimmed to thin wrapper using `Node<CdcTransport, Rng>`

**Status: DONE — protocol crate is tested and proven. Firmware integration is the next step.**

The `Transport` trait uses RPITIT (`impl Future<Output = ...>`) for async methods, making it
compatible with both embassy (no_std) and tokio/std runtimes. The `#[cfg(feature = "std")]` gate
enables `MockTransport` and test infrastructure for host-side testing.

**Success signal:** `cargo test -p microfips-protocol --features std` covers framing, transport,
and node lifecycle — all without hardware or network.

## M7: HTTP Status Page

- [ ] Tiny HTTP/1.1 server over FIPS session
- [ ] Serve status page with node info (uptime, peer state, address)
- [ ] End-to-end test: request from another FIPS peer

**Success signal:** `curl http://<fips-addr>` from VPS returns status page.
