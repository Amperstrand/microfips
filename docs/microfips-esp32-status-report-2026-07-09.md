# microFIPS-ESP32 Status Report
**Date:** 2026-07-09  
**Session:** microFIPS-esp32 Signal group  
**Status:** Phase 0 (ESP-NOW transport) ~85% complete, ready for demo work

## Project Overview

**Goal:** FIPS mesh on ESP32-C3 using ESP-NOW (peer-to-peer, no WiFi AP hierarchy)
**Repo:** ~/repos/microfips (branch feat/fips-v0-compat, commit 6fbf7c4)
**Upstream Strategy:** microfips maintains FIPS v0 interop (Noise IK). Upstream FIPS can't run on MCUs yet — maintainers need time to refactor. We run a leaner version until then.

## What Works (Done, Validated)

### 1. WiFi Transport
- ESP32-C3 connects to FIPS VPS1 (66.92.204.38) over WiFi
- Software interop test passes: Noise handshake completes, 89 TX/RX messages exchanged
- Cron runs every 60min, passing (microFIPS Interop Test)
- WiFi AP/Station mode functional

### 2. UART and USB Transports
- Both compile and flash successfully
- Binary targets exist and work (`uart.rs`, `usb.rs`)

### 3. ESP-NOW Transport Code
- 396 lines of FFI bindings + Transport trait implementation
- Init, peer management, send/receive callbacks, packet queuing
- Compiles clean as of today (commit 6fbf7c4, just pushed)
- Binary target `espnow.rs` exists
- LED blink pattern working (MAC address notification)

### 4. MAC-to-Node-Address Mapping
- `feat/mac-mapping` branch (commit 962657c, Phase 2.1)
- Mapping logic exists, not merged into main branch yet

### 5. FIPS Protocol
- Noise IK handshake path works (current VPS1 interop)
- Noise XX migration exists on `feat/noise-xx-handshake` branch (PR #132)
- FMP message handling (Msg3 variant) fixed

### 6. Monitoring Infrastructure
- Crons running: microFIPS Interop Test, FIPS VPS1 Health, FIPS Auto-Heal
- microfips-serial-logger-fix (hourly, LLM-driven, silent)
- Hardware detection working on /dev/ttyACM1 and /dev/ttyACM2

## What Doesn't Work / Blocked

### 1. ESP-NOW Binary Doesn't Link
- **Critical blocker:** cargo check passes but cargo build fails
- ESP-IDF symbols (nvs_flash_init, esp_netif_init, etc.) declared via FFI but not linked
- Error: `undefined symbol: nvs_flash_init`, `undefined symbol: esp_netif_init`
- Need esp-rtos/esp-bootloader linker config or espflash build
- **Impact:** No flashable demo possible

### 2. No Erasure Coding / Pipeline Layer
- ESP-NOW MTU is 250 bytes (max payload: 244 bytes with 6-byte header)
- FIPS frames are up to 2048 bytes
- Without fragmentation + erasure, ESP-NOW can only send tiny frames
- Source exists: ~/repos/balloon-fresh/tracker/firmware/components/erasure/erasure.c (325 lines C)
- Wirehair.cpp also available
- `feat/erasure-port` branch exists but has no erasure code yet

### 3. No Routing Layer
- FIPS STP + bloom filters not implemented
- MAC mapping exists on branch but not merged
- Without routing, ESP-NOW can only do broadcast — no multi-hop mesh

### 4. No Firmware Running on Physical ESP32
- No firmware running since July 7th evening
- HW interop cron detects ESP32-C3 on /dev/ttyACM2 but no firmware flashed
- VPS1 shows 10 stale ESP32 sessions from previous runs
- **Impact:** Can't test real hardware connectivity

### 5. Broken Crons
- `gateway-restart-fips-dispatcher` (script missing, just paused)
- `fips-exit-smoke-daily` (ModuleNotFoundError, needs conda python path fix)

## What We Learned

### 1. Build System Insights
- **Portable-atomic v1.13.1 with unsafe-assume-single-core is NOT a build blocker on ESP32-C3 RISC-V**
- Clean build passes in 73s. Cron's diagnosis was wrong
- Actual issues were FFI syntax, API mismatches, and type errors (all fixed in commit 6fbf7c4)
- Fixed: `esp_mac_type_t` FFI decl error, missing `Led::toggle()` method, `NodeIdentity` type mismatch, `spawner.spawn()` API mismatch

### 2. ESP32-C3 Hardware Constraints
- **WiFi MAC Blacklist:** Wrong WiFi password causes ESP32 to DDoS router until MAC blacklisted
- **RAM constraints:** heap reduced to 48KB for DRAM2
- **Log variants:** riscv32 log crate lacks atomic ptr — must use _racy log variants
- **Serial output:** required explicit --target flag and log gate removal

### 3. Library Version Mismatches
- **embassy-executor-macros v0.8.0** generates task functions returning `Result<SpawnToken, SpawnError>`
- **embassy-executor v0.10.0**'s spawn() takes `SpawnToken` directly
- Must unwrap before passing: `spawner.spawn(control::control_task().unwrap())`

### 4. Configuration Issues
- **VPS port mismatch:** interop scripts expect port 2121 but FIPS daemon listens on 8443
- Scripts patched but this issue keeps biting

## Implementation Plan Status

**Source:** `docs/plan-espnow-fips-mesh.md` (4 phases, estimated 17 days total)

### Phase 0: ESP-NOW Transport (2-3 days) — ~85% Complete
- [x] FFI bindings (`esp-now-sys`)
- [x] Transport trait implementation  
- [x] `espnow.rs` binary target
- [x] Build fixes (commit 6fbf7c4)
- [ ] **Linking fix** (esp-IDF integration)

### Phase 1: Pipeline (3-4 days) — 0% Complete  
- [ ] Fragmentation implementation
- [ ] PRBS23-XOR erasure coding port from balloon-fresh
- [ ] FIPS frame splitting into N fragments
- [ ] Erasure encoding (N redundant fragments)
- [ ] Receiver reassembly logic

### Phase 2: Routing (3-4 days) — ~10% Complete
- [ ] MAC-to-node-address mapping (exists on branch)
- [ ] FIPS STP + bloom filters
- [ ] Forwarding logic  
- [ ] Dynamic peer add/remove
- [ ] Peer table LRU eviction

### Phase 3: Hardening (2-3 days) — 0% Complete
- [ ] MTU adaptation
- [ ] Reliability layer (packet loss compensation)
- [ ] WiFi coexistence
- [ ] Multi-hop optimization

### Phase 4: Integration (2-3 days) — 0% Complete
- [ ] Android exit node
- [ ] Multi-hop benchmark
- [ ] 24h stability test

## Recommended Next Steps (Ordered by Impact)

### Step 1: Fix ESP-NOW Binary Linking (Critical - 1 day)
**Problem:** ESP-IDF symbols undefined during linking
**Solutions:**
- Use espflash as build tool (handles ESP-IDF linkage automatically)
- Configure .cargo/config.toml with correct linker flags for esp-rtos
- Check if esp-rtos provides build script that handles ESP-IDF linkage
**Success Criteria:** `cargo build` creates flashable binary on `riscv32imc-unknown-none-elf` target

### Step 2: Flash ESP-NOW Binary (Blocking - 2-3 hours)
**Task:** Flash espnow binary to ESP32-C3 on /dev/ttyACM2
**Verification:**
- Boot log shows "ESP-NOW initialized. MAC: xx:xx:xx:xx:xx:xx"
- LED blink pattern (3 fast blinks = ready)
- Serial output confirms ESP-NOW operational
**Hardware:** ESP32-C3 on /dev/ttyACM2 (detected by cron)

### Step 3: Port Erasure Coding from balloon-fresh (3-4 days)
**Source:** ~/repos/balloon-fresh/tracker/firmware/components/erasure/erasure.c (325 lines C)
**Target:** New Rust crate in `crates/microfips-erasure/`
**Implementation:**
- Port erasure.c logic to no_std Rust
- Implement PRBS23-XOR erasure coding
- Add fragment header format (6 bytes: block_id + frag_index + original_count + crc16)
**Success Criteria:** Can encode 2048-byte FIPS frame into 9 fragments + 3 erasure fragments

### Step 4: Two-Node ESP-NOW Demo (1 day)
**Task:** Test peer-to-peer ESP-NOW between two ESP32-C3 boards
**Hardware:** Two ESP32-C3 devices on same WiFi channel (1)
**Verification:**
- Board A broadcasts message
- Board B receives and logs message
- LED blinks confirm activity
- No router, no VPS, no WiFi — pure peer-to-peer

### Step 5: Wire FIPS Noise Handshake (1 day)  
**Task:** FIPS Noise handshake directly over ESP-NOW
**Architecture:** ESP-NOW → peer → handshake (skip WiFi→VPS1→handshake)
**Verification:** Two ESP32 boards complete FIPS handshake without IP infrastructure

## Demo Plan (Convincing Proof)

**Minimum Viable Demo:** Two ESP32-C3 boards on table. Both running microfips-esp32c3-espnow firmware. One sends FIPS message. Other shows receipt + Noise handshake completion. LED blinks confirm activity. No router, no VPS, no WiFi — pure peer-to-peer mesh.

**Prerequisites:** Steps 1-4 completed (linking fix, flash, erasure port, two-node test)
**Estimated Time:** 3-5 days of focused work

## Cron Status (2026-07-09)

### Active (Good)
- microFIPS Interop Test (hourly, passing)
- FIPS VPS1 Health (30min, passing) 
- FIPS Auto-Heal (15min, healthy)
- microfips-serial-logger-fix (hourly, LLM-driven, silent)

### Just Paused (Will Enable When Needed)
- gateway-restart-fips-dispatcher (script missing, failing daily at 4am)

### Broken (Needs Fix)
- fips-exit-smoke-daily (ModuleNotFoundError, conda python path issue)

## Branch Map

**Current:** `feat/fips-v0-compat` — main development branch (pushed to fork + ngit)
**Completed:** `feat/espnow-transport` (merged into fips-v0-compat)  
**Stale:** `feat/erasure-port` — placeholder, no erasure code
**Phase 2:** `feat/mac-mapping` — MAC-to-node-address mapping (not merged)
**Protocol:** `feat/noise-xx-handshake` — Noise XX migration (PR #132, separate)

## Files for Future Reference

- `~/repos/microfips/docs/plan-espnow-fips-mesh.md` — 4-phase implementation plan
- `~/repos/microfips/crates/microfips-esp-transport/src/esp_now_transport.rs` — ESP-NOW transport (396 lines)
- `~/repos/microfips/crates/microfips-esp32c3/src/bin/espnow.rs` — ESP-NOW binary target
- `~/repos/balloon-fresh/tracker/firmware/components/erasure/erasure.c` — erasure coding source
- `~/repos/balloon-fresh/tracker/firmware/components/wirehair/wirehair.cpp` — WireHair source

## Critical Dependencies

### Missing Erasure Coding Source
**Path:** `~/repos/microfips/crates/microfips-esp-transport/src/pipeline.rs` (doesn't exist)
**Source:** `~/repos/balloon-fresh/tracker/firmware/components/erasure/erasure.c`
**Urgency:** High — needed for any FIPS frames > 244 bytes over ESP-NOW

### ESP-IDF Linking Issue
**Path:** ESP-NOW binary build failure  
**Error:** `undefined symbol: nvs_flash_init`, `esp_netif_init`, etc.
**Urgency:** Critical — blocks all physical testing

---

**Documented by:** Hermes Agent  
**Session:** microFIPS-esp32 Signal group  
**Date:** 2026-07-09