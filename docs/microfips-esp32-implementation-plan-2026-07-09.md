# microFIPS-ESP32 Implementation Plan

**Status:** Ready for Scheduling  
**Created:** 2026-07-09  
**Based on:** Status report at `docs/microfips-esp32-status-report-2026-07-09.md`  
**Goal:** Complete ESP-NOW FIPS mesh implementation with working demo

---

## Executive Summary

This plan implements peer-to-peer FIPS mesh on ESP32-C3 using ESP-NOW transport. The approach replaces WiFi AP hierarchy with direct ESP-NOW connections, enabling mesh networking without IP infrastructure.

**Core Milestone:** Two ESP32-C3 boards demonstrating FIPS messaging over ESP-NOW (no WiFi/VPS dependency)

**Timeline:** 5-7 days of focused work  
**Risk Level:** Moderate (ESP-IDF integration challenges)  
**Hardware Required:** 2x ESP32-C3 boards (on /dev/ttyACM1/2)

---

## Phase 1: ESP-NOW Integration (Critical Path)

### Task 1.1: Fix ESP-NOW Binary Linking
**Task ID:** MFE-001  
**Priority:** Critical (Blocks all testing)  
**Duration:** 1 day  
**Description:** Resolve undefined symbol errors during ESP-NOW binary linking

#### Work Breakdown:
1. **Investigate linker error** (2h)
   ```bash
   # Current failure:
   cargo build -p microfips-esp32c3 --target riscv32imc-unknown-none-elf --features espnow --bin microfips-esp32c3-espnow
   # Error: undefined symbol: nvs_flash_init, esp_netif_init
   ```

2. **Research ESP-IDF build integration** (2h)
   - Check if espflash can handle linking automatically
   - Study other ESP-Rust projects for linker configuration
   - Test with both espflash and cargo-embuild

3. **Configure .cargo/config.toml** (1h)
   ```toml
   # Example configuration to test
   [target.riscv32imc-unknown-none-elf]
   runner = "espflash flash --monitor -p /dev/ttyUSB0 --chip esp32c3"
   rustflags = [
       "-C", "link-arg=-Tlink.x",
       "-C", "link-arg=-Wl,--no-undefined"
   ]
   ```

4. **Implement build script wrapper** (1h)
   ```bash
   # scripts/build-espnow.sh
   source ~/esp/esp-idf/export.sh
   cargo build --target riscv32imc-unknown-none-elf --features espnow
   ```

#### Success Criteria:
- `cargo build` creates flashable binary (~300KB ROM, ~100KB RAM)
- Binary contains all ESP-IDF symbols
- Linker warnings eliminated

#### Risks:
- ESP-IDF version incompatibility
- esp-rtos crate API changes
- Hardware-specific linker requirements

#### Dependencies:
- ESP-IDF environment variables set
- esp-rtos dependencies in Cargo.toml

---

### Task 1.2: Flash and Validate ESP-NOW Binary
**Task ID:** MFE-002  
**Priority:** Critical (Enables hardware testing)  
**Duration:** 2-3 hours  
**Description:** Flash ESP-NOW binary to physical ESP32-C3 hardware

#### Work Breakdown:
1. **Flash firmware** (30m)
   ```bash
   cd ~/repos/microfips
   cargo build -p microfips-esp32c3 --target riscv32imc-unknown-none-elf --features espnow --bin microfips-esp32c3-espnow
   espflash flash --monitor -p /dev/ttyACM2 target/riscv32imc-unknown-none-elf/release/microfips-esp32c3-espnow
   ```

2. **Serial log verification** (30m)
   - Confirm boot sequence
   - Verify ESP-NOW initialization message: "ESP-NOW initialized. MAC: xx:xx:xx:xx:xx:xx"
   - Check LED blink pattern (3 fast blinks = ready)

3. **Firmware validation** (1h)
   - Confirm WiFi channel 1 setup
   - Test broadcast peer addition
   - Verify no crashes or panics

#### Success Criteria:
- Firmware flashes successfully to /dev/ttyACM2
- Serial output shows "ESP-NOW initialized" with MAC address
- LED blinks correctly (3 fast blinks)
- No serial protocol errors

#### Hardware Requirements:
- ESP32-C3 on /dev/ttyACM2
- USB cable
- Power supply

#### Dependencies:
- Task 1.1 (Linking fix) completed
- espflash tool installed
- ESP-IDF environment ready

---

## Phase 2: Pipeline Implementation (Erasure Coding)

### Task 2.1: Port Erasure Coding from balloon-fresh
**Task ID:** MFE-003  
**Priority:** High (Enables large frames)  
**Duration:** 3-4 days  
**Description:** Port PRBS23-XOR erasure coding from C to Rust for FIPS fragmentation

#### Work Breakdown:
1. **Analyze source erasure.c** (4h)
   ```c
   // ~/repos/balloon-fresh/tracker/firmware/components/erasure/erasure.c
   // Study: erasure_encode(), erasure_decode(), fragment_header format
   ```

2. **Create Rust crate structure** (2h)
   ```bash
   cd ~/repos/microfips
   mkdir crates/microfips-erasure
   echo 'name = "microfips-erasure"
   version = "0.1.0"
   edition = "2021"
   [lib]
   name = "microfips_erasure"
   [dependencies]
   crc = "3.0"
   ' > crates/microfips-erasure/Cargo.toml
   ```

3. **Implement fragment header** (2h)
   ```rust
   // Fragment format (6 bytes from balloon-fresh):
   // block_id: u16, frag_index: u8, original_count: u8, crc16: u16
   pub struct FragmentHeader {
       pub block_id: u16,
       pub frag_index: u8, 
       pub original_count: u8,
       pub crc: u16,
   }
   ```

4. **Port erasure_encode() logic** (3d)
   - Convert 325 lines of C to no_std Rust
   - Implement PRBS23-XOR encoding algorithm
   - Add error checking and CRC validation

5. **Port erasure_decode() logic** (3d)
   - Implement reassembly from N + M fragments
   - Handle fragment loss gracefully
   - Return assembled FIPS frame or error

#### Success Criteria:
- Rust implementation matches C behavior for test cases
- Can encode 2048-byte FIPS frame into 9 fragments + 3 erasure fragments
- Decoding succeeds from any 9 of 12 fragments
- No heap allocations (use fixed-size arrays)
- CRC validation works correctly

#### Test Strategy:
- Unit tests for individual functions
- Integration tests with known C inputs
- Fragment corruption recovery tests
- Memory usage validation (max 256KB RAM)

#### Dependencies:
- crc crate for checksum validation
- Fragment header design finalized
- FIPS frame structure understood

#### Files to Create:
- `crates/microfips-erasure/Cargo.toml`
- `crates/microfips-erasure/src/lib.rs`
- `crates/microfips-erasure/src/fragment.rs`
- `crates/microfips-erasure/src/erasure.rs`
- `crates/microfips-erasure/tests/`

---

### Task 2.2: Implement Pipeline Layer
**Task ID:** MFE-004  
**Priority:** High (Connects erasure to transport)  
**Duration:** 2 days  
**Description:** Create pipeline layer to fragment FIPS frames and reassemble them

#### Work Breakdown:
1. **Design pipeline interface** (4h)
   ```rust
   pub trait Pipeline {
       type Error;
       fn encode(&mut self, fips_frame: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error>;
       fn decode(&mut self, fragments: &[Vec<u8>]) -> Result<Vec<u8>, Self::Error>;
       fn mtu() -> usize;
   }
   ```

2. **Implement fragmentation logic** (2d)
   - Split 2048-byte FIPS frames into ~9 fragments (244 bytes each)
   - Add FragmentHeader to each fragment
   - Handle edge cases (small frames, alignment)

3. **Implement reassembly logic** (2d)
   - Buffer incoming fragments by block_id
   - Trigger reassembly when all original fragments received
   - Use erasure coding to recover lost fragments
   - Return complete FIPS frame

4. **Integrate with ESP-NOW transport** (4h)
   ```rust
   // Modify EspNowTransport to use Pipeline
   impl Transport for EspNowTransport<Pipeline> {
       async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
           let fragments = self.pipeline.encode(data)?;
           for fragment in fragments {
               self.send_raw(&fragment).await?;
           }
           Ok(())
       }
   }
   ```

#### Success Criteria:
- Pipeline can handle 256B to 2048B FIPS frames
- Fragment overhead is minimal (6 bytes per fragment)
- Reassembly works from out-of-order fragments
- Integration with ESP-NOW transport is transparent

#### Performance Targets:
- Fragmentation: <1ms for 2048B frame
- Reassembly: <5ms for 9 fragments
- Memory overhead: <32KB per active transmission

#### Dependencies:
- Task 2.1 (Erasure coding) completed
- ESP-NOW transport working (Task 1.2)
- FIPS frame structure compatible

#### Files to Create/Modify:
- `crates/microfips-esp-transport/src/pipeline.rs`
- `crates/microfips-esp-transport/src/esp_now_transport.rs` (Pipeline integration)
- `crates/microfips-esp-transport/tests/pipeline_integration.rs`

---

## Phase 3: Routing Implementation

### Task 3.1: Merge MAC-to-Node-Address Mapping
**Task ID:** MFE-005  
**Priority:** Medium (Enables routing)  
**Duration:** 1 day  
**Description:** Merge feat/mac-mapping branch and implement node discovery

#### Work Breakdown:
1. **Review feat/mac-mapping branch** (4h)
   ```bash
   git checkout feat/mac-mapping
   git log --oneline -10
   git diff feat/fips-v0-compat..HEAD
   ```

2. **Resolve conflicts and merge** (4h)
   ```bash
   git checkout feat/fips-v0-compat
   git merge feat/mac-mapping --no-ff
   ```

3. **Test mapping functionality** (4h)
   - Verify MAC address to node_addr mapping works
   - Test with different MAC configurations
   - Ensure no compilation errors

#### Success Criteria:
- MAC mapping functionality integrated into main branch
- No new compilation errors
- MAC to node_addr conversion works correctly

#### Risks:
- Branch conflicts requiring manual resolution
- Performance impact of mapping overhead
- Testing coverage gaps

#### Dependencies:
- Task 1.2 (Flash binary) completed for testing
- NodeAddr type compatibility confirmed

---

### Task 3.2: Implement FIPS STP + Bloom Filters
**Task ID:** MFE-006  
**Priority:** Medium (Mesh routing)  
**Duration:** 2-3 days  
**Description:** Implement spanning tree protocol and bloom filters for mesh routing

#### Work Breakdown:
1. **Design routing architecture** (1d)
   ```rust
   pub struct RoutingTable {
       peers: HashMap<MacAddress, NodeInfo>,
       stp_root: MacAddress,
       bloom_filters: BloomFilter,
   }
   ```

2. **Implement STP algorithm** (1d)
   - Root election (MAC address based)
   - Path cost calculation
   - Forwarding decisions

3. **Implement bloom filters** (1d)
   - Bloom filter for seen paths
   - Cycle detection
   - Memory-efficient routing state

4. **Integrate with transport layer** (4h)
   - Route decisions in send/recv methods
   - Dynamic peer discovery
   - Broadcast vs unicast routing

#### Success Criteria:
- STP prevents routing loops
- Bloom filters reduce duplicate packets
- Multi-hop routing works (3+ nodes)
- Route convergence <1s

#### Dependencies:
- Task 3.1 (MAC mapping) completed
- Pipeline layer operational
- Memory budget available (<100KB for routing state)

---

## Phase 4: Demo Validation

### Task 4.1: Two-Node ESP-NOW Demo
**Task ID:** MFE-007  
**Priority:** High (Proof of concept)  
**Duration:** 1 day  
**Description:** Validate ESP-NOW communication between two physical ESP32-C3 boards

#### Work Breakdown:
1. **Setup two-node test** (2h)
   ```bash
   # Board A: /dev/ttyACM1 (192.168.1.101)
   # Board B: /dev/ttyACM2 (192.168.1.102)
   # Same WiFi channel, no AP needed
   ```

2. **Flash firmware to both boards** (1h)
   ```bash
   for device in ACM1 ACM2; do
     espflash flash --monitor -p /dev/tty${device} target/riscv32imc-unknown-none-elf/release/microfips-esp32c3-espnow
   done
   ```

3. **Test broadcast messaging** (2h)
   - Board A sends test message
   - Board B logs receipt
   - Verify LED activity on both boards

4. **Validate peer discovery** (1h)
   - Confirm MAC addresses seen in logs
   - Verify broadcast peer addition
   - Check no connectivity issues

#### Success Criteria:
- Messages flow A→B and B→A successfully
- Serial logs show packet receipt
- LED patterns indicate activity
- No crashes or timeouts

#### Hardware Setup:
- Two ESP32-C3 boards
- Separate USB cables (ACM1 and ACM2)
- Same WiFi channel (1)
- No router required (broadcast only)

#### Test Messages:
```rust
// Test payload
const TEST_FRAME: &[u8] = b"HELLO_MICROFIPS_ESP_NOW_DEMO_2026";
// Expected: 9 fragments + 3 erasure, each with FragmentHeader
```

#### Dependencies:
- Task 1.2 (Flash binary) working
- ESP-NOW transport operational
- Physical hardware available

---

### Task 4.2: FIPS Handshake Over ESP-NOW
**Task ID:** MFE-008  
**Priority:** High (Complete demo)  
**Duration:** 1 day  
**Description:** Demonstrate FIPS Noise handshake directly over ESP-NOW

#### Work Breakdown:
1. **Modify handshake protocol** (2h)
   ```rust
   // Current: WiFi → VPS1 → handshake
   // Target: ESP-NOW → peer → handshake (direct)
   impl FipsNode<EspNowTransport> {
       pub async fn direct_handshake(&mut self, peer_mac: MacAddress) -> Result<(), Error> {
           // Establish ESP-NOW connection
           // Perform Noise handshake
           // Verify peer authenticity
       }
   }
   ```

2. **Implement direct key exchange** (2h)
   - Skip VPS1 dependency for handshake
   - Use ESP-NOW for Noise message transport
   - Maintain FIPS security guarantees

3. **Test end-to-end handshake** (4h)
   - Board A initiates handshake with Board B
   - Both boards log handshake progress
   - Verify cryptographic verification succeeds
   - Test post-handshake messaging

#### Success Criteria:
- Direct FIPS handshake completes without VPS1
- Cryptographic verification succeeds
- Post-handshake messaging works
- Both boards log successful completion

#### Validation:
- Handshake time < 2 seconds
- Message encryption/decryption works
- No replay attacks detected
- Peer authentication succeeds

#### Dependencies:
- Task 4.1 (Two-node demo) working
- FIPS protocol layer modified
- ESP-NOW transport stable

---

## Risk Assessment

### High Risk Items
1. **ESP-IDF Linking** - Potential version incompatibility
   - Mitigation: Test with multiple build approaches
   - Fallback: Use precompiled esp-rtos if needed

2. **Memory Constraints** - ESP32-C3 has 400KB RAM total
   - Mitigation: Profile memory usage at each phase
   - Fallback: Reduce frame sizes if needed

3. **Hardware Availability** - ESP32-C3 boards may have issues
   - Mitigation: Test with different serial ports
   - Fallback: Use simulated ESP32 if hardware fails

### Medium Risk Items
1. **Erasure Coding Complexity** - C→Rust port may have bugs
   - Mitigation: Compare outputs with C implementation
   - Testing: Unit + integration + stress tests

2. **Routing Protocol Stability** - STP + bloom filters may loop
   - Mitigation: Extensive packet trace logging
   - Testing: Multi-node scenarios

3. **Real-world RF Interference** - 2.4GHz congestion
   - Mitigation: Test in controlled environment
   - Monitoring: Error rate tracking

---

## Timeline Summary

| Phase | Tasks | Duration | Dependency |
|-------|-------|----------|------------|
| **ESP-NOW Integration** | 1.1, 1.2 | 1-2 days | None |
| **Pipeline Implementation** | 2.1, 2.2 | 5-6 days | Phase 1 complete |
| **Routing Implementation** | 3.1, 3.2 | 3-4 days | Phase 2 complete |
| **Demo Validation** | 4.1, 4.2 | 2 days | Phase 3 complete |
| **TOTAL** | | **11-16 days** | |

### Critical Path: 1.1 → 1.2 → 2.1 → 2.2 → 4.1 → 4.2

### Key Milestones
1. **M1:** ESP-NOW binary flashes and runs (Day 1-2)
2. **M2:** Erasure coding ported and tested (Day 6-7)
3. **M3:** Pipeline layer integrates with transport (Day 9-10)
4. **M4:** Two-node ESP-NOW messaging (Day 11-12)
5. **M5:** Direct FIPS handshake over ESP-NOW (Day 13-14)

---

## Resource Requirements

### Hardware
- 2x ESP32-C3 boards (XIAO ESP32C3 Mini or equivalent)
- USB cables for both boards
- Testing bench with clear serial access
- Optional: Logic analyzer for debugging

### Software
- ESP-IDF v5.4.1 (tested working)
- espflash v0.7.0
- cargo-embuild (alternative build tool)
- crc crate for erasure validation
- Python for serial monitoring scripts

### Development Environment
- Rust nightly (ESP32 toolchain requires nightly)
- Cargo workspace with 17 crates
- Serial terminal monitoring (miniterm, screen)
- WiFi channel 1 available for testing

---

## Testing Strategy

### Unit Testing (Continuous)
- Each crate has comprehensive unit tests
- Rust test coverage > 80%
- CI integration on GitHub fork

### Integration Testing (Per Phase)
- Phase 1: ESP-NOW transport unit tests
- Phase 2: Pipeline fragment/reassembly tests
- Phase 3: Routing logic with simulated peers
- Phase 4: End-to-end functional tests

### Hardware Testing (Physical)
- Serial log analysis for each board
- LED pattern verification
- Memory usage monitoring
- Error rate tracking

### Performance Testing
- Throughput: Messages per second
- Latency: End-to-end message delay
- Memory: Peak RAM usage
- CPU: Load during transmission

---

## Success Metrics

### Technical Success
- ✅ ESP-NOW binary compiles and links
- ✅ Firmware flashes successfully to hardware
- ✅ Two-board messaging works without WiFi/VPS
- ✅ FIPS handshake completes over ESP-NOW
- ✅ Erasure coding recovers from packet loss

### Performance Targets
- ✅ End-to-end latency < 100ms
- ✅ Throughput > 10 messages/second
- ✅ Memory usage < 300KB total
- ✅ No crashes during 24h test

### Safety Targets
- ✅ No buffer overflows
- ✅ No memory leaks
- ✅ Cryptographic operations validated
- ✅ Safe ESP-IDF integration

---

## Kanban Task Mapping

| Kanban ID | Task Title | Epic | Priority | Estimate | Status |
|-----------|------------|------|----------|----------|--------|
| MFE-001 | Fix ESP-NOW binary linking | ESP-NOW Integration | Critical | 1d | Pending |
| MFE-002 | Flash and validate ESP-NOW binary | ESP-NOW Integration | Critical | 0.5d | Pending |
| MFE-003 | Port erasure coding from balloon-fresh | Pipeline | High | 3-4d | Pending |
| MFE-004 | Implement pipeline layer | Pipeline | High | 2d | Pending |
| MFE-005 | Merge MAC-to-node-address mapping | Routing | Medium | 1d | Pending |
| MFE-006 | Implement FIPS STP + bloom filters | Routing | Medium | 2-3d | Pending |
| MFE-007 | Two-node ESP-NOW demo | Validation | High | 1d | Pending |
| MFE-008 | FIPS handshake over ESP-NOW | Validation | High | 1d | Pending |

---

## Approval and Scheduling

This plan can be executed as individual tasks (MFE-001 through MFE-808) or as a coordinated project. Each task includes:

- Clear success criteria
- Dependency information
- Risk assessment
- Testing requirements
- Hardware needs

**Ready for scheduling once approved.**

**Estimated total effort:** 11-16 calendar days  
**Critical path duration:** 7 days (MFE-001 → MFE-002 → MFE-003 → MFE-004 → MFE-007 → MFE-008)  
**Demo achievable by:** Day 13-14 if started immediately

---

**Plan created by:** Hermes Agent  
**Based on status report:** `/home/c03rad0r/repos/microfips/docs/microfips-esp32-status-report-2026-07-09.md`  
**Date:** 2026-07-09