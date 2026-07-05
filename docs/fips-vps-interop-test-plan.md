# microFIPS ↔ FIPS VPS Interop Test Plan

> Created: 2026-07-05 | Signal group: microFIPS-esp32
> Depends on: fips-microfips-compat-audit.md (compat audit, 2026-06-29)

## TL;DR

microFIPS and upstream FIPS are currently **wire-incompatible** (FMP v1/Noise XX
vs FMP v0/Noise IK). This plan deploys a dedicated FIPS test node on VPS1,
reverts microFIPS to the compatible IK/v0 path, and runs a 5-phase interop
campaign from sim-to-hardware.

---

## Current State

### FIPS (upstream reference)
- **Repo**: ~/repos/fips (jmcorgan/fips @ 30c5808, v0.5.0-dev)
- **Wire**: FMP_VERSION = 0, Noise IK/XK, MSG1_WIRE=114B, MSG2_WIRE=69B
- **Deployed**: VPS2 (23.182.128.51) as systemd service, UDP :2121, TCP :8443
- **NOT deployed** on VPS1 (66.92.204.38)

### microFIPS
- **Repo**: ~/repos/microfips (Amperstrand/microfips, fork: c03rad0r/microfips)
- **Active branch**: feat/noise-xx-handshake (INCOMPATIBLE with FIPS v0)
- **Wire**: FMP_VERSION = 1, framing sized for Noise XX, but live driver runs IK
- **Proven**: M0-M9, M11 complete. IK handshake verified with live VPS (M3-M6)

### The Incompatibility (from compat audit)
1. **FMP version nibble**: microFIPS sends v1, FIPS hard-rejects v!=0
2. **Noise handshake**: microFIPS framing expects 3-msg XX (41/118/85B);
   FIPS only speaks 2-msg IK (114/69B)
3. **Half-finished migration**: framing bumped to v1/XX but live driver still
   runs IK — internally inconsistent

---

## Phase 0: Deploy FIPS on VPS1 (Dedicated Test Node)

**Goal**: Dedicated FIPS instance on VPS1 for interop testing, isolated from
production VPS2 traffic.

### Steps

1. **Deploy via Ansible**:
   ```bash
   cd ~/tollgate-infrastructure-kit/ansible
   source ../.env
   ansible-playbook playbooks/13-fips.yml -l vps1
   ```

2. **Configure FIPS for testing** (loose discovery, allow test peers):
   ```yaml
   # /etc/fips/fips.yaml on VPS1
   node:
     identity:
       persistent: true
     discovery:
       nostr:
         enabled: false  # disable for isolated testing
   transports:
     udp:
       bind_addr: "0.0.0.0:2121"
       advertise_on_nostr: false
   peers: []  # will add microFIPS peers dynamically
   ```

3. **Verify FIPS is listening**:
   ```bash
   ssh debian@66.92.204.38 "systemctl status fips; ss -ulnp | grep 2121"
   ```

4. **Note the FIPS node identity** (FipsAddress):
   ```bash
   ssh debian@66.92.204.38 "journalctl -u fips --no-pager | grep 'FipsAddress'"
   ```

### Success Signal
- `fips.service` active on VPS1
- UDP :2121 listening on 66.92.204.38
- FIPS node identity printed in journal

---

## Phase 1: Revert microFIPS to IK/v0 Compat (Path A)

**Goal**: Restore wire-level compatibility with upstream FIPS.

This is the recommended path from the compat audit (§5, Path A). The live
handshake driver already runs IK — only the framing constants need reverting.

### Steps

1. **Create compat branch from main** (not from feat/noise-xx-handshake):
   ```bash
   cd ~/repos/microfips
   git checkout main
   git checkout -b feat/fips-v0-compat
   ```

2. **Revert FMP_VERSION** (`crates/microfips-core/src/wire.rs:17`):
   ```rust
   // FROM: pub const FMP_VERSION: u8 = 1;
   // TO:   pub const FMP_VERSION: u8 = 0;
   ```

3. **Revert handshake message sizes** (`wire.rs:25-27`):
   Point `HANDSHAKE_MSG*_SIZE` back at IK constants instead of `noise::XX_*`.
   Drop `PHASE_MSG3` and `MSG3_*` constants. Restore `FLAG_SP = 0x04`.

4. **Revert wire message sizes** (`wire.rs:30-32`):
   ```rust
   // IK sizes (from FIPS):
   pub const MSG1_WIRE_SIZE: usize = 114;  // was 41
   pub const MSG2_WIRE_SIZE: usize = 69;   // was 118
   // Remove MSG3_WIRE_SIZE entirely
   ```

5. **Verify live driver uses IK** (should already be correct):
   ```bash
   grep -n 'NoiseIkInitiator\|NoiseIkResponder' crates/microfips-protocol/src/node.rs
   # Expected: lines ~408, ~471
   ```

6. **Re-enable IK test vectors**:
   - Check `fips_compatibility.rs`, `fsp_over_fmp.rs`, `pcap_regression.rs`
   - These were migrated to XX; revert or re-enable the IK variants
   - Un-ignore the 2 `#[ignore]`d PCAP tests

7. **Build + test**:
   ```bash
   cargo test -p microfips-core --features std
   cargo test -p microfips-protocol --features std
   cargo build -p microfips-sim
   ```

### Success Signal
- All unit tests pass
- `cargo build -p microfips-sim` succeeds
- Wire constants match FIPS: FMP_VERSION=0, MSG1=114B, MSG2=69B

---

## Phase 2: Sim-to-VPS Interop Test

**Goal**: Prove microFIPS can establish a link with the FIPS VPS node.

### Steps

1. **Set up SSH tunnel** (VPS1 FIPS → local bridge port):
   ```bash
   ssh -L 31337:127.0.0.1:2121 debian@66.92.204.38 -N &
   ```

2. **Run microFIPS sim against FIPS**:
   ```bash
   cd ~/repos/microfips
   cargo run -p microfips-sim --listen 45679
   # Then connect via bridge to localhost:31337
   ```

3. **Alternative: direct UDP to VPS1**:
   ```bash
   cargo run -p microfips-link -- 66.92.204.38:2121
   ```

4. **Monitor FIPS journal** for handshake:
   ```bash
   ssh debian@66.92.204.38 "journalctl -u fips -f" | grep -E 'promoted|active peer|handshake'
   ```

### What to Observe
- microFIPS sends MSG1 (114B) → FIPS receives and responds with MSG2 (69B)
- FIPS journal: "Connection promoted to active peer"
- Heartbeat exchange: microFIPS sends 37B heartbeat every 10s, FIPS accepts
- Sustained connection > 60 seconds with no "link dead timeout"

### Success Signal
- Handshake completes (MSG1 → MSG2 → keys derived)
- Heartbeat exchange sustained 60+ seconds
- No protocol errors in FIPS journal

---

## Phase 3: Hardware ESP32 Interop Test

**Goal**: Prove microFIPS firmware on ESP32 can reach the FIPS VPS.

### Prerequisites
- Phase 0-2 complete (FIPS deployed, microFIPS compat build verified)
- ESP32-D0WD or ESP32-S3 flashed with compat firmware
- USB CDC bridge or WiFi transport configured

### Steps (WiFi transport — simplest path)

1. **Build ESP32 firmware with WiFi + compat mode**:
   ```bash
   cd ~/repos/microfips
   cargo build -p microfips-esp32 --features wifi
   # Flash to ESP32
   ```

2. **Configure ESP32 WiFi** to connect and target VPS1:
   ```
   # ESP32 control interface over UART0:
   set_wifi_ssid <SSID>
   set_wifi_pass <PASS>
   set_fips_addr 66.92.204.38:2121
   connect
   ```

3. **Monitor via UART0**:
   ```
   show_status
   show_peers
   show_stats
   ```

4. **Monitor FIPS journal on VPS1**:
   ```bash
   ssh debian@66.92.204.38 "journalctl -u fips -f"
   ```

### Steps (USB CDC bridge transport)

1. **Set up the full bridge chain**:
   ```
   ESP32 USB CDC → serial_udp_bridge → SSH tunnel → VPS1 FIPS UDP:2121
   ```

2. **Run bridge**:
   ```bash
   python3 scripts/serial_udp_bridge.py --port /dev/ttyACM0 --remote localhost:31337
   # With SSH tunnel: ssh -L 31337:127.0.0.1:2121 debian@66.92.204.38 -N
   ```

3. **Flash firmware, observe handshake**:
   - MCU LEDs show ESTABLISHED state
   - Bridge log: CDC→UDP frames every ~10s (heartbeats)
   - FIPS journal: "Connection promoted to active peer"

### Success Signal
- ESP32 completes Noise IK handshake with FIPS VPS1
- Heartbeat exchange sustained 3+ minutes (per M6 evidence)
- No panics, no link-dead timeouts

---

## Phase 4: Evidence Capture

**Goal**: Document the interop proof with captureable evidence.

### Artifacts to Collect

| Evidence | How | Purpose |
|----------|-----|---------|
| Wireshark pcap | `tcpdump -i lo udp port 2121 -w interop.pcap` on VPS | Wire-level proof |
| FIPS journal logs | `journalctl -u fips --since "10 min ago"` | Server-side handshake + heartbeat |
| microFIPS sim output | stdout capture | Client-side handshake + stats |
| Bridge log | serial_udp_bridge.py stdout | MCU transport chain proof |
| MCU UART output | `show_status`, `show_peers`, `show_stats` | Firmware-level proof |
| Photo of MCU LEDs | Camera | ESTABLISHED state visual |

### Wireshark Dissection
microFIPS ships `tools/fips_dissector.lua` — load it in Wireshark to decode FMP frames:
- Verify FMP_VERSION = 0 in all frames
- Verify MSG1 = 114B, MSG2 = 69B
- Verify established-phase heartbeats (msg type 0x51)

---

## Phase 5: Test Matrix

### Transport × Target Matrix

| Transport | Sim → VPS1 | ESP32-D0WD → VPS1 | ESP32-S3 → VPS1 |
|-----------|-----------|-------------------|-----------------|
| UDP (sim) | Phase 2 | N/A | N/A |
| WiFi (direct) | N/A | Phase 3 | Phase 3 |
| USB CDC (bridge) | N/A | Phase 3 | Phase 3 |
| BLE GATT (bridge) | N/A | Optional | Optional |
| BLE L2CAP (direct) | N/A | Optional | Optional |

### Pass/Fail Criteria per Test

| Check | Pass | Fail |
|-------|------|------|
| MSG1 sent | 114B frame on wire | No frame or wrong size |
| MSG2 received | 69B frame from FIPS | No response |
| Keys derived | AEAD encrypt/decrypt works | Noise finalize() fails |
| Heartbeat | 37B every 10s, FIPS accepts | No heartbeats or rejected |
| Sustained link | 3+ min no link-dead | Link-dead < 60s |
| Reconnect | Auto-reconnect after disconnect | Manual reset needed |

---

## Risk: Which Path to Take

### Path A (Recommended): Revert microFIPS to IK/v0
- **Effort**: Low (framing constant revert, driver already IK)
- **Risk**: Minimal — proven state (M3-M6 all used IK/v0)
- **Outcome**: microFIPS leaf attaches to FIPS mesh

### Path B (Not recommended): FIPS adopts XX/v1
- **Effort**: High (new Noise pattern, version negotiation in FIPS)
- **Risk**: Touches upstream — requires jmcorgan coordination
- **Outcome**: Same as A but more work

### Decision Needed
The master plan says "wait for v2 protocols." If the goal is **immediate interop
proof**, Path A is the right choice. If the goal is **long-term alignment with
upstream v2 direction**, stay on XX and wait.

**Recommendation**: Do Path A now for proof, keep XX branch as the future direction.

---

## Timeline Estimate

| Phase | Duration | Blocking? |
|-------|----------|-----------|
| Phase 0: Deploy FIPS on VPS1 | 15 min | No (Ansible) |
| Phase 1: Revert microFIPS to IK/v0 | 2-4 hours | Yes (code changes + tests) |
| Phase 2: Sim interop test | 30 min | After Phase 1 |
| Phase 3: Hardware test | 1-2 hours | After Phase 2 |
| Phase 4: Evidence capture | 30 min | During Phase 2-3 |
| Phase 5: Full matrix | 2-4 hours | After Phase 3 |

**Total**: ~1-2 days of focused work.

---

## VPS Health Context

### VPS1 (66.92.204.38) — TARGET for FIPS deployment
- Disk: 11% used (85G free) — EXCELLENT
- RAM: 2.3G/7.8G — HEALTHY
- Load: 0.26 — IDLE
- Nostr track: Deploying (strfry, strfry-agg, blossom, nsite, obelisk)
- FIPS: NOT installed yet

### VPS2 (23.182.128.51) — Existing FIPS instance
- Disk: 76% used (24G free) — WARNING
- RAM: 2.9G/7.8G + 3.7G swap — PRESSURE
- Load: 0.36 — OK
- FIPS: ACTIVE (systemd, UDP :2121)
- Nostr track: Fully deployed (strfry-agg, blossom, nsite, obelisk, ngit)

### Recommendation
Deploy FIPS on VPS1 for testing. VPS1 has abundant resources. VPS2 is under
memory pressure (3.7G swap used) and disk is approaching warning threshold.
