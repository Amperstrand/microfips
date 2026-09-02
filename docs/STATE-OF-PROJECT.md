# microfips State of the Project (2026-08-31)

> **EXPERIMENTAL SOFTWARE** — microfips is an experimental FIPS leaf node
> implementation for embedded MCUs. It is not production-ready. The wire
> protocol tracks jmcorgan/fips and may break on any upstream release.
> Identities are deterministic test keys, not production credentials.

## What has been tested (all on hardware, all against fips v0.5.0)

### ✅ Fully verified end-to-end

| Transport | Chip | Path | Last verified |
|---|---|---|---|
| USB CDC (STM32) | STM32F469I-DISCO | CDC → serial_udp_bridge → UDP → daemon | 2026-08-31 |
| WiFi + mDNS | ESP32-S3 (Walter) | WiFi STA → DHCP → mDNS pinned → UDP → daemon | 2026-08-31 |
| BLE L2CAP | ESP32-D0WD (atom) | BLE scan → probe (LeRandom) → exchange (raw-SDU) → IK → heartbeats; regression-guarded (fips-lab `test_l2cap_bringup`: peripheral path, allowlist pin, FSP send+ACK — two consecutive greens) | 2026-09-02 |
| BLE L2CAP | ESP32-S3 (Walter) | Same as D0WD (role fix 10c33ad) | 2026-08-31 |
| ESP-NOW (node) | ESP32-S3 | ESP-NOW → WiFi gateway → UDP → daemon | 2026-08-19 |
| ESP-NOW (hybrid) | ESP32-S3 | WiFi↔ESP-NOW session-windowed switching | 2026-08-30 |
| Relay AP | ESP32-S3 (Walter) | !FIPS open AP → DHCP → mDNS → UDP relay → daemon | 2026-08-20 |
| HTTP over FIPS | STM32F469I-DISCO | HTTP → microfips-service → FSP (XK) → IK link → CDC | 2026-08-30 |
| Mesh forwarding | All 3 simultaneously | Daemon routes FSP between peers | 2026-08-31 |
| MCU-to-MCU mesh FSP | STM32 (CDC) + S3 (WiFi) | S3 auto-initiates FSP at STM32 target: Setup→Ack→Msg3→PING/PONG, both directions (fips-lab `test_mcu_to_mcu_mesh`; PING/PONG content hard-asserted since the 2026-09-02 promotion: 3 PINGs/3 PONGs/1 ACK per run) | 2026-09-02 |

### ✅ Protocol stack verified

| Layer | What | Evidence |
|---|---|---|
| Noise IK | Link handshake | Both ESP32s + STM32: MSG1→MSG2→keys, sustained heartbeats |
| Replay protection | Established-frame anti-replay | WireGuard-style 2048-counter window ported from fips (#181, 2026-08-31): dup/below-window frames dropped before AEAD, scripted-peer E2E test |
| Rekey (full) | Follow AND initiate rekeys | Hardware-verified 2026-09-01 (#183 Phases 1–3): epoch cascade (cur/pend/prev), promote-on-pending-decrypt, drain+zeroize, idempotent msg1 re-answer; 3 clean rotations on the bench S3, daemon's SecurityViolation cycle gone. Self-initiation = Phase 4. Bidirectional interleave (node AND daemon rotating in one session) verified 2026-09-02 (`test_rekey_bidirectional`: working point daemon=32s; zero rebuilds, zero SecurityViolations). Hour-scale interleave verified 2026-09-02 (`test_rekey_soak_long`, 1800s green in 30:31: 49 node + 21 daemon rotations, 56 cutovers/drains, ONE session throughout — zero rebuilds across 70 rotations — zero violations) |
| Key zeroization | Secret material wiped on drop | All 6 Noise state machines + session keys at steady exit (#182, 2026-08-31); deviation F8 closed; +2.6KB flash |
| Noise XX | Forward-compat link handshake (FIPS next wire) | fips-noise 37/37 + full protocol suite green under `--features std,noise-xx` (CI-enforced); test-level only — no live XX daemon to interop against |
| Noise XK | FSP session | STM32 + SIM: SessionSetup→Ack→Msg3, service request/response |
| FMP | Framing | Raw SDU (master dialect) + legacy framed (branch dialect) both parse |
| FSP | Session + data | PING/PONG (SIM→MCU through daemon), HTTP request/response |
| mDNS | LAN discovery | Pinned (npub match) + open (trust-on-first-advert) on WiFi; rogue-advert rejection scenario-hardened (#188 c2) |
| DNS fallback | VPS hostname resolution | embassy-net smoltcp DNS socket (#184, 2026-09-01): hardware-verified fallback + recovery; manual resolver retired |
| ESP-NOW | Discovery + framing | Channel sweep, fragment reassembly, gateway relay, hybrid switching |
| MMP | Link metrics | ETX, delivery ratio, loss rate, goodput (fipsctl show peers) |

### ✅ Infrastructure verified

| Component | What | Status |
|---|---|---|
| CI (15 jobs) | Unit tests, golden vectors, noise compliance, firmware builds, sim | All green on stable (2026-08-31, 924d184); protocol + fips-noise suites run under BOTH IK and noise-xx features |
| Test suite | 234 core + 140 protocol (IK) + 139 protocol (XX) + 53×2 fips-noise + 68 core-lib + 3 build = ~470 test runs, all passing | Both feature sets green (#178/#181/#182/#183 all phases/#184 closed); hang canary via nextest |
| Bench scripts | test_http_e2e.sh, test_hw_handshake.sh, test_mcu_to_mcu_fsp.sh | Working (updated for v0.5.0) |
| fips-lab | Scenario infrastructure + regression assertions | 94 tests collect; 8 live scenarios (rekey soak fast/stock, link death, mdns pinned, rekey self-init, mesh full-session, rekey bidirectional, L2CAP bring-up, rekey soak long); cross-project Bench Testing Playbook in its docs/ (11 patterns + 2026-09-02 amendments); D0WD bench tier (build_d0wd_l2cap + ftdi_tap + boards.toml atoms) |
| Device registry | Public-only, CI-enforced, build-time overrides | Working |
| Build-time validation | SEC1 check + mismatch warning + knob tracking | Working |

## What works but hasn't been recently tested

- **F746G-DISCO** (STM32F746): builds green, hardware-verified 2026-05-04 (pre-v0.5.0)
- **BLE GATT** (ESP32): builds green, bridge-verified in earlier era, not re-tested on v0.5.0
- **UART** (ESP32): builds green, bridge-verified in earlier era, not re-tested on v0.5.0
- **VPS path** (all chips → orangeclaw.dns4sats.xyz): verified in earlier era, DNS-dependent

## What remains untested or blocked

| Item | Blocker | Issue |
|---|---|---|
| ESP32-C3 | No board available | #150 (closed; reopen when board arrives) |
| Hybrid on esp-radio 1.0 | esp-hal#6220 (upstream API gap) | #168, PR #166 |
| FIPS 0.6.0-dev compatibility | Upstream hasn't shipped breaking changes yet | — |
| Noise XX live interop | No XX-speaking daemon exists (fips master = IK/v0.5.0); firmware crates don't forward `noise-xx` yet | #179 |
| Node-initiated rekey on hardware | **Verified 2026-09-01** (fips-lab `test_rekey_self_initiated`): 2 rotations/2 min, `REKEY_AFTER_SECS` build knob, default off | — |
| Relay AP + peer (3-hop chain) | Needs third Walter board | — |
| FSP initiation on BLE/L2CAP/ESP-NOW transports | Initiator is armed on every transport (same `Node::run` + dual handler). WiFi mesh verified + full-session asserted (2026-09-02); L2CAP asserted (fips-lab `test_l2cap_bringup`: FSP send + ACK received, 2026-09-02). BLE-GATT and ESP-NOW paths remain unexercised by scenarios | Backlog (BLE-GATT needs a bridge scenario; ESP-NOW needs 2nd S3) |

## Upstream alignment status

### What we track
- **jmcorgan/fips**: master = pure v0.5.0 mirror (protected). Work on fork/main (v0.5.0 + BLE dial fix + CI).
- **esp-rs/esp-hal**: on 1.1.0 stable. esp-radio 1.0.0-beta.0 on staging branch (PR #166). Waiting on #6220 for hybrid.
- **embassy-rs/embassy**: fork archived. BSP on embassy-stm32 0.6.0 (latest published). USB rewrite verified on main (harness in BSP repo).
- **embassy-rs/trouble**: on 0.7.0 published (bt-hci 0.9). Will bump to 0.8.x with esp-radio 1.0.

### Where we can better align

1. **The BLE dial fix (fips#151)**: ready to upstream. Cherry-picks cleanly onto v0.5.0. Release-target A/B evidence captured. Held by maintainer decision.

2. **mDNS interface filter (fips#150)**: the lab daemon's mDNS advert leaks to all interfaces (docker bridges, multiple NICs). The fix is an interface filter in LanRendezvousConfig. Still valid, upstreamable.

3. **greatspectations spec-quote CI**: we already dogfood this on microfips (BIP-173 in bech32.rs, CI-enforced). Extending to cover the FIPS wire protocol against both:
   - jmcorgan/fips source code (as the reference implementation)
   - The FIPS architecture/design docs (if/when they exist as canonical text)
   would catch drift between our implementation and upstream on every CI run.

4. **Noise protocol spec compliance**: our golden vectors test cross-implementation compatibility with fips, but we don't pin the spec text itself. The three documented deviations (D1-D3: empty AAD, IK se ordering, x-only ECDH) are confirmed deliberate by the fips maintainer — pinning these as spec quotes would prevent accidental "fixes" that break compatibility.

5. **FSP session protocol**: no formal spec exists upstream. Our implementation is the reference for the embedded side. The FspDualHandler on STM32 is the only complete FSP endpoint implementation in the ecosystem.

## Open issues (all repos, after 2026-08-31 cleanup)

### Amperstrand/fips (10 open — all actionable)

| # | Title | Priority |
|---|---|---|
| 151 | BLE dial fix — READY TO UPSTREAM | Held by decision |
| 150 | mDNS interface filter | Upstreamable |
| 152 | RSSI ordering (optimization) | Low |
| 107 | sk_rcvbuf tuning | Low |
| 86 | CSR8811 BLE bringup | Hardware-dependent |
| 74 | BLE L2CAP encryption | Explore |
| 73 | Privacy: cleartext pubkeys | Design |
| 70 | BLE-as-discovery-bus | Design |
| 18 | HTTP control API | Feature |
| 1 | Golden vectors | Ongoing |

### Amperstrand/microfips (8 open — all actionable)

| # | Title | Priority |
|---|---|---|
| 168 | Upstream watch: esp-hal#6220 | Blocked (external) |
| 165 | Platform migration tracker | Blocked (external) |
| 164 | SHC recovery checklist | Blocked (DNS) |
| 113 | Debug LCD display | Feature |
| 108 | rand_core 0.6→0.10 | Maintenance |
| 77 | Firmware DoS hardening | Security |
| 76 | esphome integration | Design |
| 54 | Micronuts RPC | Feature |

### Suggested greatspectations additions

Pin these as spec quotes with CI enforcement:
1. **Noise IK deviation D1** (empty AAD): pin the fips maintainer's confirmation comment
2. **Noise IK deviation D3** (x-only ECDH): pin the BIP-340-style x-coordinate DH
3. **FMP MSG1 wire format**: pin the first 4 bytes of the Noise IK initiator payload
4. **BLE L2CAP pre-handshake**: pin the raw 33-byte `[0x00][x-only 32]` master dialect
5. **FSP SessionSetup format**: pin the 2-byte port + format byte + IPv6 shim header layout
6. **mDNS TXT record keys**: pin `npub=`, `scope=`, `v=` as the canonical set

Each of these is a wire-format invariant where accidental drift would break
interop with no compiler error — exactly what spec-quote CI catches.
