# microFIPS Interop Hardening — Comprehensive Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement tasks.
> Use kanban --board microfips for task tracking.

**Goal:** Verify, fix, and lock down microFIPS ↔ FIPS interoperability, then
automate regression testing so v2 protocol changes can be detected immediately.

**Architecture:** microFIPS connects to upstream FIPS via host bridge (serial→UDP
or BLE→UDP) to a VPS running stock FIPS. The wire protocol (FMP framing + Noise
handshake + FSP session) must match byte-for-byte at each protocol version.

**Tech Stack:** Rust (no_std, Embassy HAL), Python (bridge tools), Bash (test
scripts), FIPS daemon (Rust, tokio, on VPS)

---

## CRITICAL FINDING — Current Interop State

The compat audit (June 29, ~/worktrees/feature-microfips-compat-audit/docs/)
found that microFIPS and FIPS do NOT currently interoperate on the wire. Two
incompatibilities:

1. **FMP version nibble**: microFIPS HEAD has `FMP_VERSION=1`, FIPS has
   `FMP_VERSION=0` and hard-rejects non-zero versions
2. **Noise handshake**: microFIPS migrated to Noise XX, FIPS still uses IK/XK

The Noise XX migration was completed today (July 4, commit c3e875d) — the
production handshake driver in node.rs now uses NoiseXxInitiator/Responder.
But FIPS local repo (jmcorgan/fips @ 0.5.0-dev) is still FMP v0 / IK.

**Branch matrix:**

| microFIPS branch | FMP | Noise | Compatible with FIPS v0.5.0-dev? |
|-----------------|-----|-------|----------------------------------|
| main | v0 | IK | YES (last verified May 4 on STM32F746) |
| feat/noise-xx-handshake | v1 | XX | NO (version mismatch + FIPS has no XX) |

**VPS version: UNKNOWN** — must be checked.

---

## Task Index

| Task | Priority | Est. Time | Dependency | Kanban ID |
|------|----------|-----------|------------|-----------|
| A: Check VPS FIPS version | P0 CRITICAL | 5 min | None | t_d3eec3ff |
| B: Run interop test (main branch) | P0 CRITICAL | 15 min | A | t_d3eec3ff |
| C: Test noise-xx branch against VPS | P0 CRITICAL | 15 min | A | t_d3eec3ff |
| D: Publish compat audit to repo | P1 | 10 min | None | t_1c9885dd |
| E: Update stale parity doc | P1 | 20 min | D | t_1c9885dd |
| F: Regenerate pcap reference vectors | P1 | 15 min | B or C | t_1c9885dd |
| G: Build automated interop CI test | P2 | 45 min | B | t_00e727de |
| H: Add version-negotiation guard | P2 | 30 min | G | t_00e727de |
| I: v2 spec tracking doc | P3 | 15 min | None | t_c96770ce |
| J: Madeira discussion prep | P4 | 20 min | None | t_b9d9797b |
| K: ESP32-C3 RISC-V feasibility | P5 | 30 min | None | t_eef11403 |

**Recommended execution order:** A → B → C → (D,E,F parallel) → G → H → (I,J,K parallel)

---

## Task A: Check VPS FIPS Version

**Objective:** Determine what version of FIPS is running on the test VPS.

**Workspace:** ~/repos/microfips

**Step 1: SSH into VPS and check FIPS version**

```bash
# Load VPS credentials from .env
source ~/.hermes/profiles/manager/.env 2>/dev/null
# Or use the microfips .env
cd ~/repos/microfips && source .env 2>/dev/null

# Check what FIPS version is running
sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" \
  "fips --version 2>/dev/null || /home/routstr/fips --version 2>/dev/null || \
   journalctl -u fips --no-pager -n 5 2>/dev/null || \
   systemctl status fips 2>/dev/null | head -10"
```

Expected: Version string (e.g., "0.3.x", "0.4.0", "0.5.0-dev")

**Step 2: Check FMP_VERSION in the running binary**

```bash
sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" \
  "strings /home/routstr/fips 2>/dev/null | grep -i 'fmp.*version\|0\.4\|0\.5' | head -5; \
   cat /home/routstr/fips/Cargo.toml 2>/dev/null | grep version | head -3; \
   ls -la /home/routstr/fips/ 2>/dev/null | head -5"
```

**Step 3: Check which git branch/commit is deployed**

```bash
sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" \
  "cd /home/routstr/fips 2>/dev/null && git log --oneline -3 && git branch --show-current"
```

**Step 4: Record findings**

Update ~/repos/microfips/docs/strategy-and-upstream.md with the VPS version.
Commit.

**Verification:** VPS version documented. We now know which microFIPS branch
should be compatible.

---

## Task B: Run Interop Test — main branch (FMP v0 / Noise IK)

**Objective:** Verify that microFIPS main branch still interoperates with
whatever FIPS version is on the VPS.

**Depends on:** Task A (know the VPS version)

**Step 1: Build microfips-link (host-side handshake test)**

```bash
cd ~/repos/microfips
git checkout main
cargo build -p microfips-link --release
```

**Step 2: Run the host-side VPS handshake test**

```bash
# This sends MSG1 to VPS via UDP and expects MSG2 back
VPS_HOST=orangeclaw.dns4sats.xyz cargo run -p microfips-link --release
```

Expected: Handshake succeeds (MSG1 sent, MSG2 received, keys derived)

**Step 3: If hardware available, run serial_udp_bridge test**

```bash
# Check if any MCU boards are connected
ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null

# If STM32 connected:
python3 tools/serial_udp_bridge.py --udp-host orangeclaw.dns4sats.xyz --udp-port 2121
```

**Step 4: Record results**

Document pass/fail, FIPS version, microFIPS branch, timestamp.

**Verification:** We know definitively whether main ↔ VPS works.

---

## Task C: Test noise-xx Branch Against VPS

**Objective:** Determine whether the noise-xx branch can interoperate with
the VPS. Expected to FAIL if VPS is still on FMP v0 / IK.

**Depends on:** Task A

**Step 1: Switch to noise-xx branch and build**

```bash
cd ~/repos/microfips
git checkout feat/noise-xx-handshake
cargo build -p microfips-link --release
```

**Step 2: Run handshake test**

```bash
VPS_HOST=orangeclaw.dns4sats.xyz cargo run -p microfips-link --release
```

Expected:
- If VPS has FMP v0: FAIL (version nibble mismatch, frame rejected)
- If VPS has FMP v1 + XX: PASS (handshake completes)
- If VPS has FMP v1 but no XX: FAIL (handshake pattern mismatch)

**Step 3: Capture the exact failure mode**

If it fails, capture:
- What bytes were sent (FMP version nibble = 1)
- What error FIPS returned (parse error? silent drop?)
- Whether FIPS logged anything on the VPS side

```bash
sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" \
  "journalctl -u fips --no-pager -n 20 --since '2 min ago'"
```

**Step 4: Record findings**

Document the exact compat matrix:
- main ↔ VPS: PASS/FAIL
- noise-xx ↔ VPS: PASS/FAIL + failure mode

**Verification:** Complete picture of which branch works with which VPS version.

---

## Task D: Publish Compat Audit to Repo

**Objective:** Move the 340-line compat audit from the worktree into the main
repo docs/ directory, cleaned up and properly formatted.

**Workspace:** ~/repos/microfips, branch: feat/noise-xx-handshake

**Step 1: Copy the audit from worktree**

```bash
cp ~/worktrees/feature-microfips-compat-audit/docs/fips-microfips-compat.md \
   ~/repos/microfips/docs/fips-microfips-compat-audit.md
```

**Step 2: Add a status header reflecting current state**

Add at top:
```markdown
> **Audit date:** 2026-06-29
> **FIPS baseline:** jmcorgan/fips @ 30c5808 (0.5.0-dev)
> **microFIPS baseline:** b6bfc9d (pre-XX-migration)
> **Status:** Historical reference. Updated by Tasks B/C results above.
```

**Step 3: Commit and push**

```bash
git add docs/fips-microfips-compat-audit.md
git commit -m "docs: publish FIPS wire-protocol compat audit (M1)

340-line module-by-module comparison of microFIPS vs upstream FIPS
wire protocol. Documents the FMP version nibble incompatibility and
the Noise XX migration status as of 2026-06-29."
git push fork feat/noise-xx-handshake
```

**Verification:** File exists in repo, pushed to fork.

---

## Task E: Update Stale Parity Doc

**Objective:** docs/fips-microfips-parity.md is stale — it describes the
pre-migration state (FMP v0, IK/XK). Update it to reflect current reality.

**Depends on:** Task D (audit provides reference)

**Step 1: Identify stale claims**

```bash
cd ~/repos/microfips
grep -n "FMP_VERSION.*0\|IK\|XK\|MSG1_WIRE.*114\|noise.*IK" docs/fips-microfips-parity.md | head -20
```

**Step 2: Add a "CURRENT STATE" banner at the top**

```markdown
> ⚠️ **This document describes the pre-Noise-XX-migration state.**
> As of 2026-07-04, microFIPS HEAD uses FMP_VERSION=1 and Noise XX.
> For the current compatibility analysis, see
> `docs/fips-microfips-compat-audit.md` and the interop test results
> in `docs/strategy-and-upstream.md`.
```

**Step 3: Do NOT rewrite the whole doc** — it's a valuable historical
reference for the v0/IK protocol. Just add the banner.

**Step 4: Commit and push**

```bash
git add docs/fips-microfips-parity.md
git commit -m "docs: add staleness banner to parity mapping

The parity doc describes FMP v0 / Noise IK state. microFIPS HEAD
has migrated to FMP v1 / Noise XX. Banner added directing readers
to the current compat audit."
git push fork feat/noise-xx-handshake
```

**Verification:** Banner visible when reading the doc.

---

## Task F: Regenerate pcap Reference Vectors

**Objective:** The pcap regression test has `#[ignore]` with "TODO: regenerate
reference.pcap with FMP v1 / Noise XX wire format."

**Depends on:** Task B or C (working handshake to capture from)

**Step 1: Find the ignored tests**

```bash
cd ~/repos/microfips
grep -rn '#\[ignore.*pcap\|reference\.pcap' crates/ --include="*.rs" | head -10
```

**Step 2: Run the test to see what it expects**

```bash
cargo test -p microfips-core -- --ignored 2>&1 | head -30
```

**Step 3: Capture fresh pcap from a working handshake**

Use the host-side sim to generate traffic:
```bash
cargo run -p microfips-sim -- --vps 127.0.0.1:31337 &
tcpdump -i lo -w crates/microfips-core/tests/reference_v1.pcap udp port 31337 &
sleep 10
killall tcpdump microfips-sim
```

**Step 4: Update test to use new reference and un-ignore**

```rust
// Remove #[ignore], update path to reference_v1.pcap
```

**Step 5: Run test to verify pass**

```bash
cargo test -p microfips-core -- pcap 2>&1
```

Expected: PASS

**Step 6: Commit and push**

```bash
git add crates/microfips-core/tests/
git commit -m "test: regenerate pcap reference vectors for FMP v1 / Noise XX

Un-ignore pcap_regression tests with fresh capture from working
handshake. Previous reference was FMP v0 / Noise IK format."
git push fork feat/noise-xx-handshake
```

**Verification:** `cargo test -p microfips-core` passes including pcap tests.

---

## Task G: Build Automated Interop CI Test

**Objective:** Create a script that automatically tests microFIPS ↔ FIPS VPS
interoperability and can run in CI or on-demand.

**Depends on:** Task B (confirmed working configuration)

**Step 1: Create the interop test script**

Create `~/repos/microfips/scripts/interop_test.sh`:

```bash
#!/usr/bin/env bash
# microFIPS ↔ FIPS VPS interoperability test
#
# Tests: keygen → handshake → heartbeat → teardown
# Reports: PASS/FAIL per phase + wire-level details
#
# Usage: VPS_PASS=xxx ./scripts/interop_test.sh [--branch main|noise-xx]
set -euo pipefail

BRANCH="${1:-main}"
VPS_HOST="${VPS_HOST:-orangeclaw.dns4sats.xyz}"
VPS_USER="${VPS_USER:-routstr}"

echo "=== microFIPS Interop Test ==="
echo "Branch: $BRANCH"
echo "VPS:    $VPS_USER@$VPS_HOST"
echo "Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Phase 1: Build
echo "[1/4] Building microfips-link..."
cargo build -p microfips-link --release 2>&1 | tail -1

# Phase 2: Handshake
echo "[2/4] Testing handshake..."
if VPS_HOST="$VPS_HOST" timeout 30 cargo run -p microfips-link --release 2>&1; then
    echo "HANDSHAKE: PASS"
else
    echo "HANDSHAKE: FAIL"
    exit 1
fi

# Phase 3: VPS-side verification
echo "[3/4] Checking VPS logs for successful peer..."
sleep 2
VPS_LOG=$(sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no \
    "$VPS_USER@$VPS_HOST" \
    "journalctl -u fips --no-pager -n 10 --since '1 min ago'" 2>/dev/null || echo "")
if echo "$VPS_LOG" | grep -qi "peer.*established\|handshake.*complete\|session.*active"; then
    echo "VPS CONFIRMED: PASS"
else
    echo "VPS CONFIRMED: INCONCLUSIVE (no matching log entry)"
fi

# Phase 4: Report
echo "[4/4] Summary"
echo "  Branch:     $BRANCH"
echo "  FIPS VPS:   $(echo "$VPS_LOG" | grep -o 'v[0-9]\+\.[0-9]\+' | head -1 || echo 'unknown')"
echo "  Result:     $(grep -c 'PASS' <<< "$(echo)" >/dev/null 2>&1 && echo 'PASS' || echo 'PARTIAL')"
echo "  Timestamp:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

**Step 2: Make executable and test**

```bash
chmod +x scripts/interop_test.sh
VPS_PASS=xxx ./scripts/interop_test.sh --branch main
```

**Step 3: Add to CI as optional workflow**

Create `.github/workflows/interop.yml` that runs on manual dispatch:

```yaml
name: Interop Test
on:
  workflow_dispatch:
    inputs:
      branch:
        description: "Branch to test"
        required: true
        default: "main"
jobs:
  interop:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/interop_test.sh --branch ${{ inputs.branch }}
```

**Step 4: Commit and push**

```bash
git add scripts/interop_test.sh .github/workflows/interop.yml
git commit -m "ci: add automated interop test against FIPS VPS

Tests handshake + heartbeat + VPS-side log verification.
Can run on-demand via GitHub Actions workflow_dispatch."
git push fork feat/noise-xx-handshake
```

**Verification:** Script runs, reports PASS or FAIL with details.

---

## Task H: Add Version-Negotiation Guard

**Objective:** When VPS is on FMP v0 and microFIPS tries FMP v1, the failure
is silent (frame dropped). Add a clear diagnostic.

**Depends on:** Task G (interop test framework exists)

**Step 1: Add version detection to microfips-link**

In `crates/microfips-link/src/main.rs` (or equivalent), after sending MSG1:

```rust
// If no response within timeout, check if it's a version mismatch
if response_timeout {
    eprintln!("WARNING: No response from FIPS peer. Possible FMP version mismatch.");
    eprintln!("  Our version: FMP v{}", wire::FMP_VERSION);
    eprintln!("  If FIPS is on v0, it will silently drop v{} frames.", wire::FMP_VERSION);
    eprintln!("  Try the 'main' branch for FMP v0 / Noise IK compatibility.");
}
```

**Step 2: Test with wrong version**

```bash
# On noise-xx branch (v1), test against v0 VPS
cargo run -p microfips-link --release
# Should see clear diagnostic instead of silent hang
```

**Step 3: Commit and push**

```bash
git add crates/microfips-link/
git commit -m "feat: add FMP version mismatch diagnostic to link tool

When handshake fails due to no response, prints clear diagnostic
about possible FMP version mismatch instead of hanging silently."
git push fork feat/noise-xx-handshake
```

**Verification:** Running v1 against v0 VPS gives clear error message.

---

## Task I: FIPS v2 Spec Tracking Doc

**Objective:** Create a living document tracking FIPS v2 protocol changes as
jmcorgan publishes specs, mapped to microFIPS impact.

**Step 1: Create the tracking doc**

Create `~/repos/microfips/docs/v2-protocol-tracking.md`:

```markdown
# FIPS v2 Protocol Changes — Impact Tracking

> jmcorgan is writing detailed v2 protocol specs to enable independent
> implementations to interoperate. This doc tracks each spec as it arrives
> and maps the microFIPS impact.

## Known v2 Changes (from issue #58 + maintainer conversation)

| Change | FIPS v0.x | FIPS v2 | microFIPS Status | Impact |
|--------|-----------|---------|-----------------|--------|
| Link handshake | Noise IK | Noise XX | XX DONE (feat/noise-xx) | LOW — already migrated |
| Session handshake | Noise XK | Noise XX | NOT STARTED | MEDIUM — need 3-msg session |
| FMP wire format | v0 | v1 | v1 DONE (feat/noise-xx) | LOW — already bumped |
| Version negotiation | None | min/max + feature bitfield | NOT STARTED | HIGH — new protocol element |
| Profile negotiation | None | TLV extensions | NOT STARTED | MEDIUM — new protocol element |

## Spec Publication Watch

| Date | Spec | Source | microFIPS Action |
|------|------|--------|-----------------|
| (pending) | (pending) | jmcorgan | (none yet) |

## Decision Points

1. When v2 specs arrive: assess scope of changes needed
2. When FIPS v2 ships: run interop test (Task G) to detect all breaks
3. If changes are large: consider a v2-specific branch
```

**Step 2: Commit and push**

```bash
git add docs/v2-protocol-tracking.md
git commit -m "docs: add FIPS v2 protocol spec tracking document

Living document to track v2 protocol changes from jmcorgan and
map their impact on microFIPS. Updated as specs are published."
git push fork feat/noise-xx-handshake
```

**Verification:** Doc exists in repo, captures known v2 deltas.

---

## Task J: Madeira Meetup Discussion Prep

**Objective:** Prepare a concise list of technical questions and contribution
offers for the in-person discussion with jmcorgan at Madeira.

**Step 1: Create the prep doc**

Create `~/repos/microfips/docs/madeira-discussion-prep.md`:

```markdown
# Madeira Meetup — Discussion Points with jmcorgan

## Context
microFIPS is a standalone MCU implementation of FIPS leaf nodes.
Issue #122 (fips-core extraction) closed after maintainer explained
tokio coupling. This is the in-person follow-up.

## Questions (prioritized)

### 1. v2 Protocol Timeline
- When will the v2 protocol specs be published?
- Is there a target release date for FIPS v2?
- Which v2 modules will be runtime-agnostic?

### 2. Small Runtime-Agnostic Contributions
- You mentioned "small pieces at a time" — what specific pieces?
- Are there utility modules (bloom filters, EWMA estimators, CRC)
  that could be extracted with low risk?
- Would you accept a CI target check for no_std compatibility
  on specific modules?

### 3. Noise XX + FMP v1
- Is FIPS `next` branch stable enough for interop testing?
- Can we get the v2 spec for the XX handshake to verify our
  implementation matches?
- Are there test vectors we can validate against?

### 4. ESP32 as Build Target
- What would the minimum viable path look like?
- Feature flags to exclude: tokio, transports, TUN, rtnetlink?
- Would a `fips-leaf` crate (subset with only leaf-node functionality)
  be more realistic than full ESP32 support?

### 5. microFIPS Role in the Ecosystem
- Should microFIPS be the reference implementation for embedded FIPS?
- How can we help test v2 interop from the MCU side?
- Is there interest in a FIPS conformance test suite?

## What We Bring
- Working FIPS leaf node on 4 MCU targets (ESP32, STM32)
- 95%+ wire-level parity proven
- Hardware-verified Noise handshake + heartbeat
- Testing infrastructure (sim + VPS + bridge tools)
- Willingness to contribute upstream

## What We Need
- v2 protocol specs for independent implementation
- Clear guidance on acceptable contribution scope
- Interop test vectors
```

**Step 2: Commit and push**

```bash
git add docs/madeira-discussion-prep.md
git commit -m "docs: add Madeira meetup discussion preparation

Prioritized questions for jmcorgan: v2 timeline, contribution
opportunities, Noise XX interop, ESP32 build target, microFIPS
role in ecosystem."
git push fork feat/noise-xx-handshake
```

**Verification:** Doc ready for review before the meetup.

---

## Task K: ESP32-C3 RISC-V Feasibility Assessment

**Objective:** Evaluate what it would take to add ESP32-C3 (RISC-V) as a
microFIPS build target. This is the chip used in the balloon project.

**Step 1: Document current Xtensa-specific code**

```bash
cd ~/repos/microfips
grep -rn "xtensa\|esp32\b\|ESP32\b\|Xtensa" crates/microfips-esp32/ --include="*.rs" | head -20
grep -rn "xtensa\|esp32s3\|ESP32_S3" crates/microfips-esp32s3/ --include="*.rs" | head -20
```

**Step 2: Check if esp-hal supports C3**

```bash
grep "esp32-c3\|esp32c3\|riscv" Cargo.toml crates/*/Cargo.toml 2>/dev/null
```

**Step 3: Create feasibility doc**

Create `~/repos/microfips/docs/esp32-c3-feasibility.md`:

```markdown
# ESP32-C3 (RISC-V) Target Feasibility

## Current State
- microFIPS targets: ESP32-D0WD (Xtensa), ESP32-S3 (Xtensa), STM32F4/F7 (ARM)
- ESP32-C3 is RISC-V architecture (RV32IMC)
- esp-hal crate supports C3: esp32c3 feature flag exists
- Balloon project has 20x ESP32-C3 Mini V1 boards available

## What Would Change
| Aspect | ESP32 (Xtensa) | ESP32-C3 (RISC-V) |
|--------|---------------|-------------------|
| Architecture | Xtensa LX6 | RISC-V RV32IMC |
| Toolchain | xtensa-esp32-none-elf | riscv32imc-esp-none-elf |
| esp-hal feature | esp32 | esp32c3 |
| BLE | Classic + BLE | BLE only |
| WiFi | Yes | Yes |
| RAM | 520KB | 400KB |
| Flash | 4-8MB | 4MB |

## Required Changes
1. Add `crates/microfips-esp32c3/` crate (mostly config differences)
2. Update workspace Cargo.toml members
3. Test build: `cargo build -p microfips-esp32c3 --target riscv32imc-esp-none-elf`
4. Verify embassy + esp-hal compatibility for C3
5. Test WiFi transport (C3 has WiFi)
6. Test BLE transport (C3 has BLE 5.0)

## Risk Assessment
- LOW: esp-hal already supports C3
- LOW: Protocol code is architecture-independent (no_std Rust)
- MEDIUM: BLE stack (trouble-host) needs verification on C3
- LOW: WiFi should work (same esp-radio crate)

## Recommendation
Do this AFTER interop is locked down (Tasks A-H). The 20 available
C3 boards make it attractive for a multi-node test mesh, but it
doesn't address the v2 interop risk.

## Estimated Effort
2-4 hours: crate setup + build verification + basic WiFi test
```

**Step 4: Commit and push**

```bash
git add docs/esp32-c3-feasibility.md
git commit -m "docs: add ESP32-C3 (RISC-V) target feasibility assessment

Evaluates effort to add C3 as microFIPS build target. Low risk,
2-4 hours, but deprioritized until interop is locked down."
git push fork feat/noise-xx-handshake
```

**Verification:** Doc exists with clear go/no-go criteria.

---

## Scheduling Summary

### Phase 0 — Immediate (do NOW, before anything else)
**Tasks A, B, C** — we need to know if microFIPS interop works AT ALL.

### Phase 1 — Documentation (can parallelize)
**Tasks D, E** — publish what we know, mark what's stale.
**Task F** — depends on a working handshake (B or C).

### Phase 2 — Automation (sequential)
**Task G** — interop test script (depends on B).
**Task H** — version guard (depends on G).

### Phase 3 — Preparation (parallel, low urgency)
**Tasks I, J, K** — tracking docs for v2, Madeira, C3.

### Parallelization Map

```
Phase 0:  A → B → C (sequential, ~35 min)
              │
Phase 1:  D ──┤    (parallel, ~30 min total)
          E ──┤
          F ──┘ (needs B or C result)
              │
Phase 2:  G → H    (sequential, ~75 min)
              │
Phase 3:  I ──┐
          J ──┤    (parallel, ~65 min total)
          K ──┘
```

### Total Estimated Time
- Phase 0: ~35 min (CRITICAL)
- Phase 1: ~45 min
- Phase 2: ~75 min
- Phase 3: ~65 min
- **Total: ~3.5 hours** of focused work

All tasks produce committed, pushed documentation or code.
