# microfips × upstream fips-core — status & direction (2026-10-14)

> Review scope: decide Amperstrand's direction for microfips now that upstream
> FIPS (v0.5.1/v0.5.2 shipped; macOS CoreBluetooth BLE landed; a no_std
> `fips-core` workspace crate extracted with bare-metal CI) has started its
> microcontroller-support trajectory. Sources: this repo @ `628b4da` (main),
> read-only upstream checkout `/home/ubuntu/src/fips` @ `a2d21faf`
> (fork/main, rebased onto upstream master `d208a9db`, 0.6.0-dev),
> Amperstrand/fips-protocol-defs-mvp metadata, live test runs from this review.

## 1. Current status

### Purpose & scope

Experimental **FIPS leaf node for embedded MCUs** (README, AGENTS.md): STM32F469
(display variant), STM32F746, ESP32-D0WD, ESP32-S3 (Walter/TiLDAGON), ESP32-C3
(crate exists, no board). 19 crates: three extracted portable protocol crates
(`fips-noise` IK/XK/XX, `fips-fmp`, `fips-identity`), `microfips-core`
(FSP/MMP/constants/IPv6 shim), `microfips-protocol` (leaf `Node` runtime +
`ScriptedPeer` harness), service/HTTP layers, per-chip firmware, host tools
(link/sim/http-test), `microfips-build` (device registry + env overrides).
Seven leaf transports hardware-verified: USB CDC, UART, BLE GATT, BLE L2CAP,
WiFi+mDNS (pinned/open), ESP-NOW (+WiFi hybrid, gateways), relay AP
(router/extender/peer). Protocol scope is deliberately leaf-only — no mesh
routing/bloom/STP subsystems (`docs/fips-microfips-parity.md` §11).

### Git state (2026-10-14)

- Local `main` = `amperstrand/main` **+ 1 unpushed commit** (`628b4da`,
  coordinator consolidation to ai-legion:20408, 2026-09-28).
- `felix/main` (AI collaborator) is **28 commits ahead** (15 non-merge,
  last activity 2026-10-12): `docs/console-channels.md` + a 200-line
  console-policy check script, versioned pre-push git hooks installer,
  **real ESP32-C3 bring-up fixes** (riscv32imc portable-atomic CAS, log
  backend on riscv), esp-transport config cleanup. Unmerged.
- Activity: 80 commits in Aug, 106 in Sep, **zero on main since Sep 28**
  — the repo has been quiet ~2.5 weeks except felix's docs/tooling work.
- Working tree clean; stray session artifacts at root (`mfp-std.log`,
  `mfp-xx.log`, `mn-battery2.log` — overnight/battery soak logs).

### Trajectory (last ~2 months, from `git log`)

1. **DoS hardening #77** (closed 2026-09-05): sticky peer slot, reconnect
   floor, rekey-answer rate limit — bench-proven by fips-lab
   `test_espnow_dos_floor`, RED-verified against the reverted floor.
2. **XX / FMP-v1 forward-compat wire** landed and hardware-verified
   (#178/#179/#192/#195/#196): dual-wire (IK v0 default + XX under
   `noise-xx`), CI-gated interop vs pinned upstream next `e0cc0c86`,
   live sim↔next and bench-S3↔next sessions, MMP report interop fixed.
3. **HIL modernization**: 9 live fips-lab hardware scenarios (rekey
   soak/interleave, link-death, mdns-pinned, mesh full-session, L2CAP
   bring-up, bench XX), nightly soak timer, old `labgrid/` deprecated in
   favor of `tools/hil` + fips-lab `boards.toml` safety contract,
   cross-project bench exclusivity via rig-lock→BenchLock (#199).
4. **Protocol-definition infrastructure**: vendored wire constants from
   **Amperstrand/fips-protocol-defs-mvp** (extracted from jmcorgan/fips
   v0.4.0) with a weekly drift gate (#202/#209); canonical cross-vector
   pins with **microfips as generator of record** for the IK msg1 golden
   (#210).
5. **Governance/process**: gitleaks enrollment + allowlist, per-run seeded
   bench identities (#208 — published npubs are single-use), multi-session
   coordination (tollgate-lab session registry, scoped `lab-kill`),
   process hygiene sweep (bounded tests, orphan hunt), labgrid coordinator
   consolidated to ai-legion:20408.

### CI

16 jobs in `ci.yml` (test, golden-vectors, noise-compliance, audit,
build-host, lint, sim-smoke, fips-integration, build-firmware,
spec-quotes, build-firmware-extended, sim-ping, publish-evidence,
summary, push/release) plus 4 workflows: `gitleaks.yml`,
`protocol-drift.yml` (weekly cron vs defs-mvp), `shc-reaper.yml`,
`xx-interop.yml` (builds pinned upstream next; fails on our XX regression,
warn-skips if the pin vanishes).

### Test / verify story (re-verified during this review)

- `cargo test -p microfips-core`: **175 passed, 0 failed** (+2 ignored pcap).
- `cargo test -p fips-noise`: **53 passed, 0 failed** (IK; same count under
  `noise-xx` per CI).
- `cargo test -p microfips-protocol --features std -- --test-threads=1`:
  **154 passed, 0 failed** (IK wire).
- Above that: fips-lab hardware scenarios (pytest), HIL smoke legs in
  `tools/hil/tests`, nightly soak, Makefile targets (`test-hil`,
  `hil-preflight`, `hil-status` reporting coordinator/bench-flock/ledger
  state), specquotes CI pinning wire invariants against vendored upstream
  sources (`specs/fips/` @ `0aef8ea2`, `specs/fips-next/` @ `e0cc0c86`).
- Note: AGENTS.md's "234 core tests" is stale (suite reorganized; noise
  tests moved to `fips-noise`). Today's honest unit count is
  175+53+154(=IK) plus XX-mode runs in CI.

### Coordination notes

Multi-agent bench coordination is now institutionalized: session registry
(`tollgate_lab.session_registry`), scoped `lab-kill <session-name>` instead
of pattern kills, rig-lock taking BenchLock('amperstrand-bench') first in
every path, `fips_lab/bench.py::quiesce_peer_radios` before every scenario
(two-atom BLE interference + CYD WiFi intrusion lessons), board-roles
ledger, labgrid exporter as systemd service → ai-legion:20408. The felix
fork operates reviewable `ci/t_*` branches consolidated into its main.

## 2. Overlap map: microfips vs upstream fips-core

Upstream `fips-core` (workspace member `core/`, **~32k lines**, `0.0.0`,
`publish = false`) provides, no_std+alloc:

| Upstream fips-core has | microfips counterpart | Overlap |
|---|---|---|
| Sans-IO state machines: `proto/fmp` (link lifecycle + resend scheduling), `fsp` (sessions incl. quorum), `mmp` (full metrics), bloom, routing, STP, lookup, probe, rate-limit | `fips-fmp` + `microfips-core` (FSP/MMP leaf subset) + `microfips-protocol` (leaf `Node`) | **Convergent philosophy, divergent scope**: microfips is leaf-only; upstream core is the full mesh daemon brain |
| `identity/` (secp256k1 signing, node/peer identity, encodings) | `fips-identity` (NodeAddr, FipsAddress, bech32, derivation) | Near-full overlap in leaf-relevant parts |
| `cache/` coordinate cache | none (leaf doesn't route) | No overlap |
| `entropy.rs` `EntropySource` trait (host-supplied RNG seam; core never reads randomness) | per-chip TRNG init in `microfips-esp-transport`/firmware | Same seam, different shape — trivial to adapt |
| `noise/` module | `fips-noise` full IK/XK/**XX** implementations | **Sizes only vs full crypto** — see below |
| transport value types (LinkId, TransportAddr, stats) | `microfips-protocol::transport` trait + impls | Partial (values vs async trait) |
| Bare-metal CI: thumbv7em-none-eabihf, riscv32imac-unknown-none-elf | firmware builds for thumbv7em + **xtensa** esp32/esp32s3 (+riscv32imc C3 via felix fixes) | Upstream does not build xtensa; secp256k1-sys (C) unproven there |

The load-bearing asymmetries:

1. **fips-core does NOT contain the Noise crypto.** `core/src/noise/`
   holds only wire sizes (IK-era: MSG1 106 / MSG2 57 — no XX sizes), and
   its README states the handshake and sessions "stay in the root crate's
   `noise` module" (std). The one component a microcontroller cannot do
   without — no_std IK/XX handshake + AEAD session crypto — is exactly the
   part upstream did *not* extract. microfips' `fips-noise` (3.2k lines,
   pure-Rust k256/chacha20poly1305/sha2, dual-wire IK+XX, zeroization,
   replay window, full rekey machinery) has **no upstream no_std
   equivalent**.
2. **microfips is ahead on forward-compat.** Dual-wire XX/FMP-v1 is
   implemented, CI-gated against pinned upstream next, and
   hardware-verified. fips-core today pins IK-era sizes only.
3. **Dependency strategy diverges.** fips-core rides secp256k1 0.30
   (secp256k1-sys C, cross-compiled with clang/llvm-ar); microfips uses
   pure-Rust k256 — painless on xtensa. Porting swaps a proven pure-Rust
   embedded crypto path for a C-syscrate unverified on xtensa.
4. **They already converge where it is cheap and safe**: wire constants
   and golden vectors. microfips consumes defs-mvp generated constants
   (`microfips-core/src/generated/`), the weekly drift gate watches
   upstream movement, and microfips is the generator of record for the
   canonical IK msg1 cross-vector. This is a working, low-risk
   convergence seam that does not require sharing code.

## 3. Options

- **(a) Independent golden-vector / protocol-defs reference.** Keep
  microfips as the embedded oracle: golden vectors, cross-vectors,
  specquotes wire pins, drift gates. Cost: continues dual-maintenance of
  leaf protocol code (~12k lines in fmp/core/protocol crates).
- **(b) Port microfips onto fips-core.** Rewrite the leaf runtime to drive
  fips-core's sans-IO action model, adopt its identity/transport types.
  Buys upstream-maintained state machines (incl. fixes for bug classes
  microfips hit: rekey replay, rate limiting, silent-peer policy); costs a
  rewrite of the most hardware-verified code we have, keeps fips-noise
  anyway (no upstream no_std crypto), loses XX/FMP-v1 until upstream
  extracts next into core, takes on secp256k1-sys on xtensa, and binds to
  an unpublished 0.0.0 crate via git ref.
- **(c) Narrow to hardware bring-up + device registry.** microfips owns
  transports, bench/HIL, registry, verification; protocol semantics come
  from upstream via the defs pipeline.
- **(d) Wind down.** Not justified: the bench, scenarios, and transport
  bring-up have no upstream substitute and are the scarce assets.

## 4. Recommendation

**Hybrid (a)+(c): keep microfips as the independent embedded reference —
golden-vector generator of record + hardware bring-up/verification bench —
and explicitly do NOT port onto fips-core yet.** Keep `fips-noise` as the
no_std crypto of record. Revisit the port when a concrete trigger fires
(see below). Concretely:

1. **Protocol semantics**: keep flowing through the defs-mvp pipeline
   (vendored constants, drift gate, cross-vectors, specquotes) and the
   proven findings→fork/main PR channel (e.g. the learned-address-type BLE
   dial fix). Stop growing leaf protocol features beyond what verification
   needs; treat upstream as the semantics owner.
2. **Add a low-cost fips-core watch**: a CI canary job (xx-interop
   pattern) that builds a thin crate against a pinned fips-core git ref
   for thumbv7em **and xtensa**, so API drift and xtensa viability are
   observed without committing to a port.
3. **Port trigger conditions** (any one): upstream moves Noise
   handshake/session crypto into a no_std core; upstream extracts the
   XX/next wire into core; or fips-core publishes with a stability
   promise. Until then the port is all cost and no capability gain.
4. **Housekeeping now**: push `628b4da`; review+merge felix's 28 commits
   (C3 atomics/log fixes are real bring-up value; the console-policy
   script and hooks are process wins); refresh the stale "234 core tests"
   line in AGENTS.md; delete or gitignore the root `*.log` soak artifacts
   after archiving their findings.

### Top 3 reasons

1. **The port buys nothing microfips lacks and costs the crown jewels.**
   fips-core's missing piece is precisely no_std Noise crypto — a port
   keeps `fips-noise` and rewrites the hardware-verified leaf runtime to
   call upstream state machines whose leaf subset we already run green on
   three chip families, while the mesh subsystems (routing/STP/bloom/
   lookup) are dead weight on a leaf.
2. **microfips is the compatibility leader right now.** Dual-wire IK +
   XX/FMP-v1 with CI-gated interop against pinned upstream next and bench
   hardware proof — fips-core is IK-era sizes only. Porting would regress
   forward-compat until upstream catches up.
3. **microfips' irreplaceable value is verification infrastructure, not
   protocol reimplementation.** Nine live fips-lab hardware scenarios,
   HIL smoke legs, nightly soaks, the device-registry/build-override
   system, golden/cross vectors, specquotes pins, and the multi-agent
   bench discipline are assets upstream has no equivalent of — exactly
   what upstream's microcontroller trajectory will need from a consumer
   as fips-core matures.

## Evidence (commands run during this review, 2026-10-14)

- `git status` clean; `git rev-list --left-right --count` → main vs
  amperstrand/main `1 0`; main vs felix/main `2 28`.
- `git log --format="%ad" --date=format:"%Y-%m"` → Aug 80, Sep 106, Oct 0.
- `cargo test -p microfips-core` → 175 passed / 0 failed (+2 ignored).
- `cargo test -p fips-noise` → 53 passed / 0 failed.
- `cargo test -p microfips-protocol --features std -- --test-threads=1`
  → 154 passed / 0 failed.
- Upstream: `core/Cargo.toml` (no_std, 0.0.0, publish=false, secp256k1
  alloc-only), `core/src/noise/mod.rs` (IK sizes only; "handshake and the
  sessions … stay in the root crate"), `core/src/entropy.rs`
  (EntropySource), `testing/build-core-baremetal.sh` (thumbv7em +
  riscv32imac), `core/src` ≈ 31,987 lines.
- microfips: fips-noise 3,172 + fips-fmp 1,873 + fips-identity 594 +
  microfips-core 3,919 + microfips-protocol 11,247 ≈ 20,805 lines.
- `gh issue list -R Amperstrand/microfips` (open): #200 OTA dual-boot,
  #191 HIL pattern, #190 VPS creds, #208/#204 tracking, #177 session
  plan, #168/#165 upstream watches.
- defs-mvp: "Experimental FIPS protocol definition profiles and
  generators for microcontroller and lab tooling", last push 2026-09-06.
