# microfips strategy under the library north star (2026-10-14)

> Follow-up to `docs/2026-10-14-fips-core-overlap-and-direction.md`. North
> star set by the owner: microfips is a research project today and
> eventually **a reusable library for any Rust project on an ESP32 that
> wants to talk to FIPS devices over Bluetooth or WiFi**. This document
> decides (1) the canonical git line, (2) converge-vs-replace re-examined
> under the library goal, (3) the roadmap to "works on ESP32, talks to
> latest FIPS". Evidence gathered 2026-10-14 from this repo @ `628b4da`,
> `felix/main` @ `147480e`, and the read-only upstream checkout
> `/home/ubuntu/src/fips` (fork/main @ `a2d21faf`, upstream master
> `d208a9db` = 0.6.0-dev, upstream `next` head `e0cc0c86`).

## 1. OURS vs FELIX — canonical line

### What felix/main actually contains (28 commits, merge-base `215e62d`)

Four themes, 24 files, +1206/−114:

1. **ESP32-C3 (riscv32imc) bring-up — the only real firmware-code delta.**
   - `13410b9` atomics: `portable_atomic_unsafe_assume_single_core` as a
     *target-scoped* rustflag in `.cargo/config.toml` — riscv32imc has no
     CAS instruction, `static_cell` fails E0277 without it; deliberately
     NOT workspace-wide (hard error on x86_64). Well-reasoned.
   - `logger.rs` rework: log backend install on CAS-less targets via
     `set_logger_racy` — the *same* mechanism esp-println's own `log-04`
     backend uses; without it every `log::*!` site in the C3 image was
     silently discarded. Feature gate moved from radio-features to
     `log` + chip-feature, with the invariant spelled out.
   - C3/S3 `run.rs`: backend installed on uart images (logs on USB-JTAG,
     frames on UART0 — disjoint channels).
2. **Console-channel policy — process/tooling.** `docs/console-channels.md`
   (which images may log where), `scripts/check-console-policy.sh` (200-line
   bash guard: entry-point census + silent-binary census + repo-wide call-site
   census), wired into `ci.yml` lint job as a bash-only step. Guards the
   "log text must never share a FIFO with FIPS frames" invariant that bit
   us before (espnow-gw, S3 usb image).
3. **Dev tooling.** Versioned `.githooks/pre-push` + installer
   (`scripts/install-git-hooks.sh`), `.ngit/` local `act` runner workflow.
4. **Cleanup/docs.** Dead per-chip consts dropped from
   `microfips-esp-transport/src/config.rs` (−54), AGENTS.md +81
   (console policy), README/parity touch-ups.

### Empirical quality gate (run during this review, felix tree in a
throwaway worktree)

- Host suites: **228 passed, 0 failed** (microfips-core 175 + fips-noise 53).
- `cargo clippy -D warnings` on the shared protocol crates: **clean**.
- `scripts/check-console-policy.sh`: **passes** (14 entry points, 4 silent
  bins, census 6 files / 10 calls).

### Overlap with our unpushed `628b4da`

None at file level (`628b4da` touches `Makefile` + `tools/hil/*`; felix
doesn't). AGENTS.md is touched by both but in disjoint regions (ours:
trailing process-hygiene section; felix: early sections + two mid-file
spots) — a normal merge should auto-resolve.

### CI impact

+1 bash-only lint step (no toolchain, no build), one target-scoped
`.cargo/config.toml` rustflag (no host effect). Both benign; the guard
*adds* a wire-safety invariant to CI.

### Decision

**Merge `felix/main` into `amperstrand/main`; amperstrand/main stays the
single canonical line.** Dual lines would fork CI policy, duplicate the
AGENTS contract, and accumulate merge debt against the highest-activity
contributor. Felix's flow (reviewable `ci/t_*` branches consolidated into
its main) is a contributor model — it wants a canonical trunk, not a
permanent fork. Not fast-forward (we have 2 commits it lacks, history is
merge-style already), not rebase-ours (needless history surgery, and the
repo tolerates merge commits).

Owner-run commands (this session must not merge):

```bash
git checkout main
git push amperstrand main                      # land 628b4da first
git merge --no-ff felix/main -m \
  "Merge felix/main: ESP32-C3 bring-up (portable-atomic CAS, racy log install), console-channel policy + CI guard, hooks tooling"
# if AGENTS.md conflicts: keep both regions (ours = trailing process-hygiene,
# felix = console-policy sections) — content is disjoint by intent
cargo test -p microfips-core -p fips-noise      # expect 228 green (verified on felix tree)
bash scripts/check-console-policy.sh            # expect OK (verified)
git push amperstrand main
```

### C3 (riscv) vs D0WD/S3 (xtensa) implications

Felix's work makes **riscv32imc (C3) a fully buildable target class** for
the first time. This matters twice: (a) upstream fips-core's bare-metal CI
builds **riscv32imac** + thumbv7em — the riscv family is upstream-proven
for the C-dependency path (secp256k1-sys), so **C3 is the natural first
board for any fips-core canary**; (b) note the sub-architecture nuance:
upstream proves `imac` (has CAS), the C3 is `imc` (no CAS) — a canary
build for C3 additionally needs felix's `portable_atomic_unsafe_assume_single_core`
cfg, and the same cfg question would hit any port of fips-core to the C3.
D0WD/S3 are **xtensa** — uncovered by upstream CI in any form; the canary
must add a xtensa target ourselves to know whether secp256k1-sys even
builds there.

## 2. CONVERGE vs REPLACE under the library goal

Prior verdict (2026-10-14 report): don't port onto fips-core yet; audit
against pinned upstream (defs-mvp drift gate, cross-vectors, xx-interop).
**The library goal strengthens the verdict and adds one new obligation.**

### Why still converge-by-audit

- The library deliverable needs, in order: correct wire behavior vs the
  daemons consumers actually run, no_std, small footprint, stable API,
  ESP32 toolchain fit. fips-core today helps with none of the hard parts:
  it still has **no Noise crypto** (`core/src/noise` = IK-era wire sizes;
  handshake/AEAD stay in upstream's std root crate) and is **IK-era only**
  (no XX/FMP-v1). Our `fips-noise` — dual-wire, pure-Rust k256, zeroized,
  rekey-complete, hardware-proven — IS the library's crypto core today.
- A library must not re-export an unstable dependency to its consumers.
  fips-core is `0.0.0`, `publish = false`, and reachable only via a git
  ref on a fork whose `fork/main` is **periodically rebased onto upstream
  master** — a git-dependency pin dies on every rebase (the "pins die when
  upstream rewrites history" lesson, 2026-08-31). Viable mechanically,
  desirable only for a canary/watch job with the xx-interop warn+skip
  policy when the pin vanishes — never as the shipped library's dependency.
- What the library goal DOES change: microfips' own crate layout must now
  converge *in shape* with the seam upstream already proved out — its
  BLE `io_radio` pattern (`src/transport/ble/io_radio.rs` on the 0.6.0-dev
  checkout): **`BleRadio`** — object-safe, control-plane-only trait the
  *embedder* implements; **`BleRadioBridge`** — channel machinery where
  bytes never cross the command surface (inbound pushed via
  `deliver_recv`, outbound pulled via `next_send`); **`BleRadioSlot`** —
  an installable, replaceable radio handle, because the radio's lifetime
  is not the node's (Bluetooth toggled on/off mid-run). That is precisely
  the shape a microfips library needs on ESP32: the host app owns
  esp-radio/esp-hal (or esp-idf), implements a tiny command trait or a
  byte-channel, and the library owns protocol + framing. Our existing
  `Transport` trait (`wait_ready/send/recv` + `FrameWriter`) is already a
  clean byte-level seam; the missing piece is letting the *app* retain the
  radio/controller lifetime instead of our runner owning it (we already
  learned this the hard way: "retains `WifiController` for transport
  lifetime").

### Verdict

Keep **audit-against-pinned-upstream** as the coupling. Add the library
crate split (§3 M3/M4) that mirrors upstream's seams without taking the
dependency. Re-evaluate on any port trigger below.

### Port triggers (any ONE fires a port-decision review)

1. **Crypto lands in core**: upstream moves Noise handshake + AEAD session
   crypto into the no_std fips-core crate (fips-core becomes a complete
   protocol brain; our fips-noise could then shrink to an ESP-optimized
   backend or be replaced).
2. **XX lands in core**: the upstream `next` (XX/FMP-v1 + version
   negotiation) line is extracted into fips-core — removes our dual-wire
   leadership argument.
3. **Stability signal**: fips-core is published (crates.io semver) or the
   fork serves non-rebased version tags — removes the unstable-git-dep
   objection for our library consumers.
4. **Soft trigger**: upstream's own bare-metal CI (or examples) covers an
   xtensa target — proves the secp256k1-sys/toolchain path we would
   inherit on D0WD/S3.

## 3. ROADMAP — works on ESP32, talks to latest FIPS

Delta assessment first (evidence):

- **Release line**: upstream v0.5.1 (2026-09-06) and v0.5.2 (2026-09-28)
  changed **daemon-side behavior only** — lookup dedup fixes, gateway
  conntrack, logging, `FipsAddress`→`Ipv6Address` library rename
  (deprecated alias kept). The IK wire is unchanged: master `d208a9db`
  (0.6.0-dev) carries `FMP_VERSION 0`, `MSG1_WIRE_SIZE 114`,
  `MSG2_WIRE_SIZE 69`, `ESTABLISHED_HEADER_SIZE 16`,
  `COMMON_PREFIX_SIZE 4` — byte-identical to what microfips implements
  and pins cross-vectors for.
- **next line**: our pinned `NEXT_REF e0cc0c86` **is** the current
  `next` head — nothing to re-pin; XX/FMP-v1 interop is current.
- **gap**: our *bench verification* targets 0.5.0-dev daemons; "talks to
  latest" wants scenario runs against a v0.5.2 daemon (build from a
  worktree, never `/home/ubuntu/src/fips` target/).

Milestones:

1. **M1 — canonicalize the line** (owner): push `628b4da`, merge
   `felix/main` per §1. C3 becomes a buildable target; console guard
   enters CI. Exit: `amperstrand/main` contains felix's work, host suites
   228 green, guard green.
2. **M2 — latest-release interop evidence**: rebuild lab daemon images
   from the fork @ v0.5.2 (worktree build), rerun the 9 live fips-lab
   scenarios unchanged (wire-identical ⇒ identical asserts), plus a
   loopback IK-interop CI job vs the pinned v0.5.2 tag (sim +
   handshake). Exit: scenarios green ×2 consecutive; both wires CI-gated
   (IK vs v0.5.2, XX vs `e0cc0c86`).
3. **M3 — library crate split (no behavior change)**: `microfips-client`
   (naming TBD) = fips-noise + fips-fmp + fips-identity + leaf
   Node/session, `#![no_std]` core with optional `std`; entropy + clock
   as host traits (mirroring upstream's `EntropySource`); firmware crates
   become thin composition roots. Exit: firmware binaries bit-comparable
   (`cmp` the artifacts — the #113 lesson), host suites unchanged.
4. **M4 — embedder-owned radios**: adopt the `BleRadio/BleRadioBridge/
   BleRadioSlot` shape for BLE and WiFi: (i) byte-channel `Transport`
   path for any host (esp-idf std included), (ii) feature-gated
   `client-esp` helpers that build transports when the app hands over
   peripherals/controller. Two examples in-repo: plain-cargo esp-idf
   (std, UDP + BLE) and esp-hal (no_std, one radio). Exit: examples
   build in a bare `cargo build` project template, no microfips runner
   symbols required.
5. **M5 — fips-core canary CI** (issue #canary below): weekly, thin crate
   built against a pinned Amperstrand/fips fork rev serving `fips-core`,
   targets: `riscv32imc-esp` (C3 — needs felix's atomics cfg; nearest to
   upstream-proven riscv32imac), `xtensa-esp32s3` (uncovered upstream —
   the real question), thumbv7em (control). Warn+skip on vanished pin.
   Exit: signal on API drift, secp256k1-sys-on-xtensa viability, and
   entropy-trait fit, at zero coupling cost.
6. **M6 — HIL per milestone**: a fips-lab scenario flashing the M4
   example images as bench roles (same board classes, library-built
   firmware); C3 build+boot joins hil-smoke when a board exists. Exit:
   library-built image completes handshake + heartbeats vs the v0.5.2
   lab daemon, two consecutive greens.
7. **M7 — vectors stay canonical**: regenerate cross-vectors against the
   v0.5.2 fork tag (assert no-drift — expected identical), keep the
   weekly defs-mvp drift gate and specquotes pins as the library's
   correctness evidence. Exit: defs-mvp updated, drift gate green.
8. **M8 — consumer docs**: supported daemon matrix (0.5.x IK stable /
   XX experimental vs next `e0cc0c86`), target matrix (xtensa esp32 +
   esp32s3, riscv32imc c3, thumbv7em), MSRV, feature-flag table, and the
   radio-ownership guide. Exit: a stranger can depend on the crate and
   get a link up from the README alone.

## 4. Issues landed

Created on Amperstrand/microfips during this session (numbers in the
session log): strategy umbrella, felix-merge decision, fips-core canary
(with xtensa/riscv nuance), library packaging, protocol watch. Issue text
references upstream only by commit hash / branch name, per policy.
