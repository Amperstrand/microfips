# fips-core adoption audit — what can go, what must stay

2026-10-15. Inputs: upstream fips `core/` as of `d208a9db` (31,987 LOC
including heavy embedded test suites; no_std+alloc; deps: secp256k1-sys
(C), bech32, sha2, zeroize, thiserror; bare-metal CI thumbv7em +
riscv32imac, our canary adds xtensa — all green, #219) versus our five
protocol crates (20.8k LOC total). Question asked: can we deprecate or
replace parts of our stack with upstream's now? Answer below, area by
area.

## TL;DR

Align as policy — yes (already the roadmap). Big-bang swap today — no.
Two hard blockers make replacement a capability regression right now
(upstream core has **no Noise crypto** and **no XX/FMP-v1 wire**), one
practical blocker (unstable dependency surface: `0.0.0`, `publish =
false`, and a git pin breaks every time the fork rebases onto upstream),
and one measurable open question (C-crypto flash/RAM footprint vs our
pure-Rust backend). Nothing is replace-today-unconditional. The nearest
candidates and their acceptance conditions are listed per area.

## Area-by-area

### 1. Noise crypto — `fips-noise` (3.2k) vs upstream core `noise/`

Upstream core's noise module contains **wire size constants only**; the
handshake and session AEAD live in their std-only root crate. There is
nothing to adopt. Ours is complete (IK/XK/XX, rekey, replay windows,
zeroize discipline, pure-Rust: k256 + chacha20poly1305 + hkdf + hmac +
sha2) and hardware-proven on three chip families.

**Verdict: KEEP — mandatory. This is the load-bearing wall until upstream
moves crypto into the no_std core (port trigger #1).**

### 2. XX / FMP-v1 forward-compat wire — `fips-noise` XX + `fips-fmp/negotiation.rs`

Upstream's core is IK-era. The XX line exists upstream only on `next`,
unextracted. Swapping our framing/state code for core's today silently
drops the dual-wire capability our CI pins against the current `next`
head — a documented regression, not a simplification.

**Verdict: KEEP until XX lands in core (port trigger #2).**

### 3. FMP IK framing — `fips-fmp` (1.9k) vs core `proto/fmp/wire.rs`

The closest overlap in the whole audit: byte-compatible by construction
(the bench decryptor reads both with only the MCU's 2-byte length prelude
as the difference). Pros of adopting upstream's: single source of truth,
rides their test suite. Cons: the unstable-dep blocker above; and an API
shape mismatch — core is alloc/Vec oriented, ours is the MCU-friendly
fixed-buffer style (`encrypt_and_assemble(..., &mut [u8; 256]) ->
Option<usize>`: deterministic, no heap fragmentation mid-handshake).

**Verdict: WAIT for the stability signal. When it fires, adopt and delete
ours — this crate is a mirror whose only reason to exist is that the
reflected original is not reachable as a stable dependency.**

### 4. Leaf state machine — `microfips-protocol` Node (11.2k, embassy-integrated) vs core's sans-IO machines

Upstream ships the full-mesh sans-IO state space (fmp/fsp/lookup/bloom/
routing/stp/probe/mmp). A leaf uses a slice of it and would link the
rest. Adopting means writing a new embassy runner for their machines,
losing dual-wire (see #2), and carrying mesh machinery as dead weight.
Pros when the triggers fire: upstream-tested state machines, one less
divergent implementation to maintain.

**Verdict: WAIT for XX-in-core, then adopt through the M3 library split
(shape-first: make our runner look like their machine boundaries so the
swap is a step, not a rewrite).**

### 5. Identity + entropy — `fips-identity` (0.6k) vs core `identity/` + `EntropySource`

The nearest "replace today IF" candidate: upstream's is more complete
(auth/peer types, hardened no_std paths, host-blinded secp context,
bech32 encoding) and their `EntropySource` seam is exactly the shape our
library split wants. Blockers: the unstable dep surface, and the backend
switch k256 → secp256k1-sys — builds on all our targets (canary) but the
**flash/RAM cost on ESP32 is unmeasured**; a C-backed crypto stack on a
heap-constrained MCU is a real regression vector.

**Verdict: WAIT for stability signal; add a binary-size measurement to
the canary first so the decision is data, not vibes.**

### 6. MMP, FSP leaf subset, coordinate/address types

Same shape as #4: overlapping subsets, upstream's versions ride the same
triggers, our cross-vectors already pin compatibility in both
directions.

**Verdict: WAIT (shared triggers).**

### 7. ESP bring-up, transport, console policy — `microfips-esp-*`

Upstream has no ESP HAL path at all (their seam is io_radio; the embedder
owns the radio). This is ours by definition.

**Verdict: KEEP forever.**

### 8. Bench, HIL, golden/cross-vectors, drift gates, sim, service layer

Test and verification infrastructure. Upstream ships nothing comparable.
Critically, the **cross-vectors are implementation-agnostic**: they will
verify the future upstream-based build exactly as they verify ours today.

**Verdict: KEEP forever — this is the part whose value survives full
convergence.**

## What is worth carrying forward (the honest list)

1. `fips-noise` — until upstream core grows crypto; then adopt theirs and
   retire ours without sentiment.
2. The dual-wire XX lead — it is precisely the thing upstream `next`
   still needs to extract; our CI-gated interop and vectors de-risk that
   extraction for any consumer.
3. Cross-vectors + drift gates + specquotes — permanent, verification of
   any implementation including our future upstream-based one.
4. The bench: HIL scenarios, device-registry discipline, keylog +
   offline decryption tooling, the loopback rig.
5. ESP bring-up crates and the console-channel policy.
6. The deterministic-identity scheme (generator×N) — already proven to
   interoperate with released daemons and to make captures analyzable.

## "Should we just align?"

Yes as a **policy** — that is what docs/ROADMAP.md commits to, and this
audit confirms no area contradicts it. No as a **big-bang swap today**:
the two capability blockers and the dependency-surface blocker are real,
and the honest sequencing is the ladder already written — canary watches
the triggers, M3 shapes the code like the surface it will consume, and
each adoption step deletes rather than rewrites. The one new action item
this audit adds: **extend the canary to measure binary size** of an
upstream-core-linked image vs our current one, so the identity/crypto
backend decision lands on data (#219).
