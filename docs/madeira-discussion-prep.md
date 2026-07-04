# Madeira Meetup — Discussion Prep

> Created: 2026-07-04 | Status: DRAFT | Event date: TBD
> Attendees: upstream FIPS lead maintainer, microFIPS embedded implementer

> **Naming convention:** This document uses role-based names only.
> "upstream maintainer" = the FIPS project lead;
> "embedded implementer" = the microFIPS maintainer (us).
> No real handles or personal names appear here.

## Meeting Goals

1. Establish a shared understanding of the FIPS v2 protocol timeline so
   microFIPS can sequence its migrations without guessing.
2. Identify the smallest runtime-agnostic contributions microFIPS can make
   upstream without disturbing the tightly-coupled tokio state machines.
3. Agree on a concrete Noise XX + FMP v1 interoperability test plan,
   including test vectors we can both run against.
4. Get a realistic read on ESP32 (and other MCU targets) as a first-class
   upstream build target — or an explicit "not now" with criteria for later.
5. Define microFIPS's role in the FIPS ecosystem: standalone embedded leaf,
   future `fips-core` consumer, or something else.

## What We Bring

Concrete, demonstrable capabilities — not promises. Use these as the basis
for any "what is microFIPS worth to the ecosystem" discussion.

- **Working leaf nodes on 4 MCU targets, all hardware-verified.**
  | Target | Chip | Architecture | Verified |
  |--------|------|--------------|----------|
  | ESP32-D0WD | ESP32 | Xtensa LX6 | UART, BLE GATT, BLE L2CAP, WiFi |
  | ESP32-S3 | ESP32-S3 | Xtensa LX7 | UART, BLE GATT, BLE L2CAP, WiFi |
  | STM32F469I-DISCO | STM32F4 | Cortex-M4 | UART |
  | STM32F746G-DISCO | STM32F7 | Cortex-M7 | UART (Noise IK verified against VPS, 2026-05-04) |
- **95%+ wire-level parity with upstream FIPS** (see
  `docs/fips-microfips-parity.md`, the full module-by-module mapping: noise,
  FMP link, FSP session, identity, transport, MMP, peer policy, node runtime).
- **Testing infrastructure** that upstream currently lacks on the embedded
  side: a build matrix that compile-checks every transport against both ESP32
  variants, plus an error-injection and wire-format test suite
  (`crates/microfips-core/tests/`) that asserts exact byte layouts and
  version-nibble behavior.
- **A forward-looking v2 implementation** on `feat/noise-xx-handshake`:
  link handshake IK→XX and FMP wire format v0→v1, both implemented and ready
  to validate against the upstream spec the moment it publishes.
- **A PlatformIO / ESP-IDF component wrapper**
  (`microfips-esp32-component`) that makes microFIPS consumable from the
  broader embedded ecosystem, not just bare Rust.
- **Real-world interop evidence**: STM32 ↔ VPS FIPS node Noise IK handshake
  verified 2026-05-04; ESP32 ↔ VPS over UDP/WiFi verified.

## What We Need

- **The v2 protocol specs**, published. This is the single biggest unblocker.
  Until they land, our XX + FMP v1 work is a best-effort guess
  (tracked in `docs/v2-protocol-tracking.md`). Specific asks:
  - Link handshake (XX) wire format and static-key encryption flags.
  - Session handshake migration plan (XK → ?).
  - FMP v1 full field layout, not just the version nibble.
  - Version negotiation fields and semantics.
  - Profile negotiation enum (or confirmation that "leaf" is a profile).
- **Contribution guidance.** Given the tokio-coupled state machines, we need
  the maintainer to point at the *specific* small pieces that are safe to
  extract or contribute without forcing a rewrite of the runtime core.
- **Interop test vectors.** Captured handshake transcripts (IK and XX) and
  FMP v0/v1 frame examples that both sides can run byte-for-byte, so "we
  interoperate" is a test result, not an assertion.
- **A clear yes/no on ESP32 as an upstream build target**, and if "not now",
  the criteria (CI capacity? target spec? maintainer bandwidth?) that would
  flip it to yes.
- **A statement of microFIPS's role**, even informal: e.g. "the embedded leaf
  reference, separate from core" vs "future `fips-core` consumer once v2
  stabilizes." This sets expectations on both sides for the next 6–12 months.

## Discussion Questions

### A. v2 Protocol Timeline

1. What is the rough timeline for v2 protocol spec publication — weeks,
   months, longer? What is the first spec we should expect?
2. Is the link-handshake IK→XX migration the first v2 change to land, or is
   there a different sequencing priority upstream?
3. Will there be a v1↔v2 transition window where nodes must speak both, or a
   hard flag-day cutover? This drives whether microFIPS keeps a fallback path
   (see DP-1 in the v2 tracking doc).
4. How stable is the current FMP v1 wire format? Should we expect further
   changes before spec publication, or is the version nibble the only delta?
5. Are version negotiation and profile negotiation firmly scoped for v2, or
   speculative? If scoped, what is the target shape?

### B. Small Runtime-Agnostic Contributions

> Context: issue #122 (fips-core extraction) was closed because the protocol
> state machines are tightly coupled to the tokio runtime. The maintainer
> asked for "small pieces at a time that move things in the right direction."

1. Which specific modules or functions are *not* (or only weakly) coupled to
   tokio today, and could be extracted first as standalone, runtime-agnostic
   pieces? (e.g. noise primitives, wire parsers, MMP estimators, identity
   derivation.)
2. Is there a contribution that would be valuable to upstream *and* would
   naturally be no_std-friendly — e.g. pure data-structure or wire-format
   work — that microFIPS could take on as a first PR?
3. What does the maintainer's review bar look like for these small pieces?
   Any style / test / CI requirements we should satisfy before opening a PR?
4. Would upstream accept a shared interop test-vector crate (no runtime
   dependency) as an early contribution to anchor wire compatibility?

### C. Noise XX + FMP v1 Interop Testing

1. Can the maintainer provide captured XX handshake transcripts (both
   initiator and responder sides) so we can validate our `feat/noise-xx-handshake`
   branch byte-for-byte?
2. Same ask for FMP v1 frames — a small set of version-1 common-prefix +
   established-header examples.
3. Is there an existing upstream interop harness we can plug microFIPS into,
   or do we need to build a minimal one together?
4. What's the maintainer's preferred channel for ad-hoc interop debugging
   once we have vectors (Signal group already exists; anything else)?
5. Should we schedule a live interop session (our ESP32/STM32 ↔ upstream
   node) during or right after the meetup?

### D. ESP32 as a Build Target

> Context: maintainer previously said an ESP32 port is "a lot more work than
> appears on the surface" and sympathetic in principle.

1. Has upstream's position on an ESP32 target evolved since the issue #122
   discussion? What would change the "not now" to "yes"?
2. Is the blocker technical (Xtensa LLVM, no_std story, CI capacity) or
   resourcing (maintainer review bandwidth)?
3. Would upstream accept the ESP32 target as a *separate* repo / workspace
   member that doesn't burden the core build, with microFIPS as its
   maintainer? Or must it live in the main tree?
4. Are there upstream dependencies (tokio, etc.) that fundamentally prevent
   a no_std port, and is there a path to gating them behind a feature flag?
5. For RISC-V targets specifically: would an ESP32-C3 target be more
   palatable than Xtensa (simpler toolchain), and is that worth pursuing
   first even though our current C3s are committed to another project?

### E. microFIPS Role in the Ecosystem

1. How does the maintainer currently describe microFIPS to others — as a
   parallel implementation, an embedded port, a future core consumer, or
   something else? Aligning this language helps both sides.
2. Post-v2-stabilization, is the `fips-core` extraction still the intended
   direction, or has v2 changed the plan? If still intended, what's the
   earliest realistic starting point?
3. Are there ecosystem roles microFIPS is uniquely positioned to fill
   (embedded leaf reference, hardware-in-the-loop testing, MCU interop
   gatekeeper) that the maintainer would formally recognize?
4. How should we coordinate going forward — periodic sync, issue-driven,
   or just-in-time around releases? What cadence works upstream?
5. Is there anything upstream needs *from* microFIPS that we haven't
   offered (e.g. embedded bug reports, MCU-specific constraints fed into
   protocol design)?

## Desired Outcomes (concrete, from this meetup)

- [ ] A date (or date range) for the first v2 spec publication.
- [ ] A short list (1–3 items) of concrete first contributions microFIPS
      should prepare, named by the maintainer.
- [ ] An agreement to exchange XX + FMP v1 test vectors within a set
      timeframe after the meetup.
- [ ] A yes/no/conditional answer on ESP32 as an upstream build target,
      with criteria if conditional.
- [ ] An agreed one-line description of microFIPS's role in the ecosystem.

## Logistics

- **Location:** Madeira (in-person).
- **Date:** TBD — confirm with upstream maintainer.
- **Bring:** laptop with `feat/noise-xx-handshake` branch checked out and
  buildable; a flashed ESP32 + STM32 if a live demo is wanted; printed copies
  of `docs/fips-microfips-parity.md` and `docs/v2-protocol-tracking.md`.
- **Follow-up:** within one week, send a written summary of agreed outcomes
  and open the tracking issues referenced in `docs/v2-protocol-tracking.md`.
