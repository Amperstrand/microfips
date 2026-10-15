# microfips roadmap — converge onto upstream, keep the bench

End goal: **run upstream fips on microcontrollers.** This repo's protocol
stack shrinks as upstream's no_std `fips-core` grows; what stays is what
upstream doesn't ship: the lab bench, HIL scenarios, golden vectors, and
ESP32 bring-up. Policy: **inherit or reuse upstream code whenever
possible** — our crates are scaffolding with a planned demolition date,
not a parallel implementation to maintain forever.

## What stays ours (indefinitely)

| Asset | Why upstream won't have it |
|---|---|
| Lab bench (fips-lab + this repo's HIL) | Test infrastructure, not product code |
| Device registry discipline + safety contract | Bench-specific |
| Cross-vectors / golden vectors (generator of record) | Verification asset for ANY implementation |
| ESP32 bring-up crates (esp-hal radios, console policy) | Upstream has no ESP HAL path |
| Bench tooling (decryptor, keylog consumers, rig) | Lab-only instrumentation |

## What converges (adoption ladder, crate by crate)

| Our crate(s) | Adopted by | Trigger |
|---|---|---|
| `fips-identity` | upstream core identity + EntropySource seam | now possible in principle; blocked on a stable dependency surface (published, or non-moving tags) |
| `microfips-core` / `microfips-protocol` state machines, `fips-fmp` framing | upstream core proto/state machines | XX/FMP-v1 wire lands in core (keeps our forward-compat lead meaningful) |
| `fips-noise` (pure-Rust IK/XK/XX, zeroized, rekey) | upstream core crypto | Noise handshake + session crypto moves into the no_std core |

The weekly **fips-core canary** (issue #219, workflow `fips-core-canary`)
watches these triggers: any one firing starts a port review for that
crate. Canary status at time of writing: all three target families build
(riscv32imc, xtensa-esp32s3, thumbv7em) — xtensa viability is proven,
so adoption is a policy question, not a technical one. The per-area
verdicts, pros/cons and acceptance conditions live in
[fips-core-adoption-audit.md](fips-core-adoption-audit.md); its one
addition to this ladder is a canary binary-size measurement to inform
the crypto-backend decision.

## Milestones

1. **Bench breadth** (issue #224): repeat the proven l2cap hardware path
   across more boards as they return from other duties; S3 + WiFi-variant
   runs when that board's dual-hat duty allows.
2. **M3 — library split** (issue #220): no_std core + optional std, host
   entropy/clock traits, embedder-owned radios mirroring the io_radio
   seam — shape the remaining code exactly like the upstream surface it
   will eventually consume, so each adoption step is a swap, not a
   rewrite.
3. **Adoption steps** as triggers fire (see ladder above).
4. **End state**: leaf firmware = upstream crates + our ESP bring-up;
   this repo = bench, vectors, bring-up, and the library entry point for
   any Rust project on an ESP32 that wants to talk to fips devices over
   BLE or WiFi.

## Non-goals

- Forking upstream fips or maintaining a competing protocol stack
  long-term.
- Posting/PR-ing upstream (upstream forbids automated AI posts; we are a
  consumer).
- Keeping protocol code alive here after upstream covers it.
