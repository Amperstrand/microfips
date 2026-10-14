# microfips testing roadmap (2026-10-14)

> Main deliverable of the 2026-10-14 consolidation run. Companions:
> `docs/2026-10-14-fips-core-overlap-and-direction.md` (status),
> `docs/2026-10-14-strategy-library-north-star.md` (library strategy, M1–M8).
> State changes incorporated: the Amperstrand fips fork line is ARCHIVED
> (`archive/fork-main-2026-10-14`, full FORK.md ledger inside); the active
> daemon line is **`amperstrand/lab-ble`** = pure upstream `d208a9db`
> (0.6.0-dev, ⊇ v0.5.2) + the BLE learned-address-type dial fix
> (`70eea3c2`, 208/208 BLE tests green). Positioning: **Amperstrand is a
> fips user** (testing/research, BLE + microcontrollers), not a fork
> maintainer. Bench source of truth: **conwrt-bench** (`/home/ubuntu/src/
> conwrt-bench`, Amperstrand/conwrt) — `data/lab.yaml` device inventory,
> `labgrid/` conventions, `runs/`+`captures/` artifact layout,
> `docs/fieldlab*.md`, `roles/fips-gateway`. We must not drift from it.

Guiding rule (unchanged, from the Bench Testing Playbook): every
interactive finding graduates into a fips-lab scenario the same session;
presence signatures for everything we assert; artifacts captured once and
analyzed from files.

## P1 — Bench bring-up per conwrt-bench conventions

Re-establish a green bench after the restructure, using the conwrt
conventions verbatim.

- Coordinator `ai-legion:20408` (per the microfips/fips-lab consolidation),
  `labgrid-exporter-microfips` systemd unit on the exporter host,
  `make hil-status` (coordinator resources + bench flock + board places +
  role ledger) and `make hil-preflight` green.
- **Gated on fips-lab#11**: conwrt `lab.yaml` still records a
  two-coordinator reality (routers on `ai-legion:20408`, embedded estate
  de-facto on `ai-legion-small:20408`) with a pending MERGE PLAN — the
  consolidation must be reconciled with the registry, not against it.
- **Exit criteria**: `hil-preflight` + `hil-status` green on the decided
  coordinator; every boards.toml board resolves to a live place; drift
  items fips-lab#12 (fips-esp32-d0wd observe-only entry, walter-1/2
  reconciliation) closed with a conwrt registry commit where required.

## P2 — Interop re-verification vs a lab-ble daemon (re-proves the BLE fix)

The bench daemon is rebuilt **from `amperstrand/lab-ble` in a worktree**
(never `/home/ubuntu/src/fips`, whose target/ now serves the archived
fork-era system build — fips-lab#13). lab-ble = upstream `d208a9db` + the
BLE dial fix, so this run simultaneously:

- re-verifies the whole 9-scenario fips-lab suite against a current
  daemon (the IK wire is unchanged through 0.6.0-dev: `FMP_VERSION 0`,
  MSG1 114/69 B — asserts stay identical), and
- **re-proves on hardware that the lab-ble BLE dial fix (`70eea3c2`) dials
  the ESP32s** — the atom L2CAP scenario (`test_l2cap_bringup`) exercises
  exactly the LeRandom-dial path the fix repairs.

**Exit criteria**: all 9 scenarios green ×2 consecutive runs against the
lab-ble daemon; `fipsctl show peers` lists every leaf; daemon git SHA
recorded in the run artifacts; zero `bad prefix`/timeout artifacts.

## P3 — Decryption instrumentation (captures → plaintext, offline)

Goal: every bench capture is decryptable offline from the run's own
artifacts.

- **Keylog patch, env-gated, stacked on lab-ble** as a clearly-labeled
  LAB-ONLY commit (WireGuard SSLKEYLOGFILE-style file: handshake
  handshake-static + traffic secrets per session index). Never enabled by
  default; documented in the lab-ble line so rebases keep it separable.
- Why it matters: registry identities are deterministic
  (generator×N ⇒ statics are free), but **per-run seeded scenario
  identities (the #208 policy) have non-derivable statics** — the keylog
  file is what makes THEIR captures decryptable.
- Capture paths: BLE legs via `btmon -w` on hci0, WiFi/UDP legs via
  `tcpdump -i <ap-if> udp port 2121 -w`; offline decryptor = the existing
  `fips-decrypt` crate + `docs/ble-capture-decrypt.md` flow, extended to
  consume the keylog format.
- **Exit criteria**: one full L2CAP session decrypted end-to-end (msg1 →
  rekey → data frames) purely from `<run>/pcap + <run>/keylog`; one UDP
  session likewise; the decryptor runs as a fips-lab check on captured
  fixtures.

## P4 — Hypothesis-testing workflow (scenario per hypothesis)

- Every new behavioral hypothesis lands as a fips-lab pytest scenario in
  the session that forms it (graduation principle); absence-signature and
  presence-signature assertions derived from the emitting firmware code,
  never guessed strings or sizes.
- Golden/cross vectors stay the wire invariant: microfips is generator of
  record (defs-mvp), weekly drift gate + specquotes pins keep watching.
- New guards get a RED-proof against the pre-fix state before they count.
- **Exit criteria (standing)**: `pytest --collect-only` clean; every
  scenario in `tests/` maps to a closed issue or hypothesis note; no
  untracked interactive findings at session end.

## P5 — Performance + recordings (benchmarks, soaks, artifact discipline)

- **Echo RTT / throughput benchmarks**: FSP PING/PONG round-trips per
  transport (L2CAP, WiFi, ESP-NOW, relay-AP chain), MMP-reported RTT/loss/
  jitter from the daemon side; BLE legs include the sk_rcvbuf sysctl sweep
  (host-side experiment; folds Amperstrand/fips#107 — code work only if
  host tuning proves insufficient).
- **Soaks**: `scripts/test_ble_overnight.sh` + `scripts/overnight_monitor.py`
  for overnight BLE legs; the nightly soak timer keeps covering the slow
  set; results report into fips-lab #7 on failure.
- **Artifact layout (conwrt runs/ convention)**:
  `runs/<YYYY-MM-DD>-<label>/{pcap,keylog,stats,serial,SHAs}` — one dated
  dir per run; `SHAs` records daemon + firmware git hashes; nothing lives
  only in a terminal scrollback.
- **Exit criteria**: one complete artifact set per benchmark/soak run;
  stats in a form the benchmark dashboard can consume; at least one
  overnight BLE soak green against the lab-ble daemon.

## P6 — Post-felix-merge: ESP32-C3 joins HIL

- After the felix merge (microfips#218): C3 (riscv32imc) becomes a
  buildable target (portable-atomic CAS cfg + racy log install); add a
  `hil-smoke` c3 leg (build + boot + USB-JTAG log visible) — no protocol
  scenario until a C3 board is on the bench (microfips#150 closed pending
  hardware).
- C3 is also the first fips-core-canary-class target (riscv family is the
  one upstream CI proves; imc-vs-imac nuance recorded in microfips#219).
- **Exit criteria**: c3 smoke leg green ×2 on real hardware; CI build
  matrix covers riscv32imc alongside xtensa.

## P7 — Strategic dogfooding: FIPS as the conwrt fieldlab management plane

- conwrt `docs/fieldlab.md` plans the escalation: "SSH (today) / FIPS mesh
  (future)" — allowlisted node identities, gated root SSH over a FIPS mesh
  (`docs/fieldlab-roadmap.md`). Our microcontrollers + daemons are the
  natural first mesh population; dogfooding FIPS for lab management is the
  strongest possible interop test.
- Router leg: `roles/fips-gateway` (conwrt-bench) deploys fips-gateway on
  OpenWrt; the mipsel line (`feature/mipsel-support-rebased`, kept per the
  FORK.md ledger as novelty upstream lacks) is the packaging prerequisite;
  router-BLE bringup (CSR8811/BCSP, Amperstrand/fips#86) is the
  radio-side follow-on.
- **Exit criteria**: one OpenWrt router runs a fips-gateway package built
  from the mipsel line and peers with the lab daemon; a fieldlab
  FIPS-transport design note (allowlist, key distribution, failure modes)
  drafted against conwrt docs.

## Standing blockers (2026-10-14)

| Blocker | Where | Owner action |
|---|---|---|
| felix merge (M1) | microfips#218 | run the recorded merge commands |
| fips `master` mirror broken (cc4d7081 gitleaks commit; can never fast-forward) | Amperstrand/fips FORK.md | lift protection + reset to upstream/master, or accept mirror+gitleaks |
| Two-coordinator merge plan | fips-lab#11 + conwrt lab.yaml | pick one, regenerate exporters, conwrt registry commit |
| C3 board availability | microfips#150 (closed pending hw) | acquire board |
| VPS credentials (orangeclaw silent since 2026-09-02) | microfips#190 | restore creds or retire the VPS leg |
| HIL pattern adoption (bolty-rs) | microfips#191 | continue tools/hil + fips-lab convergence |
