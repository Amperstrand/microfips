<!--
Published status header — microFIPS interop plan, Task D (M1).

- Audit date:       2026-06-29
- FIPS baseline:    jmcorgan/fips @ 30c5808 (0.5.0-dev)
- microFIPS baseline: b6bfc9d
- Provenance:       Copied verbatim from the read-only worktree audit at
                    worktrees/feature-microfips-compat-audit/docs/fips-microfips-compat.md
                    (original Status/Audited-by/Date block preserved below).
-->

# FIPS ↔ microfips Wire-Protocol Compatibility Audit

**Status:** Read-only source analysis (M1)
**Audited by:** kanban worker `fips-feature-three-node-ota-antenna-vali`
**Date:** 2026-06-29

---

## TL;DR — Verdict

**No. microfips and FIPS do NOT speak a mutually-compatible wire protocol at
the audited revisions. They cannot interoperate on the wire today.**

The single, decisive incompatibility is the **FMP version nibble**: microfips
bumped `FMP_VERSION` from `0` → `1` and migrated its framing to Noise **XX**,
while FIPS remains on `FMP_VERSION = 0` with Noise **IK/XK** and **hard-rejects
every frame whose version nibble is not 0** at the very first prefix parse.
FIPS additionally has **no Noise XX implementation at all**, so even if the
version nibble were ignored the two sides could not complete a handshake.

Beneath that gate, the two implementations were clearly **designed to be
compatible** — the established-phase message-type namespace, the crypto
identity derivation (`NodeAddr`/`FipsAddress`), and the MMP report format are
**byte-identical**. microfips even auto-generates a snapshot of FIPS's wire
constants (`generated/fips_compat.rs`) to stay aligned on those layers. The
divergence is concentrated entirely in the **link handshake + version field**.

A secondary finding: microfips HEAD is an **incomplete / half-finished
migration** ("migrate FMP wire format to v1 (Noise XX)") — the framing layer
was bumped to v1/XX sizes but the **live handshake driver still runs the IK
pattern**, and only test helpers were actually moved to XX. This is documented
in §7 and is relevant to any remediation plan.

---

## 1. Baselines audited

| Item | Revision | Path |
|---|---|---|
| FIPS (`jmcorgan/fips`) | `30c5808` "Merge maint into master after the v0.4.0 rollover", crate `0.5.0-dev` | `~/repos/fips/` |
| microfips (`Amperstrand/microfips`) | `b6bfc9d` "feat(core): migrate FMP wire format to v1 (Noise XX)" — **single squashed commit** | `~/repos/microfips/` |

> microfips ships its own self-assessment at `docs/fips-microfips-parity.md`.
> **That document is stale:** it describes the *pre*-migration state
> (`FMP_VERSION=0`, IK/XK, `MSG1_WIRE=114`). The current HEAD has diverged from
> what that doc claims. Every claim in this audit was verified against source,
> not against microfips's parity doc.

---

## 2. Do they use the same wire protocol?

**No.** Evidence, layer by layer:

### 2.1 Common prefix / FMP version — INCOMPATIBLE (decisive)

The first byte of every FMP frame carries `(version << 4) | phase`.

| | FIPS | microfips (HEAD) |
|---|---|---|
| `FMP_VERSION` | **`0`** (`src/node/wire.rs:28`) | **`1`** (`crates/microfips-core/src/wire.rs:17`) |

FIPS enforces this strictly with no negotiation. Every entry-point parser
rejects `version != FMP_VERSION`:

```
src/node/wire.rs:159   if version != FMP_VERSION || phase != PHASE_ESTABLISHED { ... None }
src/node/wire.rs:224   if version != FMP_VERSION || phase != PHASE_MSG1       { ... None }
src/node/wire.rs:280   if version != FMP_VERSION || phase != PHASE_MSG2       { ... None }
```

…and there is an explicit regression test proving version 1 is dropped:

```
src/node/wire.rs:466   fn test_encrypted_header_wrong_version() {
src/node/wire.rs:469       packet[0] = 0x10; // version 1, phase 0
src/node/wire.rs:470       assert!(EncryptedHeader::parse(&packet).is_none());   // rejected
```

**Conclusion:** every microfips frame (version nibble = 1) is discarded by a
FIPS node before any payload is examined. This alone makes interop impossible.

### 2.2 Link handshake — INCOMPATIBLE (Noise IK/XK vs Noise XX)

| | FIPS | microfips (HEAD) |
|---|---|---|
| Patterns implemented | **IK** + **XK** (`PROTOCOL_NAME_IK`, `PROTOCOL_NAME_XK`, `src/noise/mod.rs:52,56`) | IK + XK + **XX** (`PROTOCOL_NAME`, `PROTOCOL_NAME_XK`, `PROTOCOL_NAME_XX`, `noise.rs:110,112,116`) — but the **framing layer is wired to XX** (`HANDSHAKE_MSG*_SIZE = noise::XX_*`, `wire.rs:25-27`) |
| Handshake messages on wire | 2 (IK: msg1, msg2) | **3** (XX: msg1, msg2, msg3; `PHASE_MSG3 = 0x03`, `wire.rs:37`) |
| Noise payload sizes | IK msg1 = **106 B**, msg2 = **57 B** (`noise/mod.rs:74,77`); XK 33/57/73 | XX msg1 = **33 B**, msg2 = **106 B**, msg3 = **73 B** (`noise.rs:119,122,125`) |
| Full wire msg sizes | `MSG1_WIRE_SIZE = 114`, `MSG2_WIRE_SIZE = 69` (`wire.rs:46,49`) | `MSG1_WIRE_SIZE = 41`, `MSG2_WIRE_SIZE = 118`, `MSG3_WIRE_SIZE = 85` (`wire.rs:30-32`, reconciles with the commit msg) |
| `FLAG_SP` | present (`0x04`, `wire.rs:67`) | **removed** by the v1 migration |

Size derivation (sanity-checked against both sources):
- FIPS IK: `33+33+16+24 = 106` (msg1), `33+24 = 57` (msg2); wire `4+4+106 = 114`, `4+4+4+57 = 69`.
- microfips XX: `33` (msg1), `33+(33+16)+(8+16) = 106` (msg2), `(33+16)+(8+16) = 73` (msg3); wire `4+4+33 = 41`, `4+8+106 = 118`, `4+8+73 = 85`.

Even setting the version nibble aside, FIPS has **no XX code path** and a FIPS
responder expects a 106-byte IK msg1, not a 33-byte XX msg1 (and only two
messages, not three). The handshakes cannot complete.

### 2.3 Established-phase framing & message types — COMPATIBLE (but gated out)

Once a link is established, the inner message-type byte namespace is identical
because microfips imports it from an auto-generated snapshot of FIPS:

| Message | FIPS byte (`src/protocol/link.rs`) | microfips (`generated/fips_compat.rs`) |
|---|---|---|
| `SessionDatagram` | `0x00` | `LINK_MSG_SESSION_DATAGRAM = 0x00` |
| `SenderReport` | `0x01` | `LINK_MSG_SENDER_REPORT = 0x01` |
| `ReceiverReport` | `0x02` | `LINK_MSG_RECEIVER_REPORT = 0x02` |
| `TreeAnnounce` | `0x10` | `LINK_MSG_TREE_ANNOUNCE = 0x10` |
| `FilterAnnounce` | `0x20` | `LINK_MSG_FILTER_ANNOUNCE = 0x20` |
| `LookupRequest` / `LookupResponse` | `0x30` / `0x31` | `0x30` / `0x31` |
| `Disconnect` | `0x50` | `LINK_MSG_DISCONNECT = 0x50` |
| `Heartbeat` | `0x51` | `LINK_MSG_HEARTBEAT = 0x51` |

Established-frame layout also matches (`ESTABLISHED_HEADER_SIZE = 16`,
`INNER_HEADER_SIZE = 5` (4-byte LE timestamp + msg type), `ENCRYPTED_MIN_SIZE = 32`, AEAD `TAG_SIZE = 16`). The disconnect-reason enum (`DISC_REASON_*`)
is byte-identical.

> microfips intentionally tracks FIPS's non-handshake wire surface via
> `tools/generate_fips_compat.py`, which regenerates `generated/fips_compat.rs`
> from a FIPS checkout. This is a deliberate conformance mechanism — strong
> evidence that the data-plane was meant to stay interoperable even as the
> handshake was changed.
>
> Caveat: established frames still carry the version nibble in their common
> prefix, so FIPS would reject them too. The alignment is "designed-compatible,
> currently unreachable."

### 2.4 Crypto identity — COMPATIBLE (byte-identical)

| Derivation | FIPS | microfips |
|---|---|---|
| `NodeAddr` from x-only pubkey | `SHA256(x_only)[..16]` (`src/identity/node_addr.rs:36-41`) | `SHA256(x_only)[..16]` (`identity.rs:18-23`) |
| `FipsAddress` from `NodeAddr` | `0xFD` prefix + `node_addr[..15]` (`src/identity/address.rs:38`, `FIPS_ADDRESS_PREFIX = 0xfd`, `identity/mod.rs:25`) | `0xFD` + `node_addr[..15]` (`identity.rs:37-42`) |

Two nodes derived with the same x-only key produce the same `NodeAddr` and
`FipsAddress` in both implementations. The x-only-ECDH + SHA256 normalization
used in Noise DH is also shared (`x_only_ecdh` / `parity_normalize` in
microfips mirror FIPS internals — deviation notes D1–D3 in microfips's parity
doc are FIPS behaviors reproduced faithfully).

### 2.5 MMP (mesh measurement) — COMPATIBLE format

Both share the same MMP sender/receiver report wire format and core algorithms
(FIPS `src/mmp/*`; microfips `microfips-core/src/mmp/*` +
`microfips-protocol/src/mmp/*`). Reduced extras in microfips (session/path-MTU
fields) but the on-wire report bytes match.

### 2.6 What FIPS has that microfips omits entirely (out of wire scope)

microfips is a **leaf-only** runtime. It intentionally has no: mesh spanning
tree (`src/tree/*`), bloom-filter routing (`src/bloom/*`), discovery (`src/discovery/*` — LAN mDNS + Nostr traversal), TUN gateway / upper-layer
stack (`src/upper/*`, `src/gateway/*`), ACL/firewall, or the peer/router
subsystems. A microfips node cannot *route* in a FIPS mesh even if the link
layer were fixed — it can only be a **leaf** attached to a FIPS router.

---

## 3. What differs (beyond the wire)

| Dimension | FIPS | microfips |
|---|---|---|
| Target | std servers / desktops / routers | embedded MCUs (ESP32, ESP32-S3, STM32) + host sim |
| `std` vs `no_std` | std-only | `no_std` core (`microfips-core`, `-protocol`) with an optional `std` feature |
| Async runtime | **tokio** (`Cargo.toml`: `tokio = { features = ["rt","macros","net","time",...] }`) + `crossbeam-channel` | **embassy** (`embassy-executor`, `embassy-time`, `embassy-futures`, `embassy-sync`) |
| Crypto backend | `secp256k1` (libsecp256k1 C FFI) + `ring` (AEAD) | pure-Rust no_std implementations (`k256` in tests); hand-rolled ChaChaPoly/SHA256/HKDF to avoid C deps on MCU |
| Memory model | heap (`Vec`, `HashMap`, channels) | `heapless` fixed-size buffers, `static_cell` |
| Feature flags | monolithic binary | cargo features: `std`, `log`, `mmp`, `benchmark` |
| Transport | concrete: UDP, TCP, Ethernet (raw), BLE, Tor, Nym, loopback | a narrow async `Transport` trait (`send`/`recv`/`wait_ready` returning `impl Future`) + concrete UART/USB-CDC/BLE/WiFi/L2CAP for MCUs; serial bridge uses `[2-byte LE len][payload]` framing above FMP |
| Scope | full mesh node (routing, discovery, gateway, TUN) | leaf node only |

Both are async, but on **different and non-interchangeable runtimes** (tokio vs
embassy). Neither can link the other's runtime code; any sharing must happen at
the **algorithm/format** level, not the binary level.

---

## 4. Can microfips nodes join a FIPS mesh today?

**No.** Three independent blockers, any one of which is fatal:

1. **Version gate.** microfips emits `FMP_VERSION = 1`; FIPS rejects
   `version != 0` at every parser (`wire.rs:159/224/280`, test at `:466`).
   Frames are dropped before decryption.
2. **No shared handshake.** microfips framing expects a 3-message Noise XX
   exchange (41/118/85-byte wire messages); FIPS only speaks 2-message IK/XK
   (114/69) and contains **no XX implementation**.
3. **No mesh role.** Even with the link fixed, microfips has no
   tree/bloom/discovery/routing — it cannot act as a router, only a leaf, and a
   leaf still needs a completed FMP link handshake to attach.

A microfips node and a FIPS node cannot establish a single authenticated link.

---

## 5. What would need to change for full compatibility

There are two viable paths. **Path A is strongly recommended** (smaller, lower
risk, restores the documented design intent).

### Path A — microfips reverts the link layer to FIPS v0 / IK (recommended)

This restores the pre-migration state that microfips's *own* parity doc
describes as compatible:

1. Revert `FMP_VERSION` to `0` (`microfips-core/src/wire.rs:17`).
2. Point the handshake sizes back at the IK constants instead of
   `noise::XX_*` (`wire.rs:25-27`), drop `PHASE_MSG3`/`MSG3_*`, restore
   `FLAG_SP`.
3. The **live handshake driver already runs IK**
   (`microfips-protocol/src/node.rs:408` `NoiseIkInitiator`, `:471`
   `NoiseIkResponder`) — so this is mostly a framing-constant revert, not a
   crypto rewrite. (See §7: the half-migration means the driver was never
   actually changed to XX.)
4. Re-enable/refresh the XX→IK test vectors (`fips_compatibility.rs`,
   `fsp_over_fmp.rs`, `pcap_regression.rs` were migrated to XX and 2 PCAP
   tests are `#[ignore]`d).
5. Keep the existing IK/XK code in `noise.rs` (already present) — no new
   crypto work.

After Path A, a microfips leaf can attach to a FIPS router at the link layer.
Full mesh participation still requires implementing tree/bloom/discovery
(§2.6) unless leaf-only attachment is the goal.

### Path B — FIPS adopts Noise XX / FMP v1

1. Add a Noise XX pattern to FIPS (`src/noise/`) and a 3-message handshake
   state machine (`PHASE_MSG3`, `build_msg3`/`Msg3Header`).
2. Accept `FMP_VERSION = 1` (relax the `version != FMP_VERSION` checks; add
   version negotiation or a v1 code path).
3. Coordinate a cutover; keep IK/XK for backward compatibility during
   migration.

microfips's `noise.rs` module doc *claims* this was FIPS's plan: *"Upstream
(0.4.0-dev): The `next` branch switches both link and session layers to Noise
XX."* **That migration never landed in FIPS master** (audited at `0.5.0-dev`,
which is still IK/XK-only). Path B therefore requires new work on the FIPS side
and is out of scope for a read-only audit.

> Recommended follow-up: confirm with the FIPS maintainer whether XX/v1 is still
> the intended direction. If yes → Path B upstream; if no → Path A in microfips.

---

## 6. Which microfips modules are upstreamable to `jmcorgan/fips`?

(All credit to **Amperstrand** — https://github.com/Amperstrand — for the
microfips work. These are candidates identified from structure; recommend a
deeper per-module review before opening upstream PRs.)

| Module | Why it's valuable upstream | Effort / caveat |
|---|---|---|
| **`Transport` async trait** (`microfips-protocol/src/transport.rs`) | A clean, transport-agnostic `send`/`recv`/`wait_ready` future-returning trait. FIPS's transports are concrete and std-bound; this trait would let FIPS support embedded/serial transports uniformly. | Medium — FIPS uses tokio, so the trait would need to bridge `impl Future` ↔ tokio, or FIPS adopts a similar abstraction natively. |
| **Pure-Rust no_std crypto** (`microfips-core/src/noise.rs`) | Hand-rolled ChaCha20-Poly1305 / SHA256 / HKDF / secp256k1 ECDH with no C FFI, enabling FIPS to run on targets where `libsecp256k1`/`ring` can't compile. | High — security-sensitive; needs formal review + test vectors against FIPS's `ring`/`secp256k1` outputs. |
| **ESP32 / ESP32-S3 HAL + transports** (`microfips-esp32`, `microfips-esp32s3`, `microfips-esp-transport`, `microfips-esp-common`) | Entirely new hardware targets (UART, USB-CDC, BLE, WiFi, L2CAP) for FIPS — currently FIPS has no embedded story. | High — depends on the no_std crypto + Transport trait landing first. |
| **`tools/generate_fips_compat.py`** + `generated/fips_compat.rs` | A tool that auto-extracts FIPS wire constants so a second implementation stays byte-aligned. Useful as a **conformance/regression tooling** pattern inside the FIPS repo itself (generate golden vectors from the reference impl). | Low — process/tooling, not runtime. |
| **`tools/fips_dissector.lua`** (Wireshark dissector) + **`crates/fips-decrypt`** | Debugging/observability tooling that FIPS lacks. | Low–Medium. |
| **MMP extras** (path-MTU, session report fields) | microfips's MMP is a superset in places; specific extras may be useful to FIPS's `src/mmp/*`. | Low — format additions, needs spec discussion. |

Non-upstreamable as-is (but informative): the embassy runtime, `heapless`
buffer strategy, and leaf-only `Node` runtime are architecture-specific to
embedded and don't map onto FIPS's tokio/std mesh node.

---

## 7. Finding: microfips HEAD is a half-finished migration

The lone commit `b6bfc9d` "migrate FMP wire format to v1 (Noise XX)" changed
the **framing constants** to v1/XX but did **not** migrate the live handshake
driver:

- The **deployed** runtimes all instantiate `Node::new(...)` —
  `crates/microfips/src/main.rs:206`, `crates/microfips-sim/src/main.rs:575`,
  `crates/microfips-esp-transport/src/runner.rs:46`, `crates/microfips-link/src/main.rs:77`.
- That `Node` performs the handshake with **`NoiseIkInitiator` /
  `NoiseIkResponder` (IK)** — `microfips-protocol/src/node.rs:408` and `:471`.
- Only **test helpers** were moved to XX (`error_injection.rs`,
  `fsp_over_fmp.rs` → `do_xx_handshake`, `fips_compatibility.rs`); the commit
  message itself only lists test files for the IK→XX change, not `node.rs`.

Net effect: a deployed microfips node runs an **IK handshake** but wraps the
frames in a **version-1 / XX-sized** envelope. This is internally inconsistent
and means the "v1" framing is not actually exercised by the production path.
Any remediation (Path A or B) must reconcile `node.rs` with `wire.rs` — under
Path A the driver is already correct and only the framing constants revert;
under Path B the driver must actually be rewritten to XX.

This should be raised with the microfips maintainer (Amperstrand) regardless of
which compatibility path is chosen.

---

## 8. Methodology & limitations

- **Source-only.** This is a read-only audit; no builds or live interop tests
  were run (per task constraints: read-only, do not touch upstream FIPS).
- **Repos read:** `~/repos/fips` (`30c5808`) and `~/repos/microfips`
  (`b6bfc9d`); deliverable written in the worktree on branch
  `feature/microfips-compat-audit`.
- **microfips's own `docs/fips-microfips-parity.md` was treated as a *claim*,
  not a source of truth** — it is stale relative to HEAD and was re-verified
  file-by-file. Where it conflicts with current source, current source wins.
- **`microfips/AGENTS.md` was not consulted** — the loader flagged it for
  potential prompt-injection content. All findings come from `.rs` source and
  non-instruction-shaped docs.
- **Recommended follow-ups (out of scope here):**
  1. `cargo check`/`cargo test` microfips-core + microfips-protocol on host to
     confirm the §7 half-migration compiles/behaves as described.
  2. A live interop test: point a microfips sim node at a FIPS node and observe
     the version-nibble rejection (wire shark / `tools/fips_dissector.lua`).
  3. Confirm with the FIPS maintainer whether Noise XX / FMP v1 is still the
     intended direction (decides Path A vs Path B).

---

## Appendix A — Key evidence (file:line)

FIPS (`~/repos/fips`):
- `src/node/wire.rs:28` — `FMP_VERSION = 0`
- `src/node/wire.rs:46,49` — `MSG1_WIRE_SIZE = 114`, `MSG2_WIRE_SIZE = 69`
- `src/node/wire.rs:67` — `FLAG_SP = 0x04`
- `src/node/wire.rs:159,224,280` — version/phase hard-reject
- `src/node/wire.rs:466-471` — `test_encrypted_header_wrong_version` (rejects `0x10`)
- `src/noise/mod.rs:52,56` — only `PROTOCOL_NAME_IK` / `PROTOCOL_NAME_XK` (no XX)
- `src/noise/mod.rs:74,77` — IK msg sizes 106 / 57
- `src/protocol/link.rs:74-101` — established message-type bytes
- `src/identity/node_addr.rs:36-41`, `src/identity/address.rs:38`, `src/identity/mod.rs:25` — identity derivation

microfips (`~/repos/microfips`):
- `crates/microfips-core/src/wire.rs:17` — `FMP_VERSION = 1`
- `crates/microfips-core/src/wire.rs:25-27,37` — `HANDSHAKE_MSG*_SIZE = noise::XX_*`, `PHASE_MSG3 = 0x03`
- `crates/microfips-core/src/wire.rs:30-32` — `MSG1/2/3_WIRE_SIZE` = 41 / 118 / 85
- `crates/microfips-core/src/noise.rs:110,112,116` — IK / XK / **XX** protocol names
- `crates/microfips-core/src/noise.rs:119,122,125` — XX msg sizes 33 / 106 / 73
- `crates/microfips-core/src/generated/fips_compat.rs` — auto-generated FIPS constant snapshot (proves established-layer + identity alignment intent)
- `crates/microfips-protocol/src/node.rs:408,471` — **live handshake uses IK**, not XX (half-migration)
- `crates/microfips-core/src/identity.rs:18-42` — identity derivation (matches FIPS)
- `crates/microfips-protocol/src/transport.rs:14-20` — no_std async `Transport` trait
