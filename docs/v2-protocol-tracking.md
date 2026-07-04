# FIPS v2 Protocol Change Tracking

> Created: 2026-07-04 | Owner: microFIPS | Status: LIVING DOCUMENT
> Branch context: `feat/noise-xx-handshake`

## Purpose

This is a living document that tracks announced and anticipated changes in the
upstream FIPS v2 wire protocol and records microFIPS readiness for each. It is
the single source of truth for "what is changing in v2 and where do we stand."

Upstream has stated that v2 protocols are in active development and that
**detailed v2 protocol specs will be published** to enable independent
interoperability. Until those specs land, this document tracks changes
inferentially from maintainer statements and from the direction implied by
the v1→v2 migrations already in flight.

**Related docs:**
- `docs/strategy-and-upstream.md` — overall upstream relationship & posture
- `docs/fips-microfips-parity.md` — module-by-module v1 parity baseline
  (note: parity baseline was audited against upstream `FMP_VERSION=0` /
  Noise IK + XK; the deltas below are layered on top of that baseline)
- `docs/madeira-discussion-prep.md` — upcoming in-person maintainer meetup

## Status Legend

| Marker | Meaning |
|--------|---------|
| ✅ DONE | Implemented on a merged or feature branch, interop-validated |
| 🟡 ON BRANCH | Implemented on `feat/noise-xx-handshake`, not yet merged / not yet spec-confirmed |
| 🔵 PLANNED | Understood, not yet started, blocked on spec or sequencing |
| ⚪ WAITING | No action possible until upstream publishes the spec |
| ❌ N/A | Will not apply to microFIPS (leaf-only scope) |

## Known v2 Protocol Changes

| # | Change | v1 (current) | v2 (target) | Source | microFIPS Status | Notes |
|---|--------|--------------|-------------|--------|------------------|-------|
| 1 | **Link handshake pattern** | Noise `IK` | Noise `XX` | Maintainer direction; both-static-keys-exchanged interactively | 🟡 ON BRANCH | `c3e875d` migrates `Node` link handshake IK→XX. Awaiting spec to confirm message layout & static-key encryption flags. |
| 2 | **Session handshake pattern** | Noise `XK` (3-message) | Noise `XX` | Inferred from v2 direction | 🔵 PLANNED | FSP layer still uses `XK_HANDSHAKE_MSG{1,2,3}` (sizes 33/57/73). Will migrate once link XX is validated and session spec drops. |
| 3 | **FMP wire format version** | `FMP_VERSION = 0` | `FMP_VERSION = 1` | `b6bfc9d`; `wire.rs:17` now `1` | 🟡 ON BRANCH | Byte-0 version nibble bumped `0x0_ → 0x1_`. Parse path rejects mismatched versions. Parity audit doc still reflects v0 baseline. |
| 4 | **Version negotiation** | none (implicit v0) | explicit on-wire | Anticipated v2 requirement | ⚪ WAITING | No spec yet. microFIPS will adopt the published negotiation fields verbatim; do not invent a local scheme. |
| 5 | **Profile negotiation** | none | anticipated (leaf / router / etc.) | Anticipated v2 requirement | ⚪ WAITING | No spec yet. microFIPS will advertise a leaf-only profile; exact encoding TBD. |

### Notes on each change

**1. Link handshake IK → XX.** Upstream indicated XX is the v2 direction
(both static keys exchanged interactively, removing the initiator-must-know-
responder-static assumption). microFIPS implemented XX for the link layer on
`feat/noise-xx-handshake`. **Open risk:** until the spec publishes, our XX
message framing is a best-effort match; an upstream wire-format delta would
force a rework. Decision needed on whether to keep an IK fallback path during
the v1↔v2 transition window (see Decision Points).

**2. Session handshake XK → XX.** The session (FSP) layer still uses the
3-message XK pattern. Migration is planned but deliberately sequenced *after*
the link-layer XX change is validated, to avoid changing two handshakes
simultaneously and complicating interop debugging.

**3. FMP wire format v0 → v1.** The version nibble in the common prefix byte
was bumped and the parse path enforces it. This is the smallest of the v2
changes but the most visible on the wire — a v0 node and a v1 node will now
refuse each other's frames at the version check. The parity audit document
(`docs/fips-microfips-parity.md`) was written against the v0 baseline and will
need a refresh once v1 is merged.

**4–5. Version & Profile negotiation.** Pure speculation until specs land.
No code should be written against these yet.

## Spec Publication Watch

> **Status: EMPTY — no v2 specs published yet.**
>
> Upstream has committed to writing detailed v2 protocol specs to enable
> independent interoperability. None have been published as of 2026-07-04.

When a spec lands, add an entry here:

| Spec | Published | Repo / URL | microFIPS Tracking Issue | Status |
|------|-----------|------------|--------------------------|--------|
| _(none yet)_ | — | — | — | — |

Template for a new entry:

```
| FIPS-v2-link-handshake | YYYY-MM-DD | <url> | #N | reading / implementing / done |
```

Watch points:
- Upstream FIPS repository (reference only, do not send PRs against v2 work)
- Maintainer announcements (Signal group: microFIPS-esp32)
- In-person sync at the Madeira meetup (see `docs/madeira-discussion-prep.md`)

## Decision Points

Open decisions that must be resolved before / during v2 adoption. Each should
become a tracking issue when activated.

### DP-1: Keep an IK / v0 fallback path during transition?

- **Context:** FMP v1 + link XX will not interop with v0/IK nodes. If upstream
  runs a mixed fleet during rollout, microFIPS leaf nodes may need to speak
  both.
- **Options:** (a) hard cutover, drop v0; (b) feature-flagged dual stack;
  (c) negotiation-driven selection (depends on DP-4 spec).
- **Default:** hard cutover on `feat/noise-xx-handshake` merge; revisit if
  upstream signals a long transition window.
- **Owner:** microFIPS | **Blocked on:** Madeira meetup answer on v2 timeline.

### DP-2: Land `feat/noise-xx-handshake` before or after spec publication?

- **Context:** Branch implements XX + FMP v1 inferentially. Landing now gives
  us early validation; landing after spec avoids rework if our guess is wrong.
- **Default:** hold merge until spec confirms wire format; keep branch as the
  reference implementation and interop testbed.
- **Owner:** microFIPS | **Blocked on:** spec publication (Spec Watch).

### DP-3: Sequence session XK→XX relative to link XX.

- **Context:** Changing both handshakes at once doubles interop debug surface.
- **Default:** link XX first (already on branch), validate end-to-end, *then*
  session XK→XX as a separate change with its own audit.
- **Owner:** microFIPS.

### DP-4: Version negotiation wire format.

- **Context:** No spec. microFIPS must NOT invent a local scheme.
- **Default:** no action until spec; implement verbatim when published.
- **Owner:** microFIPS | **Blocked on:** spec publication.

### DP-5: Profile negotiation — which profiles does microFIPS advertise?

- **Context:** microFIPS is leaf-only (no mesh/tree/filter/TUN). If v2
  introduces profiles, microFIPS should advertise exactly one leaf profile.
- **Default:** defer; advertise leaf-only once profile enum is specified.
- **Owner:** microFIPS | **Blocked on:** spec publication.

### DP-6: Parity audit refresh.

- **Context:** `docs/fips-microfips-parity.md` reflects the v0/IK/XK baseline.
  After v1/XX lands, the FMP version row and the noise handshake rows go stale.
- **Default:** refresh the parity doc as part of the merge that closes DP-2.
- **Owner:** microFIPS.

## How to Maintain This Document

1. When upstream announces a v2 change, add a row to **Known v2 Protocol
   Changes** with status ⚪ WAITING or 🔵 PLANNED.
2. When a spec publishes, add a row to **Spec Publication Watch** and unblock
   any DP whose status depended on it.
3. When microFIPS starts / completes work on a change, advance the status
   marker (🔵 → 🟡 → ✅).
4. When a Decision Point is resolved, record the resolution inline and mark
   the DP closed.
5. Keep dates in `YYYY-MM-DD` form. Cite commit hashes for code changes.
