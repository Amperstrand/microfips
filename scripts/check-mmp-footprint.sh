#!/usr/bin/env bash
# #234 footprint canary: the facade's mmp opt-in must be the only path
# that puts the protocol's mmp layer into a facade consumer's graph.
#
# Three assertions, all at cargo's feature-RESOLUTION level (compile
# happens for real in CI's build jobs; this script catches graph leaks
# deterministically). Format note: `cargo tree -e features` alone does
# not annotate workspace-member feature edges reliably — `{p} {f}` does
# (observed 2026-10-16: --features mmp resolved mmp onto the protocol
# node while the default tree output showed nothing).
#
# 1. mmp-OFF  (microfips-client --no-default-features): the
#    microfips-protocol node carries NO mmp feature.
# 2. mmp-ON   (microfips-client --features mmp): it DOES.
# 3. Firmware invariance: microfips-esp-transport's protocol node still
#    carries mmp via its direct edge (defaults unchanged) — the leak fix
#    must not change firmware feature sets (cmp-identical parity).
#
# Usage: bash scripts/check-mmp-footprint.sh   (exit 0 = graph is honest)
set -u

cd "$(dirname "$0")/.." || exit 2
fails=0
ok() { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }

# The protocol node's feature list in the CLIENT graph, dev-deps
# excluded (the client's self dev-dep unifies std in for tests only).
# Tree lines are indented (the protocol is never the root), so the
# feature list is whatever follows the path paren on the protocol's
# line — an empty remainder means "default only, no mmp".
client_protocol_features() {
    (cd crates/microfips-client && \
        cargo tree "$@" -e normal -f "{p} {f}" 2>/dev/null | \
        grep "microfips-protocol v.*crates/microfips-protocol)" | \
        head -1 | sed 's/.*crates\/microfips-protocol) //')
}

off="$(client_protocol_features --no-default-features)"
on="$(client_protocol_features --features mmp)"

case "$off" in
    *mmp*) bad "mmp-OFF still carries mmp on the protocol edge: '$off' — the #234 leak is back" ;;
    *) ok "mmp-OFF excludes mmp from the client graph (protocol features: '$off')" ;;
esac

case "$on" in
    *mmp*) ok "mmp-ON activates the protocol's mmp layer (features: '$on')" ;;
    *) bad "mmp-ON does NOT reach the protocol (features: '$on') — the opt-in is broken" ;;
esac

fw="$(cargo tree -p microfips-esp-transport -e normal -f "{p} {f}" 2>/dev/null \
    | grep "microfips-protocol v.*crates/microfips-protocol)" \
    | head -1 | sed 's/.*crates\/microfips-protocol) //')"
case "$fw" in
    *mmp*) ok "firmware edge unchanged: esp-transport's protocol still carries mmp ('$fw')" ;;
    *) bad "firmware feature set changed (protocol features: '$fw') — cmp-identical will DIFF" ;;
esac

exit $((fails > 0))
