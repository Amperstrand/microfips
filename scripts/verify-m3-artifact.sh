#!/bin/bash
# cmp-identical artifact verification for the M3 library split (#220).
#
# Builds the same firmware binary from two refs (baseline vs candidate)
# with identical env knobs and toolchain settings, then byte-compares
# the artifacts. "Never reason about build equality — cmp it" (#113).
#
# Usage: ./scripts/verify-m3-artifact.sh <baseline_ref> <candidate_ref>
# Exit 0 = identical; exit 1 = differ; exit 2 = build failure.

set -euo pipefail

BASELINE_REF="${1:?usage: $0 <baseline_ref> <candidate_ref>}"
CANDIDATE_REF="${2:?usage: $0 <baseline_ref> <candidate_ref>}"
TARGET="xtensa-esp32-none-elf"
BIN="microfips-esp32-wifi"
FEATURES="wifi"
OUTDIR="/tmp/m3-artifact-check"

# Identical env knobs for both builds (deterministic, from the registry's
# public test identities — no secrets).
export DEVICE_NPUB_HEX_vps="020e7a0da01a255cde106a202ef4f573676ef9e24f1c8176d03ae83a2a3a037d21"
export DEVICE_NSEC_HEX_esp32="0000000000000000000000000000000000000000000000000000000000000002"
export DEVICE_NPUB_HEX_esp32="02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
export DEVICE_NODE_ADDR_esp32="0135da2f8acf7b9e3090939432e47684"
export WIFI_SSID="cmp-test"
export WIFI_PASSWORD="cmp-test-pass"

mkdir -p "$OUTDIR"

build_ref() {
    local ref="$1" output="$2"
    echo "  building $BIN from $ref..."
    git checkout --quiet "$ref"
    # Clean only the firmware crate to force a rebuild while reusing
    # dependency artifacts (fast enough for CI, deterministic for cmp).
    cargo clean -p microfips-esp32 --release --target "$TARGET" 2>/dev/null || true
    . /home/ubuntu/export-esp.sh
    RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 \
        --release --target "$TARGET" \
        -Zbuild-std=core,alloc \
        --features "$FEATURES" --bin "$BIN" 2>&1 | tail -1
    cp "/home/ubuntu/.cargo-target/$TARGET/release/$BIN" "$output"
    sha256sum "$output"
}

echo "=== M3 artifact verification ==="
echo "  baseline: $BASELINE_REF"
echo "  candidate: $CANDIDATE_REF"
echo "  target: $TARGET"
echo "  binary: $BIN (features: $FEATURES)"
echo ""

build_ref "$BASELINE_REF" "$OUTDIR/baseline.bin"
BASELINE_SHA=$(sha256sum "$OUTDIR/baseline.bin" | awk '{print $1}')

build_ref "$CANDIDATE_REF" "$OUTDIR/candidate.bin"
CANDIDATE_SHA=$(sha256sum "$OUTDIR/candidate.bin" | awk '{print $1}')

echo ""
echo "  baseline  sha256: $BASELINE_SHA"
echo "  candidate sha256: $CANDIDATE_SHA"

if cmp --silent "$OUTDIR/baseline.bin" "$OUTDIR/candidate.bin"; then
    echo "  RESULT: IDENTICAL ✓"
    exit 0
else
    echo "  RESULT: DIFFER ✗"
    exit 1
fi
