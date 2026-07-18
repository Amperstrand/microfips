#!/usr/bin/env bash
set -euo pipefail

# Sim-to-FIPS handshake test — validates the full FIPS protocol stack
# (Noise IK → FMP → FSP → MMP → heartbeats) without any hardware.
#
# Requirements:
#   - FIPS daemon running on localhost with UDP transport (port 2121)
#   - microfips-sim binary built (cargo build -p microfips-sim --release)
#
# Usage:
#   bash scripts/test_sim_handshake.sh [duration_secs]
#
# Output:
#   Exit 0 = PASS (handshake completed + heartbeats exchanged)
#   Exit 1 = FAIL
#   Exit 2 = ERROR (prerequisites not met)

DURATION="${1:-15}"
SIM_BIN="$(cd "$(dirname "$0")/.." && pwd)/target/release/microfips-sim"
FIPS_PUB_FILE="/etc/fips/fips.pub"
LOG_FILE="/tmp/sim-handshake-test.log"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
info() { echo -e "${YELLOW}>>>>>${NC} $1"; }
pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; }

# --- Prerequisites ---

if [[ ! -x "$SIM_BIN" ]]; then
    info "Building microfips-sim..."
    cd "$(dirname "$0")/.."
    cargo build -p microfips-sim --release || { fail "Build failed"; exit 2; }
fi

if ! sudo fipsctl show status >/dev/null 2>&1; then
    fail "FIPS daemon not running (fipsctl not responding)"
    exit 2
fi

if [[ ! -f "$FIPS_PUB_FILE" ]]; then
    fail "FIPS pubkey file not found at $FIPS_PUB_FILE"
    exit 2
fi

# --- Decode npub to hex ---

NPUB=$(cat "$FIPS_PUB_FILE" | tr -d '\n')
FIPS_PUBKEY=$(python3 -c "
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def bech32_decode(s):
    pos = s.rfind('1')
    data = s[pos+1:]
    decoded = [CHARSET.index(c) for c in data]
    result = bytearray()
    for i in range(0, len(decoded) - 6, 8):
        value = 0
        for j in range(8):
            value = (value << 5) | decoded[i + j]
        result.extend(value.to_bytes(5, 'big'))
    return bytes(result)
raw = bech32_decode('$NPUB')
print(f'02{raw.hex()[:64]}')
" 2>/dev/null) || { fail "Failed to decode npub"; exit 2; }

info "FIPS pubkey: $FIPS_PUBKEY"
info "Starting sim handshake test (${DURATION}s)..."

# --- Run handshake ---

FIPS_PEER_NPUB="$FIPS_PUBKEY" \
RUST_LOG=info \
timeout "$((DURATION + 5))" \
"$SIM_BIN" --udp 127.0.0.1:2121 --sim-a > "$LOG_FILE" 2>&1 || true

# --- Verify results ---

PASS_COUNT=0
FAIL_COUNT=0

check() {
    if grep -q "$1" "$LOG_FILE"; then
        pass "$2"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        fail "$2"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

check "MSG1 sent" "Noise IK MSG1 sent"
check "RX 69B phase=0x2" "Noise IK MSG2 received"
check "handshake complete" "FSP handshake completed"
check "phase=0x0 msg=0x0" "Heartbeat exchange started"

HEARTBEAT_COUNT=$(grep -c "phase=0x0" "$LOG_FILE" || echo 0)
if [[ "$HEARTBEAT_COUNT" -gt 5 ]]; then
    pass "Sustained heartbeats ($HEARTBEAT_COUNT frames)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    fail "Insufficient heartbeats ($HEARTBEAT_COUNT frames, expected >5)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# --- Check FIPS sees the peer ---

PEERS=$(sudo fipsctl show peers 2>/dev/null)
if echo "$PEERS" | grep -q "npub1lycg"; then
    pass "FIPS registered SIM-A as authenticated peer"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    fail "FIPS did not register SIM-A"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

CONNECTIVITY=$(echo "$PEERS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['peers'][0]['connectivity'] if d['peers'] else 'none')" 2>/dev/null || echo "unknown")
if [[ "$CONNECTIVITY" == "connected" ]]; then
    pass "Peer connectivity: connected"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    fail "Peer connectivity: $CONNECTIVITY (expected: connected)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
info "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "Log: $LOG_FILE"

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}SOME TESTS FAILED${NC}"
    exit 1
fi
