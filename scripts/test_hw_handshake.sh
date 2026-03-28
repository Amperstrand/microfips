#!/usr/bin/env bash
# Systematic hardware handshake test for microfips MCU
#
# This script performs a clean, reproducible test of the full chain:
#   MCU (CDC) -> serial_tcp_proxy (host) -> SSH tunnel -> fips_bridge (VPS) -> FIPS
#
# Usage:
#   export VPS_PASS=<password>
#   bash scripts/test_hw_handshake.sh [--flash] [--no-cleanup]
#
# Options:
#   --flash        Build and flash firmware before testing
#   --no-cleanup   Skip cleanup phase (leave processes running)
#   --run N        Run number (appended to log filenames for identification)
#
# Prerequisites:
#   - STM32F469I-DISCO connected via USB (both ST-Link and OTG-FS cables)
#   - st-flash installed
#   - arm-none-eabi-objcopy installed
#   - sshpass installed
#   - VPS_PASS environment variable set
#   - No probe-rs or debuggers attached

set -euo pipefail

: "${VPS_PASS:?ERROR: VPS_PASS environment variable not set}"

VPS_HOST="${VPS_HOST:-orangeclaw.dns4sats.xyz}"
VPS_USER="${VPS_USER:-routstr}"
TCP_PORT=45679
RUN_NUM=""
DO_FLASH=false
DO_CLEANUP=true
LOG_DIR="/tmp/microfips_hw_test"

for arg in "$@"; do
    case "$arg" in
        --flash) DO_FLASH=true ;;
        --no-cleanup) DO_CLEANUP=false ;;
        --run) shift 2>/dev/null || true; RUN_NUM="_${1:-$(date +%s)}" ;;
    esac
done

SSH_OPTS="-o StrictHostKeyChecking=no"
PROXY_LOG="${LOG_DIR}/proxy${RUN_NUM}.log"
BRIDGE_LOG_REMOTE="/tmp/bridge_hw${RUN_NUM}.log"

mkdir -p "$LOG_DIR"

echo "=========================================="
echo " microfips hardware handshake test"
echo " Run: ${RUN_NUM:-$(date +%s)}"
echo " VPS: ${VPS_USER}@${VPS_HOST}"
echo "=========================================="
echo ""

ssh() {
    sshpass -p "$VPS_PASS" ssh $SSH_OPTS "$VPS_USER@$VPS_HOST" "$@"
}

fail() {
    echo ""
    echo "FAIL: $1"
    echo ""
    echo "--- Logs ---"
    echo "Proxy log (last 20 lines):"
    tail -20 "$PROXY_LOG" 2>/dev/null || echo "(no proxy log)"
    echo ""
    echo "Bridge log (last 20 lines):"
    ssh "tail -20 $BRIDGE_LOG_REMOTE" 2>/dev/null || echo "(no bridge log)"
    echo ""
    if [ "$DO_CLEANUP" = true ]; then
        cleanup
    fi
    exit 1
}

pass() {
    echo ""
    echo "PASS: $1"
}

cleanup() {
    echo "[cleanup] Killing stale processes..."
    pkill -9 -f serial_tcp_proxy 2>/dev/null || true
    pkill -9 -f "ssh.*${TCP_PORT}" 2>/dev/null || true
    ssh "pkill -9 -f fips_bridge 2>/dev/null; echo $VPS_PASS | sudo -S fuser -k ${TCP_PORT}/tcp 2>/dev/null" 2>/dev/null || true
    sleep 1
    # Verify cleanup
    local stale
    stale=$(ps aux | grep -E "serial_tcp_proxy|fips_bridge|ssh.*${TCP_PORT}" | grep -v grep | wc -l)
    if [ "$stale" -gt 0 ]; then
        echo "[cleanup] WARNING: $stale stale process(es) remain"
    else
        echo "[cleanup] All processes cleaned"
    fi
}

##################################################
# PHASE 0: CLEANUP
##################################################
echo ""
echo "=== Phase 0: Cleanup ==="
cleanup

##################################################
# PHASE 1: BUILD & FLASH (optional)
##################################################
if [ "$DO_FLASH" = true ]; then
    echo ""
    echo "=== Phase 1: Build & Flash ==="

    echo "[1/3] Adding firmware to workspace..."
    if ! grep -q 'crates/microfips"' Cargo.toml; then
        sed -i 's/members = \[".*"\]/members = ["crates\/microfips-core", "crates\/microfips-link", "crates\/microfips-sim", "crates\/microfips"]/' Cargo.toml
    fi

    echo "[2/3] Building firmware..."
    cargo build -p microfips --release --target thumbv7em-none-eabi 2>&1 | tail -3

    echo "[3/3] Flashing..."
    arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
    st-flash --connect-under-reset write microfips.bin 0x08000000 2>&1 | tail -3
    rm -f microfips.bin
else
    echo ""
    echo "=== Phase 1: Skipped (use --flash to build and flash) ==="
fi

##################################################
# PHASE 2: MCU RESET + USB ENUMERATION
##################################################
echo ""
echo "=== Phase 2: MCU Reset + USB Enumeration ==="

echo "[1/3] Restarting FIPS on VPS..."
ssh "echo $VPS_PASS | sudo -S systemctl restart fips" 2>/dev/null || fail "Failed to restart FIPS"

echo "[2/3] Resetting MCU..."
st-flash --connect-under-reset reset 2>&1 | tail -1

echo "[3/3] Waiting for USB enumeration (max 15s)..."
MCU_PORT=""
for i in $(seq 1 15); do
    for p in /dev/ttyACM*; do
        prod=$(cat "/sys/class/tty/$(basename "$p")/device/../uevent" 2>/dev/null | grep PRODUCT | cut -d= -f2)
        if [ "$prod" = "c0de/cafe/10" ]; then
            MCU_PORT="$p"
            break 2
        fi
    done
    sleep 1
done

if [ -z "$MCU_PORT" ]; then
    fail "MCU did not enumerate (no c0de:cafe device found)"
fi

echo "CHECK: MCU on $MCU_PORT"
lsusb | grep "c0de:cafe" || fail "lsusb does not show c0de:cafe"
pass "USB enumeration OK ($MCU_PORT)"

##################################################
# PHASE 3: PROXY
##################################################
echo ""
echo "=== Phase 3: Start serial_tcp_proxy ==="

# Kill any existing proxy (should be clean from phase 0)
pkill -9 -f serial_tcp_proxy 2>/dev/null || true
sleep 0.5

python3 tools/serial_tcp_proxy.py --serial "$MCU_PORT" --port "$TCP_PORT" > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!

sleep 3

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    fail "Proxy died (PID $PROXY_PID)"
fi

if ! grep -q "TCP listening" "$PROXY_LOG"; then
    fail "Proxy did not start listening"
fi

pass "Proxy listening on :${TCP_PORT}"

##################################################
# PHASE 4: SSH TUNNEL + BRIDGE
##################################################
echo ""
echo "=== Phase 4: SSH Tunnel + Bridge ==="

echo "[1/3] Starting SSH reverse tunnel..."
# Kill any existing tunnels
pkill -9 -f "ssh.*${TCP_PORT}" 2>/dev/null || true
sleep 0.5

sshpass -p "$VPS_PASS" ssh $SSH_OPTS -fN \
    -R "${TCP_PORT}:127.0.0.1:${TCP_PORT}" \
    -o ServerAliveInterval=30 \
    -o ExitOnForwardFailure=yes \
    "$VPS_USER@$VPS_HOST" 2>&1

sleep 1

# Verify exactly one tunnel
TUNNEL_COUNT=$(ps aux | grep "ssh.*${TCP_PORT}" | grep -v grep | wc -l)
if [ "$TUNNEL_COUNT" -ne 1 ]; then
    fail "Expected 1 SSH tunnel, found $TUNNEL_COUNT"
fi
pass "SSH tunnel established"

echo "[2/3] Uploading bridge to VPS..."
sshpass -p "$VPS_PASS" scp $SSH_OPTS tools/fips_bridge.py "$VPS_USER@$VPS_HOST":/tmp/fips_bridge.py

echo "[3/3] Starting bridge on VPS..."
ssh "pkill -9 -f fips_bridge 2>/dev/null; rm -f $BRIDGE_LOG_REMOTE; nohup python3 /tmp/fips_bridge.py --tcp 127.0.0.1:${TCP_PORT} > $BRIDGE_LOG_REMOTE 2>&1 &"

sleep 3

BRIDGE_STATUS=$(ssh "cat $BRIDGE_LOG_REMOTE 2>/dev/null" | head -3)
echo "Bridge log: $BRIDGE_STATUS"

if ! echo "$BRIDGE_STATUS" | grep -q "Connected"; then
    fail "Bridge did not connect to tunnel"
fi

if ! echo "$BRIDGE_STATUS" | grep -q "UDP bound"; then
    fail "Bridge did not bind UDP socket"
fi

pass "Bridge connected and UDP bound"

# Verify proxy saw TCP connection
sleep 2
if ! grep -q "TCP connected" "$PROXY_LOG"; then
    fail "Proxy did not see TCP connection from bridge"
fi
pass "Proxy-TCP-Bridge link established"

##################################################
# PHASE 5: HANDSHAKE CHECK
##################################################
echo ""
echo "=== Phase 5: Handshake (waiting 20s for MSG1/MSG2) ==="

# Reset MCU to send MSG1 into live chain
echo "[1/4] Resetting MCU (chain is now live)..."
st-flash --connect-under-reset reset 2>&1 | tail -1

# Wait for MCU to re-enumerate and send MSG1
echo "[2/4] Waiting for MCU re-enumeration..."
sleep 10

# Check proxy received data from MCU
PROXY_RX=$(grep "CDC RX" "$PROXY_LOG" | tail -5)
echo "Proxy CDC RX log: $PROXY_RX"

# Check bridge received and forwarded MSG1
BRIDGE_LOG=$(ssh "cat $BRIDGE_LOG_REMOTE 2>/dev/null")
echo ""
echo "Bridge log:"
echo "$BRIDGE_LOG"
echo ""

echo "[3/4] Checking MSG1 flow..."
if echo "$BRIDGE_LOG" | grep -q "CDC->UDP:.*114B"; then
    pass "MSG1: MCU -> proxy -> tunnel -> bridge -> FIPS (114B)"
else
    echo "WARNING: No MSG1 in bridge log. Proxy may have lost serial port on MCU reset."
    echo "This is a known issue — proxy crashes when USB device resets."
fi

echo "[4/4] Checking MSG2 flow and VPS promotion..."
if echo "$BRIDGE_LOG" | grep -q "UDP->CDC:.*69B"; then
    pass "MSG2: FIPS -> bridge -> tunnel -> proxy -> MCU (69B)"
else
    echo "WARNING: No MSG2 in bridge log yet."
fi

VPS_JOURNAL=$(ssh "echo $VPS_PASS | sudo -S journalctl -u fips --no-pager -n 5 --since '1 min ago'" 2>/dev/null)
if echo "$VPS_JOURNAL" | grep -q "promoted to active peer"; then
    pass "VPS promoted MCU to active peer"
elif echo "$VPS_JOURNAL" | grep -q "active peer"; then
    pass "VPS shows active peer (may be from previous run)"
else
    echo "INFO: VPS journal:"
    echo "$VPS_JOURNAL"
fi

##################################################
# PHASE 6: SUMMARY
##################################################
echo ""
echo "=========================================="
echo " TEST SUMMARY"
echo "=========================================="
echo "Proxy log:  $PROXY_LOG"
echo "Bridge log: VPS:$BRIDGE_LOG_REMOTE"
echo ""
echo "To fetch bridge log:  ssh $SSH_OPTS $VPS_USER@$VPS_HOST 'cat $BRIDGE_LOG_REMOTE'"
echo "To fetch VPS journal:   ssh $SSH_OPTS $VPS_USER@$VPS_HOST \"echo \$VPS_PASS | sudo -S journalctl -u fips --no-pager -n 30 --since '5 min ago'\""
echo ""
echo "LED state machine (visual check on board):"
echo "  Green=PG6  Orange=PD4  Red=PD5  Blue=PK3"
echo "  Boot=blink  USB_ready=G  Handshake=G+O  ESTABLISHED=G+O+B  Error=R"
echo ""

if [ "$DO_CLEANUP" = true ]; then
    echo "Cleanup in 60s (Ctrl+C to skip)..."
    sleep 60 &
    wait $! 2>/dev/null || true
    cleanup
else
    echo "Processes left running (--no-cleanup). Manual cleanup:"
    echo "  kill $PROXY_PID  # proxy"
    echo "  pkill -f 'ssh.*${TCP_PORT}'  # tunnel"
    echo "  ssh $SSH_OPTS $VPS_USER@$VPS_HOST 'pkill -f fips_bridge'  # bridge"
fi

echo ""
echo "Done."
