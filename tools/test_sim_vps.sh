#!/usr/bin/env bash
# Test microfips-sim against live VPS using fips_bridge.py --tcp
#
# Usage: ./tools/test_sim_vps.sh [vps-host] [ssh-user]
#
# This pipes microfips-sim through an SSH tunnel to fips_bridge.py on the VPS,
# testing the full FIPS handshake + heartbeat lifecycle without any hardware.
#
# Prerequisites:
#   - SSH access to VPS with fips_bridge.py at /tmp/fips_bridge.py
#   - FIPS daemon running on VPS (listening on UDP port 2121)
#   - microfips-sim built: cargo run -p microfips-sim

set -euo pipefail

VPS_HOST="${1:?usage: test_sim_vps.sh <vps-host> [ssh-user]}"
SSH_USER="${2:-routstr}"
LOCAL_PORT=45679

echo "=== microfips-sim VPS integration test ==="
echo "VPS: ${SSH_USER}@${VPS_HOST}"
echo "Local TCP port: ${LOCAL_PORT}"
echo ""

echo "[1/5] Killing old processes..."
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VPS_HOST}" \
    "pkill -f 'fips_bridge.py.*${LOCAL_PORT}' 2>/dev/null || true"
sleep 1

echo "[2/5] Starting SSH reverse tunnel (-R ${LOCAL_PORT}:127.0.0.1:${LOCAL_PORT})..."
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no \
    -fNR "${LOCAL_PORT}:127.0.0.1:${LOCAL_PORT}" "${SSH_USER}@${VPS_HOST}"
sleep 1

echo "[3/5] Starting fips_bridge.py on VPS..."
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VPS_HOST}" \
    "nohup python3 /tmp/fips_bridge.py --tcp 127.0.0.1:${LOCAL_PORT} > /tmp/bridge_sim.log 2>&1 &"
sleep 2

BRIDGE_LOG=$(sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VPS_HOST}" \
    "cat /tmp/bridge_sim.log 2>/dev/null")
echo "Bridge log: ${BRIDGE_LOG}"

if ! echo "$BRIDGE_LOG" | grep -q "Connected"; then
    echo "ERROR: bridge did not connect"
    sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VPS_HOST}" \
        "pkill -f 'fips_bridge.py.*${LOCAL_PORT}' 2>/dev/null || true"
    exit 1
fi

echo "[4/5] Starting microfips-sim (60s test window)..."
echo "---"
timeout 60 cargo run -p microfips-sim 2>&1 || true
echo "---"

echo "[5/5] Checking results..."
BRIDGE_LOG=$(sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VPS_HOST}" \
    "cat /tmp/bridge_sim.log 2>/dev/null")
echo "Bridge final log:"
echo "$BRIDGE_LOG"

if echo "$BRIDGE_LOG" | grep -q "CDC->UDP: 114B"; then
    echo ""
    echo "PASS: MSG1 sent from simulator to VPS"
else
    echo ""
    echo "FAIL: MSG1 not received by VPS"
fi

if echo "$BRIDGE_LOG" | grep -q "UDP->CDC: 69B"; then
    echo "PASS: MSG2 received from VPS"
else
    echo "FAIL: MSG2 not received from VPS"
fi

echo ""
echo "Cleaning up..."
sshpass -p 'Elci9quadAd' ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VPS_HOST}" \
    "pkill -f 'fips_bridge.py.*${LOCAL_PORT}' 2>/dev/null || true"

echo "Done."
