#!/bin/bash
# Lab-bench FIPS daemon launcher (see AGENTS.md "Lab Bench Test Rig").
#
# Robustness rules baked in (lessons learned 2026-08-29):
#  - setsid: survive tool/SSH session termination (nohup alone does NOT
#    block SIGTERM delivered to the process group on shell timeout).
#  - No pkill -f: we locate the previous instance by config path via pgrep
#    and kill that exact PID. Never use patterns that match your own shell.
#  - Interface-scoped bind: the daemon must only listen on the lab AP
#    interface, not 0.0.0.0 (no host firewall on the workstation).
set -euo pipefail

CONFIG="${1:-/tmp/opencode/fips-lab.yaml}"
LOG="${2:-/tmp/opencode/fips-lab.log}"
FIPS_BIN="${FIPS_BIN:-/home/ubuntu/src/fips/target/release/fips}"

OLD_PID=$(pgrep -f "fips --config ${CONFIG}" | head -1 || true)
if [ -n "$OLD_PID" ]; then
    echo "stopping previous lab daemon pid $OLD_PID"
    kill "$OLD_PID" || true
    sleep 2
fi

setsid "$FIPS_BIN" --config "$CONFIG" > "$LOG" 2>&1 < /dev/null &
sleep 4
NEW_PID=$(pgrep -f "fips --config ${CONFIG}" | head -1 || true)
if [ -z "$NEW_PID" ]; then
    echo "ERROR: daemon did not start; log tail:" >&2
    tail -5 "$LOG" >&2
    exit 1
fi
echo "$NEW_PID" > "${CONFIG%.yaml}.pid"
echo "lab daemon pid $NEW_PID (config $CONFIG, log $LOG)"
grep -E "npub:|node_addr:" "$LOG" | head -2
