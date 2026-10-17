#!/bin/bash
# verify_flash_boot.sh — fail-closed post-flash boot verification (#237).
#
# THE DEFECT THIS CLOSES
#
# A flash write that "verifies" against its own bytes proves nothing about
# what the ROM boots: the esptool 0x0-ELF trap stored a raw ELF at 0x0 while
# the second-stage image at 0x1000 kept booting — the session reported
# success and the board ran STALE firmware (#237, HW-232 2026-10-16). The
# AGENTS.md rule ("verify a flash took effect by matching a boot-log line
# only the new build can emit") was documentation; this script enforces it.
#
# Usage: verify_flash_boot.sh <port> <expected-marker> [timeout-secs]
# Exit codes (pinned by --self-test):
#   0  PROVEN-FRESH — the marker appeared in the post-reset boot log
#   2  BOARD-SILENT — no serial output at all (bricked image / wrong port)
#   3  STALE-SIGNATURE — the board talks but never emits the marker:
#                       something ELSE is running (the #237 class)
#   4  usage error
set -uo pipefail

if [ "${1:-}" = "--self-test" ]; then
    bash -n "$0" || { echo "self-test: syntax check failed"; exit 1; }
    # exit-code contract is pinned textually (see check-flash-policy.sh gate)
    for code in "exit 2" "exit 3" "exit 4"; do
        grep -qF "$code" "$0" || { echo "self-test: lost exit contract '$code'"; exit 1; }
    done
    echo "verify_flash_boot self-test: PASS"
    exit 0
fi

PORT="${1:-}"
MARKER="${2:-}"
TIMEOUT="${3:-30}"

if [ -z "$PORT" ] || [ -z "$MARKER" ]; then
    echo "usage: verify_flash_boot.sh <port> <expected-marker> [timeout-secs]" >&2
    echo "  <expected-marker>: a boot-log line ONLY the newly flashed build emits" >&2
    exit 4
fi

echo "[verify_flash_boot] port=$PORT marker='$MARKER' timeout=${TIMEOUT}s"

# Reset the board and capture the boot log. If a capture source is provided
# (tests), use it instead of live serial.
if [ -n "${MICROFIPS_VERIFY_CAPTURE_CMD:-}" ]; then
    CAPTURE="$(eval "$MICROFIPS_VERIFY_CAPTURE_CMD")"
else
    CAPTURE="$(python3 - "$PORT" "$TIMEOUT" <<'PYEOF' 2>/dev/null
import serial, sys, time
port, timeout = sys.argv[1], float(sys.argv[2])
try:
    s = serial.Serial(port, 115200, timeout=0.2)
except Exception as e:
    print(f"OPEN_FAIL:{e}", flush=True)
    sys.exit(0)
# EN/RTS reset pulse (same idiom as scripts/capture_serial.py)
s.dtr = False; s.rts = True; time.sleep(0.1)
s.dtr = True;  s.rts = True; time.sleep(0.05)
s.dtr = False; s.rts = False
start = time.time()
buf = []
while time.time() - start < timeout:
    data = s.read(4096)
    if data:
        text = data.decode(errors="replace")
        buf.append(text)
        sys.stdout.write(text)
        sys.stdout.flush()
s.close()
PYEOF
)"
fi

if [ -n "${CAPTURE##*OPEN_FAIL*}" ] && [ -z "${CAPTURE##OPEN_FAIL*}" ]; then
    echo "[verify_flash_boot] FAIL BOARD-SILENT: cannot open serial ($CAPTURE)" >&2
    exit 2
fi

if [ -z "$(printf '%s' "$CAPTURE" | tr -d '[:space:]')" ]; then
    echo "[verify_flash_boot] FAIL BOARD-SILENT: no serial output within ${TIMEOUT}s —" >&2
    echo "  the write may not have persisted (the FT232 0xFF read-back class) or" >&2
    echo "  the board is bricked. Do NOT trust the flash session." >&2
    exit 2
fi

if printf '%s' "$CAPTURE" | grep -qF -- "$MARKER"; then
    echo "[verify_flash_boot] PROVEN-FRESH: marker seen in boot log"
    exit 0
fi

echo "[verify_flash_boot] FAIL STALE-SIGNATURE: board produced serial output but the" >&2
echo "  marker '$MARKER' never appeared — the running firmware is NOT the build you" >&2
echo "  flashed (#237 class: write verified against its own bytes; ROM booted the" >&2
echo "  old image). Do NOT draw conclusions from this board until re-flashed + verified." >&2
exit 3
