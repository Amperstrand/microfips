#!/usr/bin/env bash
# HTTP-over-FIPS E2E test on the STM32F469 (microfips issue #12).
# Chain: http-test (host responder+client) <-> serial_udp_bridge <-> USB CDC <-> MCU
# The demo service answers {"ok":true,...} on GET /health via FSP over Noise IK+XK.
#
# Keys: MCU pins sim-b (G*4, from device-registry.json); http-test runs as sim-b,
# pinning the MCU (G*1 stm32). Read keys from the registry — never hand-copy hex.
set -euo pipefail
cd "$(dirname "$0")/.."

REG=crates  # unused; registry path below
SIM_B=$(python3 -c "import json; print(json.load(open('device-registry.json'))['devices']['sim-b']['npub_hex'])")
STM32=$(python3 -c "import json; print(json.load(open('device-registry.json'))['devices']['stm32']['npub_hex'])")
SIM_B_NSEC=0000000000000000000000000000000000000000000000000000000000000004

PORT=""
for p in /dev/ttyACM*; do
    prod=$(cat "/sys/class/tty/$(basename "$p")/device/../uevent" 2>/dev/null | grep PRODUCT | cut -d= -f2 || true)
    [ "$prod" = "c0de/cafe/10" ] && PORT=$p
done
[ -n "$PORT" ] || { echo "MCU CDC port not found (VID:PID c0de:cafe)"; exit 1; }
echo "MCU on $PORT"

echo "== build (pinned to sim-b; touch identity to defeat the stale-pin trap) =="
touch crates/microfips-core/src/identity.rs
DEVICE_NPUB_HEX_vps="$SIM_B" cargo build -p microfips --release --target thumbv7em-none-eabi
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips /tmp/microfips-http-e2e.bin
python3 - "$SIM_B" <<'EOF'
import sys
d = open('/tmp/microfips-http-e2e.bin','rb').read()
k = bytes.fromhex(sys.argv[1][2:])
sys.exit(0 if k in d else (print("FATAL: host key not in binary"), 1))
EOF
echo "binary pin verified"

echo "== flash =="
st-flash --connect-under-reset write /tmp/microfips-http-e2e.bin 0x08000000
st-flash --connect-under-reset reset
sleep 8
for p in /dev/ttyACM*; do
    prod=$(cat "/sys/class/tty/$(basename "$p")/device/../uevent" 2>/dev/null | grep PRODUCT | cut -d= -f2 || true)
    [ "$prod" = "c0de/cafe/10" ] && PORT=$p
done

echo "== run =="
cleanup() { [ -n "${BRIDGE_PID:-}" ] && kill "$BRIDGE_PID" 2>/dev/null || true; }
trap cleanup EXIT
FIPS_NSEC=$SIM_B_NSEC FIPS_PEER_NPUB=$STM32 \
    timeout 90 ./target/release/microfips-http-test &
TEST_PID=$!
sleep 2
python3 tools/serial_udp_bridge.py --serial "$PORT" --udp-host 127.0.0.1 --udp-port 31338 &
BRIDGE_PID=$!
wait $TEST_PID
