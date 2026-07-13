#!/usr/bin/env bash
# Automated BLE L2CAP handshake + heartbeat hardware test.
#
# Coordinates two remote hosts:
#   ai-legion-small: FIPS daemon + ESP32 build toolchain
#   ai-legion:        ESP32-D0WD via CP210x serial port
#
# Usage:
#   bash scripts/test_ble_l2cap.sh              # build + flash + test
#   bash scripts/test_ble_l2cap.sh --no-build   # skip build, just flash current + test
#
# Exit codes:
#   0 = PASS (handshake ok + hb_tx > 0)
#   1 = FAIL (handshake failed or no heartbeats)
#   2 = ERROR (build/flash/connectivity issue)

set -euo pipefail

SSH_SMALL="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion-small"
SSH_LEGION="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion"
CAPTURE_SECS=45
DO_BUILD=1

[[ "${1:-}" == "--no-build" ]] && DO_BUILD=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; }
info() { echo -e "${YELLOW}>>>>>${NC} $1"; }

# --- 1. Build (optional) ---
if [[ "$DO_BUILD" -eq 1 ]]; then
    info "Pulling latest code on ai-legion-small..."
    $SSH_SMALL 'cd /home/ubuntu/src/microfips && git fetch origin && git reset --hard origin/main' 2>/dev/null

    info "Building ESP32 firmware (IK mode, l2cap)..."
    BUILD_OUTPUT=$($SSH_SMALL '
        export PATH="/home/ubuntu/.rustup/toolchains/esp/bin:/home/ubuntu/.rustup/toolchains/esp/xtensa-esp-elf/esp-15.2.0_20250920/xtensa-esp-elf/bin:/home/ubuntu/.cargo/bin:$PATH"
        export LIBCLANG_PATH="/home/ubuntu/.rustup/toolchains/esp/xtensa-esp32-elf-clang/esp-20.1.1_20250829/esp-clang/lib"
        export RUSTUP_TOOLCHAIN=esp
        cd /home/ubuntu/src/microfips
        cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features l2cap 2>&1
    ' 2>&1) || { fail "Build failed"; echo "$BUILD_OUTPUT" | tail -5; exit 2; }
    echo "$BUILD_OUTPUT" | tail -1
fi

# --- 2. Convert ELF to binary ---
info "Converting ELF to flash binary..."
$SSH_SMALL '
    export PATH="/home/ubuntu/.rustup/toolchains/esp/bin:/home/ubuntu/.rustup/toolchains/esp/xtensa-esp-elf/esp-15.2.0_20250920/xtensa-esp-elf/bin:/home/ubuntu/.cargo/bin:$PATH"
    esptool --chip esp32 elf2image /home/ubuntu/src/microfips/target/xtensa-esp32-none-elf/release/microfips-esp32-l2cap --output /tmp/fw-test.bin 2>&1
' 2>/dev/null || { fail "ELF conversion failed"; exit 2; }

# --- 3. Copy to ai-legion and flash ---
info "Flashing ESP32..."
$SSH_SMALL 'cat /tmp/fw-test.bin' | $SSH_LEGION 'cat > /tmp/fw-test.bin' || { fail "Copy failed"; exit 2; }
$SSH_LEGION 'sudo esptool --chip esp32 --port /dev/ttyUSB0 --before default-reset -b 460800 write-flash 0x10000 /tmp/fw-test.bin 2>&1' 2>/dev/null | tail -2

# --- 4. Restart FIPS daemon ---
info "Restarting FIPS daemon..."
$SSH_SMALL 'sudo systemctl restart fips' 2>/dev/null &
sleep 3

# --- 5. Reset ESP32 + capture serial + parse results ---
info "Capturing serial for ${CAPTURE_SECS}s (reset + handshake + heartbeats)..."
RESULT=$($SSH_LEGION "sudo python3 -c \"
import serial, time, json, sys
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=0.1)
s.dtr=False; s.rts=True; time.sleep(0.1)
s.dtr=True; s.rts=True; time.sleep(0.05)
s.dtr=False; s.rts=False; time.sleep(0.2)
start=time.time()
got_handshake=False
got_hb_tx=False
got_hb_rx=False
while time.time()-start < $CAPTURE_SECS:
    data=s.read(4096)
    if data:
        for line in data.decode(errors='replace').splitlines():
            l=line.strip()
            if 'handshake ok' in l: got_handshake=True
            if 'sending heartbeat' in l and 'timer' in l: got_hb_tx=True
            if 'heartbeat received' in l: got_hb_rx=True
s.write(b'show_stats\n')
time.sleep(2)
data=s.read(4096)
hb_tx=0; hb_rx=0; msg2_rx=0
for line in data.decode(errors='replace').splitlines():
    l=line.strip()
    if l.startswith('{'):
        d=json.loads(l)['data']
        hb_tx=d['hb_tx']; hb_rx=d['hb_rx']; msg2_rx=d['msg2_rx']
s.close()
print(f'handshake={got_handshake} hb_tx={hb_tx} hb_rx={hb_rx} msg2_rx={msg2_rx}')
\"" 2>&1) || true

info "Results: $RESULT"

# --- 6. Parse and report ---
if echo "$RESULT" | grep -q "handshake=True" && echo "$RESULT" | grep -qE "hb_tx=[1-9]"; then
    pass "BLE L2CAP handshake + heartbeats verified"
    echo "  $RESULT"
    exit 0
else
    fail "Handshake or heartbeat verification failed"
    echo "  $RESULT"
    exit 1
fi
