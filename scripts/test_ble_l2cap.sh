#!/usr/bin/env bash
set -euo pipefail

SSH_SMALL="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion-small"
SSH_LEGION="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion"
CAPTURE_SECS=45
DO_BUILD=1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

[[ "${1:-}" == "--no-build" ]] && DO_BUILD=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
info() { echo -e "${YELLOW}>>>>>${NC} $1"; }
pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; }

if [[ "$DO_BUILD" -eq 1 ]]; then
    info "Pulling + building ESP32 firmware..."
    $SSH_SMALL 'cd /home/ubuntu/src/microfips && git fetch origin && git reset --hard origin/main' 2>/dev/null
    $SSH_SMALL '
        export PATH="/home/ubuntu/.rustup/toolchains/esp/bin:/home/ubuntu/.rustup/toolchains/esp/xtensa-esp-elf/esp-15.2.0_20250920/xtensa-esp-elf/bin:/home/ubuntu/.cargo/bin:$PATH"
        export LIBCLANG_PATH="/home/ubuntu/.rustup/toolchains/esp/xtensa-esp32-elf-clang/esp-20.1.1_20250829/esp-clang/lib"
        export RUSTUP_TOOLCHAIN=esp
        cd /home/ubuntu/src/microfips
        cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features l2cap 2>&1
    ' 2>&1 | tail -1 || { fail "Build failed"; exit 2; }
fi

info "Converting ELF..."
$SSH_SMALL '
    export PATH="/home/ubuntu/.rustup/toolchains/esp/bin:/home/ubuntu/.rustup/toolchains/esp/xtensa-esp-elf/esp-15.2.0_20250920/xtensa-esp-elf/bin:/home/ubuntu/.cargo/bin:$PATH"
    esptool --chip esp32 elf2image /home/ubuntu/src/microfips/target/xtensa-esp32-none-elf/release/microfips-esp32-l2cap --output /tmp/fw-test.bin 2>&1
' 2>/dev/null || { fail "ELF conversion failed"; exit 2; }

info "Copying firmware + capture script..."
$SSH_SMALL 'cat /tmp/fw-test.bin' | $SSH_LEGION 'cat > /tmp/fw-test.bin' || { fail "Copy failed"; exit 2; }
scp -o BatchMode=yes -o ConnectTimeout=10 "$SCRIPT_DIR/capture_serial.py" ubuntu@ai-legion:/tmp/capture_serial.py 2>/dev/null

info "Restarting FIPS daemon (before flash, gives it time to be ready)..."
$SSH_SMALL 'sudo systemctl restart fips' 2>/dev/null

info "Flashing ESP32..."
$SSH_LEGION 'sudo esptool --chip esp32 --port /dev/ttyUSB0 --before default-reset -b 460800 write-flash 0x10000 /tmp/fw-test.bin 2>&1' 2>/dev/null | tail -2

info "Capturing serial for ${CAPTURE_SECS}s..."
set +e
$SSH_LEGION "sudo python3 /tmp/capture_serial.py $CAPTURE_SECS" 2>&1
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]]; then
    pass "BLE L2CAP handshake + heartbeats verified"
    exit 0
else
    fail "Handshake or heartbeat verification failed"
    exit 1
fi
