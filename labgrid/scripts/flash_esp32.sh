#!/bin/bash
# Flash ESP32-D0WD firmware
# Usage: flash_esp32.sh <variant> [port]
# Variants: uart, ble, l2cap, wifi
#
# Called by labgrid FlashScriptDriver with the serial port as first arg.

set -euo pipefail

VARIANT="${1:-l2cap}"
PORT="${2:-}"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Load ESP toolchain
source /home/ubuntu/export-esp.sh 2>/dev/null || true

# Map variant to binary
case "$VARIANT" in
    uart)   BINARY="target/xtensa-esp32-none-elf/release/microfips-esp32" ;;
    ble)    BINARY="target/xtensa-esp32-none-elf/release/microfips-esp32-ble" ;;
    l2cap)  BINARY="target/xtensa-esp32-none-elf/release/microfips-esp32-l2cap" ;;
    wifi)   BINARY="target/xtensa-esp32-none-elf/release/microfips-esp32-wifi" ;;
    *)      echo "Unknown variant: $VARIANT" >&2; exit 1 ;;
esac

# Detect port by VID:PID if not provided
if [ -z "$PORT" ]; then
    for p in /dev/ttyUSB*; do
        vid=$(cat "/sys/class/tty/$(basename "$p")/device/../uevent" 2>/dev/null | grep PRODUCT | cut -d= -f2)
        if [ "$vid" = "10c4/ea60/100" ]; then
            PORT="$p"
            break
        fi
    done
fi

if [ -z "$PORT" ]; then
    echo "ERROR: ESP32-D0WD not found (no CP210x 10c4:ea60 detected)" >&2
    exit 1
fi

echo "Flashing $VARIANT to ESP32-D0WD on $PORT"

# Kill stale processes
fuser -k "$PORT" 2>/dev/null || true
sleep 1

# Flash
RUSTUP_TOOLCHAIN=esp espflash flash -p "$PORT" --chip esp32 \
    "$PROJECT_ROOT/$BINARY"
