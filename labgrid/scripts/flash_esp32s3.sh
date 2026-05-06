#!/bin/bash
# Flash ESP32-S3 TiLDAGON firmware
# Usage: flash_esp32s3.sh <variant> [port]
# Variants: wifi, l2cap

set -euo pipefail

VARIANT="${1:-l2cap}"
PORT="${2:-}"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

source /home/ubuntu/export-esp.sh 2>/dev/null || true

case "$VARIANT" in
    wifi)   BINARY="target/xtensa-esp32s3-none-elf/release/microfips-esp32s3" ;;
    l2cap)  BINARY="target/xtensa-esp32s3-none-elf/release/microfips-esp32s3-l2cap" ;;
    *)      echo "Unknown variant: $VARIANT" >&2; exit 1 ;;
esac

if [ -z "$PORT" ]; then
    for p in /dev/ttyACM*; do
        vid=$(cat "/sys/class/tty/$(basename "$p")/device/../uevent" 2>/dev/null | grep PRODUCT | cut -d= -f2)
        if [ "$vid" = "303a/1001/101" ]; then
            PORT="$p"
            break
        fi
    done
fi

if [ -z "$PORT" ]; then
    echo "ERROR: ESP32-S3 not found (no USB JTAG 303a:1001 detected)" >&2
    exit 1
fi

echo "Flashing $VARIANT to ESP32-S3 on $PORT"

fuser -k "$PORT" 2>/dev/null || true
sleep 1

RUSTUP_TOOLCHAIN=esp espflash flash -p "$PORT" --chip esp32s3 \
    "$PROJECT_ROOT/$BINARY"
