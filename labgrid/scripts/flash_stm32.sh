#!/bin/bash
# Flash STM32F469I-DISCO firmware via ST-Link
# Usage: flash_stm32.sh [binary_path]

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="${1:-$PROJECT_ROOT/target/thumbv7em-none-eabi/release/microfips}"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY" >&2
    echo "Build with: cargo build -p microfips --release --target thumbv7em-none-eabi" >&2
    exit 1
fi

echo "Flashing STM32F469 via ST-Link"

arm-none-eabi-objcopy -O binary "$BINARY" /tmp/microfips.bin
st-flash --connect-under-reset write /tmp/microfips.bin 0x08000000
rm -f /tmp/microfips.bin
