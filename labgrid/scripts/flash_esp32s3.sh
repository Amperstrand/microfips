#!/bin/bash
# Flash ESP32-S3 TiLDAGON firmware
# Usage: flash_esp32s3.sh <variant> [port]
# Variants: wifi, l2cap

set -uo pipefail

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
FLASH_RC=$?

# Fail-closed post-flash verification (#237): a write that verifies against
# its own bytes proves nothing — require a boot-log marker only THIS build
# emits before declaring success. No marker configured => NOT VERIFIED.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "${MICROFIPS_FLASH_NO_VERIFY:-0}" = "1" ]; then
    echo "WARNING: boot verification SKIPPED by MICROFIPS_FLASH_NO_VERIFY=1 —" >&2
    echo "         the flash is UNPROVEN; do not draw conclusions from this board (#237)." >&2
    exit "$FLASH_RC"
fi
if [ -z "${MICROFIPS_BOOT_MARKER:-}" ]; then
    echo "FLASH NOT VERIFIED: MICROFIPS_BOOT_MARKER is unset (#237 fail-closed)." >&2
    echo "  Provide a boot-log line only this build emits, e.g.:" >&2
    echo "    MICROFIPS_BOOT_MARKER='<unique boot line>' $0 $VARIANT [port]" >&2
    echo "  The write may have verified against its own bytes while the ROM" >&2
    echo "  boots an older image — stale firmware. Refusing success." >&2
    exit 5
fi
"$SCRIPT_DIR/verify_flash_boot.sh" "$PORT" "$MICROFIPS_BOOT_MARKER" "${MICROFIPS_BOOT_TIMEOUT:-30}"
VERIFY_RC=$?
if [ "$VERIFY_RC" -ne 0 ]; then
    echo "FLASH NOT VERIFIED: boot verification exit=$VERIFY_RC (see above). Treat the board as stale/unproven (#237)." >&2
    exit "$VERIFY_RC"
fi
exit "$FLASH_RC"
