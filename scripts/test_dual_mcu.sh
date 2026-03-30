#!/usr/bin/env bash
# Dual-MCU test: STM32 + ESP32 bridges to VPS via serial_udp_bridge.py
#
# Usage:
#   export VPS_PASS=<password>
#   bash scripts/test_dual_mcu.sh [--flash] [--no-cleanup]
#
# Options:
#   --flash        Build and flash both firmwares before testing
#   --no-cleanup   Leave bridges running after test (for manual inspection)

set -euo pipefail

: "${VPS_PASS:?ERROR: VPS_PASS environment variable not set}"

VPS_HOST="${VPS_HOST:-orangeclaw.dns4sats.xyz}"
VPS_USER="${VPS_USER:-routstr}"
SSH_OPTS="-o StrictHostKeyChecking=no"
LOG_DIR="/tmp/microfips_dual"
STM32_BIND_PORT=31337
ESP32_BIND_PORT=31338
DO_FLASH=false
DO_CLEANUP=true

for arg in "$@"; do
    case "$arg" in
        --flash) DO_FLASH=true ;;
        --no-cleanup) DO_CLEANUP=false ;;
    esac
done

mkdir -p "$LOG_DIR"

ssh_remote() {
    sshpass -p "$VPS_PASS" ssh $SSH_OPTS "$VPS_USER@$VPS_HOST" "$@"
}

find_mcu_port() {
    local product="$1"
    local label="$2"
    local port=""
    for i in $(seq 1 15); do
        for p in /dev/ttyACM* /dev/ttyUSB*; do
            [ -e "$p" ] || continue
            local vid
            vid=$(cat "/sys/class/tty/$(basename "$p")/device/../uevent" 2>/dev/null | grep PRODUCT | cut -d= -f2)
            if [ "$vid" = "$product" ]; then
                port="$p"
                break 2
            fi
        done
        sleep 1
    done
    if [ -z "$port" ]; then
        echo "FAIL: $label not found after 15s" >&2
        return 1
    fi
    echo "$port"
}

kill_stale() {
    for port in "$STM32_BIND_PORT" "$ESP32_BIND_PORT"; do
        fuser -k "${port}/tcp" 2>/dev/null || true
    done
    if [ -n "${STM32_BRIDGE_PID:-}" ]; then
        kill "$STM32_BRIDGE_PID" 2>/dev/null || true
    fi
    if [ -n "${ESP32_BRIDGE_PID:-}" ]; then
        kill "$ESP32_BRIDGE_PID" 2>/dev/null || true
    fi
}

wait_for_log_pattern() {
    local file="$1" pattern="$2" timeout="$3" label="$4"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if [ -f "$file" ] && grep -q "$pattern" "$file"; then
            echo "CHECK: $label found after ${elapsed}s"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    echo "WARN: $label not found after ${timeout}s" >&2
    return 1
}

echo "=========================================="
echo " microfips dual-MCU test"
echo " VPS: ${VPS_USER}@${VPS_HOST}"
echo " STM32 port: ${STM32_BIND_PORT}"
echo " ESP32 port: ${ESP32_BIND_PORT}"
echo "=========================================="
echo ""

##########################################################
# PHASE 0: CLEANUP + RESET
##########################################################
echo "=== Phase 0: Cleanup + Reset ==="
kill_stale
sleep 1

echo "[1/3] Restarting FIPS on VPS..."
ssh_remote "echo $VPS_PASS | sudo -S systemctl restart fips" 2>/dev/null || true
sleep 2

echo "[2/3] Resetting STM32..."
st-flash --connect-under-reset reset 2>&1 | tail -1 || echo "  (st-flash not available, skipping)"

echo "[3/3] Resetting ESP32..."
if python3 -c "
import serial, time
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=0.5)
s.dtr = False; s.rts = True; time.sleep(0.1)
s.dtr = True;  s.rts = False; time.sleep(0.1)
s.dtr = False; time.sleep(0.1)
s.close()
" 2>/dev/null; then
    echo "  DTR reset OK"
else
    echo "  (ESP32 not on /dev/ttyUSB0 yet, will retry after enumeration)"
fi

echo "Waiting 10s for MCU boot + USB enumeration..."
sleep 10
echo "Done"
echo ""

##########################################################
# PHASE 1: BUILD & FLASH (optional)
##########################################################
if [ "$DO_FLASH" = true ]; then
    echo "=== Phase 1: Build & Flash ==="

    echo "[1/4] Building STM32 firmware..."
    cargo build -p microfips --release --target thumbv7em-none-eabi 2>&1 | tail -3

    echo "[2/4] Building ESP32 firmware..."
    . /home/ubuntu/export-esp.sh
    RUSTUP_TOOLCHAIN=esp cargo build -p microfips-esp32 --release \
        --target xtensa-esp32-none-elf -Zbuild-std=core,alloc 2>&1 | tail -3

    echo "[3/4] Flashing STM32..."
    arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
    st-flash --connect-under-reset write microfips.bin 0x08000000 2>&1 | tail -3
    rm -f microfips.bin

    echo "[4/4] Flashing ESP32..."
    RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 \
        target/xtensa-esp32-none-elf/release/microfips-esp32 2>&1 | tail -3
else
    echo "=== Phase 1: Skipped (use --flash to build and flash) ==="
fi
echo ""

##########################################################
# PHASE 2: USB ENUMERATION
##########################################################
echo "=== Phase 2: USB Enumeration ==="

echo "[1/2] Finding STM32 (c0de:cafe)..."
STM32_PORT=$(find_mcu_port "c0de/cafe/10" "STM32")
echo "CHECK: STM32 on $STM32_PORT"

echo "[2/2] Finding ESP32 (10c4:ea60)..."
ESP32_PORT=$(find_mcu_port "10c4/ea60/100" "ESP32")
echo "CHECK: ESP32 on $ESP32_PORT"
echo ""

##########################################################
# PHASE 3: START BRIDGES
##########################################################
echo "=== Phase 3: Start Bridges ==="

STM32_LOG="$LOG_DIR/bridge_stm32.log"
ESP32_LOG="$LOG_DIR/bridge_esp32.log"

echo "[1/2] Starting STM32 bridge ($STM32_PORT -> :$STM32_BIND_PORT)..."
python3 tools/serial_udp_bridge.py \
    --serial "$STM32_PORT" \
    --bind-port "$STM32_BIND_PORT" \
    --udp-host "$VPS_HOST" \
    > "$STM32_LOG" 2>&1 &
STM32_BRIDGE_PID=$!
echo "  PID: $STM32_BRIDGE_PID"

sleep 1

echo "[2/2] Starting ESP32 bridge ($ESP32_PORT -> :$ESP32_BIND_PORT)..."
python3 tools/serial_udp_bridge.py \
    --serial "$ESP32_PORT" \
    --bind-port "$ESP32_BIND_PORT" \
    --udp-host "$VPS_HOST" \
    > "$ESP32_LOG" 2>&1 &
ESP32_BRIDGE_PID=$!
echo "  PID: $ESP32_BRIDGE_PID"

sleep 2

if ! kill -0 "$STM32_BRIDGE_PID" 2>/dev/null; then
    echo "FAIL: STM32 bridge died immediately" >&2
    cat "$STM32_LOG"
    exit 1
fi
if ! kill -0 "$ESP32_BRIDGE_PID" 2>/dev/null; then
    echo "FAIL: ESP32 bridge died immediately" >&2
    cat "$ESP32_LOG"
    exit 1
fi

echo "CHECK: Both bridges running"
echo "  STM32 log: $STM32_LOG"
echo "  ESP32 log: $ESP32_LOG"
echo ""

##########################################################
# PHASE 4: IK HANDSHAKES
##########################################################
echo "=== Phase 4: Wait for IK Handshakes (max 45s) ==="

wait_for_log_pattern "$STM32_LOG" ">> CDC->UDP: frame#1 114B" 45 "STM32 MSG1" || true
wait_for_log_pattern "$ESP32_LOG" ">> CDC->UDP: frame#1 114B" 45 "ESP32 MSG1" || true
wait_for_log_pattern "$STM32_LOG" "<< UDP->CDC: frame#[0-9]* 69B" 45 "STM32 MSG2" || true
wait_for_log_pattern "$ESP32_LOG" "<< UDP->CDC: frame#[0-9]* 69B" 45 "ESP32 MSG2" || true

echo ""
echo "--- VPS journal (last 10 lines) ---"
ssh_remote "echo $VPS_PASS | sudo -S journalctl -u fips --no-pager -n 10 --since '2 min ago'" 2>/dev/null | grep -v password | grep -v "\[sudo\]" || echo "(no journal entries)"
echo ""

##########################################################
# PHASE 5: FSP SETUP (ESP32 -> STM32)
##########################################################
echo "=== Phase 5: Wait for FSP SessionSetup (max 30s) ==="

if wait_for_log_pattern "$ESP32_LOG" ">> CDC->UDP: frame#[0-9]* 149B" 30 "ESP32 FSP setup"; then
    echo ""
    echo "Checking for FSP SessionAck from VPS/STM32..."
    if wait_for_log_pattern "$ESP32_LOG" "<< UDP->CDC:.*1[0-4][0-9]B.*from" 15 "FSP ack (100-149B from VPS)"; then
        echo "CHECK: Potential FSP SessionAck received (check log for phase byte 0x02)"
        grep "1[0-4][0-9]B.*from" "$ESP32_LOG" | tail -3
    else
        echo "WARN: No FSP SessionAck received (see issue #31 — VPS may not route between local peers)"
    fi
else
    echo "WARN: No FSP SessionSetup sent (ESP32 may not have started FSP initiator)"
fi
echo ""

##########################################################
# PHASE 6: HEARTBEAT MONITORING
##########################################################
echo "=== Phase 6: Heartbeat Check ==="

STM32_HB=$(grep -c ">> CDC->UDP: frame#[0-9]* 37B" "$STM32_LOG" 2>/dev/null || echo 0)
ESP32_HB=$(grep -c ">> CDC->UDP: frame#[0-9]* 37B" "$ESP32_LOG" 2>/dev/null || echo 0)
echo "STM32 heartbeats sent: $STM32_HB"
echo "ESP32 heartbeats sent: $ESP32_HB"
echo ""

##########################################################
# SUMMARY
##########################################################
echo "=========================================="
echo " SUMMARY"
echo "=========================================="
echo "STM32: $STM32_PORT -> :$STM32_BIND_PORT -> $VPS_HOST:2121"
echo "ESP32: $ESP32_PORT -> :$ESP32_BIND_PORT -> $VPS_HOST:2121"
echo ""
echo "Logs:"
echo "  STM32: $STM32_LOG"
echo "  ESP32: $ESP32_LOG"
echo ""
echo "VPS: ssh $SSH_OPTS $VPS_USER@$VPS_HOST"
echo "     'echo \$VPS_PASS | sudo -S journalctl -u fips -f --no-pager'"
echo ""

if [ "$DO_CLEANUP" = true ]; then
    echo "Cleanup in 60s (Ctrl+C to skip)..."
    sleep 60 &
    wait $! 2>/dev/null || true
    echo ""
    echo "=== Cleanup ==="
    kill_stale
    echo "Done"
else
    echo "Bridges left running (--no-cleanup)."
    echo "  kill $STM32_BRIDGE_PID  # STM32 bridge"
    echo "  kill $ESP32_BRIDGE_PID  # ESP32 bridge"
    echo ""
    echo "Monitor logs:"
    echo "  tail -f $STM32_LOG"
    echo "  tail -f $ESP32_LOG"
fi

echo ""
echo "Done."
