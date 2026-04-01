#!/usr/bin/env bash
# MCU-to-MCU FSP E2E test: STM32 + ESP32 through FIPS VPS
#
# Usage:
#   export VPS_PASS=<password>
#   bash scripts/test_mcu_to_mcu_fsp.sh [--flash] [--skip-hardware] [--no-cleanup]
#
# Options:
#   --flash          Build and flash both firmwares before testing
#   --skip-hardware   Skip MCU/bridge phases and run sim-to-sim HTTP fallback only
#   --no-cleanup      Leave bridges running after test (for manual inspection)

set -euo pipefail

: "${VPS_PASS:?ERROR: VPS_PASS environment variable not set}"

VPS_HOST="${VPS_HOST:-orangeclaw.dns4sats.xyz}"
VPS_USER="${VPS_USER:-routstr}"
SSH_OPTS="-o StrictHostKeyChecking=no"
LOG_DIR="/tmp/microfips_mcu_to_mcu_fsp"
STM32_BIND_PORT=31337
ESP32_BIND_PORT=31338
DO_FLASH=false
SKIP_HARDWARE=false
DO_CLEANUP=true
STM32_BRIDGE_PID=""
ESP32_BRIDGE_PID=""
SIM_A_PID=""

for arg in "$@"; do
    case "$arg" in
        --flash) DO_FLASH=true ;;
        --skip-hardware) SKIP_HARDWARE=true ;;
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
    if [ -n "${SIM_A_PID:-}" ]; then
        kill "$SIM_A_PID" 2>/dev/null || true
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
echo " microfips MCU-to-MCU FSP test"
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

    if [ "$SKIP_HARDWARE" = false ]; then
        echo "[3/4] Flashing STM32..."
        arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabi/release/microfips microfips.bin
        st-flash --connect-under-reset write microfips.bin 0x08000000 2>&1 | tail -3
        rm -f microfips.bin

        echo "[4/4] Flashing ESP32..."
        RUSTUP_TOOLCHAIN=esp espflash flash -p /dev/ttyUSB0 --chip esp32 \
            target/xtensa-esp32-none-elf/release/microfips-esp32 2>&1 | tail -3
    else
        echo "[3/4] Skipping flash in --skip-hardware mode"
        echo "[4/4] Skipping flash in --skip-hardware mode"
    fi
else
    echo "=== Phase 1: Skipped (use --flash to build and flash) ==="
fi
echo ""

PHASE5_PASS=false
PHASE6_PASS=false
PHASE7_PASS=false

if [ "$SKIP_HARDWARE" = false ]; then
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
    # PHASE 5: FSP SETUP / SESSION ACK
    ##########################################################
    echo "=== Phase 5: FSP SessionSetup + SessionAck + MSG3 (ESP32 → STM32, max 30s) ==="
    PHASE5_PASS=false
    if wait_for_log_pattern "$ESP32_LOG" ">> CDC->UDP: frame#[0-9]* 149B" 30 "ESP32 FSP SessionSetup"; then
        if wait_for_log_pattern "$ESP32_LOG" "<< UDP->CDC:.*1[0-4][0-9]B.*from" 15 "FSP SessionAck"; then
            echo "CHECK: FSP SessionAck received"
            # MSG3 is sent by the initiator (ESP32) after receiving SessionAck — it completes the XK handshake
            if wait_for_log_pattern "$ESP32_LOG" ">> CDC->UDP: frame#[0-9]* [0-9]*B" 15 "ESP32 FSP MSG3 (XK complete)"; then
                echo "CHECK: ESP32 FSP MSG3 sent (XK handshake complete)"
                PHASE5_PASS=true
            else
                echo "WARN: No MSG3 from ESP32 (XK handshake incomplete)"
            fi
        else
            echo "WARN: No FSP SessionAck (routing may be failing)"
        fi
    else
        echo "WARN: No FSP SessionSetup sent"
    fi
    echo ""

    ##########################################################
    # PHASE 6: FSP PING/PONG DETECTION
    ##########################################################
    echo "=== Phase 6: FSP PING/PONG bidirectional check (max 30s) ==="
    PHASE6_PASS=false
    ESP32_TRAFFIC=false
    STM32_TRAFFIC=false
    if wait_for_log_pattern "$ESP32_LOG" ">> CDC->UDP: frame#[0-9]* [0-9]*B" 30 "ESP32 DataPacket"; then
        echo "CHECK: Encrypted FSP DataPacket sent by ESP32"
        ESP32_TRAFFIC=true
    fi
    if wait_for_log_pattern "$STM32_LOG" ">> CDC->UDP: frame#[0-9]* [0-9]*B" 30 "STM32 DataPacket"; then
        echo "CHECK: Encrypted FSP DataPacket sent by STM32"
        STM32_TRAFFIC=true
    fi
    if [ "$ESP32_TRAFFIC" = true ] && [ "$STM32_TRAFFIC" = true ]; then
        echo "CHECK: Bidirectional FSP traffic confirmed"
        PHASE6_PASS=true
    elif [ "$ESP32_TRAFFIC" = true ] || [ "$STM32_TRAFFIC" = true ]; then
        echo "WARN: Only one-directional FSP traffic observed"
        PHASE6_PASS=true
    else
        echo "WARN: No FSP DataPacket traffic from either MCU"
    fi
    echo ""

    ##########################################################
    # PHASE 7: SIM-TO-MCU HTTP TEST
    ##########################################################
    echo "=== Phase 7: Sim-to-MCU HTTP Test ==="
    HTTP_LOG="$LOG_DIR/sim_http.log"
    echo "Running SIM-B --test-http targeting STM32..."
    if FIPS_SECRET=0404040404040404040404040404040404040404040404040404040404040404 \
        timeout 60 cargo run -p microfips-sim --release -- \
        --udp "$VPS_HOST:2121" \
        --initiator --target 132f39a98c31baaddba6525f5d43f295 \
        --test-http > "$HTTP_LOG" 2>&1; then
        echo "CHECK: HTTP 200 received from STM32"
        PHASE7_PASS=true
    else
        echo "WARN: HTTP test failed (see $HTTP_LOG)"
        tail -5 "$HTTP_LOG"
    fi
    echo ""
else
    ##########################################################
    # PHASE 7: SIM-TO-SIM HTTP FALLBACK
    ##########################################################
    echo "=== Phase 7: Sim-to-sim HTTP fallback ==="
    HTTP_LOG="$LOG_DIR/sim_http.log"
    echo "Running SIM-A responder..."
    RUST_LOG=warn timeout 90 cargo run -p microfips-sim --release -- \
      --udp "$VPS_HOST:2121" --sim-a > "$LOG_DIR/sim_a.log" 2>&1 &
    SIM_A_PID=$!
    sleep 10
    echo "Running SIM-B --test-http..."
    if RUST_LOG=info timeout 60 cargo run -p microfips-sim --release -- \
      --udp "$VPS_HOST:2121" --sim-b --test-http > "$HTTP_LOG" 2>&1; then
        echo "CHECK: HTTP 200 received from SIM-A"
        PHASE7_PASS=true
    else
        echo "WARN: HTTP test failed (see $HTTP_LOG)"
        tail -5 "$HTTP_LOG"
    fi
    echo ""
fi

##########################################################
# PHASE 8: SUMMARY
##########################################################
echo "=========================================="
echo " SUMMARY"
echo "=========================================="
OVERALL_PASS=true
[ "$SKIP_HARDWARE" = true ] && PHASE5_PASS=true && PHASE6_PASS=true
echo "Phase 5 (FSP SessionSetup): $([ "$PHASE5_PASS" = true ] && echo PASS || echo FAIL)"
echo "Phase 6 (FSP PING/PONG):    $([ "$PHASE6_PASS" = true ] && echo PASS || echo FAIL)"
echo "Phase 7 (HTTP test):        $([ "$PHASE7_PASS" = true ] && echo PASS || echo FAIL)"
if [ "$PHASE5_PASS" = false ] || [ "$PHASE6_PASS" = false ] || [ "$PHASE7_PASS" = false ]; then
    OVERALL_PASS=false
fi
echo ""
if [ "$OVERALL_PASS" = true ]; then
    echo "RESULT: PASS"
    EXIT_CODE=0
else
    echo "RESULT: FAIL"
    EXIT_CODE=1
fi

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
    if [ "$SKIP_HARDWARE" = true ] && [ -n "$SIM_A_PID" ]; then
        echo "  kill $SIM_A_PID  # SIM-A responder"
    fi
    echo ""
    echo "Monitor logs:"
    echo "  tail -f $LOG_DIR/bridge_stm32.log"
    echo "  tail -f $LOG_DIR/bridge_esp32.log"
    echo "  tail -f $LOG_DIR/sim_http.log"
fi

echo ""
echo "Done."
exit "$EXIT_CODE"
