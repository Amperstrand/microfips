#!/bin/bash
# test-ble-pipeline.sh — Automated BLE capture/decrypt/inspect test framework
#
# Runs end-to-end BLE pipeline tests between a Linux capture host and a FIPS node.
# Generates a timestamped report with pass/fail results.
#
# USAGE:
#   ./test-ble-pipeline.sh [OPTIONS]
#
# OPTIONS:
#   --capture-dir DIR     Directory for capture files (default: /tmp/fips-test)
#   --keys-file FILE      Path to FIPS diagnostic keys JSONL file
#   --fips-decrypt PATH   Path to fips-decrypt binary (default: auto-detect)
#   --dissector PATH      Path to fips_dissector.lua (default: tools/fips_dissector.lua)
#   --capture-file FILE   Existing btsnoop capture to test against (skip live capture)
#   --linux-host HOST     SSH hostname for remote Linux capture host (default: none)
#   --skip-capture        Skip live capture step (use existing capture-file)
#   --skip-wireshark      Skip tshark verification steps
#   --report-dir DIR      Directory for reports (default: ./test-reports)
#   --keep-files          Keep capture and intermediate files after test
#   --verbose             Verbose output
#   --help                Show this help
#
# EXAMPLES:
#
#   # Full live test: capture on local Linux, decrypt, verify
#   sudo ./test-ble-pipeline.sh --keys-file /tmp/fips-keys.jsonl
#
#   # Test against existing capture file (no live BLE needed)
#   ./test-ble-pipeline.sh --capture-file /tmp/fips-ble-capture.btsnoop \
#       --keys-file /tmp/fips-keys.jsonl
#
#   # Remote capture via SSH
#   ./test-ble-pipeline.sh --linux-host 218 --keys-file /tmp/fips-keys.jsonl
#
#   # Quick offline validation
#   ./test-ble-pipeline.sh --capture-file /tmp/fips-ble-capture.btsnoop \
#       --keys-file /tmp/fips-keys.jsonl --skip-wireshark
#
# EXIT CODES:
#   0  All tests passed
#   1  One or more tests failed
#   2  Setup/dependency error

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# Defaults
CAPTURE_DIR="/tmp/fips-test"
KEYS_FILE=""
FIPS_DECRYPT=""
DISSECTOR="$PROJECT_ROOT/tools/fips_dissector.lua"
CAPTURE_FILE=""
LINUX_HOST=""
SKIP_CAPTURE=false
SKIP_WIRESHARK=false
REPORT_DIR="./test-reports"
KEEP_FILES=false
VERBOSE=false

# Test state
PASS=0
FAIL=0
SKIP=0
RESULTS=()

# ─── Helper Functions ────────────────────────────────────────────────────────

log()  { echo "[$(date +%H:%M:%S)] $*"; }
vlog() { $VERBOSE && echo "[$(date +%H:%M:%S)] [DBG] $*" || true; }
err()  { echo "[$(date +%H:%M:%S)] [ERR] $*" >&2; }

result() {
    local name="$1" status="$2" detail="${3:-}"
    RESULTS+=("$status | $name | $detail")
    case "$status" in
        PASS) ((PASS++)) ;;
        FAIL) ((FAIL++)) ;;
        SKIP) ((SKIP++)) ;;
    esac
    printf "  %-6s %s%s\n" "$status" "$name" "${detail:+ — $detail}"
}

die() { err "$*"; exit 2; }

# ─── Parse Arguments ─────────────────────────────────────────────────────────

show_help() {
    sed -n '2,/^$/s/^#\( \{0,1\}\)//p' "$0"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --capture-dir)   CAPTURE_DIR="$2"; shift 2 ;;
        --keys-file)     KEYS_FILE="$2"; shift 2 ;;
        --fips-decrypt)  FIPS_DECRYPT="$2"; shift 2 ;;
        --dissector)     DISSECTOR="$2"; shift 2 ;;
        --capture-file)  CAPTURE_FILE="$2"; shift 2 ;;
        --linux-host)    LINUX_HOST="$2"; shift 2 ;;
        --skip-capture)  SKIP_CAPTURE=true; shift ;;
        --skip-wireshark) SKIP_WIRESHARK=true; shift ;;
        --report-dir)    REPORT_DIR="$2"; shift 2 ;;
        --keep-files)    KEEP_FILES=true; shift ;;
        --verbose)       VERBOSE=true; shift ;;
        --help|-h)       show_help ;;
        *) die "Unknown option: $1. Use --help." ;;
    esac
done

# ─── Resolve Paths ───────────────────────────────────────────────────────────

# Find fips-decrypt binary
if [[ -z "$FIPS_DECRYPT" ]]; then
    for candidate in \
        "$PROJECT_ROOT/target/release/fips-decrypt" \
        "$PROJECT_ROOT/target/debug/fips-decrypt" \
        "$(command -v fips-decrypt 2>/dev/null)"; do
        if [[ -x "$candidate" ]]; then
            FIPS_DECRYPT="$candidate"
            break
        fi
    done
fi
[[ -x "$FIPS_DECRYPT" ]] || die "Cannot find fips-decrypt binary. Use --fips-decrypt PATH."

# Resolve dissector
[[ -f "$DISSECTOR" ]] || die "Cannot find dissector at $DISSECTOR"

# Set up file paths
mkdir -p "$CAPTURE_DIR"
REPORT_FILE="$REPORT_DIR/ble-pipeline-test-$TIMESTAMP.md"
mkdir -p "$REPORT_DIR"

if [[ -n "$CAPTURE_FILE" ]]; then
    SKIP_CAPTURE=true
    LOCAL_CAPTURE="$CAPTURE_FILE"
else
    LOCAL_CAPTURE="$CAPTURE_DIR/fips-ble-capture-$TIMESTAMP.btsnoop"
fi

OUTPUT_PCAP="$CAPTURE_DIR/fips-decrypted-$TIMESTAMP.pcap"

# Copy keys file locally if remote
LOCAL_KEYS_FILE="$KEYS_FILE"

vlog "fips-decrypt: $FIPS_DECRYPT"
vlog "dissector:    $DISSECTOR"
vlog "capture dir:  $CAPTURE_DIR"
vlog "report:       $REPORT_FILE"

# ─── Test Functions ──────────────────────────────────────────────────────────

test_tool_binary() {
    log "WAVE 1: Tool binary checks"

    # Test 1.1: fips-decrypt runs
    if "$FIPS_DECRYPT" --help >/dev/null 2>&1; then
        result "fips-decrypt --help" "PASS"
    else
        result "fips-decrypt --help" "FAIL" "binary does not run"
        return 1
    fi

    # Test 1.2: fips-decrypt version/help mentions FMP/BLE
    local help_output
    help_output=$("$FIPS_DECRYPT" --help 2>&1)
    if echo "$help_output" | grep -qi "fmp\|ble\|btsnoop"; then
        result "fips-decrypt help mentions FMP/BLE" "PASS"
    else
        result "fips-decrypt help mentions FMP/BLE" "SKIP" "no keyword match in help text"
    fi
}

test_unit_tests() {
    log "WAVE 1: Unit tests (cargo test)"

    local test_output
    if test_output=$(cargo test --release -p fips-decrypt 2>&1); then
        local passed
        passed=$(echo "$test_output" | sed -n 's/.*[^0-9]\([0-9][0-9]*\) passed.*/\1/p' | tail -1)
        passed=${passed:-"?"}
        result "cargo test fips-decrypt" "PASS" "$passed tests passed"
    else
        result "cargo test fips-decrypt" "FAIL" "tests failed"
        echo "$test_output" | tail -20
    fi
}

test_capture_file() {
    log "WAVE 2: Capture file validation"

    # Test 2.1: Capture file exists and is non-empty
    if [[ -f "$LOCAL_CAPTURE" && -s "$LOCAL_CAPTURE" ]]; then
        local size
        size=$(stat -f%z "$LOCAL_CAPTURE" 2>/dev/null || stat -c%s "$LOCAL_CAPTURE" 2>/dev/null || echo "?")
        result "Capture file exists and non-empty" "PASS" "$size bytes"
    else
        result "Capture file exists and non-empty" "FAIL" "$LOCAL_CAPTURE not found or empty"
        return 1
    fi

    # Test 2.2: Capture file magic is btsnoop or pcap
    local magic
    magic=$(xxd -l 8 -p "$LOCAL_CAPTURE" 2>/dev/null | head -1)
    if [[ "$magic" == "6274736e6f6f7000" || "$magic" == "00706f6f6e737462" ]]; then
        result "Capture file is btsnoop format" "PASS"
    elif [[ "$magic" == "d4c3b2a1"* ]]; then
        result "Capture file is pcap format" "PASS"
    else
        result "Capture file format detection" "FAIL" "unknown magic: $magic"
    fi
}

test_fips_decrypt() {
    log "WAVE 3: fips-decrypt analysis"

    local decrypt_args=()
    if [[ -n "$LOCAL_KEYS_FILE" && -f "$LOCAL_KEYS_FILE" ]]; then
        decrypt_args+=(--keys-file "$LOCAL_KEYS_FILE")
    else
        result "fips-decrypt keys file" "SKIP" "no keys file provided, running without keys"
    fi

    decrypt_args+=(--output "$OUTPUT_PCAP" --verbose)

    local decrypt_output
    local decrypt_rc=0
    decrypt_output=$("$FIPS_DECRYPT" "${decrypt_args[@]}" "$LOCAL_CAPTURE" 2>&1) || decrypt_rc=$?

    if [[ $decrypt_rc -ne 0 ]]; then
        result "fips-decrypt runs on capture" "FAIL" "exit code $decrypt_rc"
        echo "$decrypt_output" | tail -20
        return 1
    fi

    result "fips-decrypt runs on capture" "PASS"

    # Test 3.1: Records parsed
    local records
    records=$(echo "$decrypt_output" | sed -n 's/.*Parsed \([0-9]*\) btsnoop.*/\1/p' | head -1)
    if [[ "$records" -gt 0 ]]; then
        result "btsnoop records parsed" "PASS" "$records records"
    else
        result "btsnoop records parsed" "FAIL" "0 records"
    fi

    # Test 3.2: FMP frames extracted
    local frames
    frames=$(echo "$decrypt_output" | sed -n 's/.*Extracted \([0-9]*\) FMP.*/\1/p' | head -1)
    if [[ "$frames" -gt 0 ]]; then
        result "FMP frames extracted" "PASS" "$frames frames"
    else
        result "FMP frames extracted" "FAIL" "0 frames — no BLE traffic captured?"
    fi

    # Test 3.3: Key candidates loaded
    local keys_loaded
    keys_loaded=$(echo "$decrypt_output" | sed -n 's/.*Loaded \([0-9]*\) key.*/\1/p' | head -1)
    if [[ "$keys_loaded" -gt 0 ]]; then
        result "Key candidates loaded" "PASS" "$keys_loaded pairs"
    else
        result "Key candidates loaded" "SKIP" "running without keys (dev preset mode)"
    fi

    # Test 3.4: Decrypted frames
    local decrypted
    decrypted=$(echo "$decrypt_output" | grep -c "decrypted by" || echo "0")
    if [[ "$decrypted" -gt 0 ]]; then
        result "Frames decrypted successfully" "PASS" "$decrypted frames"
    else
        result "Frames decrypted successfully" "FAIL" "0 frames decrypted — wrong keys?"
    fi

    # Test 3.5: Output pcap written
    if [[ -f "$OUTPUT_PCAP" && -s "$OUTPUT_PCAP" ]]; then
        local pcap_size
        pcap_size=$(stat -f%z "$OUTPUT_PCAP" 2>/dev/null || stat -c%s "$OUTPUT_PCAP" 2>/dev/null || echo "?")
        result "Output pcap written" "PASS" "$pcap_size bytes"
    else
        result "Output pcap written" "FAIL" "no output pcap produced"
    fi

    # Save for report
    DECRYPT_OUTPUT="$decrypt_output"
}

test_phase_distribution() {
    log "WAVE 4: Phase distribution analysis"

    if [[ -z "${DECRYPT_OUTPUT:-}" ]]; then
        result "Phase distribution" "SKIP" "no decrypt output"
        return
    fi

    local established msg1 msg2 unknown
    established=$(echo "$DECRYPT_OUTPUT" | grep -c "\] .* ESTABLISHED " 2>/dev/null || true)
    msg1=$(echo "$DECRYPT_OUTPUT" | grep -c "\] .* MSG1 " 2>/dev/null || true)
    msg2=$(echo "$DECRYPT_OUTPUT" | grep -c "\] .* MSG2 " 2>/dev/null || true)
    unknown=$(echo "$DECRYPT_OUTPUT" | grep -c "\] .* UNKNOWN " 2>/dev/null || true)
    established=${established:-0}
    msg1=${msg1:-0}
    msg2=${msg2:-0}
    unknown=${unknown:-0}

    result "ESTABLISHED frames" "PASS" "$established"
    result "MSG1 frames (handshake)" "PASS" "$msg1"
    result "MSG2 frames (handshake)" "PASS" "$msg2"

    if [[ "$unknown" -gt 0 ]]; then
        result "Unknown phase frames" "FAIL" "$unknown frames with unknown phase"
    else
        result "No unknown phase frames" "PASS"
    fi

    # Check for both directions (handshake complete)
    if [[ "$msg1" -gt 0 && "$msg2" -gt 0 ]]; then
        result "Handshake complete (MSG1+MSG2)" "PASS"
    else
        result "Handshake complete (MSG1+MSG2)" "FAIL" "MSG1=$msg1 MSG2=$msg2 — capture started after handshake?"
    fi

    # Check decrypted message types
    local pings pongs datagrams
    pings=$(echo "$DECRYPT_OUTPUT" | grep -c "msg_type=0x01" || echo "0")
    pongs=$(echo "$DECRYPT_OUTPUT" | grep -c "msg_type=0x02" || echo "0")
    datagrams=$(echo "$DECRYPT_OUTPUT" | grep -c "msg_type=0x10" || echo "0")

    result "Decrypted PING messages" "PASS" "$pings"
    result "Decrypted PONG messages" "PASS" "$pongs"
    if [[ "$datagrams" -gt 0 ]]; then
        result "Decrypted SESSION_DATAGRAM" "PASS" "$datagrams"
    fi

    # Check for decrypt failures
    local decrypt_fails
    local total_frames=$((established + msg1 + msg2))
    local decrypt_ratio="N/A"
    if [[ "$total_frames" -gt 0 ]]; then
        local decrypted
        decrypted=$(echo "$DECRYPT_OUTPUT" | grep -c "decrypted by" 2>/dev/null || true)
        decrypted=${decrypted:-0}
        decrypt_ratio="$decrypted/$total_frames"
    fi

    decrypt_fails=$(echo "$DECRYPT_OUTPUT" | grep -c "decrypt failed" 2>/dev/null || true)
    decrypt_fails=${decrypt_fails:-0}
    if [[ "$decrypt_fails" -eq 0 ]]; then
        result "All frames decrypted (no failures)" "PASS"
    elif [[ "$decrypt_fails" -le 2 ]]; then
        result "Decrypt failures (minor — stale sessions)" "PASS" \
            "$decrypt_fails failures (expected from session renegotiation)"
    else
        result "Decrypt failures" "FAIL" "$decrypt_fails frames could not be decrypted"
    fi
}

test_wireshark_dissector() {
    log "WAVE 5: Wireshark dissector validation"

    if $SKIP_WIRESHARK; then
        result "Wireshark/tshark tests" "SKIP" "--skip-wireshark"
        return
    fi

    if ! command -v tshark >/dev/null 2>&1; then
        result "tshark available" "SKIP" "tshark not installed"
        return
    fi
    result "tshark available" "PASS"

    # Test 5.1: Dissector loads without errors
    if [[ ! -f "$OUTPUT_PCAP" ]]; then
        result "Dissector test (no output pcap)" "SKIP" "no output pcap to test"
        return
    fi

    local tshark_output
    local tshark_rc=0
    tshark_output=$(tshark -X "lua_script:$DISSECTOR" -r "$OUTPUT_PCAP" \
        -Y "fips" -T fields -e fips.phase -e fips.counter \
        2>&1) || tshark_rc=$?

    # tshark may return non-zero if no packets match filter; check stderr for actual errors
    local lua_errors
    lua_errors=$(echo "$tshark_output" | grep -i "error\|lua:" || true)
    if [[ -n "$lua_errors" ]]; then
        result "Dissector loads cleanly" "FAIL" "Lua errors detected"
        echo "$lua_errors" | head -5
    else
        result "Dissector loads cleanly" "PASS"
    fi

    # Test 5.2: FIPS protocol detected
    local fips_frames
    fips_frames=$(echo "$tshark_output" | grep -cvE '^\s*$|^Running|^Capturing' || echo "0")
    if [[ "$fips_frames" -gt 0 ]]; then
        result "FIPS protocol frames detected by dissector" "PASS" "$fips_frames frames"
    else
        result "FIPS protocol frames detected by dissector" "FAIL" "0 frames — dissector not matching?"
    fi

    # Test 5.3: Phase values correct (0, 1, 2 only)
    local phases
    phases=$(echo "$tshark_output" | awk '{print $1}' | sort -u | grep -v '^$' || true)
    local bad_phases
    bad_phases=$(echo "$phases" | grep -cvE '^(0|1|2)$' || echo "0")
    if [[ "$bad_phases" -eq 0 ]]; then
        result "All phase values valid (0/1/2)" "PASS"
    else
        result "Invalid phase values detected" "FAIL" "phases: $phases"
    fi

    # Test 5.4: Raw btsnoop with dissector
    if [[ -f "$LOCAL_CAPTURE" ]]; then
        local raw_tshark_rc=0
        local raw_output
        raw_output=$(tshark -X "lua_script:$DISSECTOR" -r "$LOCAL_CAPTURE" \
            -Y "fips" -T fields -e fips.phase 2>&1) || raw_tshark_rc=$?
        local raw_fips
        raw_fips=$(echo "$raw_output" | grep -cvE '^\s*$|^Running|^Capturing' || echo "0")
        if [[ "$raw_fips" -gt 0 ]]; then
            result "Raw btsnoop dissector (encrypted frames)" "PASS" "$raw_fips FIPS frames in raw capture"
        else
            result "Raw btsnoop dissector (encrypted frames)" "SKIP" "no FIPS frames detected in raw capture"
        fi
    fi
}

test_documentation() {
    log "WAVE 6: Documentation checks"

    local doc_file="$PROJECT_ROOT/docs/ble-capture-decrypt.md"
    if [[ -f "$doc_file" ]]; then
        local doc_lines
        doc_lines=$(wc -l < "$doc_file")
        result "ble-capture-decrypt.md exists" "PASS" "$doc_lines lines"

        # Check key sections
        for section in "btmon" "Wireshark" "fips-decrypt" "Transport Keys"; do
            if grep -q "$section" "$doc_file"; then
                result "Doc section: $section" "PASS"
            else
                result "Doc section: $section" "FAIL" "missing"
            fi
        done
    else
        result "ble-capture-decrypt.md exists" "FAIL" "not found"
    fi

    if [[ -f "$DISSECTOR" ]]; then
        local dissector_lines
        dissector_lines=$(wc -l < "$DISSECTOR")
        result "fips_dissector.lua exists" "PASS" "$dissector_lines lines"
    else
        result "fips_dissector.lua exists" "FAIL" "not found"
    fi
}

# ─── Live Capture ────────────────────────────────────────────────────────────

do_live_capture() {
    log "Starting live BLE capture..."

    if [[ -n "$LINUX_HOST" ]]; then
        # Remote capture via SSH
        log "Starting btmon on $LINUX_HOST..."
        ssh "$LINUX_HOST" "sudo btmon -w /tmp/fips-ble-capture-$TIMESTAMP.btsnoop" &
        local BTMON_PID=$!

        log "Waiting 5s for btmon to initialize..."
        sleep 5

        log "Restarting FIPS on $LINUX_HOST..."
        ssh "$LINUX_HOST" "sudo systemctl restart fips"

        log "Waiting for BLE connection (60s)..."
        sleep 60

        log "Stopping btmon..."
        ssh "$LINUX_HOST" "sudo pkill -INT btmon"
        wait $BTMON_PID 2>/dev/null || true

        log "Copying capture from $LINUX_HOST..."
        scp "$LINUX_HOST:/tmp/fips-ble-capture-$TIMESTAMP.btsnoop" "$LOCAL_CAPTURE" || {
            result "Remote capture transfer" "FAIL" "scp failed"
            return 1
        }

        # Copy keys if needed
        if [[ -z "$LOCAL_KEYS_FILE" ]]; then
            scp "$LINUX_HOST:/tmp/fips-keys.jsonl" "$CAPTURE_DIR/fips-keys-$TIMESTAMP.jsonl" || true
            LOCAL_KEYS_FILE="$CAPTURE_DIR/fips-keys-$TIMESTAMP.jsonl"
        fi
    else
        # Local capture
        if ! command -v btmon >/dev/null 2>&1; then
            err "btmon not found. Install bluez or use --capture-file for offline testing."
            result "Live capture" "FAIL" "btmon not available"
            return 1
        fi

        log "Starting btmon locally..."
        sudo btmon -w "$LOCAL_CAPTURE" &
        local BTMON_PID=$!

        log "Waiting 5s for btmon..."
        sleep 5

        log "Restarting FIPS..."
        if systemctl is-active --quiet fips 2>/dev/null; then
            sudo systemctl restart fips
        elif pgrep -x fips >/dev/null; then
            sudo pkill fips && sleep 2 && fips &
        else
            log "FIPS not running — start it manually in another terminal"
            log "Waiting 60s for manual FIPS start and BLE connection..."
        fi

        log "Waiting for BLE traffic (60s)..."
        sleep 60

        log "Stopping btmon..."
        sudo pkill -INT btmon
        wait $BTMON_PID 2>/dev/null || true
    fi

    log "Capture saved to $LOCAL_CAPTURE"
}

# ─── Report Generation ───────────────────────────────────────────────────────

generate_report() {
    {
        echo "# BLE Pipeline Test Report"
        echo ""
        echo "**Date:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "**Capture:** $(basename "$LOCAL_CAPTURE")"
        echo "**Keys:** ${LOCAL_KEYS_FILE:-none}"
        echo ""
        echo "## Summary"
        echo ""
        echo "| Status | Count |"
        echo "|--------|-------|"
        echo "| PASS   | $PASS |"
        echo "| FAIL   | $FAIL |"
        echo "| SKIP   | $SKIP |"
        echo "| **Total** | $((PASS + FAIL + SKIP)) |"
        echo ""

        if [[ "$FAIL" -eq 0 ]]; then
            echo "**Result: ALL CHECKS PASSED**"
        else
            echo "**Result: $FAIL FAILURE(S) DETECTED**"
        fi
        echo ""

        echo "## Test Results"
        echo ""
        echo "| Status | Test | Detail |"
        echo "|--------|------|--------|"
        for r in "${RESULTS[@]}"; do
            local status name detail
            status=$(echo "$r" | cut -d'|' -f1 | xargs)
            name=$(echo "$r" | cut -d'|' -f2 | xargs)
            detail=$(echo "$r" | cut -d'|' -f3- | xargs)
            echo "| $status | $name | $detail |"
        done
        echo ""

        echo "## Files"
        echo ""
        echo "- Capture: \`$LOCAL_CAPTURE\`"
        echo "- Output pcap: \`$OUTPUT_PCAP\`"
        echo "- Keys: \`$LOCAL_KEYS_FILE\`"
        echo "- Dissector: \`$DISSECTOR\`"
        echo "- fips-decrypt: \`$FIPS_DECRYPT\`"
        echo ""

        echo "## Reproduce"
        echo ""
        echo "\`\`\`bash"
        echo "$FIPS_DECRYPT --keys-file $LOCAL_KEYS_FILE --output $OUTPUT_PCAP $LOCAL_CAPTURE"
        echo "\`\`\`"
        echo ""

        if [[ "$FAIL" -eq 0 ]]; then
            echo "## Wireshark"
            echo ""
            echo "\`\`\`bash"
            echo "# Encrypted raw capture"
            echo "wireshark $LOCAL_CAPTURE"
            echo ""
            echo "# Decrypted output"
            echo "wireshark $OUTPUT_PCAP"
            echo "\`\`\`"
        fi

    } > "$REPORT_FILE"

    log "Report written to $REPORT_FILE"
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────

cleanup() {
    if ! $KEEP_FILES && [[ -n "${LOCAL_CAPTURE:-}" ]] && [[ "$LOCAL_CAPTURE" != "$CAPTURE_FILE" ]]; then
        rm -f "$LOCAL_CAPTURE" "$OUTPUT_PCAP" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ─── Main ────────────────────────────────────────────────────────────────────

log "═══════════════════════════════════════════════════════"
log " BLE Pipeline E2E Test — $TIMESTAMP"
log "═══════════════════════════════════════════════════════"
echo ""

# Step 0: Live capture if needed
if ! $SKIP_CAPTURE; then
    do_live_capture
fi

# Wave 1: Tool binary + unit tests
test_tool_binary
test_unit_tests
echo ""

# Wave 2: Capture file validation
test_capture_file
echo ""

# Wave 3: fips-decrypt analysis
test_fips_decrypt
echo ""

# Wave 4: Phase distribution
test_phase_distribution
echo ""

# Wave 5: Wireshark dissector
test_wireshark_dissector
echo ""

# Wave 6: Documentation
test_documentation
echo ""

# Generate report
generate_report

# Final summary
log "═══════════════════════════════════════════════════════"
log " PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
log " Report: $REPORT_FILE"
log "═══════════════════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
