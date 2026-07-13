#!/usr/bin/env bash
# Overnight BLE L2CAP stability + FIPS restart recovery test.
#
# Runs for a configurable duration (default 8 hours), capturing:
#   - Connection uptime and drop frequency
#   - Heartbeat counts (tx/rx) at regular intervals
#   - FIPS daemon restart recovery (does ESP32 reconnect?)
#   - Serial log for post-mortem analysis
#
# Usage:
#   bash scripts/test_ble_overnight.sh [duration_hours]
#
# Output:
#   /tmp/overnight-stats.log — periodic stats snapshots (TSV)
#   /tmp/overnight-serial.log — full ESP32 serial output
#   /tmp/overnight-fips.log — FIPS daemon journal
#
# Requirements:
#   - ai-legion: ESP32-D0WD on /dev/ttyUSB0
#   - ai-legion-small: FIPS daemon + BLE adapter
#   - Latest firmware already flashed (run test_ble_l2cap.sh first)

set -euo pipefail

DURATION_HOURS="${1:-8}"
DURATION_SECS=$((DURATION_HOURS * 3600))
SAMPLE_INTERVAL=300  # 5 minutes between stats samples
RESTART_INTERVAL=3600  # Restart FIPS every hour to test recovery

SSH_SMALL="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion-small"
SSH_LEGION="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion"

echo "=== Overnight BLE Stability Test ==="
echo "Duration: ${DURATION_HOURS}h (${DURATION_SECS}s)"
echo "Sample interval: ${DURATION_SECS}s"
echo "FIPS restart interval: ${RESTART_INTERVAL}s"
echo "Start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Initialize log files on ai-legion
$SSH_LEGION 'sudo truncate -s 0 /tmp/overnight-serial.log 2>/dev/null; echo "ts,event" > /tmp/overnight-stats.log'

# Start serial capture in background on ai-legion
info() { echo "[$(date -u +%H:%M:%S)] $1"; }

info "Starting serial capture..."
$SSH_LEGION 'sudo python3 -c "
import serial, time
s = serial.Serial(\"/dev/ttyUSB0\", 115200, timeout=1)
start = time.time()
with open(\"/tmp/overnight-serial.log\", \"a\") as f:
    while True:
        data = s.read(4096)
        if data:
            elapsed = time.time() - start
            text = data.decode(errors=\"replace\")
            for line in text.splitlines():
                if line.strip():
                    f.write(f\"[{elapsed:.0f}s] {line.strip()}\n\")
                    f.flush()
        # Periodically grab stats
        if int(time.time() - start) % 300 == 0:
            s.write(b\"show_stats\n\")
            time.sleep(1)
            stats = s.read(4096)
            if stats:
                with open(\"/tmp/overnight-stats.log\", \"a\") as sf:
                    sf.write(f\"{time.time():.0f},stats: {stats.decode(errors='replace').strip()}\n\")
                    sf.flush()
s.close()
" &' 2>/dev/null

START_TIME=$(date +%s)
LAST_RESTART=0
SAMPLE_COUNT=0

while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))
    
    if [[ $ELAPSED -ge $DURATION_SECS ]]; then
        break
    fi
    
    # FIPS restart recovery test (every RESTART_INTERVAL)
    RESTART_ELAPSED=$((NOW - LAST_RESTART))
    if [[ $RESTART_ELAPSED -ge $RESTART_INTERVAL ]]; then
        info "Restarting FIPS daemon (recovery test)..."
        $SSH_SMALL 'sudo systemctl restart fips' 2>/dev/null
        LAST_RESTART=$NOW
        info "FIPS restarted. Monitoring ESP32 reconnection..."
        sleep 30
    fi
    
    # Sample stats
    info "Elapsed: ${ELAPSED}s / ${DURATION_SECS}s ($(echo "scale=1; $ELAPSED * 100 / $DURATION_SECS" | bc)%)"
    
    # Grab current stats from ESP32
    STATS=$($SSH_LEGION 'sudo python3 -c "
import serial, time, json
s = serial.Serial(\"/dev/ttyUSB0\", 115200, timeout=1)
s.write(b\"show_stats\n\")
time.sleep(1)
data = s.read(4096)
for line in data.decode(errors=\"replace\").splitlines():
    l = line.strip()
    if l.startswith(\"{\"):
        try:
            d = json.loads(l)[\"data\"]
            print(f\"hb_tx={d[\"hb_tx\"]} hb_rx={d[\"hb_rx\"]} msg2_rx={d[\"msg2_rx\"]} drops={d[\"l2cap_rx_drops\"]} timeouts={d[\"l2cap_recv_timeouts\"]}\")
        except: pass
s.close()
"' 2>&1) || STATS="(unreachable)"
    info "Stats: $STATS"
    
    sleep $SAMPLE_INTERVAL
done

info "Test complete. Fetching logs..."
echo ""
echo "=== Duration: ${DURATION_HOURS}h ==="
echo "=== End: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# Fetch final stats and serial log summary
$SSH_LEGION 'wc -l /tmp/overnight-serial.log; echo "---"; tail -20 /tmp/overnight-stats.log' 2>&1

info "Fetching FIPS journal for analysis..."
$SSH_SMALL "sudo journalctl -u fips --since '$DURATION_HOURS hours ago' --no-pager" 2>/dev/null | grep -cE "promoted|closed|dropped|recv timeout" | while read count; do
    info "FIPS events: $count total (promoted/closed/dropped/timeouts)"
done
