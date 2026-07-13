#!/usr/bin/env python3
"""Continuous ESP32 serial monitor for overnight BLE stability testing.

Runs for a configurable duration, capturing all serial output and periodically
sampling show_stats. Handles serial line fragmentation gracefully.

Usage: sudo python3 overnight_monitor.py [duration_hours]
Output: /tmp/overnight-serial.log, /tmp/overnight-stats.tsv
"""
import serial, time, json, sys, re

DURATION_SECS = int(float(sys.argv[1]) * 3600) if len(sys.argv) > 1 else 28800
SAMPLE_INTERVAL = 300  # 5 minutes

s = serial.Serial("/dev/ttyUSB0", 115200, timeout=0.5)

serial_log = open("/tmp/overnight-serial.log", "w")
stats_log = open("/tmp/overnight-stats.tsv", "w")
stats_log.write("timestamp\telapsed_h\thb_tx\thb_rx\tmsg2_rx\tpubkey_ok\tdrops\ttimeouts\n")

start = time.time()
buffer = ""
last_sample = 0
handshake_count = 0
drop_count = 0

print(f"Overnight monitor started: {DURATION_SECS}s ({DURATION_SECS/3600:.1f}h)")

while time.time() - start < DURATION_SECS:
    elapsed = time.time() - start
    elapsed_h = elapsed / 3600

    data = s.read(4096)
    if data:
        text = data.decode("utf-8", errors="replace")
        buffer += text

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue

            serial_log.write(f"[{elapsed:.0f}s] {line}\n")
            serial_log.flush()

            if "handshake ok" in line:
                handshake_count += 1
                print(f"[{elapsed_h:.2f}h] HANDSHAKE OK (#{handshake_count})")
            elif "InvalidMessage" in line:
                print(f"[{elapsed_h:.2f}h] HANDSHAKE FAILED: {line}")
            elif "relay recv error" in line or "ChannelClosed" in line:
                drop_count += 1
                print(f"[{elapsed_h:.2f}h] CONNECTION DROP (#{drop_count})")
            elif "BLE advertising started" in line:
                print(f"[{elapsed_h:.2f}h] ESP32 ADVERTISING (post-drop recovery)")

    if elapsed - last_sample >= SAMPLE_INTERVAL:
        last_sample = elapsed
        s.write(b"show_stats\n")
        time.sleep(1.5)
        stats_data = s.read(4096)
        if stats_data:
            stats_text = stats_data.decode("utf-8", errors="replace")
            for line in stats_text.splitlines():
                l = line.strip()
                if l.startswith("{"):
                    try:
                        d = json.loads(l)["data"]
                        stats_log.write(
                            f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\t"
                            f"{elapsed_h:.3f}\t{d.get('hb_tx',0)}\t{d.get('hb_rx',0)}\t"
                            f"{d.get('msg2_rx',0)}\t{d.get('l2cap_pubkey_ok',0)}\t"
                            f"{d.get('l2cap_rx_drops',0)}\t{d.get('l2cap_recv_timeouts',0)}\n"
                        )
                        stats_log.flush()
                        print(f"[{elapsed_h:.2f}h] STATS: hb_tx={d.get('hb_tx',0)} hb_rx={d.get('hb_rx',0)} "
                              f"msg2_rx={d.get('msg2_rx',0)} drops={d.get('l2cap_rx_drops',0)} "
                              f"handshakes={handshake_count} conn_drops={drop_count}")
                    except Exception:
                        pass

serial_log.close()
stats_log.close()
s.close()

print(f"\n=== OVERNIGHT TEST COMPLETE ===")
print(f"Duration: {DURATION_SECS/3600:.1f}h")
print(f"Total handshakes: {handshake_count}")
print(f"Total connection drops: {drop_count}")
print(f"Serial log: /tmp/overnight-serial.log")
print(f"Stats log: /tmp/overnight-stats.tsv")
