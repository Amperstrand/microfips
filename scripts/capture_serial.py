#!/usr/bin/env python3
"""Capture ESP32 serial output post-reset, verify IK handshake + heartbeats."""
import serial, time, json, sys

CAPTURE_SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 45

s = serial.Serial("/dev/ttyUSB0", 115200, timeout=0.1)

# Hardware reset via DTR/RTS
s.dtr = False
s.rts = True
time.sleep(0.1)
s.dtr = True
s.rts = True
time.sleep(0.05)
s.dtr = False
s.rts = False
time.sleep(0.2)

start = time.time()
got_handshake = False
got_hb_tx = False
got_hb_rx = False

while time.time() - start < CAPTURE_SECS:
    data = s.read(4096)
    if data:
        for line in data.decode(errors="replace").splitlines():
            l = line.strip()
            if not l:
                continue
            elapsed = time.time() - start
            if "handshake ok" in l:
                got_handshake = True
                print(f"[{elapsed:5.1f}s] HANDSHAKE OK")
            elif "InvalidMessage" in l:
                print(f"[{elapsed:5.1f}s] HANDSHAKE FAILED: {l}")
            elif "sending heartbeat" in l and "timer" in l:
                got_hb_tx = True
                print(f"[{elapsed:5.1f}s] HB_TX")
            elif "heartbeat received" in l:
                got_hb_rx = True
            elif "BLE connection accepted" in l:
                print(f"[{elapsed:5.1f}s] BLE CONNECTED")
            elif "entering IK responder" in l:
                print(f"[{elapsed:5.1f}s] IK RESPONDER PATH")

# Grab stats
s.write(b"show_stats\n")
time.sleep(2)
data = s.read(4096)
hb_tx = 0
hb_rx = 0
msg2_rx = 0
pubkey_ok = 0
for line in data.decode(errors="replace").splitlines():
    l = line.strip()
    if l.startswith("{"):
        try:
            d = json.loads(l)["data"]
            hb_tx = d.get("hb_tx", 0)
            hb_rx = d.get("hb_rx", 0)
            msg2_rx = d.get("msg2_rx", 0)
            pubkey_ok = d.get("l2cap_pubkey_ok", 0)
        except Exception:
            pass
s.close()

# Output machine-parseable result on the last line
print(f"RESULT handshake={got_handshake} hb_tx={hb_tx} hb_rx={hb_rx} msg2_rx={msg2_rx} pubkey_ok={pubkey_ok}")

# Exit code: 0 = pass, 1 = fail
if got_handshake and hb_tx > 0:
    sys.exit(0)
else:
    sys.exit(1)
