#!/usr/bin/env python3
"""Test the ESP32 BLE/L2CAP control interface over UART0.

Sends commands, reads JSON responses, validates structure.
Requires L2CAP or BLE firmware flashed on ESP32 (/dev/ttyUSB0).
"""

import json
import sys
import time
from serial import Serial


def find_esp32_port():
    for p in ["/dev/ttyUSB0", "/dev/ttyUSB1"]:
        try:
            with open(f"/sys/class/tty/{p[5:]}/device/../uevent") as f:
                if "10c4/ea60/100" in f.read():
                    return p
        except (FileNotFoundError, KeyError):
            pass
    return None


def send_command(ser: Serial, cmd: str, timeout: float = 2.0) -> str:
    ser.write((cmd + "\n").encode())
    ser.flush()
    lines = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = ser.readline().decode(errors="replace").strip()
        if line and not line.startswith("["):
            return line
    return ""


def validate_json_response(raw: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"  FAIL: invalid JSON: {e}")
        print(f"  Raw: {raw}")
        sys.exit(1)

    assert "status" in data, "missing 'status' field"
    if data["status"] == "error":
        print(f"  Got expected error: {data.get('message', '?')}")
        return data

    assert data["status"] == "ok", f"expected status 'ok', got '{data['status']}'"
    assert "data" in data, "missing 'data' field"
    return data


def test_version(ser: Serial):
    print("[test] version")
    raw = send_command(ser, "version")
    assert raw.startswith("microfips-esp32"), f"bad version prefix: {raw}"
    print(f"  OK: {raw}")


def test_help(ser: Serial):
    print("[test] help")
    raw = send_command(ser, "help")
    assert "show_status" in raw, f"missing show_status in help: {raw}"
    assert "show_peers" in raw, f"missing show_peers in help: {raw}"
    assert "show_stats" in raw, f"missing show_stats in help: {raw}"
    print(f"  OK: {raw}")


def test_show_status(ser: Serial):
    print("[test] show_status")
    resp = validate_json_response(send_command(ser, "show_status"))
    d = resp["data"]
    for field in ["node_addr", "npub", "state", "uptime_secs", "transport_type"]:
        assert field in d, f"missing field '{field}' in show_status"
    assert len(d["node_addr"]) == 32, f"node_addr should be 32 hex chars, got {len(d['node_addr'])}"
    assert d["node_addr"] == "0135da2f8acf7b9e3090939432e47684", f"unexpected node_addr: {d['node_addr']}"
    print(f"  OK: state={d['state']}, uptime={d['uptime_secs']}s, transport={d['transport_type']}")


def test_show_stats(ser: Serial):
    print("[test] show_stats")
    resp = validate_json_response(send_command(ser, "show_stats"))
    d = resp["data"]
    for field in ["msg1_tx", "msg2_rx", "hb_tx", "hb_rx", "data_tx", "data_rx"]:
        assert field in d, f"missing field '{field}' in show_stats"
        assert isinstance(d[field], int), f"field '{field}' should be int, got {type(d[field])}"
    print(f"  OK: msg1_tx={d['msg1_tx']}, hb_tx={d['hb_tx']}, hb_rx={d['hb_rx']}")


def test_show_peers(ser: Serial, expect_peer: bool):
    print("[test] show_peers")
    resp = validate_json_response(send_command(ser, "show_peers"))
    if resp["status"] == "error":
        if not expect_peer:
            print(f"  OK: no peer connected (expected)")
            return
        print(f"  UNEXPECTED: expected peer but got error: {resp.get('message')}")
        return
    d = resp["data"]
    for field in ["node_addr", "pubkey"]:
        assert field in d, f"missing field '{field}' in show_peers"
    print(f"  OK: peer node_addr={d['node_addr'][:16]}...")


def test_unknown_command(ser: Serial):
    print("[test] unknown command")
    resp = validate_json_response(send_command(ser, "bogus"))
    assert resp["status"] == "error", f"expected error for unknown command, got {resp['status']}"
    print(f"  OK: {resp.get('message')}")


def test_reset(ser: Serial):
    """Send reset command, verify ESP32 reboots and responds afterward."""
    print("[test] reset")
    port = ser.port
    ser.write(b"reset\n")
    ser.flush()
    ser.close()
    print("  Waiting for reboot (rst:0x3 expected)...")
    time.sleep(3)
    booted = False
    for attempt in range(20):
        try:
            new_ser = Serial(port, 115200, timeout=2)
            time.sleep(0.3)
            while new_ser.in_waiting:
                new_ser.readline()
            new_ser.write(b"version\n")
            new_ser.flush()
            time.sleep(0.5)
            deadline = time.time() + 2
            while time.time() < deadline:
                line = new_ser.readline().decode(errors="replace").strip()
                if line and "microfips-esp32" in line:
                    print(f"  OK: Rebooted after {attempt + 1}s: {line}")
                    new_ser.close()
                    return new_ser
            new_ser.close()
        except (Exception, OSError):
            pass
        time.sleep(1)
    print("  FAIL: ESP32 did not reboot within 20s")
    return None


def drain_lines(ser: Serial, count: int = 20, timeout: float = 0.5):
    """Read and discard startup log lines."""
    deadline = time.time() + timeout
    while time.time() < deadline and count > 0:
        line = ser.readline().decode(errors="replace").strip()
        if line:
            count -= 1


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else find_esp32_port()
    if not port:
        print("ERROR: ESP32 not found on /dev/ttyUSB0 or /dev/ttyUSB1")
        sys.exit(1)

    print(f"Using port: {port}")

    ser = Serial(port, 115200, timeout=1)
    drain_lines(ser, timeout=3)

    passed = 0
    failed = 0

    try:
        test_version(ser)
        passed += 1
    except Exception as e:
        print(f"  FAIL: {e}")
        failed += 1

    try:
        test_help(ser)
        passed += 1
    except Exception as e:
        print(f"  FAIL: {e}")
        failed += 1

    try:
        test_show_status(ser)
        passed += 1
    except Exception as e:
        print(f"  FAIL: {e}")
        failed += 1

    try:
        test_show_stats(ser)
        passed += 1
    except Exception as e:
        print(f"  FAIL: {e}")
        failed += 1

    try:
        test_show_peers(ser, expect_peer=False)
        passed += 1
    except Exception as e:
        print(f"  FAIL: {e}")
        failed += 1

    try:
        test_unknown_command(ser)
        passed += 1
    except Exception as e:
        print(f"  FAIL: {e}")
        failed += 1

    try:
        new_ser = test_reset(ser)
        if new_ser is not None:
            passed += 1
            ser = new_ser
        else:
            failed += 1
    except Exception as e:
        print(f"  FAIL: {e}")
        failed += 1

    ser.close()

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)
    print("All tests passed!")


if __name__ == "__main__":
    main()
