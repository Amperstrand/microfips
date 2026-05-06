import subprocess
import time

import pytest

MSG1_SIZE = 114
MSG2_SIZE = 69

PROJECT_ROOT = "/home/ubuntu/src2/microfips"


@pytest.fixture(scope="module")
def uart_port():
    from conftest import flash_esp32
    flash_esp32(variant="uart")
    time.sleep(3)
    import os
    for p in sorted(os.listdir("/dev")):
        if not p.startswith("ttyUSB"):
            continue
        try:
            with open(f"/sys/class/tty/{p}/device/../uevent") as f:
                for line in f:
                    if "10c4/ea60" in line.strip():
                        return f"/dev/{p}"
        except FileNotFoundError:
            continue
    pytest.skip("ESP32-D0WD not found after flash")


def test_esp32_uart_handshake(uart_port, fips_with_udp):
    bridge_proc = subprocess.Popen(
        [
            "python3",
            f"{PROJECT_ROOT}/tools/serial_udp_bridge.py",
            "--serial", uart_port,
            "--udp-host", "127.0.0.1",
            "--udp-port", "2121",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        deadline = time.time() + 30
        got_msg1 = False
        got_msg2 = False

        while time.time() < deadline:
            line = bridge_proc.stdout.readline()
            if not line:
                time.sleep(0.5)
                continue
            if "CDC->UDP" in line and f"{MSG1_SIZE}B" in line:
                got_msg1 = True
            if "UDP->CDC" in line and f"{MSG2_SIZE}B" in line:
                got_msg2 = True
            if got_msg1 and got_msg2:
                break

        assert got_msg1, f"Bridge never saw MSG1 ({MSG1_SIZE}B) from ESP32"
        assert got_msg2, f"Bridge never saw MSG2 ({MSG2_SIZE}B) from FIPS"
    finally:
        bridge_proc.terminate()
        bridge_proc.wait(timeout=5)


def test_esp32_uart_heartbeat(uart_port, fips_with_udp):
    bridge_proc = subprocess.Popen(
        [
            "python3",
            f"{PROJECT_ROOT}/tools/serial_udp_bridge.py",
            "--serial", uart_port,
            "--udp-host", "127.0.0.1",
            "--udp-port", "2121",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        deadline = time.time() + 30
        got_msg2 = False
        frames_after = 0

        while time.time() < deadline:
            line = bridge_proc.stdout.readline()
            if not line:
                time.sleep(0.5)
                continue
            if "UDP->CDC" in line and f"{MSG2_SIZE}B" in line:
                got_msg2 = True
            if got_msg2 and "CDC->UDP" in line:
                frames_after += 1
            if frames_after >= 3:
                break

        assert frames_after >= 3, f"Only {frames_after} frames after handshake, expected >= 3"
    finally:
        bridge_proc.terminate()
        bridge_proc.wait(timeout=5)
