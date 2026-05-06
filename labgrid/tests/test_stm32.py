import struct
import subprocess
import time

import pytest

EXPECTED_NODE_ADDR = "132f39a98c31baaddba6525f5d43f295"

MSG1_SIZE = 114
MSG2_SIZE = 69


def find_mcu_cdc_port(timeout=15):
    import os
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in sorted(os.listdir("/dev")):
            if not p.startswith("ttyACM"):
                continue
            try:
                with open(f"/sys/class/tty/{p}/device/../uevent") as f:
                    for line in f:
                        if line.strip().startswith("PRODUCT="):
                            vid_pid = line.strip().split("=", 1)[1]
                            if vid_pid == "c0de/cafe/10":
                                return f"/dev/{p}"
            except FileNotFoundError:
                continue
        time.sleep(1)
    return None


@pytest.fixture(scope="module")
def stm32_serial():
    import serial as pyserial
    from conftest import flash_stm32

    flash_stm32()

    port = find_mcu_cdc_port(timeout=15)
    assert port is not None, "STM32 USB CDC did not enumerate after flashing"

    ser = pyserial.Serial(port, 115200, timeout=2)
    yield ser
    ser.close()


def test_stm32_fips_framing(stm32_serial):
    hdr = stm32_serial.read(2)
    assert len(hdr) == 2, "No response from STM32"
    frame_len = struct.unpack("<H", hdr)[0]
    assert frame_len > 0, f"Zero-length frame"
    assert frame_len <= 1024, f"Frame too large: {frame_len}"

    payload = stm32_serial.read(frame_len)
    assert len(payload) == frame_len, f"Short read: got {len(payload)}, expected {frame_len}"


def test_stm32_handshake_via_bridge(stm32_serial, fips_with_udp):
    port = stm32_serial.port
    stm32_serial.close()

    time.sleep(2)

    bridge_proc = subprocess.Popen(
        [
            "python3",
            "/home/ubuntu/src2/microfips/tools/serial_udp_bridge.py",
            "--serial", port,
            "--udp-host", "127.0.0.1",
            "--udp-port", "2121",
            "--bind-port", "31337",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        deadline = time.time() + 60
        got_msg1 = False
        got_msg2 = False
        got_heartbeat = False

        while time.time() < deadline:
            line = bridge_proc.stdout.readline()
            if not line:
                time.sleep(0.5)
                continue
            if "CDC->UDP" in line and f"{MSG1_SIZE}B" in line:
                got_msg1 = True
            if "UDP->CDC" in line and f"{MSG2_SIZE}B" in line:
                got_msg2 = True
            if "CDC->UDP" in line and got_msg2 and "frame#1" not in line:
                got_heartbeat = True

            if got_msg1 and got_msg2 and got_heartbeat:
                break

        assert got_msg1, f"Bridge never saw MSG1 ({MSG1_SIZE}B) from STM32"
        assert got_msg2, f"Bridge never saw MSG2 ({MSG2_SIZE}B) from FIPS"
        assert got_heartbeat, "Bridge never saw a post-handshake frame from STM32"
    finally:
        bridge_proc.terminate()
        bridge_proc.wait(timeout=5)
