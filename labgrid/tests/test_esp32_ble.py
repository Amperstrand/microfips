import subprocess
import time

import pytest

MSG1_SIZE = 114
MSG2_SIZE = 69

PROJECT_ROOT = "/home/ubuntu/src2/microfips"
BLE_DEVICE_NAME = "microfips-esp32"


def _bleak_available():
    try:
        import bleak
        return True
    except ImportError:
        return False


def _flash_ble_firmware():
    from conftest import flash_esp32
    flash_esp32(variant="ble")
    time.sleep(8)


@pytest.fixture(scope="module")
def ble_ready():
    _flash_ble_firmware()

    import asyncio
    from bleak import BleakScanner

    async def scan():
        devices = await BleakScanner.discover(timeout=10)
        found = [d for d in devices if d.name and BLE_DEVICE_NAME in d.name.lower()]
        return found

    found = asyncio.run(scan())
    assert found, f"BLE device '{BLE_DEVICE_NAME}' not found in scan"
    return found[0]


@pytest.mark.skipif(not _bleak_available(), reason="bleak not installed")
def test_esp32_ble_handshake(ble_ready, fips_with_udp):
    bridge_proc = subprocess.Popen(
        [
            "python3",
            f"{PROJECT_ROOT}/tools/ble_udp_bridge.py",
            "--ble-name", BLE_DEVICE_NAME,
            "--udp-host", "127.0.0.1",
            "--verbose",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        deadline = time.time() + 45
        got_msg1 = False
        got_msg2 = False

        while time.time() < deadline:
            line = bridge_proc.stdout.readline()
            if not line:
                time.sleep(0.5)
                continue
            if "BLE->UDP" in line and f"{MSG1_SIZE}B" in line:
                got_msg1 = True
            if "UDP->BLE" in line and f"{MSG2_SIZE}B" in line:
                got_msg2 = True
            if got_msg1 and got_msg2:
                break

        assert got_msg1, f"Bridge never saw MSG1 ({MSG1_SIZE}B) from ESP32"
        assert got_msg2, f"Bridge never saw MSG2 ({MSG2_SIZE}B) from FIPS"
    finally:
        bridge_proc.terminate()
        bridge_proc.wait(timeout=5)


@pytest.mark.skipif(not _bleak_available(), reason="bleak not installed")
def test_esp32_ble_heartbeat(ble_ready, fips_with_udp):
    bridge_proc = subprocess.Popen(
        [
            "python3",
            f"{PROJECT_ROOT}/tools/ble_udp_bridge.py",
            "--ble-name", BLE_DEVICE_NAME,
            "--udp-host", "127.0.0.1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        deadline = time.time() + 45
        got_msg2 = False
        frames_after = 0

        while time.time() < deadline:
            line = bridge_proc.stdout.readline()
            if not line:
                time.sleep(0.5)
                continue
            if "UDP->BLE" in line and f"{MSG2_SIZE}B" in line:
                got_msg2 = True
            if got_msg2 and "BLE->UDP" in line:
                frames_after += 1
            if frames_after >= 3:
                break

        assert frames_after >= 3, f"Only {frames_after} frames after handshake, expected >= 3"
    finally:
        bridge_proc.terminate()
        bridge_proc.wait(timeout=5)
