"""Per-board deployment smoke (issue #191): build → flash → boot evidence.

Thin by design — protocol depth lives in fips-lab's scenarios; this suite
proves each registry board takes a fresh pinned build, boots it, and shows
transport-level life. All machinery is fips_lab.bench (single
implementation, no drift). Needles derive from emitting firmware source /
proven scenarios (playbook pattern 10):
    s3-lab  wifi:  "WiFi connected" → "handshake ok" → heartbeat (lab daemon)
    atom-a  l2cap: "handshake ok" → heartbeat (lab daemon, BLE)
    stm32   cdc:   MSG1 within DTR-open — auto-skipped while c0de:cafe is
                   not enumerated on the bench (board off / USB absent)

Run: make test-hil (microfips repo root).
"""

import json
import sys
import time
from pathlib import Path

import pytest

FIPS_LAB_ROOT = Path(__file__).resolve().parents[4] / "fips-lab"
if str(FIPS_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(FIPS_LAB_ROOT))

from fips_lab import bench  # noqa: E402

from hil import board_role  # noqa: E402

GENERATOR_MUL = {"F4:12:FA:CF:03:84": 9, "81528A13B6": 11}
LAB_DAEMON_MUL = 8
VARIANTS = {
    "F4:12:FA:CF:03:84": "wifi",
    "81528A13B6": "l2cap",
    "9D529068B4": "l2cap",
    "cc:8d:a2:2c:91:98": "wifi",
    "cc:8d:a2:2c:94:08": "wifi",
    "stm32f469i-disco": "cdc",
}


@pytest.mark.hardware
@pytest.mark.flash_mutation
@pytest.mark.timeout(900)
def test_smoke_flash_boot_handshake(attached_board, registry, rig_lock):
    variant = VARIANTS.get(attached_board)
    if variant is None:
        pytest.skip(f"no smoke variant defined for {attached_board}")
    if variant == "cdc":
        if bench.find_stm32_cdc() is None:
            pytest.skip("STM32 CDC (c0de:cafe) not enumerated — no boot evidence path")
        _smoke_stm32(attached_board, registry)
        return

    repo = bench.MICROFIPS_REPO
    identity = registry.usb_identity(attached_board)
    skip = bench.bench_available(attached_board, vidpid=identity["vidpid"])
    if skip:
        pytest.skip(skip)

    acquired = "labgrid-place" if isinstance(rig_lock, str) else "flock"
    lock = bench.acquire_board_lock()
    run_dir = bench.make_run_dir(f"hil-smoke-{attached_board.replace(':', '')}")
    tap = None
    daemon = None
    try:
        with board_role(attached_board, variant, registry, acquired=acquired,
                        extra={"run_dir": str(run_dir)}):
            daemon = bench.LabDaemon(
                repo, 3600, run_dir / "daemon", ble=(variant == "l2cap"),
            )
            daemon.start()

            if variant == "wifi":
                binary = bench.build_firmware(
                    repo,
                    npub_hex=bench.lab_npub(repo, LAB_DAEMON_MUL),
                    nsec_hex=bench.lab_nsec(repo, GENERATOR_MUL[attached_board]),
                )
                chip = "esp32s3"
            else:
                binary = bench.build_d0wd_l2cap(
                    repo,
                    nsec_hex=bench.lab_nsec(repo, GENERATOR_MUL[attached_board]),
                    extra_allowed_xonly_hex=bench.lab_npub(
                        repo, LAB_DAEMON_MUL
                    )[2:],
                )
                chip = "esp32"

            port = bench.find_board(
                vidpid=identity["vidpid"], serial=attached_board,
            )
            assert port is not None, f"{attached_board} port vanished mid-smoke"
            bench.flash(port, binary, chip=chip)
            tap = bench.ConsoleTap(
                port, run_dir / "console.log",
                baud=115200 if identity["serial_source"] == "ftdi" else None,
            )

            if variant == "wifi":
                tap.wait_for("WiFi connected", timeout=180)
            tap.wait_for("handshake ok", timeout=180)
            tap.wait_for("heartbeat received", count=1, timeout=90)

            console = tap.read()
            verdict = {
                "board": attached_board,
                "variant": variant,
                "handshakes": console.count("handshake ok"),
                "heartbeats": console.count("heartbeat received"),
            }
            (run_dir / "verdict.json").write_text(json.dumps(verdict, indent=2))
            assert verdict["handshakes"] >= 1 and verdict["heartbeats"] >= 1
    finally:
        if tap:
            tap.stop()
        if daemon:
            daemon.stop()
        lock.release()


def _smoke_stm32(serial: str, registry: "object") -> None:
    repo = bench.MICROFIPS_REPO
    run_dir = bench.make_run_dir("hil-smoke-stm32")
    lock = bench.acquire_board_lock()
    bridge = None
    try:
        with board_role(serial, "cdc", registry,
                        extra={"run_dir": str(run_dir)}):
            binary = bench.build_stm32(
                repo, bench.lab_npub(repo, LAB_DAEMON_MUL)
            )
            bench.flash_stm32(binary)
            port = bench.find_stm32_cdc()
            assert port is not None, "CDC vanished after flash"
            time.sleep(8)  # enumeration settle (AGENTS: 7-8s post-flash)
            bridge = bench.SerialBridge(
                repo, port, bind_port=45679, udp_host="127.0.0.1",
                udp_port=21213, log_file=run_dir / "bridge.log",
            )
            bridge.wait_for(r"frame#1 114B", timeout=90)
    finally:
        if bridge:
            bridge.stop()
        lock.release()
