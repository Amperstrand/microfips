"""Framework unit tests — no hardware, no bench state.

Covers the registry adapter (fips-lab boards.toml as the contract), the
USB-identity mapping, the board-role ledger with restore-always cleanup,
and preflight severity semantics.
"""

from pathlib import Path

import pytest

from hil import DeviceRegistry, board_role
from hil.devices import BoardError
from hil.preflight import Check, SEVERITY_WARN
import hil.roles


class FakeRegistry:
    def __init__(self, permitted=("flash", "observe")):
        self.permitted = permitted

    def require(self, serial: str, op: str):
        if op not in self.permitted:
            raise BoardError(f"{serial} does not permit {op}")
        return serial


def test_registry_reads_fips_lab_contract():
    registry = DeviceRegistry()
    flash_serials = registry.serials_allowing("flash")
    assert "F4:12:FA:CF:03:84" in flash_serials
    assert "81528A13B6" in flash_serials
    assert "stm32f469i-disco" in flash_serials


def test_registry_refuses_unknown_board():
    registry = DeviceRegistry()
    with pytest.raises(BoardError, match="not in"):
        registry.require("deadbeef00", "flash")


def test_registry_refuses_underprivileged_op(tmp_path: Path):
    contract = tmp_path / "boards.toml"
    contract.write_text(
        '[boards."aa"]\nalias = "ro-board"\nchip = "esp32"\nops = ["observe"]\n'
    )
    registry = DeviceRegistry(path=contract)
    assert registry.serials_allowing("flash") == []
    with pytest.raises(BoardError, match="does not permit 'flash'"):
        registry.require("aa", "flash")
    assert registry.require("aa", "observe") is not None


def test_usb_identity_requires_mapping():
    registry = DeviceRegistry()
    with pytest.raises(BoardError, match="no USB identity"):
        registry.usb_identity("never-mapped-serial")


def test_usb_identity_covers_all_registry_serials():
    registry = DeviceRegistry()
    for serial in registry.serials_allowing("flash"):
        identity = registry.usb_identity(serial)
        assert "vidpid" in identity and "serial_source" in identity


def test_board_role_ledger_records_and_cleans_up(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(hil.roles, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(hil.roles, "LEDGER_PATH", tmp_path / "board-roles.jsonl")
    ran = []

    with board_role("81528A13B6", "l2cap", FakeRegistry()) as ctx:
        ctx["on_exit"](lambda: ran.append("tap-stop"))
        assert ctx["previous"] is None

    ledger = (tmp_path / "board-roles.jsonl").read_text().splitlines()
    events = [line for line in ledger if '"flash-end"' in line]
    assert events and '"ok": true' in events[0]
    assert ran == ["tap-stop"]


def test_board_role_cleanup_runs_on_failure(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(hil.roles, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(hil.roles, "LEDGER_PATH", tmp_path / "board-roles.jsonl")
    ran = []

    with pytest.raises(AssertionError):
        with board_role("F4:12:FA:CF:03:84", "wifi", FakeRegistry()) as ctx:
            ctx["on_exit"](lambda: ran.append("daemon-stop"))
            assert False, "boom"

    assert ran == ["daemon-stop"]
    ledger = (tmp_path / "board-roles.jsonl").read_text()
    assert '"ok": false' in ledger


def test_board_role_enforces_registry(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(hil.roles, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(hil.roles, "LEDGER_PATH", tmp_path / "board-roles.jsonl")
    with pytest.raises(BoardError):
        with board_role("aa", "wifi", FakeRegistry(permitted=("observe",))):
            pass
    assert not (tmp_path / "board-roles.jsonl").exists()


def test_warn_severity_passes_when_not_ok():
    assert Check(name="x", severity=SEVERITY_WARN, ok=False).passed
    assert not Check(name="x", severity="fail", ok=False).passed


def test_bench_lock_excludes_same_user_second_process(tmp_path: Path):
    """The #199 case: two sessions of the SAME unix user must serialize.
    A holder subprocess keeps the flock; a contender must fail with holder
    info; after the holder exits, acquire succeeds again."""
    import subprocess
    import sys
    import time

    from tollgate_lab import BenchLockHeldError, acquire_bench_lock

    ready = tmp_path / "holder-ready"
    holder = subprocess.Popen([
        sys.executable, "-c",
        f"from tollgate_lab import acquire_bench_lock; "
        f"l = acquire_bench_lock('test-bench-lock-x', project='holder'); "
        f"open({str(ready)!r}, 'w').write('go'); import time; time.sleep(5)",
    ])
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert ready.exists(), "holder never signaled"
        try:
            acquire_bench_lock("test-bench-lock-x")
            raise AssertionError("second same-user acquire succeeded")
        except BenchLockHeldError as exc:
            assert "holder" in str(exc), str(exc)
        holder.wait(timeout=10)
        lock = acquire_bench_lock("test-bench-lock-x")
        lock.release()
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait()


def test_note_board_state_is_advisory_for_missing_place():
    """Mirroring must never fail a scenario: a nonexistent coordinator
    place returns False, no exception."""
    import os
    import sys

    fips_lab_root = Path(__file__).resolve().parents[4] / "fips-lab"
    sys.path.insert(0, str(fips_lab_root))
    from fips_lab import bench

    os.environ["LABGRID_COORDINATOR"] = "127.0.0.1:1"  # nothing listens
    try:
        assert bench.note_board_state("81528A13B6", "l2cap") is False
    finally:
        os.environ.pop("LABGRID_COORDINATOR", None)
