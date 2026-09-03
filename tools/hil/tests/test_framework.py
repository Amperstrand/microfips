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
