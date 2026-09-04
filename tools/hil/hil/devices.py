"""Device registry adapter — fips-lab boards.toml is the safety contract.

One registry per bench, not one per repo: microfips and fips-lab flash the
same physical boards, so a second registry file here would drift from
fips-lab/fips_lab/boards.toml (the exact failure mode the 2026-09-02
registry-drift lesson describes). This adapter reads that file and adds
the USB-identity knowledge microfips needs to find each board
(VID:PID + how the serial is spelled in sysfs).
"""

from dataclasses import dataclass
from pathlib import Path
import os
import tomllib

DEFAULT_BOARDS_TOML = Path(__file__).resolve().parents[4] / "fips-lab" / "fips_lab" / "boards.toml"


class BoardError(RuntimeError):
    """A board/op combination is not permitted by the registry."""


@dataclass(frozen=True)
class Board:
    serial: str
    alias: str
    chip: str
    ops: tuple[str, ...]
    notes: str = ""

    def permits(self, op: str) -> bool:
        return op in self.ops


# USB identity per registry serial. serial_source: where the sysfs
# ID_SERIAL_SHORT comes from (Espressif USB-JTAG serials ARE the MAC and
# contain ':'; FTDI serials are plain hex; stm32 keys off the ST-Link).
USB_IDENTITIES: dict[str, dict[str, str]] = {
    "F4:12:FA:CF:03:84": {
        "vidpid": "303a/1001",
        "serial_source": "usb-jtag",
    },
    "cc:8d:a2:2c:91:98": {"vidpid": "303a/1001", "serial_source": "usb-jtag"},
    "cc:8d:a2:2c:94:08": {"vidpid": "303a/1001", "serial_source": "usb-jtag"},
    "81528A13B6": {
        "vidpid": "0403/6001",
        "serial_source": "ftdi",
        "note": "FTDI VID:PID shared with the OFF-LIMITS M5 Stack — "
        "always match the serial, never the VID:PID alone",
    },
    "9D529068B4": {
        "vidpid": "0403/6001",
        "serial_source": "ftdi",
        "note": "FTDI VID:PID shared with the OFF-LIMITS M5 Stack — "
        "always match the serial, never the VID:PID alone",
    },
    # CH340 exposes NO USB serial — the CYD is pinned by physical port.
    # id_path is the /dev/serial/by-path entry; it changes if the board
    # moves to another USB socket (then boards.toml notes apply too).
    "cyd-ch340": {
        "vidpid": "1a86/7523",
        "serial_source": "ch340",
        "id_path": "pci-0000:02:00.0-usb-0:1:1.0-port0",
    },
    "stm32f469i-disco": {
        "vidpid": "c0de/cafe",
        "serial_source": "cdc",
        "flash_via_vidpid": "0483/374b",
    },
    # Micronuts wallet (enrolled 2026-09-04): CDC-ACM, flashed by THEIR
    # scripts via st-flash — microfips hil never drives it (no smoke
    # variant); the mapping exists so the registry-coverage test holds
    # and observe-side taps can find the port.
    "F4691": {
        "vidpid": "16c0/27dd",
        "serial_source": "cdc",
    },
}


class DeviceRegistry:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or os.environ.get("MICROFIPS_BOARDS_TOML", DEFAULT_BOARDS_TOML))
        with open(self.path, "rb") as f:
            data = tomllib.load(f)
        self._boards: dict[str, Board] = {
            serial: Board(
                serial=serial,
                alias=spec.get("alias", serial),
                chip=spec.get("chip", "?"),
                ops=tuple(spec.get("ops", [])),
                notes=spec.get("notes", ""),
            )
            for serial, spec in data.get("boards", {}).items()
        }

    def lookup(self, serial: str) -> Board | None:
        return self._boards.get(serial)

    def require(self, serial: str, op: str) -> Board:
        board = self.lookup(serial)
        if board is None:
            raise BoardError(
                f"board {serial!r} is not in {self.path} — refusing {op}. "
                "Add an entry with explicit ops to allow it."
            )
        if not board.permits(op):
            raise BoardError(
                f"board {serial!r} ({board.alias}) does not permit '{op}' "
                f"(allowed: {', '.join(board.ops)})"
            )
        return board

    def serials_allowing(self, op: str) -> list[str]:
        return [b.serial for b in self._boards.values() if b.permits(op)]

    def usb_identity(self, serial: str) -> dict[str, str]:
        identity = USB_IDENTITIES.get(serial)
        if identity is None:
            raise BoardError(
                f"board {serial!r} has no USB identity mapping in "
                "hil/devices.py — add vidpid/serial_source before driving it"
            )
        return identity
