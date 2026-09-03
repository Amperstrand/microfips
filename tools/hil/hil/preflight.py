"""Composable preflight for the microfips bench (bolty-rs pattern).

Each check returns (name, severity, ok, detail); hard failures abort,
warnings allow a degraded run. Covers: coordinator/exporter liveness,
registry-boards physically present, toolchains, and firmware binaries.
Presence detection uses the same sysfs/udev semantics as
fips-lab bench.find_board — this preflight reports, it never mutates.
"""

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_FAIL = "fail"
SEVERITY_WARN = "warn"

LABGRID_COORDINATOR = "192.168.13.221:20408"
MICROFIPS_PLACE = "microfips-bench"
EXPORT_ESP = Path("/home/ubuntu/export-esp.sh")


@dataclass
class Check:
    name: str
    severity: str
    ok: bool
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.ok or self.severity == SEVERITY_WARN


@dataclass
class Preflight:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, severity: str, ok: bool, detail: str = "") -> Check:
        check = Check(name=name, severity=severity, ok=ok, detail=detail)
        self.checks.append(check)
        return check

    @property
    def hard_failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.severity == SEVERITY_FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.severity == SEVERITY_WARN]

    def summary(self) -> str:
        lines = [
            f"  {c.severity.upper():4} {'PASS' if c.ok else 'FAIL'}  {c.name}"
            + (f" — {c.detail}" if c.detail else "")
            for c in self.checks
        ]
        return "\n".join(lines)


def _sysfs_boards() -> dict[str, str]:
    """serial -> /dev port for every USB-serial board on the bench."""
    boards: dict[str, str] = {}
    for prefix in ("ttyACM", "ttyUSB"):
        for port in Path("/dev").glob(prefix + "*"):
            try:
                uevent = Path(
                    "/sys/class/tty", port.name, "device/../uevent"
                ).read_text()
            except OSError:
                continue
            props = subprocess.run(
                ["udevadm", "info", "-q", "property", str(port)],
                capture_output=True, text=True,
            ).stdout
            serial = next(
                (l.split("=", 1)[1] for l in props.splitlines()
                 if l.startswith("ID_SERIAL_SHORT=")),
                None,
            )
            if serial:
                boards[serial] = str(port)
    return boards


def _by_path_present(id_path: str) -> str | None:
    """Port for a serial-less board pinned by /dev/serial/by-path, or None."""
    link = Path("/dev/serial/by-path") / id_path
    if link.exists():
        try:
            return str(link.resolve())
        except OSError:
            return None
    return None


def check_boards(pf: Preflight, registry: "object", op: str = "flash") -> None:
    """Registry boards permitting `op`: absent boards WARN (the smoke
    parametrization auto-skips them — bench composition varies); the hard
    failure is NO flash-allowed board attached at all. STM32 attachment
    keys off the ST-Link (its CDC only enumerates once firmware runs —
    the smoke flashes first, then expects the CDC). Serial-less boards
    (CH340/CYD) key off their by-path pin."""
    attached = _sysfs_boards()
    cdc = _cdc_present()
    stlink = _stlink_present()
    any_present = False
    for serial in registry.serials_allowing(op):
        board = registry.lookup(serial)
        identity = registry.usb_identity(serial)
        if identity.get("serial_source") == "cdc":
            present = stlink
            detail = "ST-Link present" if stlink else "no ST-Link"
            if stlink and not cdc:
                detail += "; CDC down (smoke flashes, then expects it)"
        elif identity.get("serial_source") == "ch340":
            port = _by_path_present(identity.get("id_path", ""))
            present = port is not None
            detail = port or f"id_path {identity.get('id_path', '?')} not present"
        else:
            present = serial in attached
            detail = attached.get(serial, "not attached")
        if present:
            any_present = True
        pf.add(f"board:{board.alias}",
               SEVERITY_FAIL if present else SEVERITY_WARN,
               present, detail)
    pf.add("bench:at-least-one-flash-board", SEVERITY_FAIL, any_present,
           "ok" if any_present else "no registry flash board attached")


def _cdc_present() -> bool:
    for port in Path("/dev").glob("ttyACM*"):
        try:
            uevent = Path(
                "/sys/class/tty", port.name, "device/../uevent"
            ).read_text()
        except OSError:
            continue
        if "c0de/cafe" in uevent:
            return True
    return False


def _stlink_present() -> bool:
    try:
        out = subprocess.run(
            ["lsusb"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "0483:374b" in out


def check_stlink(pf: Preflight) -> None:
    pf.add("stm32-stlink", SEVERITY_WARN, _stlink_present(),
           "ST-Link/V2.1 present" if _stlink_present() else "not present")


def check_labgrid(pf: Preflight) -> None:
    """Coordinator + exporter liveness and the microfips-bench place."""
    try:
        who = subprocess.run(
            ["labgrid-client", "-x", LABGRID_COORDINATOR, "who"],
            capture_output=True, text=True, timeout=10,
        )
        if who.returncode != 0:
            pf.add("labgrid-coordinator", SEVERITY_WARN, False,
                   "unreachable — flock fallback applies")
            return
    except (OSError, subprocess.TimeoutExpired):
        pf.add("labgrid-coordinator", SEVERITY_WARN, False,
               "unreachable — flock fallback applies")
        return
    pf.add("labgrid-coordinator", SEVERITY_FAIL, True, LABGRID_COORDINATOR)

    try:
        resources = subprocess.run(
            ["labgrid-client", "-x", LABGRID_COORDINATOR, "resources"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        resources = ""
    exported = "microfips" in resources
    pf.add("labgrid-exporter-microfips", SEVERITY_WARN, exported,
           "resources on coordinator" if exported
           else "no microfips resources — install labgrid-exporter-microfips")


def check_toolchains(pf: Preflight) -> None:
    esp = EXPORT_ESP.exists()
    pf.add("toolchain:esp", SEVERITY_FAIL, esp,
           str(EXPORT_ESP) if esp else "export-esp.sh missing")
    st_flash = subprocess.run(
        ["which", "st-flash"], capture_output=True, text=True
    ).stdout.strip()
    pf.add("toolchain:st-flash", SEVERITY_WARN, bool(st_flash),
           st_flash or "not installed (STM32 smoke unavailable)")


def main() -> int:
    """CLI entry: `python3 -m hil.preflight` from tools/hil/."""
    from hil.devices import DeviceRegistry

    pf = Preflight()
    registry = DeviceRegistry()
    check_labgrid(pf)
    check_boards(pf, registry)
    check_stlink(pf)
    check_toolchains(pf)
    print("microfips bench preflight:")
    print(pf.summary())
    hard = pf.hard_failures
    if hard:
        print(f"\n{len(hard)} hard failure(s) — aborting")
        return 1
    warns = pf.warnings
    if warns:
        print(f"\n{len(warns)} warning(s) — degraded run continues")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
