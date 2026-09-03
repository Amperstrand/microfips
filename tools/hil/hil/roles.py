"""Per-board firmware-role ledger + restore-always guard (issue #191).

microfips boards are scenario scratch boards — unlike bolty's single-role
stick there is no one standing firmware to restore to. The honest
adaptation of bolty-rs's role_guard is therefore a LEDGER, not a reflash:
`board_role()` requires flash permission, records what the block flashed
(and what ran before, when known), and always closes taps/daemons and
releases the lock in `finally` — the restore-always discipline proven
under interruption (bolty-rs roles.py). The next session reads the ledger
instead of guessing what a board runs.
"""

import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
LEDGER_PATH = RESULTS_DIR / "board-roles.jsonl"


def role_ledger_path() -> Path:
    return LEDGER_PATH


def _append(entry: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(LEDGER_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def current_role(serial: str) -> dict | None:
    """Latest ledger entry for a board, or None if never recorded."""
    if not LEDGER_PATH.exists():
        return None
    latest = None
    for line in LEDGER_PATH.read_text().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("serial") == serial:
            latest = entry
    return latest


@contextmanager
def board_role(
    serial: str,
    variant: str,
    registry: "object",
    *,
    acquired: str = "flock",
    extra: dict | None = None,
) -> Iterator[dict]:
    """Flash-guard for one board: enforce the registry, ledger the role
    change in/out, and always run the caller's cleanup via finally.

    Yields {"previous": <last ledger entry or None>} so the caller can
    report what the board ran before. The caller owns the actual
    build/flash/tap/daemon lifecycle INSIDE the with-block; anything it
    registers in ctx["cleanup"] runs even on assertion failure or
    interrupt (restore-always).
    """
    registry.require(serial, "flash")
    previous = current_role(serial)
    payload: dict = {"previous": previous, "cleanup": []}

    def on_exit(callable_) -> None:
        payload["cleanup"].append(callable_)

    payload["on_exit"] = on_exit
    _append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "serial": serial,
        "event": "flash-begin",
        "variant": variant,
        "previous_variant": (previous or {}).get("variant"),
        "lock": acquired,
        **(extra or {}),
    })
    ok = False
    try:
        yield payload
        ok = True
    finally:
        for callable_ in payload["cleanup"]:
            try:
                callable_()
            except Exception:  # noqa: BLE001 — cleanup must never mask the body
                pass
        _append({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "serial": serial,
            "event": "flash-end",
            "variant": variant,
            "ok": ok,
        })
