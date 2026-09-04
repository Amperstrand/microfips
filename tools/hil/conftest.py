"""HIL fixtures: rig exclusivity, run ledger, Allure stamping.

Markers:
    hardware      — needs a bench board (auto-skip if absent)
    flash_mutation — flashes firmware (opt-in; run via `make test-hil`)

Rig exclusivity (bolty-rs #79 pattern): the coordinator place
`microfips-bench` supersedes the local flock when labgrid is up; the
exporter exports acquisition TOKENS only (client-side classes via
labgrid-env.yaml imports) so unacquired ports stay free for direct
espflash/tap access — presence detection stays with preflight.
"""

import fcntl
import json
import subprocess
import time
from pathlib import Path

import pytest

from tollgate_lab import BenchLockHeldError, acquire_bench_lock

from hil import BoardError, DeviceRegistry
from hil.preflight import LABGRID_COORDINATOR, MICROFIPS_PLACE

RESULTS_DIR = Path(__file__).parent / "results"
LEDGER_PATH = RESULTS_DIR / "history.jsonl"
RIG_LOCK_PATH = RESULTS_DIR / ".bench-lock"
LG_ACQUIRED_KEY = pytest.StashKey[bool]()


def pytest_configure(config):
    for marker in (
        "hardware: requires a bench board (auto-skipped if absent)",
        "flash_mutation: flashes firmware onto a registry board — opt-in only",
    ):
        config.addinivalue_line("markers", marker)


def _lg_client(*args: str, timeout_s: float = 15):
    return subprocess.run(
        ["labgrid-client", "-x", LABGRID_COORDINATOR, "-p", MICROFIPS_PLACE, *args],
        capture_output=True, text=True, timeout=timeout_s,
    )


def _lg_coordinator_up() -> bool:
    try:
        return _lg_client("who", timeout_s=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _lg_acquire_or_exit():
    acquired = _lg_client("acquire")
    if acquired.returncode != 0:
        pytest.exit(
            f"bench place {MICROFIPS_PLACE} is acquired by another session "
            f"({acquired.stderr.strip() or 'see labgrid-client who'})",
            returncode=3,
        )


def pytest_sessionstart(session):
    if session.config.getoption("lg_env", None) and _lg_coordinator_up():
        _lg_acquire_or_exit()
        session.stash[LG_ACQUIRED_KEY] = True


@pytest.fixture(scope="session")
def rig_lock(request):
    # Cross-project, cross-session flock FIRST (#199 fix: HardwareLock is
    # same-user-permissive; the place/flock below only covered hil-vs-hil;
    # two same-user sessions collided on port + target/ 2026-09-03).
    # Ordering rule: BenchLock before place/legacy locks, never reversed.
    try:
        bench_lock = acquire_bench_lock(
            "amperstrand-bench", project="microfips-hil",
            cwd=str(Path(__file__).resolve().parents[2]),
        )
    except BenchLockHeldError as exc:
        pytest.exit(f"bench flock held: {exc}", returncode=3)

    if request.session.stash.get(LG_ACQUIRED_KEY, False):
        yield "labgrid-place"
        bench_lock.release()
        return
    if _lg_coordinator_up():
        _lg_acquire_or_exit()
        yield "labgrid-place"
        _lg_client("release")
        bench_lock.release()
        return

    RESULTS_DIR.mkdir(exist_ok=True)
    lock_fd = open(RIG_LOCK_PATH, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        bench_lock.release()
        pytest.exit(
            f"bench is locked by another session ({RIG_LOCK_PATH})",
            returncode=3,
        )
    yield lock_fd
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    lock_fd.close()
    bench_lock.release()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" or report.outcome == "skipped":
        if not hasattr(item.session, "hil_results"):
            item.session.hil_results = {}
        item.session.hil_results[item.nodeid] = {
            "outcome": report.outcome,
            "duration": round(getattr(report, "duration", 0), 3),
        }


def pytest_sessionfinish(session, exitstatus):
    if session.stash.get(LG_ACQUIRED_KEY, False):
        _lg_client("release")
    RESULTS_DIR.mkdir(exist_ok=True)
    results = getattr(session, "hil_results", {})
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exit": exitstatus,
        "total": len(results),
        "passed": sum(1 for r in results.values() if r["outcome"] == "passed"),
        "failed": sum(1 for r in results.values() if r["outcome"] == "failed"),
        "skipped": sum(1 for r in results.values() if r["outcome"] == "skipped"),
    }
    try:
        with open(LEDGER_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass  # best-effort


def pytest_generate_tests(metafunc):
    """Parametrize board-consuming tests over registry flash-allowed boards;
    boards not physically attached auto-skip via the attached_board check."""
    if "attached_board" in metafunc.fixturenames:
        registry = DeviceRegistry()
        metafunc.parametrize(
            "attached_board", registry.serials_allowing("flash"), indirect=True
        )


@pytest.fixture(scope="session")
def registry() -> DeviceRegistry:
    return DeviceRegistry()


@pytest.fixture
def attached_board(request, registry: DeviceRegistry) -> str:
    """The parametrized registry serial, verified attached via sysfs
    (same semantics as fips-lab bench.find_board). Absent boards skip.
    Serial-less boards (CYD/CH340, synthetic key) verify via their
    registry id_path — /dev/serial/by-path is their only stable pin."""
    from hil.preflight import _by_path_present, _sysfs_boards

    expected = request.param
    try:
        id_path = registry.usb_identity(expected).get("id_path")
    except BoardError:
        # No USB mapping (e.g. the micronuts wallet, observe-only here) —
        # fall through to the serial check / skip below.
        id_path = None
    if id_path:
        if _by_path_present(id_path):
            return expected
    else:
        attached = _sysfs_boards()
        if expected in attached:
            return expected
    board = registry.lookup(expected)
    pytest.skip(
        f"{board.alias if board else expected} ({expected}) not attached "
        "(see /dev/serial and /dev/serial/by-path)"
    )
