"""Scripted dual-session verification of the bench exclusivity fix
(d7e3e39, #199): two concurrent SAME-USER acquires must exclude each
other — the 2026-09-03 collision was two agent sessions of one user,
which HardwareLock deliberately permits and BenchLock must not.

Each probe runs in a real subprocess: a genuine second session, not a
second in-process acquire (flock is per-fd; threads would not prove the
cross-session property). Scratch lock name — the mechanism is
name-independent, and touching the production 'amperstrand-bench' name
here would block (and be blocked by) live bench sessions.
"""

import fcntl
import os
import subprocess
import sys

from tollgate_lab import BenchLockHeldError, acquire_bench_lock

SCRATCH_NAME = "amperstrand-bench-selftest"

_ACQUIRE_PROBE = """
import sys
from tollgate_lab import BenchLockHeldError, acquire_bench_lock
try:
    lock = acquire_bench_lock("{name}", project="probe-session")
except BenchLockHeldError as exc:
    print("HELD", exc.holder.get("project", "?"))
    sys.exit(3)
lock.release()
print("ACQUIRED")
"""


def _probe(name: str = SCRATCH_NAME) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", _ACQUIRE_PROBE.format(name=name)],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_second_same_user_session_is_excluded():
    holder = acquire_bench_lock(SCRATCH_NAME, project="holder-session")
    try:
        probe = _probe()
        assert probe.returncode == 3, probe.stderr
        assert probe.stdout.startswith("HELD holder-session"), probe.stdout
    finally:
        holder.release()


def test_acquire_succeeds_once_released():
    holder = acquire_bench_lock(SCRATCH_NAME, project="holder-session")
    holder.release()
    probe = _probe()
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.startswith("ACQUIRED"), probe.stdout


def test_lock_file_names_the_holder_for_humans():
    holder = acquire_bench_lock(SCRATCH_NAME, project="holder-session")
    try:
        content = holder.path.read_text()
        assert "project: holder-session" in content
        assert f"pid: {os.getpid()}" in content
    finally:
        holder.release()


def test_legacy_flock_fallback_excludes_second_process(tmp_path):
    """conftest's fallback layer (results/.bench-lock, LOCK_EX|LOCK_NB)
    must also exclude a second same-user process."""
    lock_path = tmp_path / ".bench-lock"
    fd = open(lock_path, "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import fcntl, sys\n"
                f"fd = open({str(lock_path)!r}, 'w')\n"
                "try:\n"
                "    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                "except BlockingIOError:\n"
                "    print('EXCLUDED')\n"
                "    sys.exit(0)\n"
                "print('NOT-EXCLUDED')\n"
                "sys.exit(1)\n",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert probe.returncode == 0, probe.stderr
        assert probe.stdout.startswith("EXCLUDED"), probe.stdout
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()
