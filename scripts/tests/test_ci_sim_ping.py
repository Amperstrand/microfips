"""Unit tests for scripts/ci_sim_ping.py readiness logic.

Earned 2026-09-04 (live, SHC):
- provisioning_state can stay "provisioning" forever — on healthy VMs and on
  dead ones (VM 2428: active + IP + TCP/22 accepting, but NO SSH banner,
  bootstrap_completed_at null forever).
- A TCP accept on port 22 is therefore NOT proof of a usable VM; the SSH
  identification banner is.
These tests pin the readiness contract the provision loop relies on.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ci_sim_ping  # noqa: E402


def _serve_once(behavior: str, port_holder: list[int]) -> None:
    """Single-connection TCP server: 'banner' sends an SSH id string,
    'silent' accepts and sends nothing (the VM-2428 zombie pattern)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port_holder.append(srv.getsockname()[1])
    conn, _ = srv.accept()
    if behavior == "banner":
        conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Debian\r\n")
    # 'silent': accept, then hold the connection open saying nothing
    if behavior == "silent":
        threading.Event().wait(2.0)
    conn.close()
    srv.close()


def test_ssh_banner_reads_identification_string() -> None:
    holder: list[int] = []
    t = threading.Thread(target=_serve_once, args=("banner", holder), daemon=True)
    t.start()
    while not holder:
        pass
    banner = ci_sim_ping._ssh_banner("127.0.0.1", port=holder[0], timeout=2.0)
    t.join(timeout=5)
    assert banner.startswith("SSH-2.0-")


def test_ssh_banner_silent_accept_returns_empty() -> None:
    # VM-2428 pattern: TCP accepts, no bytes ever arrive -> not usable.
    holder: list[int] = []
    t = threading.Thread(target=_serve_once, args=("silent", holder), daemon=True)
    t.start()
    while not holder:
        pass
    banner = ci_sim_ping._ssh_banner("127.0.0.1", port=holder[0], timeout=0.5)
    assert banner == ""


def test_ssh_banner_refused_returns_empty() -> None:
    # Nothing listening on this port (bind then close to reserve a number).
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert ci_sim_ping._ssh_banner("127.0.0.1", port=port, timeout=0.5) == ""


def test_vm_ready_accepts_stuck_provisioning_with_ip() -> None:
    # Healthy-but-never-"ready": provisioning_state stays "provisioning"
    # forever; service active + IP assigned is the real orderable signal.
    vm = {
        "service_status": "active",
        "provisioning_state": "provisioning",
        "ips": [{"ip": "203.0.113.7"}],
    }
    assert ci_sim_ping._vm_ready(vm) == "203.0.113.7"


def test_vm_ready_accepts_classic_ready() -> None:
    vm = {
        "service_status": "active",
        "provisioning_state": "ready",
        "ips": [{"ip": "203.0.113.8"}],
    }
    assert ci_sim_ping._vm_ready(vm) == "203.0.113.8"


def test_vm_ready_rejects_pending_no_ip() -> None:
    vm = {"service_status": "pending", "provisioning_state": "pending", "ips": []}
    assert ci_sim_ping._vm_ready(vm) is None


def test_vm_ready_rejects_failed() -> None:
    vm = {
        "service_status": "active",
        "provisioning_state": "failed",
        "ips": [{"ip": "203.0.113.9"}],
    }
    assert ci_sim_ping._vm_ready(vm) is None


def test_vm_ready_rejects_active_without_ip() -> None:
    vm = {"service_status": "active", "provisioning_state": "provisioning", "ips": []}
    assert ci_sim_ping._vm_ready(vm) is None
