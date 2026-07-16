#!/usr/bin/env python3
"""CI helper: provision SHC VM, deploy FIPS, run sim-ping, cleanup.

Zero external dependencies — uses only Python stdlib (urllib).

Usage in GitHub Actions:

  python3 scripts/ci_sim_ping.py provision --github-output
  # ... run sim tests against $VM_IP ...
  python3 scripts/ci_sim_ping.py cleanup --service-id $SERVICE_ID

Environment:
  SHC_API_KEY: Required for SHC API access.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

BASE_URL = "https://blesta.sovereignhybridcompute.com/user-api/v2"


def _api(method: str, path: str, *, api_key: str, body: dict | None = None,
         extra_headers: dict | None = None, timeout: int = 30) -> dict:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)

    url = f"{BASE_URL}{path}"
    for attempt in range(3):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode()
                parsed = json.loads(text) if text.strip() else {}
                return parsed.get("data", parsed)
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            parsed = json.loads(text) if text.strip() else {}
            err = parsed.get("error", {})
            code = err.get("code", "unknown")
            if code == "confirmation_required" and e.code == 409:
                conf = parsed.get("confirmation", {})
                cid = conf.get("confirmation_id") or conf.get("structuredContent", {}).get("confirmation_id")
                if cid:
                    eh = dict(extra_headers) if extra_headers else {}
                    eh["X-User-Api-Confirm"] = cid
                    return _api(method, path, api_key=api_key, body=body, extra_headers=eh, timeout=timeout)
            if e.code in (429, 502, 503) and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            msg = err.get("message", text)
            print(f"API error {e.code}: {code} - {msg}", file=sys.stderr)
            raise
        except urllib.error.URLError as e:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise

    raise RuntimeError("max retries exceeded")


def _ssh(host: str, cmd: str, key: str = "/tmp/ci_key", user: str = "debian", timeout: int = 120) -> str:
    result = subprocess.run(
        ["ssh", "-i", key,
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR",
         "-o", f"ConnectTimeout={min(timeout, 15)}",
         f"{user}@{host}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        print(f"SSH failed (rc={result.returncode}): {cmd}", file=sys.stderr)
        if result.stderr:
            print(f"stderr: {result.stderr}", file=sys.stderr)
        raise RuntimeError(f"SSH command failed: {cmd}")
    return result.stdout.strip()


def _scp(host: str, local: str, remote: str, key: str = "/tmp/ci_key", user: str = "debian") -> None:
    result = subprocess.run(
        ["scp", "-i", key, "-O",
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         local, f"{user}@{host}:{remote}"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"scp failed: {result.stderr}")


def _npub_bech32_to_compressed_hex(npub_bech32: str) -> str:
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    data_part = npub_bech32[5:-6]
    values = [charset.index(c) for c in data_part]
    buf, bits, out = 0, 0, []
    for v in values:
        buf = (buf << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    x_only = bytes(out)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int.from_bytes(x_only, "big")
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if (y * y) % p != y_sq:
        raise RuntimeError("Invalid pubkey: x has no valid y on secp256k1 curve")
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return (prefix + x_only).hex()


def cmd_provision(args: argparse.Namespace) -> None:
    api_key = os.environ.get("SHC_API_KEY", "")
    if not api_key:
        print("ERROR: SHC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    key_path = Path(args.ssh_key)
    if not key_path.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-q"], check=True)
    pub_key = key_path.with_suffix(".pub").read_text().strip()

    print("=== Ordering SHC VM ===")
    idem = f"ci-{uuid.uuid4().hex[:24]}"
    order = _api("POST", "/ordering/submit", api_key=api_key, body={
        "package_id": 80,
        "pricing_id": 241,
        "hostname": f"microfips-ci-{int(time.time())}",
        "ssh_key": pub_key,
        "order_form_id": 11,
    }, extra_headers={"Idempotency-Key": idem})

    service_id = order.get("service_id") or (order.get("service_ids") or [None])[0]
    if not service_id:
        print(f"ERROR: No service_id in order response: {order}", file=sys.stderr)
        sys.exit(1)
    print(f"service_id={service_id}")

    if args.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"service_id={service_id}\n")

    invoice_id = order.get("invoice_id")
    if invoice_id:
        _api("POST", f"/payment/{invoice_id}/checkout", api_key=api_key, body={
            "gateway": "btcpay_server",
            "idempotency_key": f"pay-{uuid.uuid4().hex[:24]}",
        })
        print(f"Paid invoice {invoice_id}")

    print("=== Waiting for provisioning ===")
    deadline = time.time() + 300
    ip = None
    while time.time() < deadline:
        vm = _api("GET", f"/vm/{service_id}", api_key=api_key)
        svc = vm.get("service_status", "unknown")
        prov = vm.get("provisioning_state", "unknown")
        ips = vm.get("ips", [])
        print(f"  service={svc} provisioning={prov} ips={len(ips)}")
        if prov in ("failed", "error"):
            print(f"ERROR: provisioning failed: {vm}", file=sys.stderr)
            sys.exit(1)
        if prov == "ready" and svc == "active" and ips:
            ip = ips[0]["ip"]
            try:
                s = socket.create_connection((ip, 22), timeout=5)
                s.close()
                break
            except OSError:
                pass
        time.sleep(10)

    if not ip:
        print("ERROR: VM not ready after 300s", file=sys.stderr)
        sys.exit(1)

    print(f"vm_ip={ip}")
    if args.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"vm_ip={ip}\n")

    print("=== Probing SSH access ===")
    ssh_user = None
    for test_user in ("debian", "ubuntu", "root"):
        for attempt in range(6):
            r = subprocess.run(
                ["ssh", "-i", str(key_path),
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "LogLevel=ERROR",
                 "-o", "ConnectTimeout=10",
                 f"{test_user}@{ip}", "echo ok"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0 and "ok" in r.stdout:
                ssh_user = test_user
                print(f"SSH works as {ssh_user}")
                break
            time.sleep(10)
        if ssh_user:
            break
    if not ssh_user:
        print("ERROR: Could not establish SSH with debian/ubuntu/root", file=sys.stderr)
        sys.exit(1)

    print("=== Deploying FIPS ===")
    fips_config = (
        "dns:\n  enabled: false\n"
        "node:\n  heartbeat_interval_secs: 5\n"
        "  identity:\n    persistent: true\n"
        "transports:\n  udp:\n    bind_addr: 0.0.0.0:2121\n"
        "    accept_connections: true\n"
        "tun:\n  enabled: false\n"
    )
    Path("/tmp/fips-ci.yaml").write_text(fips_config)
    print("  SCP config...", flush=True)
    _scp(ip, "/tmp/fips-ci.yaml", "/tmp/fips.yaml", user=ssh_user)
    print("  SCP fips binary (22MB)...", flush=True)
    _scp(ip, args.fips_binary, "/tmp/fips", user=ssh_user)

    service = (
        "[Unit]\nDescription=FIPS CI\nAfter=network.target\n\n"
        "[Service]\nExecStart=/tmp/fips --config /tmp/fips.yaml\nRestart=no\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    Path("/tmp/fips-ci.service").write_text(service)
    _scp(ip, "/tmp/fips-ci.service", "/tmp/fips-ci.service", user=ssh_user)
    print("  Starting FIPS via systemd...", flush=True)
    _ssh(ip, "chmod +x /tmp/fips && sudo cp /tmp/fips-ci.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl start fips-ci", user=ssh_user, timeout=30)
    print("  FIPS started.", flush=True)

    print("=== Waiting for FIPS UDP port ===")
    for _ in range(30):
        r = subprocess.run(["nc", "-z", "-w1", ip, "2121"], capture_output=True)
        if r.returncode == 0:
            break
        time.sleep(1)
    else:
        log_tail = _ssh(ip, "tail -20 /tmp/fips.log")
        print(f"FIPS did not start. Log:\n{log_tail}", file=sys.stderr)
        sys.exit(1)

    print("=== Extracting FIPS npub ===")
    fips_log = _ssh(ip, "sudo journalctl -u fips-ci --no-pager -o cat 2>/dev/null | grep 'npub:' | tail -1", user=ssh_user)
    npub_bech32 = fips_log.split("npub:")[-1].strip() if "npub:" in fips_log else ""
    if not npub_bech32:
        print(f"ERROR: Could not extract npub from FIPS log: {fips_log}", file=sys.stderr)
        sys.exit(1)

    npub_hex = _npub_bech32_to_compressed_hex(npub_bech32)
    print(f"fips_npub_hex={npub_hex}")
    if args.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"fips_npub_hex={npub_hex}\n")

    print(f"FIPS ready on {ip}:2121")


def cmd_cleanup(args: argparse.Namespace) -> None:
    api_key = os.environ.get("SHC_API_KEY", "")
    if not api_key:
        return
    service_id = int(args.service_id)
    print(f"=== Cancelling VM {service_id} ===")
    try:
        _api("POST", f"/vm/{service_id}/cancel", api_key=api_key, body={"immediate": True},
             extra_headers={"Idempotency-Key": f"cancel-{uuid.uuid4().hex[:24]}"})
        print(f"VM {service_id} cancelled")
    except Exception as e:
        print(f"Failed to cancel VM {service_id}: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="CI sim-ping VM lifecycle")
    sub = parser.add_subparsers(dest="command", required=True)

    p_prov = sub.add_parser("provision", help="Order VM + deploy FIPS")
    p_prov.add_argument("--ssh-key", default="/tmp/ci_key")
    p_prov.add_argument("--fips-binary", default="./bin/fips")
    p_prov.add_argument("--github-output", action="store_true")
    p_prov.set_defaults(func=cmd_provision)

    p_clean = sub.add_parser("cleanup", help="Cancel VM")
    p_clean.add_argument("--service-id", required=True)
    p_clean.set_defaults(func=cmd_cleanup)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
