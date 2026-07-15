#!/usr/bin/env python3
"""CI helper: provision SHC VM, deploy FIPS, run sim-ping, cleanup.

Usage in GitHub Actions:

  # Provision + deploy FIPS, prints VM IP
  python3 scripts/ci_sim_ping.py provision --ssh-key /tmp/ci_key

  # Run tests against the VM (separate step)
  ./bin/microfips-sim --udp $VM_IP:2121 --sim-a &
  ./bin/microfips-sim --udp $VM_IP:2121 --sim-b --test-ping

  # Cleanup (always runs, even on failure)
  python3 scripts/ci_sim_ping.py cleanup --service-id 12345

Environment:
  SHC_API_KEY: Required for SHC API access.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def ssh(host: str, cmd: str, user: str = "debian", key: str = "/tmp/ci_key", timeout: int = 120) -> str:
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
        print(f"stderr: {result.stderr}", file=sys.stderr)
        raise RuntimeError(f"SSH command failed: {cmd}")
    return result.stdout.strip()


def scp(host: str, local: str, remote: str, user: str = "debian", key: str = "/tmp/ci_key") -> None:
    result = subprocess.run(
        ["scp", "-i", key, "-O",
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         local, f"{user}@{host}:{remote}"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"scp failed: {result.stderr}")


def cmd_provision(args: argparse.Namespace) -> None:
    from shc_toolkit.client import SHCClient

    c = SHCClient()

    key_path = Path(args.ssh_key)
    if not key_path.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key_path),
                        "-N", "", "-q"], check=True)

    pub_key = key_path.with_suffix(".pub").read_text().strip()

    print("=== Ordering SHC VM ===")
    order = c.order_vm(
        hostname=f"microfips-ci-{int(time.time())}",
        package_id=23,  # NVMe VPS - Starter (1 CPU, 4GB, 8GB)
        ssh_key=str(key_path.with_suffix(".pub")),
        pay=True,
    )
    service_id = order["service_id"]
    print(f"service_id={service_id}")

    if args.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"service_id={service_id}\n")

    print("=== Waiting for provisioning ===")
    vm = c.wait_for_provisioning_healthy(service_id, timeout=300, interval=10)
    ip = vm["ips"][0]["ip"]
    print(f"vm_ip={ip}")

    if args.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"vm_ip={ip}\n")

    print("=== Deploying FIPS ===")
    fips_config = """\
dns:
  enabled: false
node:
  heartbeat_interval_secs: 5
  identity:
    persistent: true
transports:
  udp:
    bind_addr: 0.0.0.0:2121
    accept_connections: true
tun:
  enabled: false
"""
    config_path = Path("/tmp/fips-ci.yaml")
    config_path.write_text(fips_config)
    scp(ip, str(config_path), "/tmp/fips.yaml", key=args.ssh_key)
    scp(ip, args.fips_binary, "/tmp/fips", key=args.ssh_key)

    ssh(ip, "chmod +x /tmp/fips && nohup /tmp/fips --config /tmp/fips.yaml > /tmp/fips.log 2>&1 &",
        key=args.ssh_key)

    print("=== Waiting for FIPS UDP port ===")
    for _ in range(30):
        result = subprocess.run(
            ["nc", "-z", "-w1", ip, "2121"],
            capture_output=True,
        )
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        log_tail = ssh(ip, "tail -20 /tmp/fips.log", key=args.ssh_key)
        print(f"FIPS did not start. Log:\n{log_tail}", file=sys.stderr)
        raise RuntimeError("FIPS failed to start within 30s")

    print("=== Extracting FIPS npub ===")
    fips_log = ssh(ip, "grep 'npub:' /tmp/fips.log | tail -1", key=args.ssh_key)
    npub_bech32 = fips_log.split("npub:")[-1].strip() if "npub:" in fips_log else ""

    if not npub_bech32:
        raise RuntimeError(f"Could not extract npub from FIPS log: {fips_log}")

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
    npub_hex = (prefix + x_only).hex()

    print(f"fips_npub_hex={npub_hex}")

    if args.github_output:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"fips_npub_hex={npub_hex}\n")

    print(f"FIPS ready on {ip}:2121 (npub={npub_bech32})")


def cmd_cleanup(args: argparse.Namespace) -> None:
    from shc_toolkit.client import SHCClient

    c = SHCClient()
    service_id = int(args.service_id)
    print(f"=== Cancelling VM {service_id} ===")
    try:
        c.cancel_vm(service_id, immediate=True)
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
