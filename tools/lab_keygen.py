#!/usr/bin/env python3
"""Deterministic secp256k1 test-identity generator for the microfips lab bench.

Identities are secp256k1 generator * N (nsec = N in hex), matching the
keys.json convention (stm32=1, esp32=2, sim-a=3, sim-b=4, esp32s3=5,
esp32c3=6, esp32s3b=7, then lab assignments 8..12, see AGENTS.md).

node_addr = SHA256(x_only_pubkey)[..16]  (fips-identity NodeAddr::from_pubkey_x)

Self-checks against known vectors before printing anything.

Usage:
  lab_keygen.py 8           # one identity
  lab_keygen.py 8 9 10      # several
  lab_keygen.py --env 9     # print cargo env override lines for build pinning
"""
import hashlib
import json
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        l = (3 * p[0] * p[0]) * pow(2 * p[1], -1, P) % P
    else:
        l = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (l * l - p[0] - q[0]) % P
    return (x, (l * (p[0] - x) - p[1]) % P)


def _mul(k):
    r, b = None, (Gx, Gy)
    while k:
        if k & 1:
            r = _add(r, b)
        b = _add(b, b)
        k >>= 1
    return r


def identity(n: int) -> dict:
    x, y = _mul(n)
    nsec = f"{n:064x}"
    npub = f"{2 + (y & 1):02x}{x:064x}"
    addr = hashlib.sha256(x.to_bytes(32, "big")).digest()[:16].hex()
    return {"n": n, "nsec_hex": nsec, "npub_hex": npub, "node_addr": addr}


def selfcheck() -> None:
    """G*3 must match keys.json sim-a (cross-checked against a live daemon)."""
    id3 = identity(3)
    assert id3["npub_hex"].startswith("02f9308a019258c31049"), "G*3 x mismatch"
    assert id3["node_addr"] == "7c79f3071e28344e8153bf6c73c294eb", "G*3 addr mismatch"


def main() -> None:
    selfcheck()
    args = [a for a in sys.argv[1:] if a != "--env"]
    as_env = "--env" in sys.argv
    for a in args:
        i = identity(int(a))
        if as_env:
            print(f'export DEVICE_NSEC_HEX_vps={i["nsec_hex"]}')
            print(f'export DEVICE_NPUB_HEX_vps={i["npub_hex"]}')
        else:
            print(json.dumps(i, indent=2))


if __name__ == "__main__":
    main()
