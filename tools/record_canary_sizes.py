#!/usr/bin/env python3
"""Measure the fips-core canary size probes and write sizes.json.

Probes: canary/size-probe-{ours,upstream} — identical bare-metal binaries,
different identity/crypto backend (ours = k256 pure Rust, upstream =
secp256k1-sys C via the pinned fips-core). Feeds the backend decision in
docs/fips-core-adoption-audit.md (area 5) and microfips #219.

Output: sizes.json in the repo root (gitignored; uploaded as the
`canary-sizes` workflow artifact). Schema is append-only: future runs diff
against previous artifacts by target+config.
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PIN = os.environ.get("PIN", "unknown")
STRIP = os.environ.get("STRIP", "llvm-strip")
SIZE = os.environ.get("SIZE", "llvm-size")
CARGO_TARGET_DIR = os.environ.get("CARGO_TARGET_DIR")

TARGETS = ["xtensa-esp32-none-elf", "thumbv7em-none-eabi"]
CONFIGS = ["ours", "upstream"]


def elf_path(target: str, config: str) -> Path:
    name = f"size-probe-{config}"
    if CARGO_TARGET_DIR:
        return Path(CARGO_TARGET_DIR) / target / "release" / name
    return REPO / "canary" / name / "target" / target / "release" / name


def sections(elf: Path) -> dict:
    out = subprocess.run([SIZE, "-A", str(elf)], capture_output=True, text=True, check=True).stdout
    result = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].startswith("."):
            result[parts[0]] = int(parts[1])
    return result


def measure(target: str, config: str) -> dict:
    elf = elf_path(target, config)
    if not elf.exists():
        raise SystemExit(f"missing probe ELF: {elf}")
    stripped = Path("/tmp") / f"sizes-{target}-{config}.stripped"
    subprocess.run([STRIP, "-o", str(stripped), str(elf)], check=True)
    return {
        "target": target,
        "config": config,
        "elf_bytes": elf.stat().st_size,
        "stripped_bytes": stripped.stat().st_size,
        "sections": sections(elf),
    }


def main() -> None:
    entries = [measure(t, c) for t in TARGETS for c in CONFIGS]
    deltas = {}
    for target in TARGETS:
        ours = next(e for e in entries if e["target"] == target and e["config"] == "ours")
        upstream = next(e for e in entries if e["target"] == target and e["config"] == "upstream")
        delta = upstream["stripped_bytes"] - ours["stripped_bytes"]
        deltas[target] = {
            "stripped_delta_bytes": delta,
            "ratio_percent": round((upstream["stripped_bytes"] / ours["stripped_bytes"] - 1) * 100, 1),
        }
    document = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "pin": PIN,
        "profile": "release, opt-level=z, lto, panic=abort",
        "entries": entries,
        "deltas": deltas,
    }
    (REPO / "sizes.json").write_text(json.dumps(document, indent=1) + "\n")
    for target, delta in deltas.items():
        print(f"{target}: ours→upstream stripped delta {delta['stripped_delta_bytes']:+,} B ({delta['ratio_percent']:+.1f}%)")


if __name__ == "__main__":
    main()
