#!/usr/bin/env python3
"""Generate summary.json from ``cargo test --message-format=json`` output.

Reads NDJSON test output (one JSON object per line), extracts individual test
names + outcomes, and writes ``summary.json`` for the PRTA dashboard's test
hierarchy grouping.

Cargo's unstable JSON format (requires nightly) emits several event types per
line. This parser only cares about ``type: "test"`` events:

    {"type":"test","event":"started","name":"noise::tests::foo"}
    {"type":"test","event":"ok","name":"noise::tests::foo","duration":0.001}
    {"type":"test","event":"failed","name":"bar","duration":0.05}
    {"type":"test","event":"ignored","name":"skipped_test"}

The ``duration`` field is in **seconds** (float). We convert to milliseconds.

Output schema (matches PRTA dashboard expectations, same as nomail):

    {
        "tests": [
            {"name": "...", "outcome": "passed", "runner": "...", "duration_ms": N}
        ],
        "counts": {"passed": N, "failed": N, "skipped": N, "total": N}
    }

Outcome values align with the dashboard's ``outcomeIcon()`` switch:
``passed``, ``failed``, ``error``, ``skipped``.

Usage::

    cargo test --message-format=json > cargo-results.json 2>&1 || true
    python3 scripts/generate-summary.py cargo-results.json -o test-results/summary.json
"""

import argparse
import json
import sys
from pathlib import Path


def parse_cargo_json(lines):
    """Parse cargo test NDJSON lines into a dict of test_name -> info.

    Returns:
        Dict mapping test name to ``{"outcome": str, "duration_ms": int}``.
    """
    tests = {}

    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        if msg.get("type") != "test":
            continue

        event = msg.get("event", "")
        name = msg.get("name", "")
        if not name:
            continue

        # Duration comes in seconds (float); convert to ms.
        duration_s = msg.get("duration", 0)
        try:
            duration_ms = int(float(duration_s) * 1000)
        except (TypeError, ValueError):
            duration_ms = 0

        if event == "started":
            # Register early so ignored tests still appear.
            if name not in tests:
                tests[name] = {"outcome": "skipped", "duration_ms": 0}
        elif event == "ok":
            tests[name] = {"outcome": "passed", "duration_ms": duration_ms}
        elif event == "failed":
            tests[name] = {"outcome": "failed", "duration_ms": duration_ms}
        elif event == "ignored":
            tests[name] = {"outcome": "skipped", "duration_ms": duration_ms}

    return tests


def extract_runner(test_name):
    """Derive a suite/runner label from a Rust test path.

    ``noise::tests::noise_ik_handshake`` -> ``noise``
    ``tests::basic_math``                 -> ``tests``
    ``standalone_test``                   -> ``microfips``
    """
    parts = test_name.split("::")
    if len(parts) > 1:
        return parts[0]
    return "microfips"


def main():
    parser = argparse.ArgumentParser(
        description="Generate summary.json from cargo test --message-format=json output"
    )
    parser.add_argument(
        "input",
        help="Path to cargo test JSON output file (NDJSON)",
    )
    parser.add_argument(
        "--output", "-o",
        default="summary.json",
        help="Output summary.json path (default: summary.json)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path) as f:
        tests = parse_cargo_json(f)

    test_list = []
    passed = failed = skipped = 0

    for name, info in sorted(tests.items()):
        outcome = info["outcome"]
        test_list.append({
            "name": name,
            "outcome": outcome,
            "runner": extract_runner(name),
            "duration_ms": info["duration_ms"],
        })
        if outcome == "passed":
            passed += 1
        elif outcome == "failed":
            failed += 1
        else:
            skipped += 1

    summary = {
        "tests": test_list,
        "counts": {
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "total": len(test_list),
        },
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(
        f"Generated {output_path}: "
        f"{passed} passed, {failed} failed, {skipped} skipped, "
        f"{len(test_list)} total"
    )


if __name__ == "__main__":
    main()
