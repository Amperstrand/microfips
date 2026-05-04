#!/usr/bin/env python3
"""Generate FIPS compatibility constants from upstream FIPS source.

Usage (local dev, existing FIPS checkout):
    python3 tools/generate_fips_compat.py

Usage (clone from upstream):
    python3 tools/generate_fips_compat.py --repo https://github.com/Amperstrand/fips.git --branch macos-linux-sync

Usage (CI, pre-checked-out FIPS):
    python3 tools/generate_fips_compat.py --fips-root ./upstream-fips

Defaults are read from .fips-upstream.json when no flags are given.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / ".fips-upstream.json"
OUT_RS = REPO_ROOT / "crates/microfips-core/src/generated/fips_compat.rs"

DEFAULT_FIPS_ROOT = Path("/home/ubuntu/src/fips")

LINK_FILE = Path("src/protocol/link.rs")
MMP_FILE = Path("src/mmp/mod.rs")
NOISE_FILE = Path("src/noise/mod.rs")
PROTOCOL_FILE = Path("src/protocol/mod.rs")
SESSION_FILE = Path("src/protocol/session.rs")

LINK_ENUMS = {
    "LinkMessageType": "LINK_MSG",
    "DisconnectReason": "DISC_REASON",
}

MMP_CONSTS = [
    "SENDER_REPORT_BODY_SIZE",
    "RECEIVER_REPORT_BODY_SIZE",
    "SENDER_REPORT_WIRE_SIZE",
    "RECEIVER_REPORT_WIRE_SIZE",
]

NOISE_CONSTS = [
    "TAG_SIZE",
    "EPOCH_SIZE",
    "PUBKEY_SIZE",
    "HANDSHAKE_MSG1_SIZE",
    "HANDSHAKE_MSG2_SIZE",
    "XK_HANDSHAKE_MSG1_SIZE",
    "XK_HANDSHAKE_MSG2_SIZE",
    "XK_HANDSHAKE_MSG3_SIZE",
    "REPLAY_WINDOW_SIZE",
    "MAX_MESSAGE_SIZE",
]

INTERNAL_NOISE_CONSTS = [
    "EPOCH_ENCRYPTED_SIZE",
]

OPTIONAL_NOISE_CONSTS = [
    "NONCE_SIZE",
]

PROTOCOL_CONSTS = [
    "PROTOCOL_VERSION",
    "SESSION_SENDER_REPORT_SIZE",
    "SESSION_RECEIVER_REPORT_SIZE",
    "PATH_MTU_NOTIFICATION_SIZE",
    "COORDS_REQUIRED_SIZE",
    "MTU_EXCEEDED_SIZE",
    "SESSION_DATAGRAM_HEADER_SIZE",
]


def load_config() -> dict:
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    return {}


def resolve_fips_root(args: argparse.Namespace) -> tuple[Path, dict]:
    if args.fips_root:
        root = Path(args.fips_root)
        if not (root / "src" / "protocol" / "link.rs").exists():
            raise SystemExit(f"--fips-root does not look like a FIPS checkout: {root}")
        return root, {"mode": "local", "path": str(root)}

    repo = args.repo
    branch = args.branch
    commit = args.commit

    if not repo:
        cfg = load_config()
        repo = cfg.get("repo", "")
        branch = branch or cfg.get("branch", "")
        commit = commit or cfg.get("commit", "")

    if not repo:
        if DEFAULT_FIPS_ROOT.exists():
            return DEFAULT_FIPS_ROOT, {"mode": "local", "path": str(DEFAULT_FIPS_ROOT)}
        raise SystemExit(
            "No FIPS source available. Use --fips-root, --repo, or create .fips-upstream.json"
        )

    tmpdir = tempfile.mkdtemp(prefix="fips-compat-")
    ref = commit or branch
    if not ref:
        raise SystemExit("--branch or --commit required when using --repo")

    print(f"Cloning {repo} (ref={ref}) into {tmpdir} ...")
    subprocess.check_call(["git", "init", tmpdir])
    subprocess.check_call(["git", "remote", "add", "origin", repo], cwd=tmpdir)
    subprocess.check_call(["git", "fetch", "--depth=1", "origin", ref], cwd=tmpdir)
    subprocess.check_call(["git", "checkout", "FETCH_HEAD"], cwd=tmpdir)

    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmpdir, text=True).strip()
    short = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=tmpdir, text=True).strip()

    return Path(tmpdir), {
        "mode": "clone",
        "repo": repo,
        "branch": branch,
        "commit": actual,
        "commit_short": short,
    }


def parse_enum_values(text: str, enum_name: str) -> dict[str, str]:
    m = re.search(rf"pub enum {enum_name}\s*\{{(?P<body>.*?)\n\}}", text, re.S)
    if not m:
        raise RuntimeError(f"could not find enum {enum_name}")
    body = m.group("body")
    values: dict[str, str] = {}
    for variant, value in re.findall(
        r"^\s*([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,", body, re.M
    ):
        values[variant] = value
    return values


def parse_pub_const_values(text: str, names: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in names:
        m = re.search(rf"pub const {name}: [^=]+ = ([^;]+);", text)
        if not m:
            raise RuntimeError(f"could not find const {name}")
        out[name] = m.group(1).strip()
    return out


def parse_pub_const_defs(text: str, names: list[str]) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for name in names:
        m = re.search(rf"pub const {name}:\s*([^=]+?)\s*=\s*([^;]+);", text)
        if not m:
            raise RuntimeError(f"could not find const {name}")
        out[name] = (m.group(1).strip(), m.group(2).strip())
    return out


def parse_optional_pub_const_defs(text: str, names: list[str]) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for name in names:
        m = re.search(rf"pub const {name}:\s*([^=]+?)\s*=\s*([^;]+);", text)
        if m:
            out[name] = (m.group(1).strip(), m.group(2).strip())
    return out


def eval_const_expr(expr: str, known: dict[str, int]) -> int:
    expr = expr.strip()
    if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", expr):
        return int(expr, 0)

    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        if expr not in known:
            raise RuntimeError(f"unknown const reference in expression: {expr}")
        return known[expr]

    m = re.fullmatch(r"(.+)\s*([+\-*/])\s*(.+)", expr)
    if not m:
        raise RuntimeError(f"unsupported const expression: {expr}")

    lhs = eval_const_expr(m.group(1), known)
    rhs = eval_const_expr(m.group(3), known)
    op = m.group(2)
    if op == "+":
        return lhs + rhs
    if op == "-":
        return lhs - rhs
    if op == "*":
        return lhs * rhs
    if op == "/":
        return lhs // rhs
    raise RuntimeError(f"unsupported operator in expression: {expr}")


def resolve_typed_consts(defs: dict[str, tuple[str, str]], names: list[str]) -> dict[str, tuple[str, int]]:
    resolved: dict[str, tuple[str, int]] = {}
    numeric_values: dict[str, int] = {}

    pending = dict(defs)
    while pending:
        progress = False
        for name in list(names):
            if name not in pending:
                continue
            const_type, expr = pending[name]
            try:
                value = eval_const_expr(expr, numeric_values)
            except RuntimeError:
                continue
            resolved[name] = (const_type, value)
            numeric_values[name] = value
            del pending[name]
            progress = True
        if not progress:
            unresolved = ", ".join(sorted(pending))
            raise RuntimeError(f"could not resolve const expressions: {unresolved}")

    return resolved


def render(fips_root: Path, provenance: dict) -> str:
    link_rs = fips_root / LINK_FILE
    mmp_mod_rs = fips_root / MMP_FILE
    noise_rs = fips_root / NOISE_FILE
    protocol_mod_rs = fips_root / PROTOCOL_FILE
    session_rs = fips_root / SESSION_FILE

    if not link_rs.exists():
        raise SystemExit(f"FIPS source not found: {link_rs}")
    if not mmp_mod_rs.exists():
        raise SystemExit(f"FIPS source not found: {mmp_mod_rs}")
    if not noise_rs.exists():
        raise SystemExit(f"FIPS source not found: {noise_rs}")
    if not protocol_mod_rs.exists():
        raise SystemExit(f"FIPS source not found: {protocol_mod_rs}")
    if not session_rs.exists():
        raise SystemExit(f"FIPS source not found: {session_rs}")

    link_text = link_rs.read_text()
    mmp_text = mmp_mod_rs.read_text()
    noise_text = noise_rs.read_text()
    protocol_text = protocol_mod_rs.read_text()
    session_text = session_rs.read_text()

    blocks: list[str] = []
    for enum_name, prefix in LINK_ENUMS.items():
        for variant, value in parse_enum_values(link_text, enum_name).items():
            const_name = f"{prefix}_{re.sub(r'(?<!^)(?=[A-Z])', '_', variant).upper()}"
            blocks.append(f"pub const {const_name}: u8 = {value};")

    mmp_values = parse_pub_const_values(mmp_text, MMP_CONSTS)
    for name, value in mmp_values.items():
        blocks.append(f"pub const {name}: usize = {value};")

    noise_defs = parse_pub_const_defs(noise_text, NOISE_CONSTS + INTERNAL_NOISE_CONSTS)
    noise_defs.update(parse_optional_pub_const_defs(noise_text, OPTIONAL_NOISE_CONSTS))
    noise_eval_names = NOISE_CONSTS + INTERNAL_NOISE_CONSTS + [name for name in OPTIONAL_NOISE_CONSTS if name in noise_defs]
    noise_values = resolve_typed_consts(noise_defs, noise_eval_names)
    for name, (const_type, value) in noise_values.items():
        if name in NOISE_CONSTS or name in OPTIONAL_NOISE_CONSTS:
            blocks.append(f"pub const {name}: {const_type} = {value};")

    protocol_defs = {
        **parse_pub_const_defs(protocol_text, ["PROTOCOL_VERSION"]),
        **parse_pub_const_defs(
            session_text,
            [
                "SESSION_SENDER_REPORT_SIZE",
                "SESSION_RECEIVER_REPORT_SIZE",
                "PATH_MTU_NOTIFICATION_SIZE",
                "COORDS_REQUIRED_SIZE",
                "MTU_EXCEEDED_SIZE",
            ],
        ),
        **parse_pub_const_defs(link_text, ["SESSION_DATAGRAM_HEADER_SIZE"]),
    }
    protocol_values = resolve_typed_consts(protocol_defs, PROTOCOL_CONSTS)
    for name, (const_type, value) in protocol_values.items():
        blocks.append(f"pub const {name}: {const_type} = {value};")

    body = "\n".join(sorted(blocks))

    header_lines = [
        "// @generated by tools/generate_fips_compat.py — DO NOT EDIT.",
    ]
    if provenance["mode"] == "clone":
        header_lines.append(f"// Upstream: {provenance['repo']}")
        header_lines.append(f"// Branch:   {provenance.get('branch', 'N/A')}")
        header_lines.append(f"// Commit:   {provenance['commit']}")
    else:
        header_lines.append(f"// Source:   {provenance['path']}")

    return "\n".join(header_lines) + "\n\n" + body + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate FIPS compatibility constants from upstream source."
    )
    parser.add_argument(
        "--fips-root",
        metavar="PATH",
        help="Path to local FIPS checkout (skips cloning)",
    )
    parser.add_argument(
        "--repo",
        metavar="URL",
        help="FIPS git repository URL (triggers shallow clone)",
    )
    parser.add_argument(
        "--branch",
        metavar="NAME",
        help="FIPS branch to checkout (used with --repo)",
    )
    parser.add_argument(
        "--commit",
        metavar="HASH",
        help="Specific FIPS commit to checkout (used with --repo, overrides --branch)",
    )
    args = parser.parse_args()

    fips_root, provenance = resolve_fips_root(args)
    content = render(fips_root, provenance)

    OUT_RS.parent.mkdir(parents=True, exist_ok=True)
    OUT_RS.write_text(content)
    print(f"wrote {OUT_RS}")

    if provenance["mode"] == "clone":
        print(f"  upstream: {provenance['repo']}")
        if provenance.get("branch"):
            print(f"  branch:   {provenance['branch']}")
        print(f"  commit:   {provenance['commit']}")


if __name__ == "__main__":
    main()
