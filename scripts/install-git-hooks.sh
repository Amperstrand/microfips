#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install-git-hooks.sh -- activate THIS REPOSITORY'S OWN git hooks.
#
# WHAT YOU ARE OPTING INTO.  Running this points git at the hooks committed in
# this repo under `.githooks/`.  Once set, the following run on your local
# git operations in this repository:
#
#   .githooks/pre-commit -- refuses a commit whose staged diff matches a
#                           secret pattern from .secret-patterns.txt
#                           (no-op when that file is absent).
#   .githooks/pre-push   -- refuses a push whose outgoing history matches a
#                           secret pattern; and refuses a push of any path
#                           under `.ngit/` to a repo we do not own
#                           (fork hygiene -- see that file's header and
#                           .ngit/README.md for the policy in full).
#
# HOW.  It sets one repo-local config key:
#
#       core.hooksPath = .githooks
#
# The value is RELATIVE to the repository root on purpose: it is portable to a
# fresh clone and it works unchanged in a linked worktree.  Nothing outside
# this repository is touched -- in particular the fleet's shared ~/.git-hooks/
# is left alone (and stops being consulted in this repo, because
# core.hooksPath replaces the hooks directory wholesale rather than adding to
# it).
#
# WHY IT IS NEEDED.  Git does not run hooks just because they are committed:
# a fresh clone has the files but not the config, i.e. no guard at all.  Run
# this once per clone.
#
# Safe to re-run: if `core.hooksPath` is already `.githooks` the script changes
# nothing and says so.  If it is already set to some *other* value the script
# refuses to clobber it unless you pass --force.
#
# Usage:  scripts/install-git-hooks.sh [--force]
# ---------------------------------------------------------------------------
set -euo pipefail

TARGET_PATH=".githooks"     # repo-relative; keep it relative for portability
FORCE=0

usage() {
    cat <<'EOF'
Usage: scripts/install-git-hooks.sh [--force]

Points this repository at its own committed git hooks by setting the
repo-local config key  core.hooksPath = .githooks  (relative to the repo root,
so it is portable to a fresh clone and works in a linked worktree).

Once installed, .githooks/pre-commit and .githooks/pre-push run on local
commits/pushes in this repo -- see the header of this script for what they do,
or read .githooks/pre-push for the fork-hygiene policy.

  --force     overwrite a core.hooksPath that is already set to a different value
  -h, --help  show this help and exit

Re-running when the value is already .githooks is a no-op.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --force) FORCE=1 ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "[install-git-hooks] unknown argument: $1" >&2
            echo >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

CONFIG_FILE="$(git rev-parse --git-common-dir)/config"

# What git resolves today (repo-local wins over global) and what is set locally.
effective="$(git config --get core.hooksPath || true)"
local_value="$(git config --local --get core.hooksPath || true)"

echo "[install-git-hooks] repo: ${REPO_ROOT}"
echo "[install-git-hooks] git config: ${CONFIG_FILE}"
echo "[install-git-hooks] core.hooksPath in effect: ${effective:-(unset)}"

if [ "$effective" = "$TARGET_PATH" ]; then
    echo "[install-git-hooks] already installed -- nothing changed."
    echo "[install-git-hooks] active hooks from ${TARGET_PATH}/: pre-commit (secret scan), pre-push (secret scan + .ngit/ fork-hygiene guard)"
    exit 0
fi

if [ -n "$effective" ] && [ "$FORCE" -ne 1 ]; then
    echo "[install-git-hooks] REFUSING to clobber a different core.hooksPath." >&2
    echo "[install-git-hooks] It is currently '${effective}', not '${TARGET_PATH}'." >&2
    echo "[install-git-hooks] Re-run with --force if you really mean to replace it." >&2
    exit 1
fi

if [ "$FORCE" -eq 1 ] && [ -n "$effective" ]; then
    echo "[install-git-hooks] --force: replacing '${effective}' with '${TARGET_PATH}'"
fi

# The hooks we are about to activate must be present and executable -- git
# ignores a non-executable hook silently, which is exactly the failure mode
# this installer exists to prevent.
for h in pre-commit pre-push; do
    if [ ! -f "${TARGET_PATH}/${h}" ]; then
        echo "[install-git-hooks] ERROR: ${TARGET_PATH}/${h} is missing from this checkout." >&2
        exit 1
    fi
    if [ ! -x "${TARGET_PATH}/${h}" ]; then
        echo "[install-git-hooks] WARNING: ${TARGET_PATH}/${h} is not executable; git would silently skip it." >&2
    fi
done

git config --local core.hooksPath "$TARGET_PATH"

installed="$(git config --get core.hooksPath || true)"
if [ "$installed" != "$TARGET_PATH" ]; then
    echo "[install-git-hooks] ERROR: wrote core.hooksPath=${TARGET_PATH} but git reads back '${installed}'." >&2
    exit 1
fi

echo "[install-git-hooks] changed: was '${local_value:-(unset)}', now '${installed}'"
echo "[install-git-hooks]   -> ${CONFIG_FILE}: core.hooksPath = ${installed}"
echo "[install-git-hooks] active hooks from ${TARGET_PATH}/: pre-commit (secret scan), pre-push (secret scan + .ngit/ fork-hygiene guard)"
echo "[install-git-hooks] done. A fresh clone has neither the config nor the guard -- re-run this script there."
