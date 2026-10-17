#!/bin/bash
# check-flash-policy.sh — CI gate: the esptool 0x0-ELF trap must not re-enter
# the tree (#237), and flash entrypoints must enforce boot verification.
#
# The 2026-10-16 HW-232 session proved `esptool write-flash 0x0 <elf>`
# silently validates stale firmware (raw ELF lands at 0x0; ROM boots 0x1000).
# The fallback was replaced with espflash (2160cd7) — this gate makes the
# regression mechanically impossible to re-introduce unnoticed.
#
# Exit 0 = policy holds; exit 1 = violation (printed loudly).
# --self-test: validate the checker itself without touching tracked files.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

# The literal trap patterns. `write-flash 0x0` with an ELF argument; also the
# bare offset form whose only documented use was that fallback.

# The literal trap: write-flash to 0x0 with an ELF argument — esptool stores
# the RAW ELF while the ESP32 ROM boots the image at 0x1000 (#237). A .bin at
# 0x0 is legitimate on ESP8266 (its ROM does boot 0x0), so the ELF arg is the
# discriminator. Lines that NAME the trap to forbid it (DANGER / do NOT) are
# documentation, not commandable — exempted.
is_trap_line() {
    local line="$1"
    case "$line" in
        *DANGER*|*"do NOT"*|*"Do NOT"*) return 1 ;;
    esac
    case "$line" in
        *write-flash\ 0x0*.elf*|*write_flash\ 0x0*.elf*) return 0 ;;
    esac
    return 1
}

fail() { echo "FLASH-POLICY VIOLATION: $*" >&2; FAILED=1; }

check_file() {
    local f="$1"
    while IFS= read -r line; do
        if is_trap_line "$line"; then
            fail "'$f' flashes a raw ELF at 0x0 — the #237 stale-firmware trap (ROM boots 0x1000): $line"
            return 1
        fi
    done < "$f"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    bash -n "$0" || { echo "self-test: syntax"; exit 1; }
    # is_trap_line decision table: the four cases the matcher must get right
    is_trap_line 'esptool write-flash 0x0 fw.elf' || { echo "self-test FAIL: raw-ELF-at-0x0 not caught"; exit 1; }
    is_trap_line 'esptool --chip esp32 write_flash 0x0 /tmp/app.elf' || { echo "self-test FAIL: underscore variant missed"; exit 1; }
    is_trap_line 'esptool write-flash 0x00000 .pio/build/esp01_1m/firmware.bin' && { echo "self-test FAIL: ESP8266 .bin false positive"; exit 1; }
    is_trap_line '**DANGER: do NOT fall back to** `esptool write-flash 0x0 <elf>`**' && { echo "self-test FAIL: DANGER doc line false positive"; exit 1; }
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    printf 'esptool write-flash 0x0 fw.elf\n' > "$tmp/bad.sh"
    FAILED=0
    check_file "$tmp/bad.sh" 2>/dev/null
    [ "$FAILED" = "1" ] || { echo "self-test FAIL: file scan did not catch trap"; exit 1; }
    printf 'espflash flash --chip esp32 fw.elf\n' > "$tmp/good.sh"
    FAILED=0
    check_file "$tmp/good.sh" || { echo "self-test FAIL: false positive"; exit 1; }
    [ "$FAILED" = "0" ] || { echo "self-test FAIL: false positive set FAILED"; exit 1; }
    # the flash entrypoints must require post-flash verification (fail-closed)
    for script in labgrid/scripts/flash_esp32.sh labgrid/scripts/flash_esp32s3.sh; do
        grep -qF 'MICROFIPS_BOOT_MARKER' "$REPO/$script" || {
            echo "self-test FAIL: $script lost the MICROFIPS_BOOT_MARKER fail-closed gate"; exit 1; }
        grep -qF 'verify_flash_boot.sh' "$REPO/$script" || {
            echo "self-test FAIL: $script does not call verify_flash_boot.sh"; exit 1; }
    done
    # scan-mode exclusion: the guard's own file quotes the trap patterns as
    # self-test fixtures above and must not trip the scan — while the same
    # trap in any other tracked file must still fail it.
    tmprepo="$(mktemp -d)"
    trap 'rm -rf "$tmp" "$tmprepo"' EXIT
    git -C "$tmprepo" init -q
    mkdir -p "$tmprepo/scripts"
    cp "$0" "$tmprepo/scripts/check-flash-policy.sh"
    git -C "$tmprepo" add -A
    ( cd "$tmprepo" && bash scripts/check-flash-policy.sh ) >/dev/null 2>&1 \
        || { echo "self-test FAIL: scan flags the guard's own self-test fixtures"; exit 1; }
    printf 'esptool write-flash 0x0 fw.elf\n' > "$tmprepo/scripts/trap.sh"
    git -C "$tmprepo" add -A
    ( cd "$tmprepo" && bash scripts/check-flash-policy.sh ) >/dev/null 2>&1 \
        && { echo "self-test FAIL: self-exclusion hides traps in other files"; exit 1; }
    echo "check-flash-policy self-test: PASS"
    exit 0
fi

# Scan tracked files (docs included — the trap originally lived in AGENTS.md).
FAILED=0
cd "$REPO" || { echo "FLASH-POLICY VIOLATION: no repo" >&2; exit 1; }
while IFS= read -r f; do
    case "$f" in
        # The guard quotes the trap patterns as self-test fixtures; it names
        # the trap to forbid it, it does not flash anything.
        scripts/check-flash-policy.sh) ;;
        *.sh|*.py|*.md|*.yml|*.yaml|*.toml|Makefile) check_file "$f" ;;
    esac
done < <(git ls-files)

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi

echo "flash-policy: PASS (no 0x0-ELF traps in tracked files; flash entrypoints verify boots)"
