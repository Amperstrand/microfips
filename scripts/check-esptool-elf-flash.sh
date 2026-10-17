#!/usr/bin/env bash
# esptool raw-ELF flash guard - see #237.
#
# The rule: esptool write-flash NEVER takes an ELF image argument. esptool
# stores the RAW ELF bytes on flash — no chip's ROM reads ELF magic, so the
# image can never boot. The documented AGENTS.md "fallback" wrote the ELF at
# 0x0 while the ESP32 ROM boots from 0x1000: the write "verified" against its
# own bytes and the OLD firmware at 0x1000 kept running — a flash session
# that silently validates stale firmware (caught live on the #232 acceptance
# bench, 2026-10-16; fixed in AGENTS.md by 2160cd7).
#
# Like check-console-policy.sh this is a source-text guard on every push: the
# failure mode it catches is the trap being re-introduced by copy-paste from
# an old transcript or a stale chat answer, where a Rust compile-time check
# cannot see it (docs and shell scripts are not compiled at all).
#
# What is flagged: any `esptool ... write-flash <offset> <image>` line whose
# image argument is an unconverted ELF — either an explicit `.elf`, or a
# cargo release artifact (target/.../release/<name>, ~/.cargo-target
# equivalents) which carries NO file extension: the historical trap path
# `write-flash 0x0 target/xtensa-esp32-none-elf/release/microfips-esp32`
# ends in the bare crate name, not ".elf".
#
# What is NOT flagged, deliberately:
#   - any `.bin`/`.img` image (converted) at any offset — including
#     offset 0x0/0x00000, correct for ESP8266 and esptool single-bins
#     (esp8266-wifi-bridge/README.md)
#   - multi-bin esp-idf layouts (bootloader.bin + partition-table.bin + app)
#   - lines that WARN about the trap ("do NOT" / "never" / "DANGER" on the
#     line), so documentation may keep naming it
#   - this script itself
#
# Usage:
#   bash scripts/check-esptool-elf-flash.sh              (exit 0 = tree is clean)
#   bash scripts/check-esptool-elf-flash.sh --self-test  (exit 0 = guard works)
set -u

cd "$(dirname "$0")/.." || exit 2
ROOT=$PWD
GUARD_NAME=$(basename "$0")

# Coarse matcher: any esptool write-flash command line. Image-argument
# classification (converted bin vs raw ELF/cargo artifact) happens in bash
# below — see the header for the rule. Comment-only hits are filtered by
# the warn-line exemption.
PATTERN='esptool[^#]*write[ _-]?flas[h]'

# Extract the image argument (the token after the offset) from a matched
# line; prints it, or nothing when no offset+image pair is present.
image_arg() {
    printf '%s' "$1" | grep -oiE 'write[ _-]?flash[[:space:]]+0x[0-9a-f]+[[:space:]]+[^[:space:]]+' \
        | head -1 | awk '{print $NF}'
}

# True when the image argument is an unconverted ELF: explicit .elf, or a
# cargo release/debug artifact (no extension — target/<triple>/release/<crate>,
# the ~/.cargo-target variant, or a bare target/release path).
is_raw_elf() {
    local img=$1
    case "$img" in
        *.bin|*.img) return 1 ;;
    esac
    case "$img" in
        *.elf|*/release/*|*/debug/*) return 0 ;;
    esac
    return 1
}

fails=0
ok() { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }

scan_tree() {
    # git ls-files when in a repo; fall back to a bounded find.
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git ls-files
    else
        find . -type f \( -name '*.md' -o -name '*.sh' -o -name '*.py' \
            -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' \)
    fi
}

scan_file() {
    local file=$1
    grep -niE "$PATTERN" "$file" 2>/dev/null | while IFS= read -r hit; do
        local line_no content img
        line_no=${hit%%:*}
        content=${hit#*:}
        case "$content" in
            *[Dd]o[[:space:]]*[Nn][Oo][Tt]*|*[Nn]ever*|*[Dd][Aa][Nn][Gg][Ee][Rr]*)
                continue ;; # warning/documentation line — exempt
        esac
        img=$(image_arg "$content")
        [ -n "$img" ] || continue
        if is_raw_elf "$img"; then
            printf '%s:%s:%s\n' "$file" "$line_no" "$content"
        fi
    done
}

run_scan() {
    local hits=0
    while IFS= read -r file; do
        [ -f "$file" ] || continue
        [ "$(basename "$file")" = "$GUARD_NAME" ] && continue
        while IFS= read -r offender; do
            [ -n "$offender" ] || continue
            bad "raw-ELF esptool flash target: $offender"
            hits=1
        done < <(scan_file "$file")
    done < <(scan_tree)
    if [ "$hits" -eq 0 ]; then
        ok "no esptool write-flash command targets an ELF image"
    else
        bad "esptool must never write a raw ELF — convert first (espflash, or elf2image) and flash the .bin at the image's real offset"
    fi
}

self_test() {
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN
    # The historical trap verbatim: unsuffixed cargo artifact, no .elf.
    printf 'esptool --chip esp32 --port /dev/ttyUSB0 --before default-reset -b 460800 write-flash 0x0 target/xtensa-esp32-none-elf/release/microfips-esp32\n' \
        > "$tmp/bad-cargo.sh"
    printf 'esptool --chip esp32 write-flash 0x0 /home/ubuntu/.cargo-target/xtensa-esp32-none-elf/release/ledwifi\n' \
        > "$tmp/bad-cargohome.sh"
    printf 'esptool --chip esp32 write-flash 0x1000 image.elf\n' \
        > "$tmp/bad-elf.sh"
    printf 'esptool --chip esp32 write-flash 0x10000 /tmp/fw-test.bin\n' \
        > "$tmp/ok-bin.sh"
    printf 'esptool --chip esp8266 write_flash 0x00000 firmware.bin\n' \
        > "$tmp/ok-esp8266.sh"
    printf 'sudo esptool --chip esp32 --port /dev/ttyUSB1 write-flash 0x1000 /tmp/bootloader.bin 2>&1\n' \
        > "$tmp/ok-idf.sh"
    printf 'do NOT fall back to `esptool write-flash 0x0 target/release/microfips-esp32` (#237)\n' \
        > "$tmp/warn-doc.md"

    local flagged=0 f hits
    for f in "$tmp"/bad-cargo.sh "$tmp"/bad-cargohome.sh "$tmp"/bad-elf.sh \
             "$tmp"/ok-bin.sh "$tmp"/ok-esp8266.sh "$tmp"/ok-idf.sh "$tmp"/warn-doc.md; do
        hits=$(scan_file "$f")
        case "$f" in
            */bad-*)
                if [ -n "$hits" ]; then
                    flagged=$((flagged + 1)); ok "self-test: flags the trap line ($f)"
                else
                    bad "self-test: MISSED the trap line in $f"
                fi ;;
            *)
                if [ -n "$hits" ]; then
                    bad "self-test: false positive on $f: $hits"
                else
                    ok "self-test: clean file passes ($f)"
                fi ;;
        esac
    done
    [ "$flagged" -eq 3 ] || bad "self-test: expected 3 flagged fixtures, got $flagged"
}

case "${1:-}" in
    --self-test) self_test ;;
    *) run_scan ;;
esac

if [ "$fails" -gt 0 ]; then
    exit 1
fi
exit 0
