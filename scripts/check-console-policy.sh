#!/usr/bin/env bash
# Console-channel policy guard - see docs/console-channels.md.
#
# The rule is "an image may install the log backend only when esp-println's output
# channel differs from the channel its FIPS frames leave on". The install half of the
# rule is a call you can read; the *silence* half is the absence of a call, and no Rust
# compile-time construct can assert an absence (compile_error! can be gated on a cfg or a
# const-evaluable condition, not on "this body does not call X", and the transport crate
# deliberately has no compile-time "logger already initialised" state to gate on). So the
# absence is asserted here, from the source text, on every push. The failure mode this
# catches is the real one: the `uart` entry body copied into `run_usb_node`, or a new
# image that installs the backend without anybody deciding it should.
#
# Three sections, all table-driven so a policy change is a one-line diff:
#   A. entry-point bodies: install-early | install | silent
#   B. silent binaries     : an image that must not install, checked at the bin too
#   C. repo-wide census    : exact per-file counts of `logger::init()` call sites, so a
#                            call in a file nobody declared fails the run.
#
# Comment lines are ignored when counting, so the `// Deliberately NO logger::init()`
# remarks in the silent bodies are not mistaken for calls.
#
# Usage: bash scripts/check-console-policy.sh      (exit 0 = policy holds)
set -u

cd "$(dirname "$0")/.." || exit 2
ROOT=$PWD

fails=0
ok() { printf 'ok    %s\n' "$1"; }
bad() {
    printf 'FAIL  %s\n' "$1"
    fails=$((fails + 1))
}

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

# --- helpers ----------------------------------------------------------------------
# body_of FILE FN - print FN's definition body, brace-matched. Exit 1 if the function
# is absent or its braces do not balance, so a renamed entry point FAILS instead of
# passing vacuously.
body_of() {
    awk -v pat="^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+$2[[:space:]]*[(<]" '
        state == 0 { if ($0 ~ pat) state = 1; next }
        state >= 1 {
            line = $0
            n = gsub(/\{/, "{", line)
            m = gsub(/\}/, "}", line)
            depth += n - m
            print line
            if (state == 1) {
                if (n > 0) { state = 2; if (depth <= 0) { done = 1; exit } }
                next
            }
            if (depth <= 0) { done = 1; exit }
        }
        END { exit (done ? 0 : 1) }
    ' "$1"
}

# calls FILE - numbered lines that hold a real `logger::init()` call (comment lines and
# block-comment continuations excluded).
calls() {
    grep -n 'logger::init()' "$1" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*(//|\*)'
}

# first_line_of CMD... - first line number out of a numbered grep stream
first_line() { head -1 | cut -d: -f1; }

# Entry points that are thin wrappers over an installing helper (relay_ap's
# `run_relay_ap` / `run_relay_ap_peer` -> `run_relay_ap_opts`) are listed by the helper
# that actually installs: section C pins each file's call count, so a wrapper cannot
# add a second install without failing this script.
echo "== A. entry-point console policy =="
while IFS=: read -r file fn policy; do
    [ -n "${file:-}" ] || continue
    if [ ! -f "$file" ]; then
        bad "$file :: $fn - file missing (entry point moved?)"
        continue
    fi
    if ! body_of "$file" "$fn" >"$tmp/body"; then
        bad "$file :: $fn - body not found or braces unbalanced (renamed?)"
        continue
    fi
    body_lines=$(wc -l <"$tmp/body")
    if [ "$body_lines" -lt 3 ]; then
        bad "$file :: $fn - extracted body is only $body_lines line(s); refusing to pass vacuously"
        continue
    fi
    n=$(calls "$tmp/body" | wc -l)

    case "$policy" in
    silent)
        if [ "$n" -eq 0 ]; then
            ok "$file :: $fn  silent (0 logger::init() calls, body $body_lines lines)"
        else
            bad "$file :: $fn  declared silent but has $n logger::init() call(s): $(calls "$tmp/body" | head -1)"
        fi
        ;;
    install)
        if [ "$n" -ge 1 ]; then
            ok "$file :: $fn  install ($n call(s))"
        else
            bad "$file :: $fn  declared install but no logger::init() call in the body"
        fi
        ;;
    install-early)
        init_at=$(calls "$tmp/body" | first_line)
        setup_at=$(grep -nE 'heap::init\(\)|runner::make_led|runner::init_trng|runner::run_node' "$tmp/body" |
            grep -vE '^[0-9]+:[[:space:]]*(//|\*)' | first_line)
        if [ "$n" -ne 1 ]; then
            bad "$file :: $fn  declared install-early but has $n logger::init() call(s) (want exactly 1)"
        elif [ -z "$setup_at" ]; then
            bad "$file :: $fn  install-early: no heap/runner setup call found to order against (extraction problem?)"
        elif [ "$init_at" -lt "$setup_at" ]; then
            ok "$file :: $fn  install-early (call at body line $init_at, first setup call at body line $setup_at)"
        else
            bad "$file :: $fn  install-early violated: setup call at body line $setup_at precedes the install at $init_at"
        fi
        ;;
    *)
        bad "$file :: $fn - unknown policy '$policy' in this guard's table"
        ;;
    esac
done <<'EOF'
crates/microfips-esp32s3/src/run.rs:run_uart_node:install-early
crates/microfips-esp32s3/src/run.rs:run_usb_node:silent
crates/microfips-esp32c3/src/run.rs:run_uart_node:install-early
crates/microfips-esp32c3/src/run.rs:run_usb_node:silent
crates/microfips-esp32/src/run.rs:run_uart_node:silent
crates/microfips-esp-transport/src/espnow_gateway.rs:run_espnow_gateway:silent
crates/microfips-esp-transport/src/espnow_wifi_gateway.rs:run_espnow_wifi_gateway:install
crates/microfips-esp-transport/src/relay_ap.rs:run_relay_ap_opts:install
crates/microfips-esp-transport/src/run_tasks.rs:run_ble_node:install
crates/microfips-esp-transport/src/run_tasks.rs:run_l2cap_node:install
crates/microfips-esp-transport/src/run_tasks.rs:run_wifi_node:install
crates/microfips-esp-transport/src/run_tasks.rs:run_hybrid_node:install
crates/microfips-esp-transport/src/run_tasks.rs:run_esp_now_node:install
crates/microfips-esp32s3/src/bin/mdns_spike.rs:main:install
EOF

echo
echo "== B. silent binaries (the bin itself, not only the entry point) =="
while IFS= read -r bin; do
    [ -n "$bin" ] || continue
    if [ ! -f "$bin" ]; then
        bad "$bin - file missing"
        continue
    fi
    n=$(calls "$bin" | wc -l)
    if [ "$n" -eq 0 ]; then
        ok "$bin  silent (0 logger::init() calls)"
    else
        bad "$bin  has $n logger::init() call(s): $(calls "$bin" | head -1)"
    fi
done <<'EOF'
crates/microfips-esp32s3/src/bin/usb.rs
crates/microfips-esp32c3/src/bin/usb.rs
crates/microfips-esp32s3/src/bin/espnow_gw.rs
crates/microfips-esp32/src/bin/uart.rs
EOF

echo
echo "== C. repo-wide logger::init() call-site census =="
if ! git ls-files '*.rs' >"$tmp/files" 2>/dev/null; then
    find crates -name '*.rs' >"$tmp/files"
fi
: >"$tmp/actual"
while IFS= read -r f; do
    [ -f "$f" ] || continue
    n=$(calls "$f" | wc -l)
    [ "$n" -gt 0 ] && printf '%s:%s\n' "$f" "$n" >>"$tmp/actual"
done <"$tmp/files"

cat >"$tmp/expected" <<'EOF'
crates/microfips-esp-transport/src/espnow_wifi_gateway.rs:1
crates/microfips-esp-transport/src/relay_ap.rs:1
crates/microfips-esp-transport/src/run_tasks.rs:5
crates/microfips-esp32c3/src/run.rs:1
crates/microfips-esp32s3/src/bin/mdns_spike.rs:1
crates/microfips-esp32s3/src/run.rs:1
EOF
sort -o "$tmp/expected" "$tmp/expected"
sort -o "$tmp/actual" "$tmp/actual"

if diff -u "$tmp/expected" "$tmp/actual" >"$tmp/census.diff"; then
    ok "census matches the declared call sites ($(wc -l <"$tmp/actual") file(s), $(awk -F: '{s += $2} END {print s}' "$tmp/actual") call(s))"
else
    bad "the logger::init() call-site census changed (- expected / + actual); update this script's table if the policy really changed:"
    sed 's/^/      /' "$tmp/census.diff"
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "console-channel policy: OK"
    exit 0
fi
echo "console-channel policy: $fails violation(s)"
exit 1
