#!/usr/bin/env bash
# Idempotently (re)create the microfips-bench place with its resource
# matches. Coordinator restarts wipe in-memory place definitions — run
# this after any labgrid-coordinator restart (bolty-rs labgrid-place.sh).
set -euo pipefail

COORDINATOR="${LABGRID_COORDINATOR:-192.168.13.221:20408}"
EXPORTER_NAME="${LABGRID_EXPORTER_NAME:-ai-legion-small-microfips}"
PLACE="microfips-bench"

lg() { labgrid-client -x "$COORDINATOR" -p "$PLACE" "$@"; }

if lg show >/dev/null 2>&1; then
    echo "place $PLACE exists"
else
    lg create
    echo "place $PLACE created"
fi

lg add-match "${EXPORTER_NAME}/s3-lab-serial/BenchSerialToken"
lg add-match "${EXPORTER_NAME}/atom-a-serial/BenchSerialToken"
lg add-match "${EXPORTER_NAME}/atom-b-serial/BenchSerialToken"
lg add-match "${EXPORTER_NAME}/cyd-serial/BenchSerialToken"
lg add-match "${EXPORTER_NAME}/stm32-stlink/BenchSerialToken"
lg show | sed -n '1,5p'

# Per-board DOCUMENTATION places: never acquired for exclusivity (that is
# microfips-bench + the amperstrand-bench flock) — they carry state tags
# (firmware/test/owner) mirrored by fips_lab.note_board_state, so any
# project or machine can ask labgrid what a board currently runs.
BOARD_PLACE() {  # $1 = token resource, $2 = place suffix
    local p="microfips-$2"
    labgrid-client -x "$COORDINATOR" -p "$p" create 2>/dev/null || true
    labgrid-client -x "$COORDINATOR" -p "$p" \
        add-match "${EXPORTER_NAME}/$1/BenchSerialToken" 2>/dev/null || true
    labgrid-client -x "$COORDINATOR" -p "$p" \
        set-comment "state record for $2 (tags: firmware/test/owner/ts)" \
        2>/dev/null || true
}
BOARD_PLACE s3-lab-serial  s3-lab
BOARD_PLACE atom-a-serial  atom-a
BOARD_PLACE atom-b-serial  atom-b
BOARD_PLACE cyd-serial     cyd
BOARD_PLACE stm32-stlink   stm32
