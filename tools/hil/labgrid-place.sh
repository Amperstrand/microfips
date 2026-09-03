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
lg add-match "${EXPORTER_NAME}/stm32-stlink/BenchSerialToken"
lg show | sed -n '1,5p'
