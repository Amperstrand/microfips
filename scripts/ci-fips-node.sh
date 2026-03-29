#!/usr/bin/env bash
# ci-fips-node.sh — Build and run a full FIPS node for CI integration tests.
#
# Adapted from https://gist.github.com/Amperstrand/3905c17eacd9a0c2274c21de4793e6ed
# Simplified for GitHub Actions: no systemd, no firewall, runs in foreground.
#
# TODO: Not yet used in CI. Requires key format conversion (raw secret → npub)
# to inject matching identities into both the FIPS node config and leaf tools.
# See the fips-integration CI job for the current approach using http-test.
#
# Usage:
#   scripts/ci-fips-node.sh start   # clone, build, start FIPS in background
#   scripts/ci-fips-node.sh stop    # kill background FIPS process
#   scripts/ci-fips-node.sh status  # show FIPS process status and logs
set -Eeuo pipefail

REPO_URL="https://github.com/jmcorgan/fips.git"
FIPS_DIR="${HOME}/fips-ci"
FIPS_CONFIG="/tmp/fips-ci.yaml"
FIPS_PID_FILE="/tmp/fips-ci.pid"
FIPS_LOG="/tmp/fips-ci.log"
FIPS_BIND="0.0.0.0:2121"

log() { printf '[ci-fips] %s\n' "$*"; }
die() { printf '[ci-fips] ERROR: %s\n' "$*" >&2; exit 1; }

cmd_start() {
    log "=== Starting FIPS node for CI ==="

    # --- Install build deps ---
    if ! command -v cargo >/dev/null 2>&1; then
        log "Installing Rust toolchain"
        curl https://sh.rustup.rs -sSf | sh -s -- -y
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    fi

    # --- Clone / update ---
    if [[ ! -d "${FIPS_DIR}/.git" ]]; then
        log "Cloning FIPS from ${REPO_URL}"
        git clone --depth 1 "${REPO_URL}" "${FIPS_DIR}"
    else
        log "Updating existing FIPS checkout"
        git -C "${FIPS_DIR}" fetch --depth 1 origin
        git -C "${FIPS_DIR}" reset --hard origin/HEAD
    fi

    # --- Build ---
    log "Building FIPS (release, no default features + tui)"
    # shellcheck disable=SC1091
    [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
    (cd "${FIPS_DIR}" && cargo build --release --no-default-features --features tui)
    local fips_bin="${FIPS_DIR}/target/release/fips"
    [[ -x "${fips_bin}" ]] || die "Build failed: ${fips_bin} not found"
    log "Built: ${fips_bin}"

    # --- Write config ---
    log "Writing config to ${FIPS_CONFIG}"
    cat > "${FIPS_CONFIG}" <<EOF
node:
  identity:
    persistent: false
  control:
    enabled: false

tun:
  enabled: false

dns:
  enabled: false

transports:
  udp:
    bind_addr: "${FIPS_BIND}"
    recv_buf_size: 2097152
    send_buf_size: 2097152
EOF

    # --- Start ---
    if [[ -f "${FIPS_PID_FILE}" ]]; then
        local old_pid
        old_pid=$(cat "${FIPS_PID_FILE}")
        if kill -0 "${old_pid}" 2>/dev/null; then
            log "Stopping previous FIPS (pid ${old_pid})"
            kill "${old_pid}" || true
            sleep 1
        fi
        rm -f "${FIPS_PID_FILE}"
    fi

    log "Starting FIPS (bind ${FIPS_BIND})"
    "${fips_bin}" -c "${FIPS_CONFIG}" > "${FIPS_LOG}" 2>&1 &
    local pid=$!
    echo "${pid}" > "${FIPS_PID_FILE}"
    log "FIPS started (pid ${pid})"

    # --- Wait for ready ---
    local i
    for i in $(seq 1 30); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            log "FIPS exited prematurely, log:"
            cat "${FIPS_LOG}" >&2
            die "FIPS failed to start"
        fi
        # Check if the UDP port is bound
        if ss -lunp 2>/dev/null | grep -q ":2121 " || \
           netstat -lunp 2>/dev/null | grep -q ":2121 "; then
            log "FIPS is listening on ${FIPS_BIND}"
            return 0
        fi
        sleep 1
    done

    log "Timed out waiting for FIPS to bind. Log tail:"
    tail -20 "${FIPS_LOG}" >&2
    die "FIPS did not bind within 30s"
}

cmd_stop() {
    if [[ -f "${FIPS_PID_FILE}" ]]; then
        local pid
        pid=$(cat "${FIPS_PID_FILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            log "Stopping FIPS (pid ${pid})"
            kill "${pid}" || true
            sleep 1
        fi
        rm -f "${FIPS_PID_FILE}"
    else
        log "No PID file found"
    fi
}

cmd_status() {
    if [[ -f "${FIPS_PID_FILE}" ]]; then
        local pid
        pid=$(cat "${FIPS_PID_FILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            log "FIPS running (pid ${pid})"
        else
            log "FIPS not running (stale pid ${pid})"
        fi
    else
        log "FIPS not started"
    fi
    if [[ -f "${FIPS_LOG}" ]]; then
        log "--- log tail ---"
        tail -20 "${FIPS_LOG}"
    fi
}

case "${1:-start}" in
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    *)      die "Usage: $0 {start|stop|status}" ;;
esac
