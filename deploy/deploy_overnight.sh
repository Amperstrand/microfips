#!/usr/bin/env bash
# Deploy overnight monitoring infrastructure to remote hosts.
#
# Sets up:
#   ai-legion:        systemd service for ESP32 serial monitor (auto-starts on boot)
#   ai-legion-small:  systemd timer for hourly FIPS restart (recovery testing)
#
# Usage:
#   bash deploy/deploy_overnight.sh          # deploy services
#   bash deploy/deploy_overnight.sh --start  # deploy + start immediately
#   bash deploy/deploy_overnight.sh --stop   # stop services
#   bash deploy/deploy_overnight.sh --status # check status

set -euo pipefail

SSH_LEGION="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion"
SSH_SMALL="ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu@ai-legion-small"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

ACTION="${1:-deploy}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
info() { echo -e "${YELLOW}>>>>>${NC} $1"; }
success() { echo -e "${GREEN}OK${NC}: $1"; }

case "$ACTION" in
  --stop)
    info "Stopping services..."
    $SSH_LEGION 'sudo systemctl stop fips-overnight-monitor 2>/dev/null; echo done'
    $SSH_SMALL 'sudo systemctl stop fips-restart.timer 2>/dev/null; echo done'
    success "Services stopped"
    ;;

  --status)
    info "ai-legion monitor:"
    $SSH_LEGION 'systemctl is-active fips-overnight-monitor 2>/dev/null || echo "not installed"; echo "---"; wc -l /tmp/overnight-serial.log 2>/dev/null || echo "no serial log"; echo "---"; tail -3 /tmp/overnight-stats.tsv 2>/dev/null || echo "no stats"'
    echo ""
    info "ai-legion-small restart timer:"
    $SSH_SMALL 'systemctl is-active fips-restart.timer 2>/dev/null || echo "not installed"; echo "---"; cat /tmp/fips-restart-scheduler.log 2>/dev/null | tail -5 || echo "no restart log"'
    ;;

  deploy|--start)
    info "Deploying overnight monitor to ai-legion..."
    $SSH_LEGION 'sudo mkdir -p /opt/fips-monitor'
    scp -o BatchMode=yes "$REPO_DIR/scripts/overnight_monitor.py" ubuntu@ai-legion:/tmp/overnight_monitor.py 2>/dev/null
    $SSH_LEGION 'sudo cp /tmp/overnight_monitor.py /opt/fips-monitor/overnight_monitor.py'
    scp -o BatchMode=yes "$SCRIPT_DIR/fips-overnight-monitor.service" ubuntu@ai-legion:/tmp/fips-overnight-monitor.service 2>/dev/null
    $SSH_LEGION 'sudo cp /tmp/fips-overnight-monitor.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable fips-overnight-monitor'
    success "Monitor service installed on ai-legion (auto-starts on boot)"

    info "Deploying FIPS restart timer to ai-legion-small..."
    scp -o BatchMode=yes "$SCRIPT_DIR/fips-restart.service" "$SCRIPT_DIR/fips-restart.timer" ubuntu@ai-legion-small:/tmp/ 2>/dev/null
    $SSH_SMALL 'sudo cp /tmp/fips-restart.service /tmp/fips-restart.timer /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable fips-restart.timer'
    success "Restart timer installed on ai-legion-small (hourly FIPS restart)"

    if [[ "$ACTION" == "--start" ]]; then
      info "Starting services..."
      $SSH_LEGION 'sudo systemctl start fips-overnight-monitor'
      $SSH_SMALL 'sudo systemctl start fips-restart.timer'
      success "Services started"
      echo ""
      info "Monitor status:"
      sleep 5
      $SSH_LEGION 'systemctl is-active fips-overnight-monitor; wc -l /tmp/overnight-serial.log 2>/dev/null || echo "log starting..."'
    fi

    echo ""
    success "Deployment complete. Services auto-start on boot."
    echo "  Check status: bash deploy/deploy_overnight.sh --status"
    echo "  Stop:        bash deploy/deploy_overnight.sh --stop"
    ;;

  *)
    echo "Usage: $0 [--start|--stop|--status]"
    exit 1
    ;;
esac
