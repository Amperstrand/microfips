#!/bin/bash
set -e

sudo tee /etc/fips/fips-bootstrap.yaml << 'ENDOFFILE'
node:
  identity:
    persistent: true
  control:
    enabled: true
    socket_path: "/run/fips/control.sock"

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"
  port: 5354

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    recv_buf_size: 2097152
    send_buf_size: 2097152

peers:
  - npub: "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
    alias: "fips-test-node"
    addresses:
      - transport: udp
        addr: "217.77.8.91:2121"
    connect_policy: auto_connect
  - npub: "npub1vdtfdhzl0n9k3hmexckfahe4ud0xzmt6aphuacng5tm5j3ftdppqj0ujhf"
    alias: "microfips-stm32"
    connect_policy: auto_connect
ENDOFFILE

echo "Config written."

echo "Looking for FIPS service..."
SERVICE=$(sudo systemctl list-units --type=service 2>/dev/null | grep -i fips | awk '{print $1}' | head -1)
if [ -n "$SERVICE" ]; then
    echo "Restarting service: $SERVICE"
    sudo systemctl restart "$SERVICE"
else
    echo "No systemd service found, sending SIGHUP to process..."
    FIPS_PID=$(pgrep -f "/usr/local/bin/fips")
    if [ -n "$FIPS_PID" ]; then
        sudo kill -9 "$FIPS_PID"
        sleep 1
        nohup /usr/local/bin/fips -c /etc/fips/fips-bootstrap.yaml > /tmp/fips.log 2>&1 &
        echo "FIPS restarted with PID: $!"
    else
        nohup /usr/local/bin/fips -c /etc/fips/fips-bootstrap.yaml > /tmp/fips.log 2>&1 &
        echo "FIPS started with PID: $!"
    fi
fi

sleep 2
echo "FIPS process:"
ps aux | grep fips | grep -v grep
echo "Final config:"
sudo cat /etc/fips/fips-bootstrap.yaml
