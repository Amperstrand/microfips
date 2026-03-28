#!/bin/bash
set -e
: "${VPS_PASS:?ERROR: VPS_PASS not set}"
echo "$VPS_PASS" | sudo -S bash -c 'cat > /etc/fips/fips-bootstrap.yaml << ENDOFFILE
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
ENDOFFILE'

echo "$VPS_PASS" | sudo -S systemctl restart fips
sleep 2
echo "$VPS_PASS" | sudo -S systemctl status fips --no-pager
echo ""
echo "Waiting for any incoming UDP..."
echo "$VPS_PASS" | sudo -S timeout 8 tcpdump -i any udp port 2121 -c 10 -nn 2>&1 &
sleep 1
echo "Test complete"
