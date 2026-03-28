#!/bin/bash
set -e
: "${VPS_PASS:?ERROR: VPS_PASS not set}"
echo "$VPS_PASS" | sudo -S bash -c 'cat > /etc/systemd/system/fips.service << ENDOFFILE
[Unit]
Description=FIPS Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fips -c /etc/fips/fips-bootstrap.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
ENDOFFILE'

echo "$VPS_PASS" | sudo -S systemctl daemon-reload
echo "$VPS_PASS" | sudo -S systemctl enable fips
echo "$VPS_PASS" | sudo -S systemctl start fips
sleep 2
echo "$VPS_PASS" | sudo -S systemctl status fips --no-pager
ss -ulnp | grep 2121
