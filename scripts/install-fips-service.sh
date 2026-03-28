#!/bin/bash
set -e
: "${VPS_PASS:?ERROR: VPS_PASS not set}"

echo "Creating systemd service..."
sudo tee /etc/systemd/system/fips.service << 'ENDOFFILE'
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
ENDOFFILE

echo "Enabling and starting fips..."
sudo systemctl daemon-reload
sudo systemctl enable fips
sudo systemctl start fips
sleep 2
sudo systemctl status fips --no-pager
echo ""
echo "Port check:"
ss -ulnp | grep 2121
