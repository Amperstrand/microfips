#!/bin/bash
echo "Elci9quadAd" | sudo -S bash -c 'cat > /etc/systemd/system/fips.service << ENDOFFILE
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

echo "Elci9quadAd" | sudo -S systemctl daemon-reload
echo "Elci9quadAd" | sudo -S systemctl enable fips
echo "Elci9quadAd" | sudo -S systemctl start fips
sleep 2
echo "Elci9quadAd" | sudo -S systemctl status fips --no-pager
ss -ulnp | grep 2121
