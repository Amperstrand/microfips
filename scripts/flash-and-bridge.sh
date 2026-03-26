#!/bin/bash
set -e

VPS="routstr@orangeclaw.dns4sats.xyz"
VPASS="Elci9quadAd"
VPS_SSH="sshpass -p '$VPASS' ssh -o StrictHostKeyChecking=no $VPS"

echo "=== Step 1: Flash MCU ==="
sudo fuser -k /dev/bus/usb/001/* 2>/dev/null || true
sleep 1
sudo /home/ubuntu/.cargo/bin/probe-rs download --chip STM32F469NIHx \
    /home/ubuntu/src/microfips/target/thumbv7em-none-eabi/release/microfips 2>&1
echo "Flash done"

echo "=== Step 2: Reset MCU ==="
sleep 1
sudo /home/ubuntu/.cargo/bin/probe-rs reset --chip STM32F469NIHx 2>&1 || true
echo "Reset done"

echo "=== Step 3: Wait for USB enumeration ==="
for i in $(seq 1 20); do
    if ls /dev/ttyACM1 2>/dev/null; then
        if lsusb 2>/dev/null | grep -q "c0de:cafe"; then
            echo "USB enumerated at /dev/ttyACM1 (attempt $i)"
            break
        fi
    fi
    sleep 1
done

if ! ls /dev/ttyACM1 2>/dev/null; then
    echo "ERROR: USB did not enumerate"
    exit 1
fi

echo "=== Step 4: Start local bridge ==="
nohup socat -d -d TCP:91.99.211.197:5000,nodelay=1 \
    /dev/ttyACM1,raw,echo=0,b115200 \
    > /tmp/socat_bridge.log 2>&1 &
BRIDGE_PID=$!
echo "Bridge PID: $BRIDGE_PID"

echo "=== Step 5: Wait for data transfer ==="
sleep 15

echo "=== Step 6: Bridge log ==="
cat /tmp/socat_bridge.log

echo "=== Step 7: Ping from VPS ==="
$VPS_SSH "echo '$VPASS' | sudo -S ping6 -I sl0 -c 3 -W 3 fe80::1" 2>&1 || true

echo "=== Step 8: VPS sl0 traffic ==="
$VPS_SSH "echo '$VPASS' | sudo -S timeout 3 tcpdump -i sl0 -c 5 -nn" 2>&1 || true

echo "=== DONE ==="
