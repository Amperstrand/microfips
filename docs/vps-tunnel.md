# VPS Tunnel Setup

This guide covers bridging the STM32's USB CDC ACM serial link to a VPS
running stock FIPS via SLIP-over-TCP.

## Architecture

```
STM32 (USB CDC ACM)
  |
  v
/dev/ttyACM0 (local machine)
  |
  v
socat (raw serial -> TCP)
  |
  v
TCP tunnel (plain, over internet)
  |
  v
socat (VPS: TCP -> PTY)
  |
  v
slattach (PTY -> SLIP line discipline -> sl0)
  |
  v
sl0 (kernel SLIP interface, IPv6)
  |
  v
stock FIPS on VPS (UDP :2121)
```

## Prerequisites

### Tools

```sh
# Both local machine and VPS
sudo apt install socat slattach

# Optional: auto-reconnect
sudo apt install autossh
```

### Kernel modules (VPS only)

```sh
sudo modprobe slip
sudo modprobe slhc 2>/dev/null || true

# Verify
lsmod | grep slip

# Persist across reboot
echo "slip" | sudo tee /etc/modules-load.d/slip.conf
```

If `modprobe slip` fails, install extra modules:
```sh
sudo apt install linux-modules-extra-$(uname -r)
```

### udev rule (local machine, optional)

Create `/etc/udev/rules.d/99-stm32-cdc.rules`:
```
SUBSYSTEM=="tty", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", SYMLINK+="stm32_slip", MODE="0666"
```

Reload: `sudo udevadm control --reload-rules && sudo udevadm trigger`

Now use `/dev/stm32_slip` instead of `/dev/ttyACM0`.

## VPS Setup

### 1. Create socat + slattach pipeline

```sh
# Clean up any previous run
sudo killall slattach 2>/dev/null; sudo killall socat 2>/dev/null
sudo ip link set sl0 down 2>/dev/null; sleep 1

# socat: listen TCP and bridge to a PTY
socat TCP-LISTEN:5000,reuseaddr,keepalive=1,keepidle=30,keepintvl=10,keepcnt=3 \
  PTY,link=/tmp/slip_pty,raw,echo=0 &
SOCAT_PID=$!
sleep 1

# slattach: attach SLIP line discipline to the PTY
# -p slip  = standard SLIP (RFC 1055), no header compression
# -L        = set local mode (ignore carrier detect)
# -s 115200 = baud rate (cosmetic for PTY, must match local side)
sudo slattach -p slip -s 115200 -L /tmp/slip_pty &
SLATTACH_PID=$!
sleep 1
```

### 2. Configure sl0 interface

```sh
# Bring interface up
sudo ip link set sl0 up

# Set MTU (IPv6 requires >= 1280, default SLIP MTU is 296)
sudo ip link set sl0 mtu 1500

# Assign IPv6 link-local address
sudo ip -6 addr add fe80::2/64 dev sl0

# Enable IPv6 forwarding (so FIPS can route to MCU)
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

### 3. Verify

```sh
# Check interface is up
ip -brief link show sl0
# Expected: sl0 UP ... mtu 1500

# Check IPv6 address
ip -6 addr show dev sl0
# Expected: inet6 fe80::2/64 scope link

# Monitor traffic (once MCU is connected)
sudo tcpdump -i sl0
```

### 4. systemd service (optional)

Create `/etc/systemd/system/slip-tunnel.service`:

```ini
[Unit]
Description=SLIP-over-TCP tunnel
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash -c '\
  socat TCP-LISTEN:5000,reuseaddr,keepalive=1,keepidle=30,keepintvl=10,keepcnt=3 \
    PTY,link=/tmp/slip_pty,raw,echo=0 & \
  SOCAT_PID=$!; sleep 1; \
  slattach -p slip -s 115200 -L /tmp/slip_pty & \
  SLATTACH_PID=$!; sleep 1; \
  ip link set sl0 up; \
  ip link set sl0 mtu 1500; \
  ip -6 addr add fe80::2/64 dev sl0; \
  echo "slip-tunnel ready (socat=$SOCAT_PID slattach=$SLATTACH_PID)"'

ExecStop=/bin/bash -c '\
  killall slattach 2>/dev/null; \
  killall socat 2>/dev/null; \
  ip link set sl0 down 2>/dev/null; \
  rm -f /tmp/slip_pty'

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now slip-tunnel
```

## Local Machine Setup

### 1. Bridge serial to TCP

```sh
SERIAL_DEV=/dev/ttyACM0    # or /dev/stm32_slip with udev rule
VPS_HOST=your-vps.example.com
VPS_PORT=5000

socat \
  "${SERIAL_DEV}",raw,echo=0,b115200,cs8,clocal,nonblock=1 \
  TCP:${VPS_HOST}:${VPS_PORT},keepalive=1,keepidle=30,keepintvl=10,keepcnt=3,nodelay=1
```

### 2. With auto-reconnect

```sh
#!/bin/bash
SERIAL_DEV=${1:-/dev/ttyACM0}
VPS_HOST=${2:-your-vps.example.com}
VPS_PORT=${3:-5000}

while true; do
  echo "Connecting ${SERIAL_DEV} -> ${VPS_HOST}:${VPS_PORT}..."
  socat \
    "${SERIAL_DEV}",raw,echo=0,b115200,cs8,clocal,nonblock=1 \
    TCP:${VPS_HOST}:${VPS_PORT},keepalive=1,keepidle=30,keepintvl=10,keepcnt=3,nodelay=1
  echo "Disconnected, retrying in 3s..."
  sleep 3
done
```

### 3. systemd service (optional)

Create `/etc/systemd/system/slip-local.service`:

```ini
[Unit]
Description=SLIP serial-to-TCP bridge
After=network.target

[Service]
ExecStart=/usr/bin/socat \
  /dev/ttyACM0,raw,echo=0,b115200,cs8,clocal,nonblock=1 \
  TCP:your-vps.example.com:5000,keepalive=1,keepidle=30,keepintvl=10,keepcnt=3,nodelay=1
Restart=on-failure
RestartSec=3
RestartPreventExitStatus=0

[Install]
WantedBy=multi-user.target
```

## Testing

### After connecting the STM32 (M4+ firmware):

```sh
# On VPS: ping the MCU
ping6 -I sl0 fe80::1

# On VPS: listen for UDP datagrams (M5+)
nc -6 -u -l -p 2121

# On VPS: monitor all traffic
sudo tcpdump -i sl0 -vv
```

### Verify SLIP framing (M2 firmware, before IP stack):

```sh
# On VPS: raw hex dump of what comes through
socat TCP-LISTEN:5000,reuseaddr HEXDUMP

# Then from local machine, connect MCU and bridge:
socat /dev/ttyACM0,raw,echo=0 TCP:vps:5000
```

You should see SLIP frames: `C0 <data> C0` with `DB DC` / `DB DD` escapes.

## How It Works

1. **socat on VPS** creates a PTY (e.g. `/dev/pts/7`) and exposes its path via symlink at `/tmp/slip_pty`
2. **slattach** opens the PTY, sets raw 8N1 mode, then issues `ioctl(fd, TIOCSETD, N_SLIP)` — this tells the kernel to interpret bytes on this fd as SLIP-framed IP packets and route them through the `sl0` interface
3. **socat on local machine** opens `/dev/ttyACM0` in raw mode and bridges bytes to TCP
4. The STM32 firmware sends SLIP-encoded IP packets out USB CDC ACM
5. Bytes flow: STM32 → USB → ttyACM0 → socat → TCP → socat → PTY → kernel SLIP driver → sl0

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `sl0` doesn't appear | `sudo modprobe slip`; check `lsmod \| grep slip` |
| `socat: PTY alloc failed` | Check PTY availability: `ls /dev/pts/` |
| `slattach` exits immediately | Check PTY path exists: `ls -la /tmp/slip_pty`; try running slattach manually |
| No traffic on sl0 | `sudo tcpdump -i sl0`; check MCU is sending SLIP frames; check socat is connected |
| Ping fails | Check `ip -6 addr show sl0`; verify both sides have fe80::/64 addresses; check MTU >= 1280 |
| Serial device not found | `ls /dev/ttyACM*`; check USB cable; `dmesg \| tail` for enumeration |
| Connection drops frequently | Add TCP keepalives; use the auto-reconnect script; check USB cable quality |
| Permission denied on serial | Add user to `dialout` group: `sudo usermod -aG dialout $USER` |

## Security Note

This setup uses **plain TCP** — SLIP-encapsulated IP packets are sent in the clear over the internet. For production use, consider wrapping the TCP tunnel in SSH or WireGuard:

```sh
# SSH tunnel alternative
autossh -M 0 -N -T \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 15000:127.0.0.1:5000 \
  user@your-vps.example.com &

# Then connect local socat to the forwarded port:
socat /dev/ttyACM0,raw,echo=0 TCP:127.0.0.1:15000
```

With SSH, change the VPS socat to bind localhost only:
```sh
socat TCP-LISTEN:5000,bind=127.0.0.1,reuseaddr PTY,link=/tmp/slip_pty,raw,echo=0
```
