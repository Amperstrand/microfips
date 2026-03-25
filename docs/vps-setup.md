# VPS Setup: SLIP Tunnel over TCP

Quick-reference commands for the SLIP tunnel. For full documentation
including systemd services, troubleshooting, and SSH tunneling, see
[vps-tunnel.md](vps-tunnel.md).

## Transport Path

```
STM32 (USB CDC ACM)
  -> /dev/ttyACM0 (local machine)
  -> socat (raw serial -> TCP)
  -> TCP tunnel (plain, over internet)
  -> socat (VPS: TCP -> PTY)
  -> slattach (PTY -> SLIP line discipline -> sl0)
  -> sl0 (kernel SLIP interface, IPv6)
  -> stock FIPS on VPS (UDP :2121)
```

## VPS Commands

### 1. Load kernel module

```bash
sudo modprobe slip
```

### 2. Create socat + slattach pipeline

```bash
socat TCP-LISTEN:5000,reuseaddr,keepalive=1,keepidle=30,keepintvl=10,keepcnt=3 \
  PTY,link=/tmp/slip_pty,raw,echo=0 &
sleep 1
sudo slattach -p slip -s 115200 -L /tmp/slip_pty &
sleep 1
```

### 3. Configure sl0 interface

```bash
sudo ip link set sl0 up
sudo ip link set sl0 mtu 1500
sudo ip -6 addr add fe80::2/64 dev sl0
```

### 4. Verify

```bash
ip -brief link show sl0
ping6 -I sl0 fe80::1        # once MCU is running M4+
sudo tcpdump -i sl0 -vv     # monitor traffic
```

## Local Machine Commands

```bash
socat /dev/ttyACM0,raw,echo=0,b115200,cs8,clocal,nonblock=1 \
  TCP:your-vps.example.com:5000,keepalive=1,keepidle=30,keepintvl=10,keepcnt=3,nodelay=1
```

## Cleanup

```bash
sudo killall slattach; sudo killall socat
sudo ip link set sl0 down 2>/dev/null; rm -f /tmp/slip_pty
```

## FIPS Integration

Once the SLIP link is up and ICMP works (M4), FIPS on the VPS can route
through the sl0 interface to reach the MCU's IPv6 address. The MCU's
FIPS-derived fd00::/8 address will be reachable via this link.

## Troubleshooting

- `slattach` requires root or CAP_NET_ADMIN
- If sl0 doesn't appear: `sudo modprobe slip`
- No traffic on sl0: `sudo tcpdump -i sl0`; check MCU is sending SLIP frames
- Serial permission denied: `sudo usermod -aG dialout $USER`
- See [vps-tunnel.md](vps-tunnel.md) for full troubleshooting table
