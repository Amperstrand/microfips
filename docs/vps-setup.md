# VPS Setup: SLIP Tunnel over TCP

This document describes how to set up the VPS side of the serial-to-IP tunnel
that connects the STM32 MCU to the VPS running stock FIPS.

## Transport Path

```
STM32 (USB CDC ACM)
  -> /dev/ttyACM0 on local machine
  -> socat (local) -> TCP tunnel -> VPS
  -> socat (VPS) -> PTY -> slattach -> sl0
  -> IP link -> UDP -> stock FIPS on VPS
```

## VPS Commands

### 1. Create the SLIP tunnel endpoint

```bash
# Create a PTY and bridge it to a TCP listener
socat TCP-LISTEN:12345,reuseaddr,fork \
  SYSTEM:'slattach -6 -p slip -s 115200 /dev/ptmx',pty,raw,echo=0 &
```

### 2. Configure the SLIP interface

```bash
# Wait for sl0 to appear, then bring it up
sleep 1
ip link set sl0 up

# Assign IPv6 link-local addresses
ip addr add fe80::2/64 dev sl0

# Add route to MCU
ip -6 route add fe80::1 dev sl0
```

### 3. Verify

```bash
# Ping the MCU (once it's running M4+)
ping6 -I sl0 fe80::1

# Check interface
ip -6 addr show sl0
```

## Local Machine Commands

### Bridge USB CDC ACM to TCP tunnel

```bash
# Forward raw bytes from USB serial to VPS TCP port
socat /dev/ttyACM0,raw,echo=0,nonblock TCP:vps-ip:12345
```

## Alternative: Direct serial (no TCP tunnel)

If the VPS has direct serial access (e.g., via serial server):

```bash
# On VPS
slattach -6 -p slip -s 115200 /dev/ttyUSB0 &
ip link set sl0 up
ip addr add fe80::2/64 dev sl0
```

## FIPS Integration

Once the SLIP link is up and ICMP works (M4), FIPS on the VPS can route
through the sl0 interface to reach the MCU's IPv6 address. The MCU's
FIPS-derived fd00::/8 address will be reachable via this link.

## Troubleshooting

- `slattach` requires root or CAP_NET_ADMIN
- If sl0 doesn't appear, check that the SLIP kernel module is loaded:
  `lsmod | grep slip` or `modprobe slip`
- Use `tcpdump -i sl0` to verify traffic on the SLIP interface
- Check that socat is running and the TCP connection is established
- Use `stty -F /dev/ttyACM0` to verify serial port settings
