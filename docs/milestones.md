# Milestones

## M0: Environment & Workspace

- [x] Confirm board (STM32F469I-DISCO) and tooling (probe-rs, thumbv7em-none-eabihf)
- [x] Create git repo and GitHub remote
- [x] Create project scaffold and documentation
- [x] Verify toolchain targets are installed

## M1: USB CDC ACM + Echo

- [ ] Embassy firmware with clock config (HSE bypass, 168 MHz)
- [ ] USB OTG FS enumeration with CDC ACM class
- [ ] LED heartbeat blink (PG6)
- [ ] Echo received USB packets back to host
- [ ] defmt logging via RTT
- [ ] Build verification
- [ ] Flash and verify USB enumeration on host

**Success signal:** `ls /dev/ttyACM*` shows device; `picocom /dev/ttyACM0` echoes text.

## M2: SLIP Framing

- [ ] SLIP encoder module (async, zero-copy)
- [ ] SLIP decoder module (async, handles ESC sequences)
- [ ] Send SLIP-encoded heartbeats from MCU
- [ ] Verify framing with host-side hex dump
- [ ] Consider refactoring to workspace (microfips-transport crate)

**Success signal:** Host receives valid SLIP frames from MCU.

## M3: VPS Tunnel Plumbing

- [ ] Document exact socat/slattach/ip commands
- [ ] Test with mock SLIP source on VPS
- [ ] Verify sl0 interface with IPv6 link-local
- [ ] Test end-to-end with USB CDC ACM connected

**Success signal:** `ping6 -I sl0 fe80::2` works locally on VPS.

## M4: Embedded IP + ICMP Ping

- [ ] Implement embassy-net-driver Device for SLIP-over-CDC-ACM
- [ ] Create embassy-net Stack with IPv6 + ICMPv6
- [ ] smoltcp handles ICMPv6 Echo Request/Response
- [ ] Assign link-local IPv6 address to MCU

**Success signal:** `ping6 fe80::1%sl0` from VPS gets replies from MCU.

## M5: Bidirectional UDP

- [ ] Open UDP socket on MCU
- [ ] Send/receive datagrams between VPS and MCU
- [ ] Verify payload integrity

**Success signal:** MCU sends "hello from MCU" UDP datagram; VPS receives it.

## M6: FIPS Leaf Node

- [ ] Generate secp256k1 keypair (k256 crate)
- [ ] Persist keypair to flash
- [ ] Derive npub and fd00::/8 IPv6 address
- [ ] Implement Noise IK handshake (link layer)
- [ ] Implement Noise XK handshake (session layer)
- [ ] FMP: single-peer link, no transit
- [ ] FSP: single session to VPS peer, port 256
- [ ] Wire format compatible with stock FIPS

**Success signal:** MCU appears as FIPS peer on VPS `fipsctl show peers`.

## M7: HTTP Server

- [ ] Tiny HTTP/1.1 server over FIPS session
- [ ] Serve "hello fips" response
- [ ] Include node status (uptime, peer state, address)
- [ ] Optional: sensor data endpoint

**Success signal:** `curl http://npub1xxx.fips` from VPS returns status page.
