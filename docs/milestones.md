# Milestones

## M0: Environment & Workspace

- [x] Confirm board (STM32F469I-DISCO) and tooling (probe-rs, thumbv7em-none-eabihf)
- [x] Create git repo and GitHub remote
- [x] Create project scaffold and documentation
- [x] Verify toolchain targets are installed

## M1: USB CDC ACM + Echo

- [x] Embassy firmware with clock config (HSE bypass, 168 MHz)
- [x] USB OTG FS enumeration with CDC ACM class
- [x] LED heartbeat blink (PG6)
- [x] Echo received USB packets back to host
- [x] defmt logging via RTT
- [x] Build verification
- [ ] Flash and verify USB enumeration on host

**Success signal:** `ls /dev/ttyACM*` shows device; `picocom /dev/ttyACM0` echoes text.

## M2: SLIP Framing

- [x] SLIP encoder module (RFC 1055, zero-copy)
- [x] SLIP decoder module (handles ESC sequences, frame reassembly)
- [x] SLIP-framed echo over USB CDC ACM
- [ ] Verify framing with host-side hex dump
- [ ] Consider refactoring to workspace (microfips-transport crate)

**Success signal:** Host receives valid SLIP frames from MCU.

## M3: VPS Tunnel Plumbing

- [x] Document exact socat/slattach/ip commands
- [ ] Test with mock SLIP source on VPS
- [ ] Verify sl0 interface with IPv6 link-local
- [ ] Test end-to-end with USB CDC ACM connected

**Success signal:** `ping6 -I sl0 fe80::2` works locally on VPS.

## M4: Embedded IP + ICMP Ping

- [x] Implement embassy-net-driver Driver for SLIP-over-CDC-ACM
- [x] Create embassy-net Stack with IPv6 + ICMPv6
- [x] smoltcp handles ICMPv6 Echo Request/Response
- [x] Assign static IPv6 address to MCU (fe80::1)
- [ ] Verify ping6 from VPS reaches MCU

**Success signal:** `ping6 fe80::1%sl0` from VPS gets replies from MCU.

## M5: Bidirectional UDP

- [x] Open UDP socket on MCU
- [x] Send/receive datagrams between VPS and MCU
- [ ] Verify payload integrity
- [ ] Verify end-to-end with VPS tunnel

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
