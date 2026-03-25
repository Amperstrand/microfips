# Architecture

## Overview

microfips is a minimal FIPS leaf node running on an STM32F469I-DISCO board.
It connects to a VPS running stock FIPS over a USB serial link (CDC ACM)
with SLIP framing, carrying IP packets that transport FIPS UDP datagrams.

## Layer Stack

```
+---------------------------+
|  HTTP status page (M7)    |
+---------------------------+
|  FIPS session (FSP)       |  Noise XK, end-to-end encrypted
+---------------------------+
|  FIPS mesh (FMP)          |  Noise IK, single peer, no transit
+---------------------------+
|  UDP                      |  FIPS transport
+---------------------------+
|  IPv6 / ICMPv6            |  smoltcp (no_std)
+---------------------------+
|  SLIP framing             |  Custom codec over CDC ACM
+---------------------------+
|  USB CDC ACM              |  embassy-usb
+---------------------------+
|  STM32F469 USB OTG FS     |  embassy-stm32
+---------------------------+
```

## What's Proven Early vs What Needs FIPS

### Proven without FIPS (M1-M5)

- **M1:** USB CDC ACM enumeration and byte-level communication
- **M2:** SLIP framing over the CDC ACM byte stream
- **M3:** Linux-side socat/slattach tunnel to VPS
- **M4:** smoltcp responds to ICMPv6 ping over the SLIP link
- **M5:** Bidirectional UDP datagrams over SLIP-backed IP

These milestones prove the transport foundation works end-to-end before
any FIPS protocol code is written.

### Requires FIPS Port (M6+)

- secp256k1 keypair generation and flash persistence
- Noise IK (link) and Noise XK (session) handshakes in no_std
- ChaCha20-Poly1305 AEAD, SHA-256, HKDF
- FMP peer authentication with single VPS peer
- FSP session establishment for end-to-end encrypted channel
- IPv6 address derivation from npub (fd00::/8 ULA)

### Final Demo (M7)

- `ping6 npub1xxx.fips` reaches the MCU from the VPS through FIPS
- MCU serves "hello fips" HTTP page with node status over the FIPS session

## MCU as FIPS Leaf Node

The MCU is explicitly a **leaf-only** node:
- No spanning tree root candidacy
- No transit forwarding or routing
- No bloom filters (single peer, no discovery needed)
- No MMP metrics (or minimal subset)
- Single FMP link to the VPS peer
- Single FSP session to the VPS peer

This dramatically reduces the FIPS port scope.

## No TUN on MCU

Unlike stock FIPS (which uses a Linux TUN device), the MCU implements
the IPv6 adaptation service directly:
- ICMPv6 echo responder (built into smoltcp)
- Tiny HTTP server for status page
- No TUN/TAP, no Linux kernel networking stack

## Crypto Strategy

| Primitive | Crate | no_std |
|-----------|-------|--------|
| secp256k1 ECDH | `k256` | Yes (alloc) |
| ChaCha20-Poly1305 | `chacha20poly1305` | Yes |
| SHA-256 | `sha2` | Yes |
| HMAC | `hmac` | Yes |

`k256` is chosen over `secp256k1` (C bindings) because it is pure Rust,
no cross-compilation of C needed, and is audited by NCC Group.

## Memory Budget (STM32F469NI: 1 MB Flash, 384 KB SRAM)

| Component | Flash | RAM |
|-----------|-------|-----|
| Embassy runtime | ~30 KB | ~5 KB |
| USB CDC ACM | ~15 KB | ~2 KB |
| smoltcp (minimal) | ~30 KB | ~10 KB |
| SLIP codec | ~2 KB | ~1 KB |
| FIPS core (est.) | ~100 KB | ~30 KB |
| HTTP server | ~10 KB | ~5 KB |
| **Total** | **~190 KB** | **~53 KB** |

Comfortable fit within the 1 MB / 384 KB budget.

## Workspace Layout

Currently a single crate. Will evolve to a workspace at M2+:

```
crates/
  microfips-board/       Pin defs, clock config for STM32F469I-DISCO
  microfips-transport/   USB CDC ACM + SLIP codec
  microfips-net/         SLIP -> embassy-net Device bridge
  microfips-core/        FIPS protocol (no_std)
  microfips-app/         Main binary, HTTP server
```
