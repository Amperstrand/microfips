# Architecture

## Overview

microfips is a minimal FIPS leaf node on STM32F469I-DISCO. It connects to a VPS
running stock FIPS over USB CDC ACM serial with length-prefixed framing, bridged
through an SSH tunnel to a Python bridge on the VPS that speaks UDP to FIPS.

## Layer Stack

```
+---------------------------+
|  FIPS session (FSP)       |  End-to-end encrypted sessions  [PLANNED]
+---------------------------+
|  FIPS mesh (FMP)          |  Noise IK, single peer, no transit  [DONE]
+---------------------------+
|  Length-prefixed framing  |  2-byte LE length + payload     [DONE]
+---------------------------+
|  USB CDC ACM              |  embassy-usb, 64B packets       [DONE]
+---------------------------+
|  STM32F469 USB OTG FS     |  embassy-stm32 (upstream)       [DONE]
+---------------------------+
```

The original plan used SLIP + IPv6 + smoltcp for IP tunneling. This was abandoned
because the MCU is leaf-only (no routing, no transit, no discovery), and
length-prefixed frames over CDC are simpler and sufficient for single-peer
communication.

## Transport: MCU <-> Host <-> VPS

```
  STM32F469I-DISCO          Host (Linux)               VPS
  +----------------+    +-------------------+    +------------------+
  | microfips fw   |    | serial_tcp_proxy  |    | fips_bridge.py   |
  |                |CDC | (auto-detect MCU  |TCP | --tcp localhost  |
  | FIPS protocol  |<-->|  by USB VID/PID)  |<-->|                  |
  | Noise_IK       |    |                   |SSH | UDP <-> TCP      |
  | FMP framing    |    | serial <-> TCP    |-R  |                  |
  | Heartbeats     |    +-------------------+    +--------+---------+
  +----------------+                                     |
         ^                                              | UDP :2121
         | USB OTG FS                                   v
    /dev/ttyACM*                                  +------------------+
    (VID:PID = c0de:cafe)                         | FIPS daemon     |
                                                   | peer config:   |
                                                   | 127.0.0.1:31337|
                                                   +------------------+
```

### Why the bridge runs on the VPS

FIPS replies to the **source address** of incoming UDP packets, not the
configured peer address. When the bridge runs on the host, FIPS replies to the
host's public IP (unreachable from behind NAT). When the bridge runs on the VPS,
it sends from `127.0.0.1:31337` — which matches the peer address in FIPS's
config — so replies route correctly back through the SSH tunnel.

### Startup sequence

1. MCU boots, enumerates USB CDC, waits 2s for host-side setup
2. `serial_tcp_proxy.py` starts on host, listens for TCP connections, auto-detects
   MCU by USB VID/PID (`c0de:cafe`)
3. SSH reverse tunnel: `ssh -fNR 45678:127.0.0.1:45678 vps`
4. `fips_bridge.py --tcp 127.0.0.1:45678` starts on VPS, connects through tunnel
5. MCU sends MSG1 → proxy → tunnel → bridge → UDP → FIPS
6. FIPS replies MSG2 → bridge → tunnel → proxy → CDC → MCU

### Serial framing

All data over CDC ACM uses length-prefixed frames:
```
[2 bytes: payload_len LE] [payload_len bytes: payload]
```

Parsed by `recv_frame()` on the MCU and by `fips_bridge.py` on the host/VPS.
USB bulk transfers use 64-byte max packet size. A zero-length packet (ZLP) is
sent after any transfer whose length is an exact multiple of 64 bytes.

## FIPS Protocol (FMP Layer)

### FMP Frame Format

```
[4 bytes: prefix] [variable: payload]
Prefix: [version:4bits | phase:4bits] [flags:8] [payload_len:16 LE]
```

### FMP Message Types

| Phase | Name        | Wire Size | Contents                                      |
|-------|-------------|-----------|-----------------------------------------------|
| 0x01  | MSG1        | 114 B     | prefix(4) + sender_idx(4) + noise(106)        |
| 0x02  | MSG2        | 69 B      | prefix(4) + sender(4) + receiver(4) + noise(57) |
| 0x00  | ESTABLISHED | variable  | prefix(4) + receiver_idx(4) + counter(8) + encrypted |

### Noise IK Handshake

Pattern: `Noise_IK_secp256k1_ChaChaPoly_SHA256`

```
  <- s                    (pre-message: responder's static key, parity-normalized)
  -> e, es, s, ss         (msg1: 106 bytes = 33 + 49 + 24)
  <- e, ee, se            (msg2: 57 bytes = 33 + 24)
```

#### FIPS Deviation: Empty AAD during handshake

The Noise spec says `EncryptAndHash(pt)` should use `h` (hash state) as AAD.
FIPS passes empty AAD (`&[]`). We match FIPS.

#### `se` Token — NOT a Deviation

Earlier analysis claimed FIPS deviated on the `se` DH. This was incorrect.
The Noise spec says `se = DH(s_init, re_resp)` and `se = DH(e_resp, rs_init)`.
These are the same because ECDH is commutative. Our implementation's
`read_message2()` computes `se = DH(e_init, rs_resp)` which is the same as the
`es` token. Both sides agree, so keys match.

#### Transport Key Derivation: `finalize()` / `split()`

**Critical fix (2026-03-27):** Our `finalize()` originally used two HKDF calls
(`mix_key(ck, [0;32])` then `mix_key(ck, k1)`), but FIPS's `split()` does a single
`HKDF-SHA256(ck, &[])` expanding to 64 bytes, split into k1 (send) and k2 (recv).

```rust
// Correct implementation matching FIPS:
pub fn finalize(&self) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);  // empty IKM
    let mut okm = [0u8; 64];
    hk.expand(&[], &mut okm).unwrap();
    let mut k1 = [0u8; 32]; k1.copy_from_slice(&okm[..32]);
    let mut k2 = [0u8; 32]; k2.copy_from_slice(&okm[32..]);
    (k1, k2)  // (k_send, k_recv) for initiator
}
```

### Established Messages

After handshake, both sides derive `k_send` and `k_recv`. Messages use:
```
AEAD(key, nonce=counter, aad=outer_header, plaintext=inner)
```
- `outer_header` = first 16 bytes of FMP frame (`prefix(4) + receiver_idx(4) + counter(8)`)
- `counter` = 8-byte LE nonce from the ESTABLISHED header (NOT a local counter)
- `inner` = [timestamp:4 LE] [msg_type:1] [payload:variable]

The `counter` in the ESTABLISHED header IS the AEAD nonce. The receiver uses the
counter from the incoming header, not a local counter. FIPS does an O(1) session
lookup using `receiver_idx`, so the heartbeat must include FIPS's index.

| Type       | Value | Description                          |
|------------|-------|--------------------------------------|
| HEARTBEAT  | 0x51  | Keep-alive, sent every 10 seconds    |
| DISCONNECT | 0x50  | Peer disconnect notification         |
| SESSION_DATAGRAM | 0x00 | FSP session data                |

## MCU Identity

```
Seed:    b'microfips-stm32fips-test-seed-001'
Secret:  ac68af89462e7ed26ff670c186b4eeb53c4e82d72c8ef6cec4e676c7843f832e
Pubkey:  02633860dc5f7ccb68df79362c9edf35e35e616d7ae86fcee268a2f749452b6842
npub:    npub1vdtfdhzl0n9k3hmexckfahe4ud0xzmt6aphuacng5tm5j3ftdppqj0ujhf
```

## What's Proven

### Protocol (71 tests in microfips-core)

- Noise IK full handshake simulation (initiator + test responder)
- FMP MSG1/MSG2/ESTABLISHED build and parse roundtrips
- AEAD encrypt/decrypt with correct and wrong keys/nonce/AAD
- ECDH keypair derivation, SLIP encode/decode, identity derivation
- `finalize()` / `split()` produces correct transport keys matching FIPS

### Sim-to-VPS (microfips-sim, host-side)

- `microfips-sim --listen 45679` completes Noise IK handshake with live VPS
- ESTABLISHED messages decrypt correctly (counter from header, not local counter)
- Sustained heartbeat exchange for 70+ seconds with no FIPS timeout
- Non-ESTABLISHED messages from other peers are ignored gracefully

### Host-to-VPS (microfips-link, raw UDP)

- `microfips-link` completes Noise IK handshake with live VPS over UDP
- VPS responds with MSG2 containing valid Noise payload
- VPS accepts MCU identity and promotes to active peer
- Transport keys derived correctly

### USB (hardware)

- CDC enumeration (device appears as `c0de:cafe` on `/dev/ttyACM*`)
- Bidirectional CDC echo (verified with multiple packet sizes)
- ZLP handling for 64-byte-aligned transfers

### Bridge-on-VPS architecture

- Bridge receives MSG1 from MCU via SSH tunnel, forwards to VPS FIPS via UDP
- Bridge receives MSG2 from VPS FIPS, writes to tunnel → proxy → MCU
- Full exchange confirmed: `CDC->UDP: 114B` (MSG1) and `UDP->CDC: 69B` (MSG2)
- Sim heartbeat exchange confirmed through bridge: 7 heartbeats sent, 22 ESTABLISHED received

## Known Issues and Risks

### 1. RNG quality for ephemeral keys

The STM32F469 hardware RNG generates ephemeral keys for each handshake. We don't
currently check for RNG seed errors or health status. Should verify RNG produces
different keys across handshakes.

### 2. Nonce counter wrap

`SEND_COUNTER` is u32, wraps at 2^32. At one message per 10s (heartbeat), wrap
occurs after ~136 years. Not practical concern unless high-rate data transfer is
added.

### 3. FIPS protocol version compatibility

Our FMP uses version 0 against FIPS v0.3.0-dev. Future FIPS updates may change
the wire format.

### 4. Other peers' data arrives through bridge

When the MCU is connected, the bridge also forwards UDP from other peers trying to
reach FIPS. The sim receives MSG1 from other peers during steady state — these
must be ignored (sim handles this; MCU firmware also ignores non-ESTABLISHED).

## Host-Side Simulator

`microfips-sim` is a host-side crate that simulates the MCU's full FIPS lifecycle
without hardware. It uses the same `microfips-core` protocol code as the firmware
and speaks length-prefixed framing over TCP or stdin/stdout.

Modes:
- `microfips-sim --listen PORT` — TCP server mode (preferred for bridge testing)
- `microfips-sim tcp_addr` — TCP client mode
- `microfips-sim` — stdin/stdout mode (for socat piping)

This enables:
- Fast iteration: `cargo run -p microfips-sim` vs build/flash/wait cycle
- VPS integration testing without hardware
- Proven working: sustained heartbeat exchange for 70+ seconds against live VPS

## Clock Configuration

```
HSI (16 MHz) → PLL → 168 MHz sysclk
                   → 48 MHz USB (PLL_Q, Clk48sel)
                   → 42 MHz APB1
                   → 84 MHz APB2
```

HSE bypass hangs on this board. Do NOT use HSE.

## Workspace Layout

```
microfips/
  Cargo.toml                    # Workspace root, patch cortex-m
  AGENTS.md                     # Build/flash/test/debug reference
  src/main.rs                   # MCU firmware (FIPS leaf node)
  crates/
    microfips-core/             # no_std FIPS protocol: Noise, FMP, FSP, SLIP, identity
    microfips-link/             # Host-side handshake test (UDP, proven against VPS)
    microfips-sim/              # Host-side full lifecycle simulator (stdio framing)
  tools/
    fips_bridge.py              # CDC/TCP <-> UDP bridge (runs on VPS)
    serial_tcp_proxy.py         # Serial <-> TCP proxy (runs on host)
    test_sim_vps.sh             # VPS integration test for microfips-sim
  docs/
    architecture.md             # This file
    milestones.md               # M0-M7 tracking
    adr/                        # Architecture decision records
```

## External Dependencies (Patched)

| Crate | Version | Patch | Reason |
|-------|---------|-------|--------|
| `cortex-m` | 0.7.7 (patched) | `cortex-m-patch/` | Nightly asm `inout("r0")` → `inout(reg)` |
| `embassy-*` | upstream | `embassy/` | No patches — fork was fully reverted |
| `stm32-metapac` | generated | `stm32-data-generated/` | defmt 0.3→1.0 version bump |
