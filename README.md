# microfips

Minimal FIPS leaf node on STM32F469I-DISCO.

A Rust embedded firmware that implements a leaf-only FIPS (Free Internetworking
Peering System) node on an STM32F469-based board, using Embassy for async HAL,
USB CDC ACM for serial transport, SLIP framing for IP, and a no_std FIPS
protocol stack with k256/secp256k1 identity and Noise_IK handshake.

## Network Diagram

```
                          ┌─────────────────────┐
                          │     FIPS Network     │
                          │   (other peers)      │
                          └──────────┬──────────┘
                                     │ FIPS UDP :2121
                          ┌──────────┴──────────┐
                          │  stock FIPS (VPS)   │
                          │  npub1peaqmgq...    │
                          └──────────┬──────────┘
                                     │ UDP
                                     │
                          ┌──────────┴──────────┐
                          │  sl0 (SLIP iface)    │
                          │  link-local IPv6     │
                          └──────────┬──────────┘
                                     │ SLIP frames
                          ┌──────────┴──────────┐
                          │  slattach + PTY     │
                          └──────────┬──────────┘
                                     │ raw bytes
                          ┌──────────┴──────────┐
                          │  socat (TCP↔PTY)    │
                          └──────────┬──────────┘
                                     │ TCP :5000
              ════════════════════════╪══════════════════════
                          internet   │
              ════════════════════════╪══════════════════════
                                     │ TCP :5000
                          ┌──────────┴──────────┐
                          │  socat (TCP↔serial) │
                          └──────────┬──────────┘
                                     │ raw serial
                          ┌──────────┴──────────┐
                          │  /dev/ttyACM1       │
                          │  (USB CDC ACM)       │
                          └──────────┬──────────┘
                                     │ USB (CN13)
                          ┌──────────┴──────────┐
                          │  STM32F469I-DISCO   │
                          │  (microfips fw)      │
                          │  npub1vdtfdhz...    │
                          │                     │
                          │  ┌───────────────┐  │
                          │  │ embassy-net   │  │
                          │  │ IPv6 stack    │  │
                          │  │ ICMP echo     │  │
                          │  │ UDP :2121     │  │
                          │  │ Noise_IK      │  │
                          │  │ FMP framing   │  │
                          │  │ SLIP encode   │  │
                          │  └───────────────┘  │
                          └─────────────────────┘
```

## MCU Identity

```
nsec:  ac68af89462e7ed26ff670c186b4eeb53c4e82d72c8ef6cec4e676c7843f832e
npub:  npub1vdtfdhzl0n9k3hmexckfahe4ud0xzmt6aphuacng5tm5j3ftdppqj0ujhf
```

Deterministic seed: `b'microfips-stm32f469-test-seed-001'`

## How to Test Ping from FIPS

Once the SLIP tunnel is up and the MCU is connected to the VPS via FIPS:

1. Ask a FIPS peer to ping the MCU's FIPS address:
   ```
   fips ping npub1vdtfdhzl0n9k3hmexckfahe4ud0xzmt6aphuacng5tm5j3ftdppqj0ujhf
   ```

2. Or from the VPS directly over the SLIP link:
   ```
   ping6 -I sl0 fe80::1
   ```

3. The MCU responds to ICMPv6 echo requests automatically (embassy-net
   `auto-icmp-echo-reply` feature).

## Proof of Reachability

The MCU is reachable when:
1. `ping6 -I sl0 fe80::1` from VPS gets replies (SLIP tunnel + ICMP works)
2. FIPS on VPS logs "Connection promoted to active peer" (Noise_IK handshake
   succeeds — the MCU authenticates with its static key)
3. FIPS heartbeat keepalive is maintained (10s interval, 30s timeout)

## Hardware

- **Board:** STM32F469I-DISCO
- **MCU:** STM32F469NI (Cortex-M4F, 180 MHz, 1 MB Flash, 384 KB SRAM)
- **Debug:** ST-LINK/V2.1 (CN1, SWD)
- **USB OTG FS:** CN13 (micro-AB, PA11/PA12)
- **Clocks:** HSI 16MHz + PLL -> 168MHz sys, 48MHz USB

## Transport

```
STM32 USB CDC ACM -> local socat -> TCP -> VPS socat -> PTY -> slattach/sl0 -> IP -> UDP -> FIPS
```

## Build

Requires nightly Rust with `thumbv7em-none-eabi` target and `probe-rs`:

```sh
cargo build --target thumbv7em-none-eabi
cargo build --target thumbv7em-none-eabi --release
```

## Flash

```sh
sudo probe-rs run --chip STM32F469NIHx --connect-under-reset \
  target/thumbv7em-none-eabi/release/microfips
```

## Milestones

| Milestone | Description | Status |
|-----------|-------------|--------|
| M0 | Environment, repo, scaffold | Done |
| M1 | USB CDC ACM + echo | Done |
| M2 | SLIP framing over CDC ACM | Done |
| M3 | VPS tunnel plumbing (socat/slattach) | Done |
| M4 | Embedded IP stack + ICMP ping | Done |
| M5 | Bidirectional UDP over SLIP | Done |
| M6 | FIPS leaf node (identity, Noise, single peer) | In Progress |
| M7 | HTTP server over FIPS | Planned |

## Architecture

See [docs/architecture.md](docs/architecture.md) for details.

## License

MIT OR Apache-2.0
