# microfips

Minimal FIPS leaf node on STM32F469I-DISCO.

A Rust embedded firmware that implements a leaf-only FIPS (Free Internetworking
Peering System) node on an STM32F469-based board, using Embassy for async HAL,
USB CDC ACM for serial transport, SLIP framing for IP, and eventually a
no_std FIPS protocol stack with secp256k1 identity.

## Hardware

- **Board:** STM32F469I-DISCO
- **MCU:** STM32F469NI (Cortex-M4F, 180 MHz, 1 MB Flash, 384 KB SRAM)
- **USB:** OTG FS (PA9/PA11/PA12) with ST-LINK/V2.1 debug probe

## Transport Plan

```
STM32 USB CDC ACM -> local socat -> TCP -> VPS socat -> PTY -> slattach/sl0 -> IP -> UDP -> FIPS
```

## Build

Requires nightly Rust with `thumbv7em-none-eabi` target and `probe-rs`:

```sh
cargo build
# or
cargo build --release
```

## Flash

```sh
probe-rs run --chip STM32F469NIHx --target thumbv7em-none-eabi
```

## Milestones

| Milestone | Description | Status |
|-----------|-------------|--------|
| M0 | Environment, repo, scaffold | Done |
| M1 | USB CDC ACM + echo | In progress |
| M2 | SLIP framing over CDC ACM | Planned |
| M3 | VPS tunnel plumbing (socat/slattach) | Planned |
| M4 | Embedded IP stack + ICMP ping | Planned |
| M5 | Bidirectional UDP over SLIP | Planned |
| M6 | FIPS leaf node (identity, Noise, single peer) | Planned |
| M7 | HTTP server over FIPS | Planned |

## Architecture

See [docs/architecture.md](docs/architecture.md) for details.

## License

MIT OR Apache-2.0
