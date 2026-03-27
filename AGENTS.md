# microfips

Minimal FIPS leaf node on STM32F469I-DISCO. Uses Embassy for async HAL, USB CDC ACM for serial transport, SLIP framing for IP.

## Build

```bash
cargo build
cargo build --release
```

## Architecture

```
src/
├── main.rs       — Embassy executor, USB CDC init, SLIP/IP stack
├── identity.rs   — secp256k1 FIPS identity
├── noise.rs      — Noise protocol handshake
├── slip.rs       — SLIP framing
└── slip_net.rs   — SLIP-over-USB network interface

crates/
├── microfips-core   — Shared FIPS protocol logic
└── microfips-link   — Link-layer abstraction
```

## Hardware

- Board: STM32F469I-DISCO
- MCU: STM32F469NI (Cortex-M4F, 180 MHz, 1 MB Flash, 384 KB SRAM)
- USB: OTG FS (PA9/PA11/PA12)

## Key Dependencies

- `embassy-stm32`, `embassy-usb`, `embassy-usb-synopsys-otg` (local path deps)
- `embassy-net`, `embassy-net-driver` (local path deps)
- `smoltcp` 0.13 — IP stack

## Upstream Interaction Policy

**NEVER file PRs or issues on upstream projects (embassy-rs, stm32-rs, etc.) without human review and approval.** AI-generated bug diagnoses can be confidently wrong. If you find a potential upstream bug:
1. Document your findings in an Amperstrand repo issue first
2. Include all evidence (register dumps, test results, methodology)
3. Let a human decide whether to escalate

See [Amperstrand/micronuts#19](https://github.com/Amperstrand/micronuts/issues/19) for a retrospective on how a confident misdiagnosis wasted upstream maintainer time.
