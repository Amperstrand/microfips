# ADR 0006: Modular Crate Separation

## Status

Accepted

## Context

FIPS is a single monolithic crate. This works well for a Linux daemon with ample memory,
a full standard library, and a single deployment target. microfips targets multiple
MCUs (STM32F469, ESP32-D0WD, ESP32-S3) and also runs as host-side simulators and test
tools. The constraints differ wildly: the STM32 has 384 KB SRAM, the ESP32 has ~155 KB
available DRAM, and host tools have gigabytes.

A single crate for all of this would force `#[cfg(target)]` throughout the codebase,
embed hardware-specific dependencies into protocol logic, and make it impossible to run
crypto or framing tests without pulling in Embassy or `esp-hal`. The protocol logic
(NFMP framing, FSP session, Noise handshakes) is identical across all targets and
should be tested without any embedded dependencies.

## Decision

The workspace is split into layers with clear dependency boundaries:

**Protocol layers (no_std, no hardware dependencies):**

| Crate | Purpose |
|-------|---------|
| `microfips-core` | Cryptographic primitives: Noise IK/XK, FMP wire format, FSP session, identity, MMP metrics |
| `microfips-protocol` | State machine: `Transport` trait, framing, `Node` runtime, `PeerPolicy`, `FspDualHandler` |

Both crates are `no_std` and have no Embassy or HAL dependencies. They compile and test
on host (`cargo test -p microfips-core`, `cargo test -p microfips-protocol --features std`)
without any embedded toolchain. This is where 215+ unit tests live.

**Service layer (no_std, optional std):**

| Crate | Purpose |
|-------|---------|
| `microfips-service` | Transport-neutral request/response layer above the protocol. Defines `ServicePort`, request/response framing, and a multiplexing handler. |

Depends only on `microfips-core`. Does not depend on `microfips-protocol` or any
transport. Application-level, not wire-protocol-level.

**ESP shared code (no_std, HAL dependencies):**

| Crate | Purpose |
|-------|---------|
| `microfips-esp-common` | Chip-agnostic ESP code: DNS resolver, config constants, `UdpTransport`, `WifiTransport`, `NodeIdentity`, stats helpers |
| `microfips-esp-transport` | Shared ESP transport implementations: `UartTransport`, `BleTransport`, `L2capTransport`, LED, RNG, control interface |

`microfips-esp-common` depends on `embassy-net` but not on `esp-hal` directly, making it
reusable across D0WD and S3. `microfips-esp-transport` depends on `esp-hal` and
`embassy-executor` for BLE and UART peripherals.

**Firmware crates (composition roots):**

| Crate | Target |
|-------|--------|
| `microfips` | STM32F469NI (`thumbv7em-none-eabihf`) |
| `microfips-esp32` | ESP32-D0WD (`xtensa-esp32-none-elf`) |
| `microfips-esp32s3` | ESP32-S3 (`xtensa-esp32s3-none-elf`) |

Each firmware crate is a thin composition root: it wires together the protocol `Node`,
a concrete `Transport`, and hardware-specific initialization (clocks, GPIO, USB, BLE).
Feature flags select the transport variant (default UART, `ble`, `l2cap`, `wifi`).

**Host tools (std only):**

| Crate | Purpose |
|-------|---------|
| `microfips-link` | Standalone Noise IK handshake test against VPS |
| `microfips-sim` | Full `Node` simulator using UDP transport |
| `microfips-http-test` | FIPS responder for HTTP integration tests |
| `microfips-http-demo` | Optional HTTP adapter demo |

## Consequences

- The core protocol can be tested on any machine with `cargo test`, no cross-compilation
  needed. CI runs 215+ tests on standard x86_64 before attempting firmware builds.
- Adding a new MCU target requires only a new firmware crate that depends on the existing
  protocol and shared ESP crates. The S3 target was added this way with minimal new code.
- Clean dependency graph: core has zero dependencies on protocol or transport crates.
  Protocol depends only on core. No circular dependencies.
- Feature flags are confined to firmware crates. The `ble`, `l2cap`, and `wifi` features
  select which transport binary to build; they do not leak into the protocol layer.
- The HTTP demo (`microfips-http-demo`) is isolated in its own crate. It can be compiled
  out entirely without affecting any other crate.
- Trade-off: more crates means more `Cargo.toml` maintenance and longer initial compile
  times. In practice, Cargo's incremental compilation and crate caching make this a
  non-issue for development iteration.
