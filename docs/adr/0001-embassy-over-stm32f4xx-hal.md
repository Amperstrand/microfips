# ADR 0001: Embassy over stm32f4xx-hal

## Status

Accepted

## Context

The STM32F469I-DISCO board has an existing Rust board support crate
(`/home/ubuntu/src/stm32f469i-disc`) based on `stm32f4xx-hal`. We need
to choose between `stm32f4xx-hal` and `embassy-stm32` for this project.

## Decision

Use `embassy-stm32` (Embassy HAL) instead of `stm32f4xx-hal`.

## Rationale

1. **Async-first:** Embassy provides an async executor and async HAL APIs.
   USB CDC ACM, networking, and timer operations are all async, enabling
   concurrent tasks without manual state machines or RTOS.

2. **USB stack included:** `embassy-usb` provides a complete USB device stack
   with CDC ACM, HID, and other class support. `stm32f4xx-hal` has no
   equivalent; you would need to use `usb-device` separately with more
   boilerplate.

3. **Network stack:** `embassy-net` wraps `smoltcp` with async socket APIs.
   This is essential for M4+ (embedded IP stack). No equivalent exists for
   `stm32f4xx-hal`.

4. **STM32F469 support:** Embassy has explicit `stm32f469ni` feature flag
   and examples for this chip. Confirmed working.

5. **Active maintenance:** Embassy is under active development with frequent
   releases and a large community.

## Consequences

- Requires nightly Rust (embassy-executor macros need it)
- Different HAL API from `stm32f4xx-hal` (not drop-in compatible)
- The existing `stm32f469i-disc` BSC serves as pin reference only,
  not as a dependency
- Embassy's async model requires `#[embassy_executor::main]` and
  `Spawner` for task management

## Alternatives Considered

- **stm32f4xx-hal + usb-device:** Would work for basic USB but lacks async,
  no built-in network stack, more boilerplate for concurrent operations.
- **RTIC:** Good for bare-metal RTOS-like patterns but doesn't provide
  USB/network abstractions. Could be combined with Embassy but adds
  complexity.
