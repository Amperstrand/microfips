# ADR 0002: Per-Device Flash Key Storage

## Status

Proposed

## Context

All device identities in microfips are currently compiled-in pattern keys:
31 zero bytes followed by a single device-discriminator byte (e.g., `0x01` for
STM32, `0x02` for ESP32-D0WD, `0x05` for ESP32-S3). These keys are read at
build time from `keys.json` → `microfips-build` → `env!("DEVICE_NSEC_HEX_*")`.

This approach is acceptable for development and CI but unsuitable for production:
every device of the same type would have an identical identity, which breaks FIPS
peer authentication and leaks the private key to anyone with the binary. For
production deployment, each device needs a unique, persistent secret (`nsec`)
stored in non-volatile memory.

The control interface (`control.rs`) already accepts line-delimited commands over
UART0 and returns JSON responses. A provisioning command can be added to that
interface without changing the transport or protocol layers.

## Decision

Define a `KeyStore` trait and a per-platform storage layout that enables:

1. Per-device identity stored in persistent flash (NVS on ESP32, dedicated flash
   sector on STM32).
2. A fallback chain that allows development firmware to continue using
   compiled-in keys without any provisioning step.
3. A first-boot migration path that moves a compiled-in key into flash
   automatically, preserving the existing identity during upgrades.
4. A UART provisioning command (`set_nsec`) for injecting a per-device key
   at manufacturing time or in the field.

## API Surface

```rust
/// Errors from flash key storage operations.
#[derive(Debug)]
pub enum KeyStoreError {
    /// Underlying flash or NVS write failed.
    WriteFailure,
    /// Storage area is corrupt or uninitialized.
    InvalidData,
}

/// Persistent key storage for a single device identity secret.
pub trait KeyStore {
    /// Read the stored nsec. Returns `None` if not yet provisioned.
    fn read_nsec(&self) -> Option<[u8; 32]>;

    /// Write a new nsec to persistent storage.
    fn write_nsec(&mut self, nsec: &[u8; 32]) -> Result<(), KeyStoreError>;

    /// Returns true if a valid nsec has been written to flash.
    fn is_provisioned(&self) -> bool;
}
```

The trait is implemented per platform. Application code calls `read_nsec()` on
startup and falls back to the compile-time constant if it returns `None`.

## Storage Layout

### ESP32 (D0WD and S3)

| Item | Value |
|------|-------|
| Storage driver | `esp-storage` (NVS namespace-compatible raw flash) |
| NVS namespace | `microfips` |
| NVS key | `nsec` |
| Value format | 32 raw bytes |
| Flash region | NVS partition (default: 0x9000, 24 KB) as defined in partition table |

NVS handles wear leveling and atomic updates internally. No additional flash
management is required.

### STM32F469NI

| Item | Value |
|------|-------|
| Storage driver | Custom raw flash write via `embassy-stm32` flash peripheral |
| Flash sector | Sector 11 (0x080E0000, 128 KB) |
| Magic bytes | Bytes 0-3: `0x46 0x49 0x50 0x53` ("FIPS") |
| nsec location | Bytes 4-35 (32 bytes) |
| Erase granularity | Full sector (128 KB) — must erase before write |

Sector 11 is the last 128 KB sector of the 2 MB Flash on STM32F469NI. It is
outside the firmware image region (firmware ends well before 0x080E0000) and
safe to use for data storage. The magic prefix distinguishes a provisioned sector
from an erased (all-0xFF) one.

## Fallback Chain

On startup, the firmware attempts to load the nsec using this ordered fallback:

1. **Flash nsec** — call `KeyStore::read_nsec()`. If `Some(nsec)` → use it.
2. **Compile-time nsec** — read `DEVICE_NSEC` constant from `config.rs` (injected
   at build time from `keys.json` via `microfips-build`). Use it.
3. **Panic** — if neither source yields a valid key (e.g., deliberately zeroed
   compile-time constant in a production build that requires provisioning):
   `panic!("No identity: run provisioning via 'set_nsec <hex>' on UART0")`.

Development firmware always has a valid compile-time fallback. Production firmware
can use an all-zero placeholder to force provisioning on first boot.

## Migration Path

On first boot of a newly flashed device that has not been provisioned yet:

1. `KeyStore::is_provisioned()` returns `false`.
2. Firmware loads the compile-time `DEVICE_NSEC` constant (pattern key or custom key
   injected at build time).
3. Firmware calls `KeyStore::write_nsec(&DEVICE_NSEC)` to persist it.
4. Subsequent boots skip step 2-3 and read directly from flash.

This preserves the existing node identity (NodeAddr, npub) across firmware upgrades
as long as the flash sector is not erased. A factory reset erases the sector and
reverts to the compile-time key on the next boot.

## Provisioning

A new control command `set_nsec` is added to the UART0 control interface
(implemented in `crates/microfips-esp-transport/src/control.rs` and the STM32
equivalent):

| Command | Format | Response |
|---------|--------|----------|
| `set_nsec <64 hex chars>` | Line-delimited | `{"status":"ok"}` or error JSON |
| `show_nsec_source` | Line-delimited | `{"status":"ok","data":{"source":"flash"}}` or `"compile_time"` |

Provisioning workflow:

1. Flash firmware with all-zero compile-time key (forces provisioning mode).
2. Connect serial terminal to UART0.
3. Send: `set_nsec <device-unique-hex-secret>`
4. Device writes key to flash, responds `{"status":"ok"}`.
5. Device reboots (or operator resets). Next boot uses flash key.

For batch provisioning, a host-side script can iterate over devices and send unique
keys derived from a master seed: `HMAC-SHA256(master_seed, device_serial_number)`.

## Security Considerations

Flash storage on these devices is not a security boundary against a determined
attacker with physical access:

- ESP32: NVS partition is readable via `esptool.py read_flash`. Anyone with physical
  USB access and `esptool` can extract the nsec.
- STM32: Flash sector is readable via `st-flash read` or `probe-rs`. No readback
  protection is applied by default.

This design provides **convenience isolation** (key is not in the firmware binary
that gets shared or version-controlled) but not **cryptographic isolation** (key
can still be extracted from the hardware).

For stronger isolation, ESP32-S3 supports encrypted flash via eFuse-based XTS-AES.
STM32F469NI supports read protection (PCROP/RDP). These are out of scope for this
ADR; see "What This ADR Does Not Cover" below.

Threat model assumption: the device is deployed in a physically secured environment,
or key disclosure via physical extraction is an acceptable risk for the use case.

## Dependencies

| Dependency | Platform | Purpose |
|------------|----------|---------|
| `esp-storage` | ESP32 (D0WD, S3) | NVS-compatible raw flash access |
| `embassy-stm32` flash peripheral | STM32 | Flash erase + write API |

`esp-storage` is already a transitive dependency via `esp-hal`. No new external
crates are required.

## What This ADR Does Not Cover

- **Secure boot / verified boot** — preventing execution of unauthorized firmware.
- **Key rotation** — updating the nsec after initial provisioning without factory
  reset.
- **Backup and recovery** — storing a secondary key copy or recovery mechanism.
- **Factory reset** — erasing the flash sector and reverting to pattern keys.
- **Hardware security modules** — offloading key operations to a dedicated HSM
  or TrustZone/TEE.
- **Key derivation from hardware UID** — using the MCU's unique ID to derive a
  per-device key without explicit provisioning.
- **Encrypted flash** — ESP32-S3 eFuse XTS-AES or STM32 PCROP/RDP.
- **Key attestation** — proving to a remote party that a specific key is stored
  in hardware and has not been extracted.

These topics may be addressed in future ADRs as the security requirements evolve.
