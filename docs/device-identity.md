# Device Identity Key Provisioning

## Current State

All device keys are deterministic test keys compiled at build time from `keys.json`. Each device
gets a secp256k1 keypair derived from the generator point × N (where N is the last byte index).

This works for development but every firmware build of the same board type shares the same
identity — a real deployment needs per-device unique keys.

## ESP32 Options

### SHA256(MAC + salt) — default for development

- Derive device identity at runtime from the BLE MAC address and a compile-time salt
- Zero provisioning: flash same firmware to any ESP32, each gets a unique key
- Salt prevents key derivation by anyone who doesn't know it
- Tradeoff: anyone with debug access + the salt can derive the key
- ESP32-D0WD BLE MAC: read from `ESP32_NSEC[27..32]` in current firmware
- ESP32-S3 WiFi MAC: available from `wifi` subsystem after init

### NVS factory partition — recommended for reference implementation

- Espressif's official per-device data storage pattern
- Separate `fctry` NVS partition (not user config) stores per-device keys
- Provisioning: generate keypair off-device, write nsec to NVS partition image with
  `nvs_partition_gen.py`, flash the partition image
- One provisioning step per device, no per-device firmware compilation
- Keys survive firmware updates (separate partition from app)
- Tradeoff: in flash, readable with physical access and debug tools
- Max NVS value size: 1968 bytes (secp256k1 nsec is 32 bytes, no issue)

### eFuse key blocks — reserved for production

- 3 blocks × 256 bits on ESP32-D0WD, write-once, hardware-protected
- Can enable read protection (key can be used for crypto but never read back)
- Better reserved for secure boot signing keys, not application identity
- Limited supply — burning one for identity leaves fewer for other uses
- Not suitable for development boards

## STM32 Options

### SHA256(UID + salt) — default for development

- STM32F4/F7 have a 96-bit unique device ID at register `0x1FFF7A10`
- Derive key at runtime: `nsec = SHA256(UID || salt)` then use as secp256k1 scalar
- Zero provisioning: same firmware, each board gets unique identity
- Tradeoff: UID is readable by anyone with ST-LINK or debug probe access
- Salt prevents derivation by attackers who only know the UID

### Last flash sector — recommended for reference implementation

- STM32F469: sector 11 (128 KB at `0x080E0000`)
- STM32F746: sector 7 (128 KB at `0x08060000`)
- Write 32-byte nsec to the sector, firmware reads at boot
- Provisioning: generate keypair off-device, write nsec with `st-flash`, register npub
- Re-writable during development (unlike OTP)
- Tradeoff: readable with physical access, no hardware protection
- Must exclude the key sector from firmware flash range (offset linker script)

### OTP area — reserved for production

- STM32F4: 16 blocks × 32 bytes at `0x1FFF7800`, plus 16 lock bytes at `0x1FFF7C00`
- A secp256k1 nsec fits exactly in one 32-byte OTP block
- Write once, lockable per block, cannot be erased
- Write via ST-LINK (STM32CubeProgrammer) or at runtime with flash unlock
- Not suitable for development — wasted OTP blocks if keys change

## Chosen Approach

For development and the reference implementation phase:

1. **SHA256(hardware_id + salt)** as the default — zero provisioning, works out of the box
   - ESP32: `SHA256(BLE_MAC || SALT)` where SALT is a compile-time constant
   - STM32: `SHA256(UID_96bit || SALT)` where SALT is a compile-time constant
2. **Flash sector / NVS partition** as the upgrade path — for users who want per-device
   provisioning without deterministic derivation
3. **OTP / eFuse** deferred to production — too permanent for development boards

## Production Considerations (deferred)

- Secure element (ATECC608) for key storage — key never leaves silicon
- STM32 OTP with block locking after provisioning
- ESP32 eFuse-backed NVS encryption for flash sector protection
- Certificate-based attestation (Matter DAC pattern) if FIPS adopts PKI
- Key rotation and re-provisioning flows
