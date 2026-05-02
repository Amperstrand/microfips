# ADR 0007: FRAME_CAP vs MTU Split

## Status

Accepted

## Context

BLE L2CAP connections negotiate an MTU (Maximum Transmission Unit) with the remote
peer during channel setup. FIPS uses a default MTU of 2048 bytes, which is the maximum
the `trouble` BLE stack supports on Linux. The MTU determines the largest L2CAP
Service Data Unit (SDU) that can be sent in a single frame.

On the ESP32-D0WD, available DRAM is limited. After the WiFi/BLE stack, Embassy
executor, heap allocator, and protocol state, roughly 155 KB remains for everything
else. The L2CAP transport uses `heapless::Vec` buffers backed by static memory for
both RX and TX channels. Each channel slot allocates a fixed-size buffer, and the
channel capacity determines how many frames can be queued concurrently.

The memory budget for L2CAP is:

| Component | Size (bytes) |
|-----------|-------------:|
| RX channel: 16 slots x FRAME_CAP | 16 x 770 = 12,320 |
| TX channel: 8 slots x FRAME_CAP | 8 x 770 = 6,160 |
| Heap (embassy-alloc) | ~72,000 |
| BLE PacketPool (MTU + overhead) | ~65,000 |
| Other (stack, state, peripherals) | remainder |
| **Total available** | **~155,000** |

A naive approach would set FRAME_CAP equal to the L2CAP MTU (2048). But 2048-byte
buffers would require 16 x 2050 + 8 x 2050 = 49,200 bytes just for channel slots,
plus the PacketPool must be at least MTU + overhead. This exceeds the DRAM budget.

## Decision

Split the concept into two separate constants:

- **MTU = 2048** (kernel/BLE controller level): The negotiated L2CAP MTU. This is
  set during BLE channel setup and matches FIPS's default. It determines the maximum
  SDU size the controller will accept. The PacketPool MTU is set to 2054 (2048 + 6
  bytes L2CAP header overhead) via `.cargo/config.toml`.

- **FRAME_CAP = 768** (application level): The maximum payload size for any single
  FIPS protocol frame sent over L2CAP. The `L2capTransport` rejects frames larger than
  768 bytes and the RX channel drops oversized incoming SDUs. This is defined as
  `L2CAP_FRAME_CAP` in `microfips-esp-transport/src/config.rs`.

The value 768 was chosen by binary search over the DRAM budget. Values tested:

| FRAME_CAP | Channel memory | Fits budget? |
|-----------|---------------:|:------------:|
| 512 | 16 x 514 + 8 x 514 = 12,288 | Yes |
| 768 | 16 x 770 + 8 x 770 = 18,480 | Yes (max) |
| 1024 | 16 x 1026 + 8 x 1026 = 24,576 | No (overflow) |
| 2048 | 16 x 2050 + 8 x 2050 = 49,200 | No (overflow) |

## Consequences

- **FilterAnnounce cannot be sent.** The FIPS `FilterAnnounce` message is 1071 bytes,
  which exceeds FRAME_CAP (768). Leaf nodes skip bloom filters entirely. This is
  accepted per FIPS issue #82 ("FilterAnnounce exceeds L2CAP MTU"), which was closed
  as accepted. FIPS skips FilterAnnounce to MTU-limited peers (FIPS #66).

- **All link-layer frames fit within 768 bytes.** The largest frames in the FIPS
  protocol are MSG1 (114 bytes), SessionSetup (148 bytes), and heartbeats (~32 bytes).
  Even with encrypted payload expansion, no leaf-originated frame approaches 768 bytes.
  The 768-byte limit only blocks mesh-specific messages that leaf nodes do not send.

- **RX channel overflow is mitigated.** The RX channel was increased from 5 to 16 slots
  (FIPS issue #90) to handle burst traffic. At 768 bytes per slot, 16 slots consume
  12,320 bytes, which fits the budget.

- **The MTU/FRAME_CAP split is invisible to FIPS.** FIPS sees a BLE peer with MTU 2048
  and sends frames accordingly. The ESP32 firmware simply discards any frame larger
  than 768 bytes. Since FIPS skips FilterAnnounce and other oversized messages for
  MTU-limited peers, this rarely triggers in practice.

- **Future targets with more RAM could increase FRAME_CAP.** The ESP32-S3 has more
  available memory than the D0WD. The constant is per-crate, so `microfips-esp32s3`
  could use a larger FRAME_CAP without affecting the D0WD build.
