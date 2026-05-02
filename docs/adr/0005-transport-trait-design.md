# ADR 0005: Transport Trait Design

## Status

Accepted

## Context

FIPS has a rich `Transport` trait at the center of its runtime. The trait exposes
packet channels (`PacketTx`/`PacketRx`), disconnect events, congestion state,
link statistics, and transport lifecycle management. FIPS is a full mesh daemon:
it manages multiple concurrent connections, routes between them, and needs to know
when any link goes up or down.

microfips is a leaf node. It connects to exactly one peer (a FIPS VPS or local FIPS
daemon) over a single transport. It does not route traffic, does not manage multiple
peers, and does not need an event bus for transport state changes. The `Node` runtime
owns the transport directly and polls it in a single loop.

The range of physical transports is wide: USB CDC serial (STM32), UART serial (ESP32),
BLE GATT (ESP32 with Python bridge), BLE L2CAP (ESP32 direct to FIPS), WiFi UDP
(ESP32 direct to FIPS), and host-side UDP (simulators and test tools). Each has
different framing requirements: serial transports use 2-byte LE length prefixes,
L2CAP uses 2-byte BE length prefixes, UDP uses raw frames with no prefix.

## Decision

microfips defines a minimal `Transport` trait in `microfips-protocol/src/transport.rs`:

```rust
pub trait Transport {
    type Error: Debug;
    fn wait_ready(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
    fn send(&mut self, data: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>>;
}
```

Three methods, no event bus, no congestion signaling, no link stats interface. The
trait is async (Embassy futures) and `no_std` compatible. `wait_ready()` blocks until
the transport is available (e.g., USB CDC waits for DTR assertion from the host).

Framing is handled outside the trait. `FrameWriter<T>` and `FrameReader<T>` wrap any
`Transport` with 2-byte LE length-prefixed framing for serial links. BLE L2CAP uses
its own 2-byte BE prefix in `l2cap_transport.rs`. UDP transports skip framing entirely
and pass raw payloads.

Concrete transport implementations:

| Transport | Crate | Use case |
|-----------|-------|----------|
| `UartTransport` | `microfips-esp-transport` | ESP32 UART serial (default) |
| `UsbTransport` | `microfips` (STM32) | STM32 USB CDC ACM |
| `BleTransport` | `microfips-esp-transport` | ESP32 BLE GATT (bridge) |
| `L2capTransport` | `microfips-esp-transport` | ESP32 BLE L2CAP (direct) |
| `WifiTransport` | `microfips-esp-common` | ESP32 WiFi UDP (direct) |
| `UdpTransport` | `microfips-esp-common` | ESP32/Sim UDP |
| `MockTransport` | `microfips-protocol` | Unit tests |
| `ChannelTransport` | `microfips-protocol` | Integration tests |

## Consequences

- Simple enough to implement on constrained hardware. The STM32F469 and ESP32-D0WD
  both support this trait without dynamic allocation.
- Cannot support mesh features (multi-peer routing, link aggregation, transport
  failover) without extending the trait. If microfips ever needs multi-peer support,
  the trait would need `connect()`, `disconnect()`, and transport identification.
- The `Node` runtime handles reconnection internally via `PeerPolicy` backoff timers.
  Transport errors bubble up as `ProtocolError::Disconnected` and the node retries.
- `wait_ready()` is transport-specific: USB CDC blocks on DTR, UART returns
  immediately, BLE blocks on connection establishment. This is intentional; each
  transport knows its own readiness conditions better than a generic signal could.
- FIPS's drain task and rate limiter (added in the `ble-transport-reliability` branch)
  are daemon-side concerns. The ESP32 writes directly to BLE at controller speed with
  no rate limiting, which is correct for a leaf node that sends infrequent heartbeats
  and small data frames.
