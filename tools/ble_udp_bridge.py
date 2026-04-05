#!/usr/bin/env python3
"""BLE GATT-to-UDP bridge: forwards length-prefixed MCU frames to a UDP peer via BLE.

Scans for a BLE peripheral named "microfips-esp32" (or by address), connects,
subscribes to TX notifications, writes to RX characteristic, and forwards frames
bidirectionally between BLE and UDP (FIPS daemon on VPS or localhost sim).

GATT UUIDs (shared with firmware):
  Service: 6f696670-7300-4265-8001-000000000001
  RX (host writes to ESP32): 6f696670-7300-4265-8002-000000000002
  TX (ESP32 notifies host):  6f696670-7300-4265-8003-000000000003

Framing:
  BLE side: [2-byte LE length][payload]  (one frame per GATT notify / write)
  UDP side: raw payload (no length prefix)

Usage:
    python3 ble_udp_bridge.py --udp-host orangeclaw.dns4sats.xyz
    python3 ble_udp_bridge.py --ble-name microfips-esp32 --udp-host 127.0.0.1 --udp-port 31338
    python3 ble_udp_bridge.py --ble-addr AA:BB:CC:DD:EE:FF --udp-host orangeclaw.dns4sats.xyz --verbose
"""

import argparse
import asyncio
import socket
import struct
import sys
import time

from bleak import BleakClient, BleakScanner

# ── GATT UUIDs (must match firmware) ──────────────────────────────────────────
SERVICE_UUID = "6f696670-7300-4265-8001-000000000001"
RX_UUID      = "6f696670-7300-4265-8002-000000000002"  # host writes here
TX_UUID      = "6f696670-7300-4265-8003-000000000003"  # host subscribes here

# ── Limits ────────────────────────────────────────────────────────────────────
MAX_FRAME_LEN = 1500
BLE_MAX_WRITE = 252      # firmware BLE_MAX_FRAME (250 payload + 2 header)
RECONNECT_DELAY = 2.0   # seconds between reconnect attempts
SCAN_TIMEOUT = 10.0     # seconds per scan attempt


def ts() -> str:
    return time.strftime("%H:%M:%S") + f".{int(time.time()*1000)%1000:03d}"


# ──────────────────────────────────────────────────────────────────────────────
class BleUdpBridge:
    def __init__(
        self,
        ble_name: str,
        ble_addr: str | None,
        udp_host: str,
        udp_port: int,
        bind_addr: str,
        bind_port: int,
        verbose: bool,
    ):
        self.ble_name = ble_name
        self.ble_addr = ble_addr
        self.udp_peer = (udp_host, udp_port)
        self.verbose = verbose

        # Notify queue: notification callback → ble_to_udp coroutine
        self._notify_queue: asyncio.Queue[bytes] = asyncio.Queue()

        # Counters
        self.ble_rx_bytes = 0
        self.ble_tx_bytes = 0
        self.udp_tx_bytes = 0
        self.udp_rx_bytes = 0
        self.ble_to_udp_frames = 0
        self.udp_to_ble_frames = 0

        # UDP socket (blocking, used from async via executor)
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((bind_addr, bind_port))
        self._udp.settimeout(1.0)

        actual = self._udp.getsockname()
        print(f"{ts()} UDP bound on {actual[0]}:{actual[1]}", file=sys.stderr)
        print(
            f"{ts()} Bridge: BLE({self.ble_addr or self.ble_name!r}) <-> "
            f"{udp_host}:{udp_port}",
            file=sys.stderr,
        )

    # ── BLE scanning ──────────────────────────────────────────────────────────

    async def _scan(self):
        """Return a device matching addr or name, or None."""
        if self.ble_addr:
            print(f"{ts()} Scanning for BLE addr {self.ble_addr} ...", file=sys.stderr)
            device = await BleakScanner.find_device_by_address(
                self.ble_addr, timeout=SCAN_TIMEOUT
            )
        else:
            print(
                f"{ts()} Scanning for BLE device {self.ble_name!r} ...", file=sys.stderr
            )
            device = await BleakScanner.find_device_by_name(
                self.ble_name, timeout=SCAN_TIMEOUT
            )
        return device

    # ── Notification callback ─────────────────────────────────────────────────

    def _on_notify(self, _handle, data: bytearray):
        """Called from bleak internals on each TX notification."""
        self._notify_queue.put_nowait(bytes(data))

    # ── BLE → UDP coroutine ───────────────────────────────────────────────────

    async def _ble_to_udp(self, stop: asyncio.Event):
        frame_count = 0
        last_alive = time.time()
        loop = asyncio.get_event_loop()

        while not stop.is_set():
            try:
                raw = await asyncio.wait_for(self._notify_queue.get(), timeout=10.0)
            except asyncio.TimeoutError:
                if time.time() - last_alive >= 10:
                    print(
                        f"{ts()} >> alive, frames={frame_count}, rx={self.ble_rx_bytes}B",
                        file=sys.stderr,
                    )
                    last_alive = time.time()
                continue

            self.ble_rx_bytes += len(raw)

            # Parse length-prefixed frame
            if len(raw) < 2:
                print(f"{ts()} >> BLE->UDP: short notify ({len(raw)}B), skip", file=sys.stderr)
                continue

            msg_len = struct.unpack("<H", raw[:2])[0]
            if msg_len == 0 or msg_len > MAX_FRAME_LEN:
                print(
                    f"{ts()} >> BLE->UDP: invalid frame length {msg_len}, skip",
                    file=sys.stderr,
                )
                continue

            payload = raw[2 : 2 + msg_len]
            if len(payload) < msg_len:
                print(
                    f"{ts()} >> BLE->UDP: truncated frame {len(payload)}/{msg_len}B, skip",
                    file=sys.stderr,
                )
                continue

            frame_count += 1
            self.ble_to_udp_frames += 1
            self.udp_tx_bytes += len(payload)

            await loop.run_in_executor(None, self._udp.sendto, payload, self.udp_peer)

            first_bytes = payload[:8].hex() if len(payload) >= 8 else payload.hex()
            print(
                f"{ts()} >> BLE->UDP: frame#{frame_count} {len(payload)}B hex={first_bytes}",
                file=sys.stderr,
            )
            last_alive = time.time()

    # ── UDP → BLE coroutine ───────────────────────────────────────────────────

    async def _udp_to_ble(self, client: BleakClient, stop: asyncio.Event):
        frame_count = 0
        last_alive = time.time()
        loop = asyncio.get_event_loop()

        while not stop.is_set():
            try:
                data, addr = await loop.run_in_executor(None, self._udp.recvfrom, 65535)
            except socket.timeout:
                if time.time() - last_alive >= 30:
                    print(
                        f"{ts()} << alive (timeout), frames={frame_count}, tx={self.ble_tx_bytes}B",
                        file=sys.stderr,
                    )
                    last_alive = time.time()
                continue
            except OSError as e:
                print(f"{ts()} << UDP error: {e}", file=sys.stderr)
                stop.set()
                break

            frame_count += 1
            self.udp_to_ble_frames += 1
            self.udp_rx_bytes += len(data)

            # Prepend 2-byte LE length header for BLE framing
            hdr = struct.pack("<H", len(data))
            framed = hdr + data
            self.ble_tx_bytes += len(framed)

            if len(framed) > 252:
                print(
                    f"{ts()} << UDP->BLE: frame too large ({len(framed)}B > 252B), dropped",
                    file=sys.stderr,
                )
                continue

            try:
                await client.write_gatt_char(RX_UUID, framed)
            except Exception as e:
                print(f"{ts()} << BLE write error: {e}", file=sys.stderr)
                stop.set()
                break

            first_bytes = data[:8].hex() if len(data) >= 8 else data.hex()
            print(
                f"{ts()} << UDP->BLE: frame#{frame_count} {len(data)}B from {addr} hex={first_bytes}",
                file=sys.stderr,
            )
            last_alive = time.time()

    # ── Main session loop ─────────────────────────────────────────────────────

    async def _run_session(self, device):
        """Connect, subscribe, run bridge, return when disconnected."""
        stop = asyncio.Event()

        def on_disconnect(_client):
            print(f"{ts()} BLE disconnected", file=sys.stderr)
            stop.set()

        print(f"{ts()} Connecting to {device.address} ({device.name}) ...", file=sys.stderr)
        async with BleakClient(device, disconnected_callback=on_disconnect) as client:
            print(f"{ts()} BLE connected: {device.address}", file=sys.stderr)

            # Subscribe to TX notifications
            await client.start_notify(TX_UUID, self._on_notify)
            print(f"{ts()} Subscribed to TX notifications", file=sys.stderr)

            # Drain any stale items in queue (e.g., from prior session)
            while not self._notify_queue.empty():
                try:
                    self._notify_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

            # Run both directions concurrently
            ble2udp = asyncio.create_task(self._ble_to_udp(stop))
            udp2ble = asyncio.create_task(self._udp_to_ble(client, stop))

            try:
                # Wait until either direction signals stop (disconnect / error)
                done, pending = await asyncio.wait(
                    [ble2udp, udp2ble],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                stop.set()
                for t in pending:
                    t.cancel()
                    try:
                        await t
                    except (asyncio.CancelledError, Exception):
                        pass
            except asyncio.CancelledError:
                stop.set()
                ble2udp.cancel()
                udp2ble.cancel()
                raise

            await client.stop_notify(TX_UUID)

    # ── Top-level run loop with reconnect ─────────────────────────────────────

    async def run(self):
        try:
            while True:
                device = None
                while device is None:
                    device = await self._scan()
                    if device is None:
                        print(
                            f"{ts()} BLE device not found, retrying in {RECONNECT_DELAY}s ...",
                            file=sys.stderr,
                        )
                        await asyncio.sleep(RECONNECT_DELAY)

                try:
                    await self._run_session(device)
                except Exception as e:
                    print(f"{ts()} Session error: {e}", file=sys.stderr)

                print(
                    f"{ts()} Reconnecting in {RECONNECT_DELAY}s ...", file=sys.stderr
                )
                await asyncio.sleep(RECONNECT_DELAY)

        except KeyboardInterrupt:
            print(f"\n{ts()} Interrupted", file=sys.stderr)

    def summary(self) -> str:
        return (
            f"BLE_RX={self.ble_rx_bytes}B BLE_TX={self.ble_tx_bytes}B "
            f"UDP_TX={self.udp_tx_bytes}B UDP_RX={self.udp_rx_bytes}B "
            f"frames: >>{self.ble_to_udp_frames} <<{self.udp_to_ble_frames}"
        )

    def close(self):
        try:
            self._udp.close()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "BLE GATT-to-UDP bridge (single-hop, replaces serial_udp_bridge for ESP32 BLE)"
        )
    )
    parser.add_argument(
        "--ble-name",
        default="microfips-esp32",
        help="BLE peripheral name to scan for (default: microfips-esp32)",
    )
    parser.add_argument(
        "--ble-addr",
        default=None,
        help="BLE peripheral MAC address (skips name scan if provided)",
    )
    parser.add_argument(
        "--udp-host",
        default="orangeclaw.dns4sats.xyz",
        help="UDP peer host (default: orangeclaw.dns4sats.xyz)",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=2121,
        help="UDP peer port (default: 2121)",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Local UDP bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--bind-port",
        type=int,
        default=0,
        help="Local UDP bind port (default: 0 = OS-assigned)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    bridge = BleUdpBridge(
        ble_name=args.ble_name,
        ble_addr=args.ble_addr,
        udp_host=args.udp_host,
        udp_port=args.udp_port,
        bind_addr=args.bind,
        bind_port=args.bind_port,
        verbose=args.verbose,
    )

    try:
        asyncio.run(bridge.run())
    finally:
        print(f"{ts()} Summary: {bridge.summary()}", file=sys.stderr)
        bridge.close()


if __name__ == "__main__":
    main()
