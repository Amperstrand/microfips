#!/usr/bin/env python3
"""Serial-to-UDP bridge: forwards length-prefixed MCU frames directly to a UDP peer.

Single-hop replacement for the serial_tcp_proxy + SSH tunnel + fips_bridge pipeline.
Reads length-prefixed frames from USB CDC serial, sends raw FMP payload as UDP to
a remote peer (e.g., FIPS daemon on VPS). Reverse direction adds length prefix back.

Usage:
    python3 serial_udp_bridge.py --serial /dev/ttyACM2 --udp-host orangeclaw.dns4sats.xyz --udp-port 2121
    python3 serial_udp_bridge.py --udp-host 127.0.0.1 --udp-port 31337  # auto-detect MCU
    python3 serial_udp_bridge.py --serial /dev/ttyUSB0 --baud 115200 --udp-host orangeclaw.dns4sats.xyz --udp-port 2121
"""

import argparse
import os
import select
import serial
import serial.tools.list_ports
import socket
import struct
import sys
import threading
import time


PRODUCT_MCU = "c0de/cafe"
PRODUCT_ESP32 = "10c4/ea60"
EPOCH_MS = 1700000000000


def ts():
    return time.strftime("%H:%M:%S") + f".{int(time.time()*1000)%1000:03d}"


def find_port(product_match):
    for p in serial.tools.list_ports.comports():
        vid_hex = f"{p.vid:04x}" if p.vid else ""
        pid_hex = f"{p.pid:04x}" if p.pid else ""
        if f"{vid_hex}/{pid_hex}" == product_match:
            return p.device
    return None


def find_any_mcu():
    for match in [PRODUCT_MCU, PRODUCT_ESP32]:
        port = find_port(match)
        if port:
            return port, match
    return None, None


class SerialUdpBridge:
    def __init__(self, serial_port, baud, udp_host, udp_port, bind_addr, bind_port):
        self.udp_peer = (udp_host, udp_port)
        self.stop_event = threading.Event()
        self.serial_buf = b""
        self.lock = threading.Lock()

        self.cdc_rx_bytes = 0
        self.cdc_tx_bytes = 0
        self.udp_tx_bytes = 0
        self.udp_rx_bytes = 0
        self.cdc_to_udp_frames = 0
        self.udp_to_cdc_frames = 0

        self._open_serial(serial_port, baud)

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock.bind((bind_addr, bind_port))
        self.udp_sock.settimeout(30)

    def _open_serial(self, port, baud):
        for attempt in range(40):
            try:
                self.ser = serial.Serial(
                    port, baud, timeout=0, dsrdtr=True, rtscts=False
                )
                print(f"{ts()} SERIAL opened: {port} @ {baud} baud", file=sys.stderr)
                return
            except (serial.SerialException, FileNotFoundError, OSError) as e:
                if attempt % 10 == 0:
                    print(f"{ts()} SERIAL open attempt {attempt+1}/40: {e}", file=sys.stderr)
                time.sleep(0.25)
        raise RuntimeError(f"Failed to open {port}")

    def _parse_frames(self):
        frames = []
        while len(self.serial_buf) >= 2:
            msg_len = struct.unpack("<H", self.serial_buf[:2])[0]
            if msg_len == 0 or msg_len > 1500:
                print(f"{ts()} >> invalid frame length {msg_len}, skipping 2B", file=sys.stderr)
                self.serial_buf = self.serial_buf[2:]
                continue
            if len(self.serial_buf) < 2 + msg_len:
                break
            frames.append(self.serial_buf[2:2 + msg_len])
            self.serial_buf = self.serial_buf[2 + msg_len:]
        return frames

    def serial_to_udp(self):
        frame_count = 0
        last_alive = time.time()
        while not self.stop_event.is_set():
            try:
                if self.ser.in_waiting:
                    data = self.ser.read(self.ser.in_waiting)
                    if data:
                        self.cdc_rx_bytes += len(data)
                        with self.lock:
                            self.serial_buf += data
                            frames = self._parse_frames()
                        for frame in frames:
                            frame_count += 1
                            self.cdc_to_udp_frames += 1
                            self.udp_tx_bytes += len(frame)
                            self.udp_sock.sendto(frame, self.udp_peer)
                            first_bytes = frame[:8].hex() if len(frame) >= 8 else frame.hex()
                            print(
                                f"{ts()} >> CDC->UDP: frame#{frame_count} {len(frame)}B hex={first_bytes}",
                                file=sys.stderr,
                            )
                else:
                    if time.time() - last_alive >= 10:
                        print(
                            f"{ts()} >> alive, buf={len(self.serial_buf)}B, frames={frame_count}, rx={self.cdc_rx_bytes}B",
                            file=sys.stderr,
                        )
                        last_alive = time.time()
                    time.sleep(0.001)
            except serial.SerialException as e:
                print(f"{ts()} >> SERIAL disconnected: {e}", file=sys.stderr)
                self.stop_event.set()
                break
            except OSError as e:
                print(f"{ts()} >> SERIAL error: {e}", file=sys.stderr)
                self.stop_event.set()
                break

    def udp_to_serial(self):
        frame_count = 0
        last_alive = time.time()
        while not self.stop_event.is_set():
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                frame_count += 1
                self.udp_to_cdc_frames += 1
                self.udp_rx_bytes += len(data)
                self.cdc_tx_bytes += len(data) + 2
                hdr = struct.pack("<H", len(data))
                self.ser.write(hdr + data)
                self.ser.flush()
                first_bytes = data[:8].hex() if len(data) >= 8 else data.hex()
                print(
                    f"{ts()} << UDP->CDC: frame#{frame_count} {len(data)}B from {addr} hex={first_bytes}",
                    file=sys.stderr,
                )
            except socket.timeout:
                if time.time() - last_alive >= 30:
                    print(
                        f"{ts()} << alive (timeout), frames={frame_count}, tx={self.cdc_tx_bytes}B",
                        file=sys.stderr,
                    )
                    last_alive = time.time()
                continue
            except serial.SerialException as e:
                print(f"{ts()} << SERIAL write error: {e}", file=sys.stderr)
                self.stop_event.set()
                break
            except OSError as e:
                print(f"{ts()} << error: {e}", file=sys.stderr)
                self.stop_event.set()
                break

    def run(self):
        t1 = threading.Thread(target=self.serial_to_udp, daemon=True)
        t2 = threading.Thread(target=self.udp_to_serial, daemon=True)
        t1.start()
        t2.start()
        try:
            while t1.is_alive() and t2.is_alive():
                t1.join(timeout=30)
        except KeyboardInterrupt:
            print(f"\n{ts()} Interrupted", file=sys.stderr)
            self.stop_event.set()
        self.stop_event.set()
        t1.join(timeout=5)
        t2.join(timeout=5)

    def stop(self):
        self.stop_event.set()
        try:
            self.ser.close()
        except Exception:
            pass
        self.udp_sock.close()

    def summary(self):
        return (
            f"CDC_RX={self.cdc_rx_bytes}B CDC_TX={self.cdc_tx_bytes}B "
            f"UDP_TX={self.udp_tx_bytes}B UDP_RX={self.udp_rx_bytes}B "
            f"frames: >>{self.cdc_to_udp_frames} <<{self.udp_to_cdc_frames}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Serial-to-UDP bridge (single-hop, replaces serial_tcp_proxy + SSH tunnel + fips_bridge)"
    )
    parser.add_argument("--serial", default=None, help="Serial port path (auto-detect if omitted)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--udp-host", default="orangeclaw.dns4sats.xyz", help="UDP peer host (default: orangeclaw.dns4sats.xyz)")
    parser.add_argument("--udp-port", type=int, default=2121, help="UDP peer port (default: 2121)")
    parser.add_argument("--bind", default="0.0.0.0", help="Local UDP bind addr")
    parser.add_argument("--bind-port", type=int, default=0, help="Local UDP bind port (0=auto)")
    parser.add_argument("--reset", action="store_true", help="Reset STM32 via st-flash before opening serial")
    args = parser.parse_args()

    if args.reset:
        print(f"{ts()} Resetting STM32 via st-flash...", file=sys.stderr)
        os.system("st-flash --connect-under-reset reset 2>/dev/null")
        time.sleep(2)

    port_name = args.serial
    if not port_name:
        for i in range(20):
            port_name, match = find_any_mcu()
            if port_name:
                device_type = "STM32" if match == PRODUCT_MCU else "ESP32"
                print(f"{ts()} Auto-detected {device_type} on {port_name}", file=sys.stderr)
                break
            if i % 5 == 0:
                print(f"{ts()} Scanning for MCU (VID:PID={PRODUCT_MCU} or {PRODUCT_ESP32})...", file=sys.stderr)
            time.sleep(0.25)

    if not port_name:
        print(f"{ts()} ERROR: MCU serial port not found", file=sys.stderr)
        sys.exit(1)

    print(
        f"{ts()} Bridge: {port_name} <-> {args.udp_host}:{args.udp_port}",
        file=sys.stderr,
    )

    bridge = SerialUdpBridge(
        port_name, args.baud, args.udp_host, args.udp_port, args.bind, args.bind_port
    )

    actual_port = bridge.udp_sock.getsockname()[1]
    print(f"{ts()} UDP bound on {args.bind}:{actual_port}", file=sys.stderr)

    try:
        bridge.run()
    finally:
        print(f"{ts()} Summary: {bridge.summary()}", file=sys.stderr)
        bridge.stop()


if __name__ == "__main__":
    main()
