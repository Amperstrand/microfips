#!/usr/bin/env python3
"""Serial-to-TCP proxy: bridges MCU CDC ACM serial to a TCP listening socket.

Opens serial port immediately and buffers incoming data until a TCP client connects.
All data flows through as raw bytes — this is a dumb relay, no protocol awareness.

Usage:
    python3 serial_tcp_proxy.py --serial /dev/ttyACM1 --port 45679
    python3 serial_tcp_proxy.py --port 45679  # auto-detect MCU by VID/PID
"""

import argparse
import os
import select
import socket
import serial
import serial.tools.list_ports
import struct
import sys
import threading
import time

PRODUCT_MATCH = "c0de/cafe"
EPOCH_MS = 1700000000000


def ts():
    return time.strftime("%H:%M:%S") + f".{int(time.time()*1000)%1000:03d}"


def elapsed():
    return f"+{int(time.time()*1000 - EPOCH_MS)}ms"


def find_mcu_port():
    for p in serial.tools.list_ports.comports():
        vid_hex = f"{p.vid:04x}" if p.vid else ""
        pid_hex = f"{p.pid:04x}" if p.pid else ""
        if f"{vid_hex}/{pid_hex}" == PRODUCT_MATCH:
            return p.device
    return None


class SerialBridge:
    def __init__(self, port_name):
        self.port_name = port_name
        self.ser = None
        self.serial_buf = b""
        self.lock = threading.Lock()
        self.tcp_conn = None
        self.stop_event = threading.Event()
        self.cdc_rx_bytes = 0
        self.tcp_tx_bytes = 0
        self.tcp_rx_bytes = 0
        self.serial_tx_bytes = 0
        self._open_serial()

    def _open_serial(self):
        for attempt in range(40):
            try:
                self.ser = serial.Serial(
                    self.port_name, 115200, timeout=0, dsrdtr=False, rtscts=False
                )
                print(f"{ts()} SERIAL opened: {self.port_name}", file=sys.stderr)
                return
            except (serial.SerialException, FileNotFoundError, OSError) as e:
                if attempt % 10 == 0:
                    print(f"{ts()} SERIAL open attempt {attempt+1}/40: {e}", file=sys.stderr)
                time.sleep(0.25)
        raise RuntimeError(f"Failed to open {self.port_name}")

    def serial_reader(self):
        while not self.stop_event.is_set():
            try:
                if self.ser.in_waiting:
                    data = self.ser.read(self.ser.in_waiting)
                    if data:
                        self.cdc_rx_bytes += len(data)
                        with self.lock:
                            was_empty = len(self.serial_buf) == 0
                            self.serial_buf += data
                            print(
                                f"{ts()} CDC RX: +{len(data)}B total={self.cdc_rx_bytes}B buf={len(self.serial_buf)}B",
                                file=sys.stderr,
                            )
                        self._flush_to_tcp()
                else:
                    time.sleep(0.001)
            except serial.SerialException as e:
                print(f"{ts()} SERIAL disconnected: {e}", file=sys.stderr)
                self.stop_event.set()
                break
            except OSError as e:
                print(f"{ts()} SERIAL error: {e}", file=sys.stderr)
                self.stop_event.set()
                break

    def _flush_to_tcp(self):
        if self.tcp_conn and self.serial_buf:
            try:
                n = self.tcp_conn.sendall(self.serial_buf)
                sent = len(self.serial_buf)
                self.tcp_tx_bytes += sent
                print(
                    f"{ts()} TCP TX: +{sent}B total={self.tcp_tx_bytes}B (flushed buffer)",
                    file=sys.stderr,
                )
                self.serial_buf = b""
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                print(f"{ts()} TCP TX FAILED: {e} — {len(self.serial_buf)}B lost", file=sys.stderr)
                self.serial_buf = b""
                self.tcp_conn = None

    def handle_tcp(self, conn):
        self.tcp_conn = conn
        peer = conn.getpeername()
        print(f"{ts()} TCP connected from {peer}", file=sys.stderr)

        with self.lock:
            if self.serial_buf:
                print(
                    f"{ts()} TCP TX: +{len(self.serial_buf)}B (pre-buffered CDC data)",
                    file=sys.stderr,
                )
        self._flush_to_tcp()

        try:
            while not self.stop_event.is_set():
                r, _, x = select.select([conn], [], [conn], 0.1)
                if conn in r or conn in x:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            print(f"{ts()} TCP EOF from {peer}", file=sys.stderr)
                            break
                        self.tcp_rx_bytes += len(data)
                        self.ser.write(data)
                        self.ser.flush()
                        self.serial_tx_bytes += len(data)
                        if len(data) <= 128:
                            print(
                                f"{ts()} TCP RX: +{len(data)}B total={self.tcp_rx_bytes}B -> SERIAL TX hex={data[:32].hex()}{'...' if len(data) > 32 else ''}",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                f"{ts()} TCP RX: +{len(data)}B total={self.tcp_rx_bytes}B -> SERIAL TX",
                                file=sys.stderr,
                            )
                    except (BrokenPipeError, ConnectionResetError, OSError) as e:
                        print(f"{ts()} TCP RX error: {e}", file=sys.stderr)
                        break
        except Exception as e:
            print(f"{ts()} TCP handle error: {e}", file=sys.stderr)
        finally:
            self.tcp_conn = None
            conn.close()
            print(f"{ts()} TCP disconnected (bytes: rx={self.tcp_rx_bytes} tx={self.tcp_tx_bytes})", file=sys.stderr)

    def stop(self):
        self.stop_event.set()
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Serial-to-TCP proxy (dumb relay for MCU CDC ACM)")
    parser.add_argument("--port", type=int, default=45679, help="TCP listen port (default: 45679)")
    parser.add_argument("--serial", default=None, help="Serial port path (auto-detect by VID/PID if omitted)")
    parser.add_argument("--reset", action="store_true", help="Reset MCU via st-flash before opening serial")
    args = parser.parse_args()

    if args.reset:
        print(f"{ts()} Resetting MCU via st-flash...", file=sys.stderr)
        os.system("st-flash --connect-under-reset reset 2>/dev/null")
        time.sleep(2)

    port_name = args.serial
    if not port_name:
        for i in range(20):
            port_name = find_mcu_port()
            if port_name:
                break
            if i % 5 == 0:
                print(f"{ts()} Scanning for MCU (VID:PID={PRODUCT_MATCH})...", file=sys.stderr)
            time.sleep(0.25)

    if not port_name:
        print(f"{ts()} ERROR: MCU serial port not found", file=sys.stderr)
        sys.exit(1)

    print(f"{ts()} Using serial port: {port_name}", file=sys.stderr)

    bridge = SerialBridge(port_name)
    reader = threading.Thread(target=bridge.serial_reader, daemon=True)
    reader.start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    print(f"{ts()} TCP listening on :{args.port}", file=sys.stderr)

    try:
        while not bridge.stop_event.is_set():
            print(f"{ts()} Waiting for TCP connection...", file=sys.stderr)
            try:
                conn, addr = srv.accept()
            except OSError:
                break
            bridge.handle_tcp(conn)
    except KeyboardInterrupt:
        print(f"\n{ts()} Interrupted", file=sys.stderr)
    finally:
        print(f"{ts()} Summary: CDC_RX={bridge.cdc_rx_bytes} TCP_TX={bridge.tcp_tx_bytes} TCP_RX={bridge.tcp_rx_bytes} SERIAL_TX={bridge.serial_tx_bytes}", file=sys.stderr)
        bridge.stop()
        srv.close()


if __name__ == "__main__":
    main()
