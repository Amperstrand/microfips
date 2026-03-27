#!/usr/bin/env python3
"""Serial-to-TCP proxy: bridges /dev/ttyACM1 to a TCP listening socket.
Opens serial port immediately and buffers incoming data until a TCP client connects."""

import argparse
import os
import select
import socket
import serial
import serial.tools.list_ports
import sys
import threading
import time

PRODUCT_MATCH = "c0de/cafe"


def find_mcu_port():
    for p in serial.tools.list_ports.comports():
        if PRODUCT_MATCH in (p.vid and f"{p.vid:04x}/{p.pid:04x}" or ""):
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
        self._open_serial()

    def _open_serial(self):
        for attempt in range(40):
            try:
                self.ser = serial.Serial(
                    self.port_name, 115200, timeout=0, dsrdtr=False, rtscts=False
                )
                print(f"Serial port opened: {self.port_name}", file=sys.stderr)
                return
            except (serial.SerialException, FileNotFoundError, OSError) as e:
                print(f"  serial open attempt {attempt+1}: {e}", file=sys.stderr)
                time.sleep(0.25)
        raise RuntimeError(f"Failed to open {self.port_name}")

    def serial_reader(self):
        while not self.stop_event.is_set():
            try:
                if self.ser.in_waiting:
                    data = self.ser.read(self.ser.in_waiting)
                    if data:
                        ts = time.strftime("%H:%M:%S")
                        with self.lock:
                            self.serial_buf += data
                            print(
                                f"{ts} CDC RX: {len(data)}B (buf={len(self.serial_buf)}B)",
                                file=sys.stderr,
                            )
                        self._flush_to_tcp()
                else:
                    time.sleep(0.001)
            except serial.SerialException:
                print("Serial disconnected", file=sys.stderr)
                self.stop_event.set()
                break

    def _flush_to_tcp(self):
        if self.tcp_conn and self.serial_buf:
            try:
                self.tcp_conn.sendall(self.serial_buf)
                self.serial_buf = b""
            except Exception:
                pass

    def handle_tcp(self, conn):
        self.tcp_conn = conn
        self._flush_to_tcp()
        try:
            while not self.stop_event.is_set():
                r, _, x = select.select([conn], [], [conn], 0.1)
                if conn in r or conn in x:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            break
                        self.ser.write(data)
                        self.ser.flush()
                    except Exception:
                        break
        except Exception as e:
            print(f"TCP error: {e}", file=sys.stderr)
        finally:
            self.tcp_conn = None
            conn.close()

    def stop(self):
        self.stop_event.set()
        if self.ser:
            self.ser.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=45679, help="TCP listen port")
    parser.add_argument("--serial", default=None, help="Serial port (auto-detect if omitted)")
    parser.add_argument("--reset", action="store_true", help="Reset MCU via st-flash first")
    args = parser.parse_args()

    if args.reset:
        print("Resetting MCU via st-flash...", file=sys.stderr)
        os.system("st-flash --connect-under-reset reset 2>/dev/null")
        time.sleep(1.5)

    port_name = args.serial
    if not port_name:
        for _ in range(20):
            port_name = find_mcu_port()
            if port_name:
                break
            time.sleep(0.25)

    if not port_name:
        print("MCU serial port not found", file=sys.stderr)
        sys.exit(1)

    print(f"Using serial port: {port_name}", file=sys.stderr)

    bridge = SerialBridge(port_name)
    reader = threading.Thread(target=bridge.serial_reader, daemon=True)
    reader.start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    print(f"TCP listening on :{args.port}", file=sys.stderr)

    try:
        while not bridge.stop_event.is_set():
            print("Waiting for TCP connection...", file=sys.stderr)
            try:
                conn, addr = srv.accept()
            except OSError:
                break
            print(f"TCP connected from {addr}", file=sys.stderr)
            bridge.handle_tcp(conn)
            print("TCP disconnected", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        bridge.stop()
        srv.close()


if __name__ == "__main__":
    main()
