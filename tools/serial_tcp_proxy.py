#!/usr/bin/env python3
"""Serial-to-TCP proxy: bridges /dev/ttyACM1 to a TCP listening socket.
Handles USB device disappearance (MCU reset) by reconnecting."""

import argparse
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


def handle_client(conn, port_name, stop_event):
    try:
        ser = serial.Serial(port_name, 115200, timeout=0)
    except Exception as e:
        print(f"Failed to open {port_name}: {e}", file=sys.stderr)
        conn.close()
        return

    try:
        while not stop_event.is_set():
            r, _, x = select.select([conn, ser], [], [conn, ser], 0.1)
            if conn in r or conn in x:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    ser.write(data)
                except Exception:
                    break
            if ser in r or ser in x:
                try:
                    data = ser.read(ser.in_waiting or 1)
                    if data:
                        conn.sendall(data)
                except Exception:
                    break
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    finally:
        ser.close()
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=45678, help="TCP listen port")
    parser.add_argument("--serial", default=None, help="Serial port (auto-detect if omitted)")
    args = parser.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    print(f"Serial TCP proxy listening on :{args.port}", file=sys.stderr)

    while True:
        print("Waiting for TCP connection...", file=sys.stderr)
        conn, addr = srv.accept()
        print(f"TCP connected from {addr}", file=sys.stderr)

        port_name = args.serial
        if not port_name:
            for _ in range(40):
                port_name = find_mcu_port()
                if port_name:
                    break
                time.sleep(0.25)

        if not port_name:
            print("MCU serial port not found", file=sys.stderr)
            conn.close()
            continue

        print(f"Using serial port: {port_name}", file=sys.stderr)
        stop = threading.Event()
        t = threading.Thread(target=handle_client, args=(conn, port_name, stop), daemon=True)
        t.start()
        t.join()
        print("Client disconnected", file=sys.stderr)


if __name__ == "__main__":
    main()
