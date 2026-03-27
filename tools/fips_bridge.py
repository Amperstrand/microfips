#!/usr/bin/env python3
"""FIPS bridge: forwards length-prefixed frames between CDC ACM serial and UDP."""

import argparse
import os
import select
import socket
import serial
import struct
import subprocess
import sys
import threading
import time


class TcpSerial:
    """TCP socket with pyserial-like read/write interface."""

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.sock.settimeout(0)
        self.in_waiting = 0

    def read(self, n=1):
        self.in_waiting = 0
        try:
            return self.sock.recv(n)
        except (BlockingIOError, socket.timeout):
            return b""

    def write(self, data):
        return self.sock.sendall(data)

    def flush(self):
        pass

    def _update_waiting(self):
        r, _, _ = select.select([self.sock], [], [], 0)
        self.in_waiting = 1 if r else 0

    def close(self):
        self.sock.close()


def open_port(args):
    """Open serial or TCP connection based on args."""
    if args.tcp:
        host, port = args.tcp.rsplit(":", 1)
        port = int(port)
        for attempt in range(40):
            try:
                return TcpSerial(host, port)
            except (ConnectionRefusedError, OSError):
                time.sleep(0.25)
        print(f"Failed to connect to {args.tcp}", file=sys.stderr)
        sys.exit(1)
    else:
        for attempt in range(40):
            try:
                ser = serial.Serial(args.serial, args.baud, timeout=0)
                ser.dtr = True
                ser.rts = True
                return ser
            except (serial.SerialException, FileNotFoundError, OSError):
                time.sleep(0.25)
        print(f"Failed to open {args.serial}", file=sys.stderr)
        sys.exit(1)


def recv_frame(sock, timeout=30):
    hdr = b""
    while len(hdr) < 2:
        sock.settimeout(timeout)
        chunk = sock.recv(2 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    msg_len = struct.unpack("<H", hdr)[0]
    if msg_len == 0 or msg_len > 65535:
        return None
    data = b""
    while len(data) < msg_len:
        sock.settimeout(timeout)
        chunk = sock.recv(msg_len - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def serial_to_udp(ser, send_sock, log_prefix):
    buf = b""
    while True:
        try:
            if hasattr(ser, "_update_waiting"):
                ser._update_waiting()
            n = ser.read(ser.in_waiting or 1)
            if n:
                buf += n
                while len(buf) >= 2:
                    msg_len = struct.unpack("<H", buf[:2])[0]
                    if msg_len == 0 or msg_len > 1500:
                        buf = buf[2:]
                        continue
                    if len(buf) < 2 + msg_len:
                        break
                    frame = buf[2:2 + msg_len]
                    buf = buf[2 + msg_len:]
                    ts = time.strftime("%H:%M:%S")
                    print(f"{ts} {log_prefix} CDC->UDP: {len(frame)}B", file=sys.stderr)
                    send_sock.sendto(frame, udp_peer)
        except (serial.SerialException, ConnectionResetError, BrokenPipeError):
            print(f"{log_prefix} disconnected", file=sys.stderr)
            break
        except Exception as e:
            print(f"{log_prefix} error: {e}", file=sys.stderr)
            break


def udp_to_serial(ser, udp_sock, log_prefix):
    while True:
        try:
            udp_sock.settimeout(30)
            data, addr = udp_sock.recvfrom(65535)
            hdr = struct.pack("<H", len(data))
            ser.write(hdr + data)
            ser.flush()
            ts = time.strftime("%H:%M:%S")
            print(f"{ts} {log_prefix} UDP->CDC: {len(data)}B from {addr}", file=sys.stderr)
        except socket.timeout:
            continue
        except serial.SerialException:
            print(f"{log_prefix} CDC disconnected", file=sys.stderr)
            break
        except Exception as e:
            print(f"{log_prefix} UDP error: {e}", file=sys.stderr)
            break


def main():
    parser = argparse.ArgumentParser(description="FIPS CDC<->UDP bridge")
    parser.add_argument("--serial", default="/dev/ttyACM1", help="Serial port")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--tcp", default=None, help="TCP address instead of serial (host:port)")
    parser.add_argument("--udp-host", default="orangeclaw.dns4sats.xyz", help="UDP host")
    parser.add_argument("--udp-port", type=int, default=2121, help="UDP port")
    parser.add_argument("--bind", default="0.0.0.0", help="Local bind addr")
    parser.add_argument("--local-port", type=int, default=31337, help="Local UDP port")
    parser.add_argument("--reset", action="store_true", help="Reset MCU via probe-rs first")
    parser.add_argument(
        "--probe-chip",
        default="STM32F469NIHx",
        help="probe-rs chip name",
    )
    args = parser.parse_args()

    global udp_peer
    udp_peer = (args.udp_host, args.udp_port)

    src = f"tcp:{args.tcp}" if args.tcp else args.serial
    print(f"Bridge: {src} <-> {args.udp_host}:{args.udp_port}", file=sys.stderr)

    if args.reset:
        print(f"Resetting MCU via probe-rs...", file=sys.stderr)
        subprocess.run(
            ["probe-rs", "reset", "--chip", args.probe_chip, "--connect-under-reset"],
            check=True,
            capture_output=True,
        )
        time.sleep(0.5)

    ser = open_port(args)
    print(f"Connected: {src}", file=sys.stderr)

    while True:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind((args.bind, args.local_port))
        print(f"UDP bound on {args.bind}:{args.local_port} (send + recv)", file=sys.stderr)

        t1 = threading.Thread(target=serial_to_udp, args=(ser, udp_sock, ">>"), daemon=True)
        t2 = threading.Thread(target=udp_to_serial, args=(ser, udp_sock, "<<"), daemon=True)
        t1.start()
        t2.start()

        try:
            t1.join(timeout=120)
            t2.join(timeout=1)
        except KeyboardInterrupt:
            print("\nShutting down...", file=sys.stderr)
            break

        if t1.is_alive() and t2.is_alive():
            continue

        print(f"Connection lost, reconnecting...", file=sys.stderr)
        udp_sock.close()
        time.sleep(0.5)
        ser.close()
        ser = open_port(args)
        print(f"Reconnected: {src}", file=sys.stderr)

    ser.close()
    try:
        udp_sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
