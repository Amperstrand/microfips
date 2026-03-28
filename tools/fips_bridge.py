#!/usr/bin/env python3
"""FIPS bridge: forwards length-prefixed frames between TCP (from host proxy) and UDP (to FIPS).

Runs on the VPS. Receives frames over TCP from serial_tcp_proxy (via SSH tunnel),
strips the 2-byte length prefix, and forwards the raw FMP payload as UDP to the
local FIPS daemon. Reverse direction adds the length prefix back.

Usage:
    python3 fips_bridge.py --tcp 127.0.0.1:45679
    python3 fips_bridge.py --serial /dev/ttyACM0  # direct serial mode
"""

import argparse
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time

EPOCH_MS = 1700000000000


def ts():
    return time.strftime("%H:%M:%S") + f".{int(time.time()*1000)%1000:03d}"


class TcpSerial:
    """TCP socket with pyserial-like read/write interface."""

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.sock.settimeout(0)
        self.in_waiting = 0
        self.rx_bytes = 0
        self.tx_bytes = 0

    def read(self, n=1):
        self.in_waiting = 0
        try:
            data = self.sock.recv(n)
            self.rx_bytes += len(data)
            return data
        except (BlockingIOError, socket.timeout):
            return b""

    def write(self, data):
        self.sock.sendall(data)
        self.tx_bytes += len(data)

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
                if attempt % 10 == 0:
                    print(f"{ts()} TCP connect attempt {attempt+1}/40 to {args.tcp}", file=sys.stderr)
                time.sleep(0.25)
        print(f"{ts()} ERROR: Failed to connect to {args.tcp}", file=sys.stderr)
        sys.exit(1)
    else:
        import serial
        for attempt in range(40):
            try:
                ser = serial.Serial(args.serial, args.baud, timeout=0, dsrdtr=False, rtscts=False)
                return ser
            except (serial.SerialException, FileNotFoundError, OSError):
                time.sleep(0.25)
        print(f"{ts()} ERROR: Failed to open {args.serial}", file=sys.stderr)
        sys.exit(1)


def serial_to_udp(ser, send_sock, log_prefix, state):
    """Read length-prefixed frames from serial/TCP, forward as raw UDP to FIPS."""
    buf = b""
    frame_count = 0
    last_alive = time.time()
    while not state["stop"]:
        try:
            if hasattr(ser, "_update_waiting"):
                ser._update_waiting()
            n = ser.read(ser.in_waiting or 1)
            if n:
                buf += n
                while len(buf) >= 2:
                    msg_len = struct.unpack("<H", buf[:2])[0]
                    if msg_len == 0 or msg_len > 1500:
                        print(f"{ts()} {log_prefix} invalid frame length {msg_len}, skipping 2B", file=sys.stderr)
                        buf = buf[2:]
                        continue
                    if len(buf) < 2 + msg_len:
                        break
                    frame = buf[2:2 + msg_len]
                    buf = buf[2 + msg_len:]
                    frame_count += 1
                    state["cdc_to_udp_frames"] += 1
                    state["cdc_to_udp_bytes"] += len(frame)
                    first_bytes = frame[:8].hex() if len(frame) >= 8 else frame.hex()
                    print(
                        f"{ts()} {log_prefix} CDC->UDP: frame#{frame_count} {len(frame)}B hex={first_bytes}",
                        file=sys.stderr,
                    )
                    send_sock.sendto(frame, state["udp_peer"])
            else:
                if time.time() - last_alive >= 10:
                    print(f"{ts()} {log_prefix} alive, buf={len(buf)}B, frames={frame_count}, rx={ser.rx_bytes}B", file=sys.stderr)
                    last_alive = time.time()
                time.sleep(0.001)
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"{ts()} {log_prefix} disconnected: {e}", file=sys.stderr)
            break
        except Exception as e:
            print(f"{ts()} {log_prefix} error: {e}", file=sys.stderr)
            break


def udp_to_serial(ser, udp_sock, log_prefix, state):
    """Receive raw UDP from FIPS, wrap in length prefix, forward to serial/TCP."""
    frame_count = 0
    last_alive = time.time()
    while not state["stop"]:
        try:
            udp_sock.settimeout(30)
            data, addr = udp_sock.recvfrom(65535)
            frame_count += 1
            state["udp_to_cdc_frames"] += 1
            state["udp_to_cdc_bytes"] += len(data)
            hdr = struct.pack("<H", len(data))
            ser.write(hdr + data)
            ser.flush()
            first_bytes = data[:8].hex() if len(data) >= 8 else data.hex()
            print(
                f"{ts()} {log_prefix} UDP->CDC: frame#{frame_count} {len(data)}B from {addr} hex={first_bytes}",
                file=sys.stderr,
            )
        except socket.timeout:
            if time.time() - last_alive >= 30:
                print(f"{ts()} {log_prefix} alive (timeout), frames={frame_count}, tx={ser.tx_bytes}B", file=sys.stderr)
                last_alive = time.time()
            continue
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"{ts()} {log_prefix} CDC disconnected: {e}", file=sys.stderr)
            break
        except Exception as e:
            print(f"{ts()} {log_prefix} error: {e}", file=sys.stderr)
            break
        except Exception as e:
            print(f"{ts()} {log_prefix} error: {e}", file=sys.stderr)
            break


def main():
    parser = argparse.ArgumentParser(description="FIPS CDC<->UDP bridge (runs on VPS)")
    parser.add_argument("--serial", default=None, help="Serial port (for direct serial mode)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--tcp", default=None, help="TCP address (host:port) for tunnel mode")
    parser.add_argument("--udp-host", default="127.0.0.1", help="FIPS UDP host (default: 127.0.0.1)")
    parser.add_argument("--udp-port", type=int, default=2121, help="FIPS UDP port (default: 2121)")
    parser.add_argument("--bind", default="0.0.0.0", help="Local UDP bind addr")
    parser.add_argument("--local-port", type=int, default=31337, help="Local UDP port (default: 31337)")
    args = parser.parse_args()

    state = {
        "stop": False,
        "udp_peer": (args.udp_host, args.udp_port),
        "cdc_to_udp_frames": 0,
        "cdc_to_udp_bytes": 0,
        "udp_to_cdc_frames": 0,
        "udp_to_cdc_bytes": 0,
    }

    src = f"tcp:{args.tcp}" if args.tcp else args.serial
    print(f"{ts()} Bridge: {src} <-> {args.udp_host}:{args.udp_port}", file=sys.stderr)

    ser = open_port(args)
    print(f"{ts()} Connected: {src}", file=sys.stderr)

    reconnect_count = 0
    while True:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            udp_sock.bind((args.bind, args.local_port))
        except OSError as e:
            print(f"{ts()} ERROR: UDP bind failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"{ts()} UDP bound on {args.bind}:{args.local_port} (attempt #{reconnect_count})", file=sys.stderr)

        state["stop"] = False
        t1 = threading.Thread(target=serial_to_udp, args=(ser, udp_sock, ">>", state), daemon=True)
        t2 = threading.Thread(target=udp_to_serial, args=(ser, udp_sock, "<<", state), daemon=True)
        t1.start()
        t2.start()

        try:
            while t1.is_alive() and t2.is_alive():
                t1.join(timeout=30)
        except KeyboardInterrupt:
            print(f"\n{ts()} Interrupted", file=sys.stderr)
            state["stop"] = True
            break

        state["stop"] = True
        t1.join(timeout=5)
        t2.join(timeout=35)

        print(f"{ts()} Thread exited (t1_alive={t1.is_alive()}, t2_alive={t2.is_alive()})", file=sys.stderr)
        reconnect_count += 1
        udp_sock.close()
        time.sleep(0.5)
        try:
            ser.close()
        except Exception:
            pass
        ser = open_port(args)
        print(f"{ts()} Reconnected: {src} (attempt #{reconnect_count})", file=sys.stderr)

    print(
        f"{ts()} Summary: CDC->UDP {state['cdc_to_udp_frames']} frames {state['cdc_to_udp_bytes']}B"
        f" | UDP->CDC {state['udp_to_cdc_frames']} frames {state['udp_to_cdc_bytes']}B",
        file=sys.stderr,
    )
    ser.close()
    try:
        udp_sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
