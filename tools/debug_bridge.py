#!/usr/bin/env python3
"""Debug bridge: hex-dumps VPS responses, sniffs UDP traffic."""

import socket
import struct
import sys
import threading
import time
import subprocess
import serial

udp_peer = ("orangeclaw.dns4sats.xyz", 2121)
frames_rx = []

def udp_listen(sock):
    while True:
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(65535)
            ts = time.strftime("%H:%M:%S")
            hex_pfx = data[: min(12, len(data))].hex()
            sys.stderr.write(f"{ts} UDP rx {len(data)}B from {addr}: {hex_pfx}...\n")
            frames_rx.append((len(data), data, addr))
            if len(data) >= 4:
                v = data[0] >> 4
                p = data[0] & 0xF
                fl = data[1]
                pl = struct.unpack("<H", data[2:4])[0]
                sys.stderr.write(f"  FMP: v={v} phase={p} flags={fl:#04x} payload_len={pl}\n")
                if p == 2 and len(data) >= 12:
                    si = struct.unpack("<I", data[4:8])[0]
                    ri = struct.unpack("<I", data[8:12])[0]
                    sys.stderr.write(f"  MSG2: sender={si:#010x} receiver={ri:#010x} noise={pl-8}B\n")
                elif p == 0 and len(data) >= 16:
                    si = struct.unpack("<I", data[4:8])[0]
                    ri = struct.unpack("<I", data[8:12])[0]
                    ep = struct.unpack("<I", data[12:16])[0]
                    sys.stderr.write(
                        f"  ESTABLISHED: sender={si:#010x} receiver={ri:#010x} epoch={ep} enc={pl-16}B\n"
                    )
        except socket.timeout:
            continue
        except Exception as e:
            sys.stderr.write(f"UDP err: {e}\n")
            break


def main():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", 31337))
    sys.stderr.write("UDP on :31337\n")

    t = threading.Thread(target=udp_listen, args=(udp_sock,), daemon=True)
    t.start()

    time.sleep(1)
    subprocess.run(
        ["probe-rs", "reset", "--chip", "STM32F469NIHx", "--connect-under-reset"],
        capture_output=True,
    )
    sys.stderr.write("MCU reset\n")
    time.sleep(1)

    ser = None
    for _ in range(30):
        try:
            ser = serial.Serial("/dev/ttyACM1", 115200, timeout=0)
            break
        except Exception:
            time.sleep(0.25)

    if ser is None:
        sys.stderr.write("Failed to open serial\n")
        sys.exit(1)

    ser.dtr = True
    sys.stderr.write("Serial opened\n")

    rbuf = b""
    while True:
        try:
            n = ser.read(ser.in_waiting or 1)
            if n:
                rbuf += n
                while len(rbuf) >= 2:
                    ml = struct.unpack("<H", rbuf[:2])[0]
                    if ml == 0 or ml > 1500:
                        rbuf = rbuf[2:]
                        continue
                    if len(rbuf) < 2 + ml:
                        break
                    frame = rbuf[2 : 2 + ml]
                    rbuf = rbuf[2 + ml :]
                    ts = time.strftime("%H:%M:%S")
                    sys.stderr.write(f"{ts} CDC->UDP: {ml}B (FMP v={frame[0]>>4} p={frame[0]&0xF})\n")
                    udp_sock.sendto(frame, udp_peer)
        except serial.SerialException:
            sys.stderr.write("CDC disconnected\n")
            break
        except Exception as e:
            sys.stderr.write(f"Err: {e}\n")
            break

    time.sleep(2)
    ser.close()
    udp_sock.close()

    sys.stderr.write(f"\n=== {len(frames_rx)} frames from VPS ===\n")
    for i, (sz, data, addr) in enumerate(frames_rx[:15]):
        sys.stderr.write(f"  [{i}] {sz}B phase={data[0]&0xF}\n")


if __name__ == "__main__":
    main()
