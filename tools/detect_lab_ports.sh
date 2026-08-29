#!/bin/bash
# Detect all known lab-bench boards by VID:PID and print stable identifiers.
# Ports move between reboots — ALWAYS detect, never hardcode tty numbers.
# NOTE: /dev/ttyUSB0 (Hades2001 M5stack) belongs to another project — do not
# flash or open it. The two M5 Atoms appear as "M5 Serial Converter" (FTDI).
echo "=== ESP32-S3 native USB-JTAG (303a:1001) ==="
for d in /dev/serial/by-id/*Espressif*; do
    [ -e "$d" ] && echo "  $d -> $(readlink -f $d)"
done
echo "=== CYD (CH340 1a86:7523 — no USB serial, pin by path) ==="
for p in /dev/ttyUSB*; do
    [ -e "$p" ] || continue
    vid=$(cat /sys/class/tty/$(basename $p)/device/../uevent 2>/dev/null | grep PRODUCT | cut -d= -f2)
    [ "$vid" = "1a86/7523" ] && echo "  CYD on $p ($(ls /dev/serial/by-path/ | grep -i "$(basename $p)" || echo 'by-path lookup'))"
done
echo "=== M5 Atoms (FTDI 0403:6001, have serials) ==="
for d in /dev/serial/by-id/*M5STACK*; do
    [ -e "$d" ] && echo "  $d -> $(readlink -f $d)"
done
echo "=== M5 Stack (OFF-LIMITS, other project) ==="
for d in /dev/serial/by-id/*Hades2001*; do
    [ -e "$d" ] && echo "  $d -> $(readlink -f $d)  [DO NOT TOUCH]"
done
