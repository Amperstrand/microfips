# ESP8266 WiFi-UDP-Serial Bridge

Minimal firmware for ESP8266 that bridges serial data to FIPS via WiFi UDP.

## Use Case

Connect any serial device (STM32, Arduino, etc.) to a FIPS daemon over WiFi
without a host computer. The ESP8266 acts as a WiFi modem:

```
MCU → Serial → ESP8266 → WiFi → UDP → FIPS daemon
```

## Build

```bash
cd esp8266-wifi-bridge
pio run
```

## Flash

```bash
esptool --port /dev/ttyUSB0 --before default-reset -b 115200 \
  write-flash 0x00000 .pio/build/esp01_1m/firmware.bin
```

## Configure

Edit `src/main.cpp`:
- `WIFI_SSID` — WiFi network name
- `WIFI_PASS` — WiFi password
- `FIPS_HOST` — FIPS daemon IP
- `FIPS_PORT` — FIPS UDP port (default: 2121)

## Serial Protocol

Frames use 2-byte big-endian length prefix:
```
[0x00][0x72][114 bytes of Noise IK MSG1]
```

The ESP8266 reads the length, reads the payload, and forwards via UDP to FIPS.
Responses from FIPS are forwarded back to serial with the same framing.

## Hardware

- ESP8266EX (any variant: ESP-01, NodeMCU, Wemos D1)
- CH340/CP2102 USB-serial converter
- 4MB flash minimum
- ~50KB free heap after WiFi init

## Why Not Full microfips?

ESP8266 cannot run the full Rust microfips stack:
- No Rust WiFi driver (esp-radio = ESP32 family only)
- Insufficient RAM (~50KB vs ~100KB needed)
- No Embassy/esp-hal support

This bridge approach gives ESP8266 devices WiFi connectivity to FIPS
without requiring a full protocol implementation on the ESP8266 itself.

## Verified Test Results (2026-07-18)

### Full FIPS Handshake Through ESP8266 WiFi Relay

```
microfips-sim → UDP → ESP8266 (192.168.13.222:2121) → WiFi → FIPS (192.168.13.221:2121)
```

| Metric | Result |
|--------|--------|
| Noise IK MSG1→MSG2 | ✅ Handshake complete |
| FSP session setup | ✅ Exchanged |
| Sustained heartbeats | ✅ 84 packets, 20+ seconds |
| Total data relayed | 8,653 bytes through ESP8266 |
| Packet loss | 0.00% (zero loss) |
| Goodput | 66 Kbps |
| ETX | 1.0 (perfect) |
| FIPS peer transport_addr | 192.168.13.222 (ESP8266's IP) |
| FIPS peer connectivity | connected |

### ESP8266 Resource Usage

| Resource | Value |
|----------|-------|
| Flash | 278KB (of 4MB) |
| RAM | 50KB free (of 80KB) |
| CPU | 80 MHz |
| WiFi RSSI | -70 dBm |
| Stability | No crashes, no disconnects |

### Hardware

- ESP8266EX, 4MB flash, CH340 USB-serial
- MAC: 5c:cf:7f:a4:87:5f
- IP: 192.168.13.222 (via WiFi DHCP)
