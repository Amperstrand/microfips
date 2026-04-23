# BLE L2CAP Capture, Decryption, and Wireshark Inspection

How to capture BLE traffic between an ESP32 and a Linux FIPS node, extract transport keys, decrypt the Noise-encrypted payload, and inspect everything in Wireshark.

This covers the L2CAP CoC path on PSM 133. For UDP capture, use `tools/capture_fips.sh` instead.

## 1. Capturing BLE Traffic with btmon (Linux only)

btmon is part of BlueZ. It captures all HCI traffic from the Bluetooth controller, including L2CAP CoC frames.

Prerequisites:

```
sudo apt install bluez
```

Start the capture before the FIPS daemon initiates or accepts a BLE connection. The handshake exchange (MSG1/MSG2) must be in the capture for the dissector to identify the session.

```
sudo btmon -w /tmp/fips-ble-capture.btsnoop
```

Then start (or restart) the FIPS daemon in another terminal:

```
sudo systemctl restart fips
# or
fips -c /etc/fips/fips.yaml
```

btmon writes btsnoop format, which Wireshark opens natively. The FMP frames ride inside L2CAP CoC on PSM 0x0085 (decimal 133).

Tips:

- In Wireshark, filter by `btatt` or the L2CAP CID to isolate FIPS traffic from other BLE activity.
- Without the FIPS dissector installed, you will see raw L2CAP data. With it (see Section 5), you get decoded FMP framing.
- Stop btmon with Ctrl-C when done. The btsnoop file is complete and ready for offline analysis.

## 2. Logging Transport Keys with the FIPS Diagnostic Feature

The FIPS daemon can print Noise transport keys to stderr after each handshake completes. This is gated behind the `diagnostic` feature flag.

Build FIPS with diagnostic output:

```
cargo build --release --features "ble diagnostic"
```

On Linux nodes that also need the benchmark feature:

```
cargo build --release --features "ble benchmark diagnostic"
```

When a Noise IK handshake completes, FIPS prints a JSON line to stderr:

```json
{"fips_diagnostic":"transport_keys","role":"initiator","remote_static":"...","k_send":"...","k_recv":"...","handshake_hash":"..."}
```

Capture keys to a file by redirecting stderr:

```
fips -c /etc/fips/fips.yaml 2>/tmp/fips-keys.jsonl
```

If FIPS runs under systemd:

```
journalctl -u fips -f | grep fips_diagnostic > /tmp/fips-keys.jsonl
```

Each handshake produces one JSON line. The file accumulates keys from multiple sessions. You only need keys from one side of the connection to decrypt both directions.

Keys are ephemeral. A new handshake generates new transport keys. If the daemon restarts or the link drops and re-establishes, capture the new keys.

> **Security warning:** Transport keys decrypt all traffic in the captured session. Never share key files from production nodes. Delete key files after analysis.

## 3. Decrypting Captures with fips-decrypt

fips-decrypt reads pcap or btsnoop captures, identifies FMP frames, and decrypts ESTABLISHED frames using transport keys.

### With a key file from diagnostic output

```
fips-decrypt --keys-file /tmp/fips-keys.jsonl /tmp/fips-ble-capture.btsnoop
```

Write decrypted output as a pcap for Wireshark:

```
fips-decrypt --keys-file /tmp/fips-keys.jsonl --output decrypted.pcap /tmp/fips-ble-capture.btsnoop
```

Verbose mode prints raw frame bytes alongside decoded fields:

```
fips-decrypt --keys-file /tmp/fips-keys.jsonl --verbose /tmp/fips-ble-capture.btsnoop
```

Filter by FMP phase:

```
# ESTABLISHED frames only (encrypted payload)
fips-decrypt --keys-file /tmp/fips-keys.jsonl --filter 0 /tmp/fips-ble-capture.btsnoop

# MSG1 only (handshake initiator)
fips-decrypt --keys-file /tmp/fips-keys.jsonl --filter 1 /tmp/fips-ble-capture.btsnoop
```

### With dev/test node presets

For nodes using the deterministic pattern keys (sim-a, sim-b, stm32, esp32), fips-decrypt can derive transport keys automatically:

```
fips-decrypt --node sim-a /tmp/capture.pcap
```

This tries all pairwise combinations between the named node and the other dev nodes.

### With manual key specification

```
fips-decrypt --keys "aabb...:ccdd..." /tmp/capture.pcap
```

The format is `k_send_hex:k_recv_hex`, each 64 hex characters (32 bytes). Separate multiple pairs with spaces.

## 4. Wireshark Inspection

### Raw btmon captures (encrypted)

```
wireshark /tmp/fips-ble-capture.btsnoop
```

Wireshark has built-in dissectors for btsnoop, HCI, and L2CAP. You will see the full BLE stack: HCI commands/events, L2CAP signaling, and L2CAP CoC data.

With the FIPS dissector installed (Section 5), FMP framing is decoded inside the L2CAP payload. You will see:

- MSG1 (IK handshake initiator, cleartext)
- MSG2 (IK handshake responder, cleartext)
- ESTABLISHED (encrypted ciphertext, with counter and receiver index visible)

Without the dissector, ESTABLISHED frames appear as opaque L2CAP data.

### Decrypted pcap files

```
wireshark decrypted.pcap
```

Decrypted output from fips-decrypt wraps FMP frames in fake UDP packets so Wireshark can parse them. Install the FIPS dissector (Section 5) to see decoded FMP fields.

Decrypted ESTABLISHED frames show:

| Field | Description |
|-------|-------------|
| `msg_type` | HEARTBEAT (0x00), PING (0x01), PONG (0x02), SESSION_DATAGRAM (0x10) |
| `timestamp` | 4-byte LE epoch |
| `payload` | Inner cleartext payload bytes |

### Display filters

```
fips.phase == 0    # ESTABLISHED frames only
fips.phase == 1    # MSG1 (IK handshake initiator)
fips.phase == 2    # MSG2 (IK handshake responder)
fips.counter       # Transport counter value
```

## 5. Installing the FMP Dissector in Wireshark

The Lua dissector at `tools/fips_dissector.lua` decodes FMP frames inside both UDP packets and L2CAP payloads.

### Linux

```
mkdir -p ~/.local/lib/wireshark/plugins
cp tools/fips_dissector.lua ~/.local/lib/wireshark/plugins/
```

System-wide:

```
sudo cp tools/fips_dissector.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/
```

### macOS

```
mkdir -p ~/.local/lib/wireshark/plugins
cp tools/fips_dissector.lua ~/.local/lib/wireshark/plugins/
```

### Verify installation

```
tshark -X lua_script:tools/fips_dissector.lua -r capture.pcap -V 2>&1 | grep FIPS
```

If the dissector is loaded, you will see FMP frame details in the protocol tree.

### One-off use (no install)

```
wireshark -X lua_script:tools/fips_dissector.lua capture.pcap
tshark -X lua_script:tools/fips_dissector.lua -r capture.pcap
```
