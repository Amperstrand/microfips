"""Tests for ble_udp_bridge.py size guard and frame validation.

Run: python3 -m pytest tools/test_ble_bridge.py -v
"""

import struct

from ble_udp_bridge import BLE_MAX_WRITE, MAX_FRAME_LEN


class TestConstants:
    def test_ble_max_write_matches_firmware(self):
        assert BLE_MAX_WRITE == 252

    def test_max_frame_len(self):
        assert MAX_FRAME_LEN == 1500


class TestFramingBoundaries:
    """Verify the size guard logic: framed = 2-byte header + payload."""

    def test_heartbeat_37b_fits(self):
        payload = bytes(37)
        framed = struct.pack("<H", len(payload)) + payload
        assert len(framed) == 39
        assert len(framed) <= BLE_MAX_WRITE

    def test_msg1_114b_fits(self):
        payload = bytes(114)
        framed = struct.pack("<H", len(payload)) + payload
        assert len(framed) == 116
        assert len(framed) <= BLE_MAX_WRITE

    def test_msg2_69b_fits(self):
        payload = bytes(69)
        framed = struct.pack("<H", len(payload)) + payload
        assert len(framed) == 71
        assert len(framed) <= BLE_MAX_WRITE

    def test_boundary_250_payload_exact(self):
        payload = bytes(250)
        framed = struct.pack("<H", len(payload)) + payload
        assert len(framed) == BLE_MAX_WRITE

    def test_boundary_251_payload_exceeds(self):
        payload = bytes(251)
        framed = struct.pack("<H", len(payload)) + payload
        assert len(framed) == 253
        assert len(framed) > BLE_MAX_WRITE

    def test_large_datagram_500b_exceeds(self):
        payload = bytes(500)
        framed = struct.pack("<H", len(payload)) + payload
        assert len(framed) == 502
        assert len(framed) > BLE_MAX_WRITE

    def test_max_udp_datagram_exceeds(self):
        payload = bytes(65535)
        framed = struct.pack("<H", len(payload)) + payload
        assert len(framed) == 65537
        assert len(framed) > BLE_MAX_WRITE
