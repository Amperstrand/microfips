import time

import pytest

EXPECTED_NODE_ADDR = "0135da2f8acf7b9e3090939432e47684"


def test_esp32_l2cap_boot_and_handshake(control, fips_service):
    """ESP32-D0WD L2CAP: boot, handshake with FIPS, reach steady state."""
    control.drain(duration=5)

    log = control.wait_for_log("steady", timeout=30)
    assert log is not None, "Timed out waiting for 'steady' in ESP32 logs"

    status = control.show_status()
    assert status is not None, "No response from show_status"
    assert status["status"] == "ok", f"show_status returned error: {status}"

    data = status["data"]
    assert data["state"] == "steady", f"Expected state=steady, got {data['state']}"
    assert data["transport_type"] == "ble_l2cap"
    assert data["node_addr"] == EXPECTED_NODE_ADDR
    assert data["uptime_secs"] > 0

    stats = control.show_stats()
    assert stats is not None, "No response from show_stats"
    assert stats["status"] == "ok"

    s = stats["data"]
    assert s["msg1_tx"] >= 1, "No MSG1 sent"
    assert s["msg2_rx"] >= 1, "No MSG2 received (handshake failed)"
    assert s["hb_tx"] >= 1, "No heartbeats sent"
    assert s["l2cap_pubkey_ok"] >= 1, "L2CAP pubkey exchange failed"
    assert s["l2cap_peripheral_connects"] >= 1


def test_esp32_l2cap_heartbeat_sustained(control, fips_service):
    """Verify heartbeat counters increment over time."""
    stats_a = control.show_stats()
    assert stats_a["status"] == "ok"
    hb_a = stats_a["data"]["hb_tx"]

    time.sleep(15)

    stats_b = control.show_stats()
    assert stats_b["status"] == "ok"
    hb_b = stats_b["data"]["hb_tx"]

    assert hb_b > hb_a, (
        f"Heartbeat count did not increase: {hb_a} -> {hb_b} after 15s"
    )


def test_esp32_l2cap_no_errors(control, fips_service):
    """Verify zero error counters in steady state."""
    stats = control.show_stats()
    assert stats["status"] == "ok"
    s = stats["data"]

    assert s["l2cap_zero_frame_disconnects"] == 0
    assert s["l2cap_send_errors"] == 0
    assert s["l2cap_rx_drops"] == 0
