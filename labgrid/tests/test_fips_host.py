import pytest


def test_host_ssh_connectivity(ssh_driver):
    stdout, _, rc = ssh_driver.run("uname -n")
    assert rc == 0
    assert len(stdout) > 0


def test_host_fips_binary_exists(ssh_driver):
    _, _, rc = ssh_driver.run("test -x /usr/local/bin/fips")
    assert rc == 0, "FIPS binary not found at /usr/local/bin/fips"


def test_host_fips_config_exists(ssh_driver):
    _, _, rc = ssh_driver.run("test -f /etc/fips/fips.yaml")
    assert rc == 0, "FIPS config not found at /etc/fips/fips.yaml"


def test_host_fips_service_active(fips_host):
    assert fips_host.is_active(), "FIPS service is not running"


def test_host_fips_config_has_ble(fips_host):
    assert fips_host.has_transport("ble"), "FIPS config missing BLE transport"


def test_host_fips_logs_readable(fips_host):
    logs = fips_host.logs(lines=5)
    assert len(logs) > 0, "FIPS logs are empty"
    assert "fips" in logs.lower()


def test_host_fips_keys_present(ssh_driver):
    _, _, rc = ssh_driver.run("test -f /etc/fips/fips.key")
    assert rc == 0, "FIPS private key not found at /etc/fips/fips.key"

    _, _, rc = ssh_driver.run("test -f /etc/fips/fips.pub")
    assert rc == 0, "FIPS public key not found at /etc/fips/fips.pub"


def test_host_ble_adapter_available(ssh_driver):
    stdout, _, rc = ssh_driver.run("hciconfig hci0")
    assert rc == 0, "BLE adapter hci0 not available"
    assert "UP RUNNING" in "\n".join(stdout)


def test_host_fips_peer_connected(fips_host):
    logs = fips_host.logs(lines=50)
    has_active = "active peer" in logs.lower()
    has_heartbeat = "heartbeat" in logs.lower()
    has_mmp = "MMP link" in logs
    has_connecting = "auto-connecting" in logs.lower() or "scanning started" in logs.lower()
    assert has_active or has_heartbeat or has_mmp or has_connecting, (
        "FIPS shows no peer activity (no active peers, heartbeats, or connection attempts)"
    )
