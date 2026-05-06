import json
import os
import subprocess
import time

import pytest


@pytest.fixture(scope="session")
def serial_port(target):
    """Get the /dev/ttyXXX path discovered by labgrid's udev matching."""
    from labgrid.resource import USBSerialPort
    resource = target.get_resource(USBSerialPort)
    return resource.port


@pytest.fixture(scope="session")
def pyserial(serial_port):
    """Open a raw pyserial connection on the labgrid-discovered port."""
    import serial as pyserial
    ser = pyserial.Serial(serial_port, 115200, timeout=2)
    yield ser
    ser.close()


@pytest.fixture(scope="session")
def fips_service():
    result = subprocess.run(["pgrep", "-x", "fips"], capture_output=True, text=True)
    was_running = result.returncode == 0

    if not was_running:
        subprocess.run(["sudo", "systemctl", "start", "fips"], check=True)
        time.sleep(3)

    yield

    if not was_running:
        subprocess.run(["sudo", "systemctl", "stop", "fips"], check=False)


@pytest.fixture(scope="session")
def fips_service_running():
    subprocess.run(["sudo", "systemctl", "start", "fips"], check=True)
    time.sleep(3)
    yield


@pytest.fixture(scope="session")
def ssh_driver(target):
    from labgrid.driver import SSHDriver
    try:
        return target.get_driver(SSHDriver)
    except Exception:
        pytest.skip("No SSHDriver in target config")


class FIPSHost:
    """Control the local FIPS daemon via systemctl."""

    def __init__(self, ssh=None):
        self._ssh = ssh

    def _run(self, cmd):
        if self._ssh:
            stdout_lines, stderr_lines, exit_code = self._ssh.run(cmd)
            return "\n".join(stdout_lines)
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return r.stdout

    def start(self):
        self._run("sudo systemctl start fips")
        time.sleep(3)

    def stop(self):
        self._run("sudo systemctl stop fips")

    def restart(self):
        self._run("sudo systemctl restart fips")
        time.sleep(3)

    def is_active(self):
        output = self._run("systemctl is-active fips")
        return "active" in output

    def logs(self, lines=20, since=None):
        cmd = f"sudo journalctl -u fips --no-pager -n {lines}"
        if since:
            cmd += f' --since "{since}"'
        return self._run(cmd)

    def write_config(self, config_yaml):
        self._run(f"echo '{config_yaml}' | sudo tee /etc/fips/fips.yaml > /dev/null")

    def start_with_config(self, config_yaml):
        self.stop()
        time.sleep(1)
        self.write_config(config_yaml)
        self.start()

    def has_transport(self, transport_name):
        output = self._run("cat /etc/fips/fips.yaml")
        return transport_name in output


@pytest.fixture(scope="session")
def fips_host(ssh_driver):
    return FIPSHost(ssh=ssh_driver)


class SerialControl:
    def __init__(self, serial_port):
        self.serial = serial_port

    def send_command(self, command, timeout=5):
        self.serial.reset_input_buffer()
        self.serial.write(f"{command}\n".encode())
        time.sleep(0.5)
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.serial.readline().decode(errors="replace").strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return None

    def show_status(self):
        return self.send_command("show_status")

    def show_stats(self):
        return self.send_command("show_stats")

    def wait_for_log(self, pattern, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.serial.readline().decode(errors="replace").strip()
            if pattern in line:
                return line
        return None

    def drain(self, duration=2):
        deadline = time.time() + duration
        while time.time() < deadline:
            self.serial.readline()


@pytest.fixture(scope="session")
def control(pyserial):
    return SerialControl(pyserial)


def flash_stm32(binary=None):
    project_root = "/home/ubuntu/src2/microfips"
    if binary is None:
        binary = f"{project_root}/target/thumbv7em-none-eabi/release/microfips"
    subprocess.run(
        ["arm-none-eabi-objcopy", "-O", "binary", binary, "/tmp/microfips.bin"],
        check=True,
    )
    subprocess.run(
        ["st-flash", "--connect-under-reset", "write", "/tmp/microfips.bin", "0x08000000"],
        check=True,
    )
    subprocess.run(["rm", "-f", "/tmp/microfips.bin"], check=False)


def find_mcu_cdc_port(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in sorted(os.listdir("/dev")):
            if not p.startswith("ttyACM"):
                continue
            try:
                with open(f"/sys/class/tty/{p}/device/../uevent") as f:
                    for line in f:
                        if line.strip().startswith("PRODUCT="):
                            vid_pid = line.strip().split("=", 1)[1]
                            if vid_pid == "c0de/cafe/10":
                                return f"/dev/{p}"
            except FileNotFoundError:
                continue
        time.sleep(1)
    return None


def flash_esp32(variant="l2cap", port=None):
    project_root = "/home/ubuntu/src2/microfips"
    binaries = {
        "uart": "target/xtensa-esp32-none-elf/release/microfips-esp32",
        "ble": "target/xtensa-esp32-none-elf/release/microfips-esp32-ble",
        "l2cap": "target/xtensa-esp32-none-elf/release/microfips-esp32-l2cap",
        "wifi": "target/xtensa-esp32-none-elf/release/microfips-esp32-wifi",
    }
    binary = f"{project_root}/{binaries[variant]}"

    if port is None:
        for p in sorted(os.listdir("/dev")):
            if not p.startswith("ttyUSB"):
                continue
            try:
                with open(f"/sys/class/tty/{p}/device/../uevent") as f:
                    for line in f:
                        if line.strip().startswith("PRODUCT=") and "10c4/ea60" in line:
                            port = f"/dev/{p}"
                            break
            except FileNotFoundError:
                continue

    if port is None:
        pytest.skip("ESP32-D0WD not found")

    subprocess.run(["fuser", "-k", port], capture_output=True)
    time.sleep(1)
    subprocess.run(
        ["bash", "-c", f". /home/ubuntu/export-esp.sh && RUSTUP_TOOLCHAIN=esp espflash flash -p {port} --chip esp32 {binary}"],
        check=True,
    )
