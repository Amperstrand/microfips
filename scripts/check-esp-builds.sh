#!/usr/bin/env bash
set -euo pipefail
source ~/export-esp.sh 2>/dev/null || source /home/ubuntu/export-esp.sh
export RUSTUP_TOOLCHAIN=esp

echo "=== ESP32 UART ==="
cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc 2>&1 | tail -1

echo "=== ESP32 BLE ==="
cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features ble 2>&1 | tail -1

echo "=== ESP32 WiFi ==="
WIFI_SSID=ci WIFI_PASSWORD=ci cargo build -p microfips-esp32 --release --target xtensa-esp32-none-elf -Zbuild-std=core,alloc --features wifi 2>&1 | tail -1

echo "=== ESP32-S3 WiFi ==="
WIFI_SSID=ci WIFI_PASSWORD=ci cargo build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf -Zbuild-std=core,alloc 2>&1 | tail -1

echo "=== ESP32-C3 UART ==="
cargo build -p microfips-esp32c3 --release --target riscv32imc-unknown-none-elf -Zbuild-std=core,alloc --no-default-features 2>&1 | tail -1

echo "=== ESP32-C3 WiFi ==="
WIFI_SSID=ci WIFI_PASSWORD=ci cargo build -p microfips-esp32c3 --release --target riscv32imc-unknown-none-elf -Zbuild-std=core,alloc --features wifi 2>&1 | tail -1

echo "=== ALL BUILDS PASSED ==="
