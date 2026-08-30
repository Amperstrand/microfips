# esp-radio 1.0-beta migration — WIP port map

Branch: `esp-radio-1.0-beta`. Target set (all coherent, verified by resolution):
- esp-hal family patched to git rev `7af0919e` (Aug 19; the exact rev trouble
  v0.8.0's esp32 examples pin — the ONLY esp-radio state with native
  `Transport for BleConnector`, bridging bt-hci 0.9/0.10 via bt-hci-transport)
- esp-radio 1.0.0-beta.0 line + `unstable` feature (needed: with_max_connections)
- trouble-host 0.8.0 + bt-hci 0.10 (crates.io)
- NOTE: esp-radio beta.0 *published* pins bt-hci 0.8 — the patch rev is required.

## DONE (builds clean, esp32 target)
- l2cap: BleHciTransport glue DELETED (~70 lines: custom HciTransport impl,
  UnsafeCell, BleHciError) — `ExternalController::new(connector)` direct,
  native Transport. HostResources generic order swapped.
- wifi: `wifi::new()` → `WifiController::new()`, `interfaces.station` →
  `Interface::station()`, `Runner<'static, Interface>` lost its lifetime arg.
  #91 power-save `with_initial_config` pattern SURVIVES the refactor.
- all bins: `SoftwareInterruptControl::new(SW_INTERRUPT)` +
  `sw_ints.software_interrupt0` → `peripherals.FROM_CPU_INTR0`.

## REMAINING (esp32s3 esp-now build enumerates them)
1. `usb_serial_jtag` module unresolved on s3 at this rev — the
   `usb_serial_jtag_driver_supported` cfg isn't being emitted; suspect a
   feature or the patch set missing `esp-metadata-generated`. Files:
   usb_transport.rs, espnow_gateway.rs.
2. `run_tasks.rs:282` — its own `esp_radio::wifi::new()` call (hybrid path).
3. esp-now: `interfaces.esp_now` → `controller.esp_now()` (BORROWS the
   controller — restructure: controller in a StaticCell or task-owned).
   Files: esp_now_transport.rs, espnow_gateway.rs, espnow_wifi_gateway.rs,
   hybrid_transport.rs.
4. relay_ap.rs: AP+STA via `Interface::access_point()` + `station()`
   singletons; `with_max_connections` needs esp-radio `unstable` (added).
5. ble_host.rs (GATT): same ExternalController simplification as l2cap.

## TEST MATRIX (before landing)
All esp32 variants (uart/ble/l2cap/wifi/espnow bins), all esp32s3 variants
(+ relay-ap/relay-ap-peer/hybrid), esp32c3, host suites, bench: atom-b l2cap
probe→exchange→IK→heartbeats vs lab daemon, S3 wifi+mdns, hybrid switch,
relay chain. Then drop the patch block when esp-radio beta.1/1.0 publishes.
