# esp-radio 1.0.0-beta.0 migration (published-crates pivot)

PIVOTED from the git-rev approach: the esp-hal family @7af0919e/main carried
mid-refactor breakage (S3 usb_serial_jtag cfg never emitted; version numbering
in flux) and esp-now's new lifetime model cannot express our hybrid's runtime
wifi+espnow interleaving without an architectural restructure.

**Chosen set (all published crates, hardware-verified):**
esp-radio 1.0.0-beta.0 (unstable feature) + trouble-host 0.7.0 + bt-hci 0.9 +
our existing verified HCI glue. Two bt-hci majors coexist (esp-radio internal
0.8 + ours 0.9) — proven shape from the pre-migration stack.

## Ported (builds + bench-verified)
- wifi: WifiController::new + Interface::station() singleton; #91 power-save
  with_initial_config pattern intact. esp32+s3 wifi green.
- esp-now: controller in StaticCell; esp_now pieces from controller.esp_now();
  espnow_gateway + espnow_wifi_gateway + run_tasks ported. Gateway supervisor
  is now shared-ref monitoring — AUTO-RECONNECT DEFERRED (see below). Both
  espnow bins green on s3.
- l2cap/ble: NO source changes needed on this set (glue stays); atom-b
  bench-verified on beta.0: probe -> exchange -> IK -> heartbeats (166/119).
- hybrid + relay-ap: still unported; hybrid now gated behind an explicit
  `hybrid` feature (bin requires esp-now+wifi+hybrid).

## The hybrid/relay blocker (design gap, not mechanics)
esp-radio 1.0's esp_now() binds EspNow lifetimes to a controller borrow;
pieces escaping into tasks force that borrow 'static, excluding the &mut
connect_async that runtime reconnection needs. Upstream's model assumes
controller mutation happens at init only. Options (tracked in PR):
1. single-task restructure: hybrid's state machine + esp-now relay in ONE
   owning task, pieces non-'static locals;
2. upstream issue proposing a detached-EspNow API (deinit-ordering via Drop
   guards instead of borrow lifetimes);
3. relay-ap: port is mechanical (AP+STA singletons + unstable dtim/max_conn)
   once hybrid's pattern is settled.

## Test matrix status
esp32: l2cap ✓ ble ✓ wifi ✓ (uart: unchanged path, untested this pass)
esp32s3: espnow ✓ espnow-wifi-gw ✓ wifi ✓ l2cap ✓ | hybrid ✗(gated) relay-ap ✗(3 errors, mechanical)
host crates: protocol check ✓
bench: atom-b l2cap full chain ✓ on beta.0
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
   Files: esp_now_transport.