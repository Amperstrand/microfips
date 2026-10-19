/* esp-wifi-sys-esp32 0.3.0 (the IDF 6.1 BTDM blob shipped with esp-radio
 * 1.0.0-beta.1) references three Classic BT scan/page callbacks that live
 * in the ESP32 ROM, but esp-rom-sys 0.1.5's ROM linker scripts predate the
 * blob and do not PROVIDE them — no ESP32 BLE image links without this
 * overlay (upstream esp-rs/esp-hal#6408; fixed on main by 6fedea34e224,
 * unreleased in esp-rom-sys at the time of writing).
 *
 * Addresses are the ROM locations from upstream main's esp32.rom.ld.
 * REMOVE this overlay once esp-rom-sys ships the fix (>= 0.1.6). */
PROVIDE ( ld_iscan_evt_start_cbk = 0x4003b58c );
PROVIDE ( ld_page_evt_start_cbk = 0x4003cf40 );
PROVIDE ( ld_pscan_evt_start_cbk = 0x4003e924 );
