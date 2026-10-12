# Console channels vs. frame channels (ESP32 family)

Rule for this repo: **an image may install the log backend only if esp-println's output
channel is a different peripheral from the one that carries its FIPS frames.**
`microfips_esp_transport::logger::init()` installs a backend that formats every
`log::info!`/`log::error!` record through `esp_println::println!`; if that printer shares the
frame channel, log text lands *inside* the byte stream the peer is parsing.

Per-image answer (measured, see "Verifying an image" below):

| Image | Frames leave on | esp-println channel | `logger::init()`? |
|---|---|---|---|
| `microfips-esp32s3-uart` | UART0 (GPIO43 TX / GPIO44 RX) | USB-Serial-JTAG FIFO (`0x6003_8000`), via `esp-println/jtag-serial` | **yes** — first statement of `run_uart_node` |
| `microfips-esp32s3-usb` | the USB-Serial-JTAG peripheral itself | the same FIFO | **no, by design** |
| `microfips-esp32s3` (wifi) / `-espnow` / `-relay-ap` / `-mdns-spike` | Wi-Fi/UDP, ESP-NOW, or mDNS | USB-Serial-JTAG FIFO | yes (through `run_tasks`, `relay_ap`, the spike's `main`) |
| `microfips-esp32s3-espnow-gw` (USB-bridged gateway) | USB serial to the host bridge | the same FIFO | **no, by design** — measured: `logger::init` mentions 0 and backend symbols 0 (the backend is not linked, not merely uncalled; `heap::init` mentions 6, so the grep is live on that ELF); log text would land in the frame stream, and the bridge's length-prefix resync skips ROM boot text and panics, not interleaved log lines |
| `microfips-esp32c3-uart` | UART0 | USB-Serial-JTAG FIFO | **yes** |
| `microfips-esp32c3-usb` | the USB-Serial-JTAG peripheral itself | the same FIFO | **no, by design** (that image also uses `panic_blink!`, not `panic_blink_print!`) |
| `microfips-esp32c3-wifi` / `-esp-now` | Wi-Fi/UDP, ESP-NOW | USB-Serial-JTAG FIFO | yes (through `run_tasks`) |
| `microfips-esp32` (uart) | UART0 (GPIO1 TX / GPIO3 RX) | **UART0** — ROM `uart_tx_one_char` (`0x4000_9200`) | **no, by design** (see below) |
| `microfips-esp32-wifi` / `-espnow` / `-espnow-wifi-gw` | Wi-Fi/UDP, ESP-NOW | UART0 | yes (through `run_tasks` / `espnow_wifi_gateway`) |

## Where the channel is selected

`crates/microfips-esp-transport/Cargo.toml`: the `esp32s3` and `esp32c3` features select
`esp-println/jtag-serial`; the `esp32` feature selects `esp-println/auto`. In esp-println
0.18.0 (the workspace pin) `auto` resolves to

* the USB-Serial-JTAG printer on chips that have that peripheral (`src/lib.rs:159-198`), and
* `uart_printer` on chips that do not — the `auto_printer` arm documented as *"models that
  only have UART"* (`src/lib.rs:227-229`), which for `esp32` pushes every byte through the
  ESP32 ROM routine `uart_tx_one_char` (`src/lib.rs:363-380`, address literal at `:366`).

(The S3's own printer is `serial_jtag_printer` and writes the FIFO at `0x6003_8000`,
`src/lib.rs:272`; the C3's at `0x6004_3000`, `:252`.)

That is why the classic **ESP32 `uart` image stays console-free**: there is no USB-Serial-JTAG
peripheral on ESP32-D0WD, so the only available printer is UART0 — the very peripheral whose
TX pin (GPIO1) carries the FIPS frames. Installing a backend there would interleave log text
into the frame stream. The chip's `wifi`/`esp-now` images are unaffected: their transport is
UDP over Wi-Fi (or ESP-NOW), so UART0 is a free console and they log as usual.

On the C3 the install is `log`'s racy variant (`set_logger_racy` / `set_max_level_racy`),
because `riscv32imc-unknown-none-elf` has no compare-and-swap; on the S3 and ESP32 targets
pointer-width atomics exist and the ordinary `log::set_logger` path is compiled. That split
lives in `crates/microfips-esp-transport/src/logger.rs`.

## Verifying an image (link/compile-time, no board needed)

```sh
source ~/export-esp.sh
# The GNU xtensa binutils (inside the esp rust toolchain) decode `entry`/`callx8`.
# llvm-nm/llvm-objdump (rustup component add llvm-tools-preview) work too, but they
# print those xtensa opcodes as <unknown>, so read l32r/callx8 pairs instead.
NM=${NM:-xtensa-esp-elf-nm}
OD=${OD:-xtensa-esp-elf-objdump}
cargo +esp build -p microfips-esp32s3 --release --target xtensa-esp32s3-none-elf \
  -Zbuild-std=core,alloc --no-default-features --bin microfips-esp32s3-uart
ELF=target/xtensa-esp32s3-none-elf/release/microfips-esp32s3-uart

# 1. which backend symbols are linked (expect logger::init + log::set_logger on S3,
#    and *no* _racy symbols: those are the riscv32imc path)
"$NM" -C "$ELF" | grep -E 'esp_transport::logger|set_logger'

# 2. reachability: the first call in the entry body must be logger::init, heap::init
#    second. In release builds the async entry is INLINED into the embassy main-task
#    poll, so grep the whole disassembly for the call sites and compare their addresses
#    (a debug build keeps a separate `run_uart_node::{closure#0}` symbol):
"$OD" -d --demangle "$ELF" | grep -nE 'microfips_esp_transport::(logger|heap)::init>'

# 3. which printer esp-println linked (S3: 0x6003_8000 USB-Serial-JTAG FIFO;
#    ESP32: 0x4000_9200 ROM uart_tx_one_char). Neither address is a symbol: each is
#    *materialized via an l32r instruction that references a literal-pool entry*, so
#    this grep hits the pool rather than a printer function — either the annotated load
#    target, e.g.
#    `l32r a13, 420110dc <...> (60038000 <_rtc_slow_bss_end+...>)`, or, where objdump
#    decodes the pool word itself as an instruction, a raw data line such as
#    `420110d8: 60038000ffff3caf { excw; excw }`. A hit therefore means "this
#    literal-pool entry is somewhere in the image", which is the whole question here.
"$OD" -d --demangle "$ELF" | grep -E '6003.?8000|4000.?9200'
```

Re-measured with those three greps on the tree of card `balloon/t_ceae8045`
(`logger::init` mentions / backend symbols): `microfips-esp32s3-uart` 3/6, `-usb` 0/0,
`-espnow-gw` 0/0 and the wifi image `microfips-esp32s3` 3/6. The `-espnow-gw` row is the
one that used to be asserted rather than measured; `heap::init` mentions are quoted next to
it because a `0` from a grep that matches nothing anywhere proves nothing (that image
reports 6).

The nm/objdump transcript behind this doc belongs to kanban cards `balloon/t_fb69067d`
(artifacts: `evidence/ab_link.log`, `evidence/esp32_uart_collision.log`,
`evidence/builds.log`) and `balloon/t_ceae8045` (artifacts: `evidence/builds.log`,
`evidence/espnow_gw_measure.log` — shell scripts and logs, kept with the cards rather than
in-repo).

## Guarding the silent half of the rule

The install half is a call you can read in the source; the silence half is the *absence* of
a call, and Rust cannot assert an absence at compile time — `compile_error!` can be gated on
a cfg or a const-evaluable condition, but not on "this body does not call X", and there is
no compile-time "logger already initialised" state to gate on. So the panic-on-double-install
argument in the entry points (see `logger.rs`) stays an argument, and the absence itself is
checked from the source text instead: `scripts/check-console-policy.sh` declares every entry
point `install` / `install-early` / `silent` and exits non-zero if

* a `logger::init()` call appears in a body declared `silent` (`run_usb_node` on the S3 and
  the C3, the classic-ESP32 `run_uart_node`, `espnow_gateway::run_espnow_gateway`),
* the `uart` install is no longer the first thing its body does,
* a `logger::init()` call appears in a *file* that is not in the script's census — which is
  what catches a brand-new image that installs the backend without being declared.

Both CI pipelines run it (`Lint & Format` in `.github/workflows/ci.yml`, `host-tests` in
`.ngit/act/workflows/rust-test.yml`); it needs no toolchain and no build. That is what makes
these comments more than comments — the failure mode it stops is the `uart` entry body being
copy-pasted into `run_usb_node`.
