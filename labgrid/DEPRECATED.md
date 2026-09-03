# DEPRECATED — 2026-09-03 (issue #191)

This `labgrid/` harness predates fips-lab and is retired:

- `tests/conftest.py` hardcodes `/home/ubuntu/src2/microfips` (stale path
  — the repo lives at `/home/ubuntu/src/microfips`), so `flash_stm32` /
  `flash_esp32` are broken.
- `config/inventory.yaml` labels USB serial `81528A13B6` as an off-limits
  "M5 Stack". That is stale: per the current safety contract
  (fips-lab `fips_lab/boards.toml`, the AGENTS bench table) `81528A13B6`
  is **atom-a** (flash permitted). The real hazard it tried to flag is
  the SHARED FTDI VID:PID `0403:6001` with the genuinely off-limits
  M5 Stack (Hades2001) — always match the USB serial, never the VID:PID
  alone. The registry entry carries that note.
- The Makefile targets pointing here expected a `.venv` that no longer
  exists.

## Where things live now

| Need | Location |
|------|----------|
| Device registry (flash/observe ops) | `../fips-lab/fips_lab/boards.toml` — single contract |
| Deployment smoke (build+flash+boot) | `../tools/hil/` — `make test-hil` |
| Preflight / status / role ledger | `make hil-preflight`, `make hil-status` |
| Protocol scenarios (L2CAP, rekey, mesh…) | fips-lab `tests/` — `make -C ../fips-lab test-labgrid` |
| Labgrid exporter tokens + place | `../tools/hil/labgrid-exporter.yaml`, `make labgrid-place` |

The flash scripts under `scripts/` remain historically accurate for
manual use; scenario machinery lives in `fips_lab/bench.py`.
