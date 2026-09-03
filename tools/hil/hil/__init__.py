"""microfips HIL framework — the bolty-rs pattern over the shared bench.

Layers (issue #191):
    hil.devices   — device registry adapter (fips-lab boards.toml is the
                    single safety contract; no duplicate registry file)
    hil.preflight — composable, severity-aware bench checks
    hil.roles     — per-board firmware-role ledger + restore-always guard

Protocol-level scenarios stay in fips-lab (tests/ + scenarios/); this
package owns deployment-level health: build → flash → boot evidence,
registry-guarded, with a run ledger and Allure wiring.
"""

from hil.devices import Board, BoardError, DeviceRegistry
from hil.roles import board_role, role_ledger_path

__all__ = ["Board", "BoardError", "DeviceRegistry", "board_role", "role_ledger_path"]
