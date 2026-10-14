# Nostr CI (ngit-ci) for microfips

`.ngit/act/workflows/` is read by the **ngit-ci** coordinator, separately from
`.github/workflows/`, so the GitHub pipeline and this one run side by side. This
workflow ports the host-side jobs of `.github/workflows/ci.yml` (`test`,
`golden-vectors`, `build-host`).

## Where this file lives

`.ngit/` lives on `main` so the workflow runs continuously. `main` is mirrored
to ngit by `gh-ngit-ci-bridge` (which mirrors `main`/`master` only), and ngit-ci
reads `.ngit/act/workflows/` from the pushed ref — so this is the only placement
that produces CI on ordinary pushes.

`felixfelix-bot/microfips` is a fork of `c03rad0r/microfips` which forks
`Amperstrand/microfips`, so a workflow directory on the default branch is one
careless branch cut away from appearing in an upstream pull-request diff. That
risk is **enforced against**, not merely documented: the guard is **versioned
in this repo** at `.githooks/pre-push`, and refuses any push whose outgoing
diff contains `.ngit/` when the destination is `Amperstrand/microfips` or
`c03rad0r/microfips`. Pushes to our own fork and to every ngit/nostr remote are
unaffected. Install it per clone with `scripts/install-git-hooks.sh`, which
sets `core.hooksPath` to the repo-relative `.githooks` (so it also activates
`.githooks/pre-commit`). Caveat worth knowing: git does not run committed hooks
by itself, so **a fresh clone is unprotected until that installer runs**.

## What the workflow runs

| Job | Steps | Why |
|---|---|---|
| `host-tests` | `cargo test -p microfips-core --no-fail-fast`<br>`cargo test -p microfips-core --features std --no-fail-fast -- --test-threads=1`<br>`cargo test -p microfips-protocol --features std --no-fail-fast -- --test-threads=1`<br>`cargo test -p microfips-protocol --features std,noise-xx --no-fail-fast -- --test-threads=1`<br>`cargo test -p microfips-service --no-fail-fast`<br>`cargo test -p microfips-l2cap-test --no-fail-fast`<br>`cargo test -p fips-noise --no-fail-fast`<br>`cargo test -p fips-noise --features noise-xx --no-fail-fast`<br>`cargo test -p fips-fmp --no-fail-fast`<br>`cargo test -p fips-identity --no-fail-fast` | The repo's own host test suites, including the extracted `fips-noise` / `fips-fmp` / `fips-identity` crates and both sides of the `noise-xx` feature gate. `--features std` enables the env-var tests; `--test-threads=1` because they mutate process-global state. |
| `golden-vectors` | in-repo drift gate (`sha256sum` of `crates/microfips-core/tests/golden_vectors.json` vs `specs/fips/golden_vectors.json`), then `cargo test -p microfips-core --test golden_vectors --no-fail-fast` | The vendored FIPS reference must not silently diverge from the copy the tests use. Upstream's own generator and reference branch were deleted on 2026-08-31, so the in-repo copy is the surviving reference — hence a hard gate with no network fetch and nothing that can "skip as unavailable". |
| `build-host` | `cargo build -p microfips-link -p microfips-sim -p microfips-http-test --release` | Proves the host tools still compile. The GitHub job also uploads binaries as artifacts; that half is not ported because nothing consumes them inside ngit-ci. |

Triggers: `push`, `pull_request`, plus `workflow_dispatch` for manual replay.
`runs-on: ubuntu-latest`, 30-minute job timeouts, no `container:`/`services:`,
no job-level `uses:` reusable workflows, no `secrets.`/`GITHUB_TOKEN`, no
`schedule:`. `toolchain: stable` follows upstream's own CI pin — upstream has no
`rust-toolchain.toml`, so the "nightly" pin in the older fork workflow was an
invention and is gone.

## Authorization and how to read results

This deployment uses the `request-required` execution policy, so a **standing
Service Request (kind 9843)** exists for this repo:

- id `3abf21b2ee2d2abd6c4cd98285f7950a3a6cb609ce005b1efe190a49bcaa177e`
- signer `36bdeb23…` (maintainer), coordinator `765cd47b…`
- live coordinate `30617:36bdeb23…:microfips`

Read results with `ngit ci status <commit|pr>` (`ci.state` / `ci.conclusion`),
or read the events directly: kind **9841** = job result, kind **9842** =
workflow result, kind **39842** = progress.

## Measured status of this branch

**First real run on the coordinator: success.** Workflow result (kind 9842)
`12edb9d0ff6e` carries `conclusion=success` for commit `15efdd37`, with three
job results (kind 9841) — `host-tests`, `golden-vectors`, `build-host` — all
`conclusion=success`. Queued 10:02:57Z, started 10:15:29Z, finished 10:23:55Z
(≈21 min wall: 12.5 min queue behind another repo's build, then ≈8.5 min of
work). The coordinator's `w`-tag hash `736a9d66980738aa…` byte-matches the
sha256 of this workflow file, so it ran exactly this file. Log tails in the
result events are truncated (`[log-tail omitted=107059]`), so per-binary test
counts are not quotable from the run itself — the numbers below come from
running the same commands locally.

Every `run:` command below was executed locally on this branch before the
workflow was committed (host: cargo/rustc 1.98.1, `stable`, no cross targets):

| Suite | Result |
|---|---|
| `microfips-core` | **175 passed, 0 failed**, 2 ignored |
| `microfips-core --features std` | **176 passed, 0 failed**, 2 ignored |
| `microfips-protocol --features std` | **154 passed, 0 failed**, 1 ignored |
| `microfips-protocol --features std,noise-xx` | **158 passed, 0 failed**, 1 ignored |
| `microfips-service` | **5 passed, 0 failed** |
| `microfips-l2cap-test` | **50 passed, 0 failed** |
| `fips-noise` / `fips-noise --features noise-xx` | **53 / 53 passed, 0 failed** |
| `fips-fmp` / `fips-identity` | **44 / 12 passed, 0 failed** |
| `golden_vectors` (+ drift gate) | **10 passed, 0 failed**; both copies hash-equal |
| `build-host` | exit 0 |

## Deliberately NOT covered, and why

- **ESP32 / STM32 cross-builds** (`build-firmware`, `build-esp32`,
  `build-firmware-extended`): need the Xtensa (`espup`) and ARM toolchains plus
  `-Zbuild-std`; not available in the coordinator's job image.
- **`noise-compliance`**: upstream's job uses test-count floors and 3×10-round
  consistency loops; it re-runs the same suites the `host-tests` job already
  covers, at ~3× the wall-clock, which an `act` job with a 30-minute cap cannot
  afford.
- **`audit`** (`cargo install cargo-audit` + `cargo audit`): installs a binary
  from the network on every run.
- **`lint`** (`cargo fmt --check`, `cargo clippy -- -D warnings`): valuable, but
  a pre-existing warning anywhere in the workspace fails it; that is a repo
  cleanup, not a CI port.
- **`sim-smoke`** and **`fips-integration`**: the latter needs a live FIPS
  daemon (`orangeclaw.dns4sats.xyz:2121`); the former starts the sim over the
  network. Neither is hermetic.
- **`spec-quotes`**: installs a pinned package from a private git remote at run
  time.
- **Hardware tests** (board-in-the-loop, ESP-NOW benches, relay-AP): need
  physical devices.
- **`cargo nextest run`**: upstream uses it for the protocol suites via
  `taiki-e/install-action@v2`, which downloads a release binary. Plain
  `cargo test` is substituted here, with `--no-fail-fast` so one red target
  cannot hide the suites after it.

## History

This file supersedes an earlier version written against a fork branch that was
**red**: six failing tests (`microfips-core` XK/FSP, `microfips-protocol`,
`microfips-service`, `golden_vectors`) and a `microfips-l2cap-test` that
reported 0 tests. Those numbers were not flakes. The fork's
`microfips-core/src/noise.rs` returned `(k2, k1)` from
`NoiseXkResponder::finalize` where upstream and the fork's own other five
finalize sites return `(k1, k2)` — with callers on both sides destructuring
`(k_recv, k_send)`, the fork's production FSP/protocol session keys were
inverted. None of it exists on this branch, which is based on upstream
`Amperstrand/microfips` `215e62d`.
