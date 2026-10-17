//! Host clock seam: every runtime time read routes through here.
//!
//! The Node runtime and FSP handler measure elapsed time (drain windows,
//! rekey cadences, reconnect backoff, activity ages) with
//! `embassy_time::Instant` values. `Instant::now()` reads the linked
//! embassy-time driver — the right default on every image this repo ships
//! (ESP32/STM32 firmware, host tests). But embedders building on the
//! `microfips-client` facade advertise their own `Clock` seam (#235), and
//! a test runner wants a deterministic clock. Both install a provider
//! here; every `Instant::now()` call site in this crate reads
//! [`now_instant()`] instead, so an installed provider drives the real
//! timing paths — drain windows included (#230/#232 logic is fully
//! time-travel-testable, no real sleeps).
//!
//! Scope (deliberate, #235): the seam covers TIME READS. Async waits
//! (`embassy_time::Timer`) still sleep on wall-clock — a virtual-time
//! executor is the remaining M4-scale gap. Stored timestamps stay
//! `embassy_time::Instant`, so the default path is bit-identical with the
//! pre-seam code and custom providers round-trip exactly at millisecond
//! granularity (the unit every cadence in this crate is expressed in).
//!
//! Safety of the process-global install: the provider is a plain
//! `fn() -> u64` pointer (no captures, no lifetimes). Set it once at boot
//! (firmware) or per-test under the suite's single-threaded discipline;
//! swapping it concurrently with reads is not supported.

use core::sync::atomic::{AtomicUsize, Ordering};

use embassy_time::Instant;

/// Milliseconds since an arbitrary epoch — the unit the [`Clock`]-style
/// providers supply and every runtime cadence uses.
///
/// [`Clock`]: microfips_client::Clock
type NowMsFn = fn() -> u64;

/// 0 = the default (embassy-time driver); otherwise the bits of an
/// installed `fn() -> u64` provider.
static PROVIDER: AtomicUsize = AtomicUsize::new(0);

/// Current time in ms via the active provider (embassy default).
pub fn now_ms() -> u64 {
    let raw = PROVIDER.load(Ordering::Acquire);
    if raw == 0 {
        return Instant::now().as_millis();
    }
    // SAFETY: `raw` was stored by `install()` from a valid `fn() -> u64`
    // pointer; a fn pointer round-trips through usize on every target
    // this crate builds for (pointer-sized integers).
    let now: NowMsFn = unsafe { core::mem::transmute(raw) };
    now()
}

/// Current instant via the active provider. The default branch returns
/// `Instant::now()` directly (bit-identical with the pre-seam reads); an
/// installed provider is converted at whole-millisecond granularity.
pub fn now_instant() -> Instant {
    let raw = PROVIDER.load(Ordering::Acquire);
    if raw == 0 {
        return Instant::now();
    }
    // SAFETY: as in [`now_ms`].
    let now: NowMsFn = unsafe { core::mem::transmute(raw) };
    Instant::from_millis(now())
}

/// Install a clock provider. Boot-time (firmware) or single-threaded-test
/// use; last write wins. `reset_default()` restores the embassy driver.
pub fn install(now: NowMsFn) {
    PROVIDER.store(now as usize, Ordering::Release);
}

/// Restore the default embassy-time reads.
pub fn reset_default() {
    PROVIDER.store(0, Ordering::Release);
}
