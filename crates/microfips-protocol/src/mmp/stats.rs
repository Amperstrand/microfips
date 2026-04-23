use core::sync::atomic::{AtomicU32, Ordering};

static SRTT_MS: AtomicU32 = AtomicU32::new(0);
static LOSS_PCT: AtomicU32 = AtomicU32::new(0);
static GOODPUT_KBPS: AtomicU32 = AtomicU32::new(0);
static JITTER_US: AtomicU32 = AtomicU32::new(0);

pub fn update(srtt_ms: u32, loss_pct: u32, goodput_kbps: u32, jitter_us: u32) {
    SRTT_MS.store(srtt_ms, Ordering::Relaxed);
    LOSS_PCT.store(loss_pct, Ordering::Relaxed);
    GOODPUT_KBPS.store(goodput_kbps, Ordering::Relaxed);
    JITTER_US.store(jitter_us, Ordering::Relaxed);
}

pub fn srtt_ms() -> u32 {
    SRTT_MS.load(Ordering::Relaxed)
}

pub fn loss_pct() -> u32 {
    LOSS_PCT.load(Ordering::Relaxed)
}

pub fn goodput_kbps() -> u32 {
    GOODPUT_KBPS.load(Ordering::Relaxed)
}

pub fn jitter_us() -> u32 {
    JITTER_US.load(Ordering::Relaxed)
}
