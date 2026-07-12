//! BLE send rate limiter using token bucket algorithm.
//!
//! Ported from fips src/transport/ble/rate_limit.rs (SendRateLimiter only).
//!
//! Uses integer-only arithmetic (no f64) for ESP32 — no FPU in no_std.
//! Token bucket: tokens represent bytes, refill at `rate_bytes_per_sec`,
//! cap at `burst_bytes`. Before each send, `acquire(bytes)` waits until
//! enough tokens are available.

#![cfg(feature = "l2cap")]

use embassy_time::{Duration, Instant, Timer};

/// Token-bucket rate limiter for BLE outbound frames.
///
/// All arithmetic is u32-based to avoid f64 on ESP32 (no FPU in no_std).
/// - `rate_bytes_per_sec`: refill rate (bytes/sec)
/// - `burst_bytes`: bucket capacity (max accumulated tokens)
/// - `tokens`: current available bytes
pub struct SendRateLimiter {
    rate_bytes_per_sec: u32,
    burst_bytes: u32,
    tokens: u32,
    last_refill: Instant,
}

impl SendRateLimiter {
    /// Create a new rate limiter.
    ///
    /// `rate_bps` is in **bits** per second (divided by 8 for bytes/sec).
    /// `burst_bytes` is the maximum burst size (bucket capacity).
    /// Bucket starts full (`tokens = burst_bytes`).
    pub fn new(rate_bps: u32, burst_bytes: u32) -> Self {
        let rate_bytes_per_sec = rate_bps / 8;
        Self {
            rate_bytes_per_sec,
            burst_bytes,
            tokens: burst_bytes,
            last_refill: Instant::now(),
        }
    }

    /// Try to acquire `bytes` tokens without waiting.
    /// Returns `true` if tokens were available and consumed, `false` if not.
    pub fn try_acquire(&mut self, bytes: usize) -> bool {
        if self.rate_bytes_per_sec == 0 {
            return true;
        }
        self.refill();
        let bytes = bytes as u32;
        if self.tokens >= bytes {
            self.tokens -= bytes;
            return true;
        }
        false
    }

    /// Acquire `bytes` tokens, waiting if necessary.
    ///
    /// Integer wait calculation: `wait_ms = (deficit_bytes * 1000) / rate_bytes_per_sec`.
    /// Minimum wait is 1ms to avoid busy-looping.
    pub async fn acquire(&mut self, bytes: usize) {
        if self.rate_bytes_per_sec == 0 {
            return;
        }

        let bytes = bytes as u32;
        loop {
            self.refill();

            if self.tokens >= bytes {
                self.tokens -= bytes;
                return;
            }

            let deficit = bytes - self.tokens;
            // Integer wait: (deficit * 1000) / rate_bytes_per_sec, min 1ms
            let wait_ms = ((deficit as u64 * 1000) / self.rate_bytes_per_sec as u64).max(1) as u64;
            Timer::after(Duration::from_millis(wait_ms)).await;
        }
    }

    /// Standard token bucket refill: `tokens += elapsed_ms * rate_bytes_per_sec / 1000`.
    /// Caps at `burst_bytes` (bucket capacity) to prevent infinite accumulation.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.last_refill).as_millis() as u64;
        if elapsed_ms > 0 {
            // Integer refill: tokens += (elapsed_ms * rate_bytes_per_sec) / 1000
            let new_tokens = (elapsed_ms * self.rate_bytes_per_sec as u64) / 1000;
            self.tokens = self
                .tokens
                .saturating_add(new_tokens as u32)
                .min(self.burst_bytes);
            self.last_refill = now;
        }
    }
}
