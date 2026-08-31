//! Sliding replay window for established-frame counters (no_std).
//!
//! Port of fips `src/noise/replay.rs` (fork/main, 2026-08-31): WireGuard-style
//! anti-replay (RFC 6479). `check` before attempting decryption (cheap reject),
//! `accept` only after successful decryption so an attacker cannot exhaust the
//! window with garbage.

use core::fmt;

/// Window size in counters. Matches fips `REPLAY_WINDOW_SIZE`.
pub const REPLAY_WINDOW_SIZE: usize = 2048;

/// Tracks which packet counters have been received within
/// [`REPLAY_WINDOW_SIZE`]. Counters below the window or already seen are
/// rejected. Bit `i` of the bitmap corresponds to counter `highest - i`.
#[derive(Clone)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    /// Whether a counter is acceptable (not replayed, not too old).
    /// Does NOT update the window — call [`Self::accept`] after successful
    /// decryption.
    pub fn check(&self, counter: u64) -> bool {
        // A conforming sender never emits u64::MAX (nonce exhaustion guard);
        // refusing it here keeps `accept` from pinning `highest` at the
        // ceiling, which would wedge the window against every later counter.
        if counter == u64::MAX {
            return false;
        }

        if counter > self.highest {
            return true;
        }

        let diff = self.highest - counter;
        if diff as usize >= REPLAY_WINDOW_SIZE {
            return false;
        }

        let word_idx = (diff as usize) / 64;
        let bit_idx = (diff as usize) % 64;
        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// Mark a counter as seen. Call only after successful decryption.
    pub fn accept(&mut self, counter: u64) {
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift as usize >= REPLAY_WINDOW_SIZE {
                self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                self.shift_bitmap(shift as usize);
            }
            self.highest = counter;
            self.bitmap[0] |= 1;
        } else {
            let diff = self.highest - counter;
            let word_idx = (diff as usize) / 64;
            let bit_idx = (diff as usize) % 64;
            self.bitmap[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// Highest counter accepted so far.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Reset (session restart / rekey).
    pub fn reset(&mut self) {
        self.highest = 0;
        self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
    }

    fn shift_bitmap(&mut self, shift: usize) {
        if shift >= REPLAY_WINDOW_SIZE {
            self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            return;
        }

        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift > 0 {
            for i in (word_shift..self.bitmap.len()).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for i in 0..word_shift {
                self.bitmap[i] = 0;
            }
        }

        if bit_shift > 0 {
            let mut carry = 0u64;
            for i in 0..self.bitmap.len() {
                let new_carry = self.bitmap[i] >> (64 - bit_shift);
                self.bitmap[i] = (self.bitmap[i] << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("highest", &self.highest)
            .field("window_size", &REPLAY_WINDOW_SIZE)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_window_accepts_any_forward_counter() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        w.accept(0);
        assert!(w.check(1));
        w.accept(1);
        assert_eq!(w.highest(), 1);
    }

    #[test]
    fn duplicate_counter_is_rejected() {
        let mut w = ReplayWindow::new();
        w.accept(5);
        assert!(!w.check(5), "immediate duplicate must be rejected");
    }

    #[test]
    fn out_of_order_within_window_is_accepted_once() {
        let mut w = ReplayWindow::new();
        w.accept(10);
        assert!(w.check(8), "in-window unseen counter must pass");
        w.accept(8);
        assert!(!w.check(8), "second copy must be rejected");
        assert!(w.check(9));
    }

    #[test]
    fn counter_below_window_is_rejected() {
        let mut w = ReplayWindow::new();
        w.accept(10_000);
        assert!(
            !w.check(10_000 - REPLAY_WINDOW_SIZE as u64),
            "exactly one window below must be rejected"
        );
        assert!(
            w.check(10_000 - REPLAY_WINDOW_SIZE as u64 + 1),
            "newest in-window slot must pass"
        );
    }

    #[test]
    fn large_jump_resets_window_completely() {
        let mut w = ReplayWindow::new();
        for c in 0..100u64 {
            w.accept(c);
        }
        w.accept(3000);
        assert!(!w.check(100), "pre-jump counters are below the window now");
        assert!(w.check(2999), "only the accepted tip is marked seen");
        assert!(!w.check(3000));
    }

    #[test]
    fn partial_shift_preserves_seen_bits_across_words() {
        // shift 68 = 1 word + 4 bits: exercises the word-shift AND the
        // bit-shift-with-carry paths together.
        let mut w = ReplayWindow::new();
        w.accept(0);
        w.accept(1);
        w.accept(2);
        w.accept(70);
        assert!(!w.check(0));
        assert!(!w.check(1));
        assert!(!w.check(2));
        assert!(!w.check(70));
        assert!(w.check(69));
        assert!(w.check(3));
        assert_eq!(w.highest(), 70);
    }

    #[test]
    fn u64_max_is_always_rejected() {
        let mut w = ReplayWindow::new();
        assert!(!w.check(u64::MAX), "u64::MAX must never be acceptable");
        w.accept(u64::MAX - 1);
        assert!(!w.check(u64::MAX));
        assert!(w.check(u64::MAX - 2));
    }

    #[test]
    fn reset_empties_the_window() {
        let mut w = ReplayWindow::new();
        w.accept(1234);
        w.reset();
        assert!(w.check(1234), "after reset the counter is unseen again");
        assert_eq!(w.highest(), 0);
    }

    #[test]
    fn sequential_stream_never_falsely_rejects() {
        let mut w = ReplayWindow::new();
        for c in 0..10_000u64 {
            assert!(w.check(c), "sequential counter {c} must pass");
            w.accept(c);
        }
        assert_eq!(w.highest(), 9_999);
    }

    #[test]
    fn sparse_reordering_within_window_passes() {
        let mut w = ReplayWindow::new();
        // Deliver each block of 10 in a fixed shuffled order: every frame is
        // out-of-order relative to its neighbors but unique — all must pass.
        const ORDER: [u64; 10] = [9, 0, 5, 3, 7, 1, 8, 2, 6, 4];
        for base in (200..400u64).step_by(10) {
            for off in ORDER {
                let c = base + off;
                assert!(w.check(c), "shuffled counter {c} must pass");
                w.accept(c);
            }
        }
        assert!(w.highest() >= 399);
    }
}
