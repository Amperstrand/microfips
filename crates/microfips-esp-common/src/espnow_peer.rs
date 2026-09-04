//! Sticky single-peer MAC slot for ESP-NOW relays (#77 DoS hardening).
//!
//! The gateways and node transports historically registered every new
//! source MAC in the radio peer table without ever removing the previous
//! one, and switched the unicast target to whichever source spoke last.
//! Two firmware-side DoS vectors follow:
//!
//! 1. **Peer-table exhaustion** — the ESP-NOW peer table is small (~20
//!    entries); spoofed source MACs fill it and the subsequent
//!    `add_peer` of the legitimate peer fails silently, wedging the
//!    relay until reboot.
//! 2. **MAC flapping / fragment interleaving** — alternating source MACs
//!    both steal the unicast target (last speaker wins) and reset the
//!    shared reassembler's partial state, denying the legitimate node's
//!    frames.
//!
//! [`PeerSlot`] fixes both with sticky semantics: the first source to
//! speak owns the slot while it stays active (heard within
//! [`ACTIVE_HOLD_MS`]); foreign frames are ignored before they can touch
//! reassembly state, and a slot move removes the previous MAC from the
//! radio table so at most one peer is registered at any time. A silent
//! owner releases the slot after [`ACTIVE_HOLD_MS`], so a dead node is
//! replaced on the next legitimate frame. The MAC remains a routing hint
//! only — identity is proven by the Noise handshake end-to-end.

use portable_atomic::AtomicU64;

/// How long the current peer keeps the slot after its last frame.
/// Heartbeats arrive every ~10s, so an active node refreshes constantly;
/// 60s rides out link-death re-handshakes (~31s) without ever releasing
/// a live peer.
pub const ACTIVE_HOLD_MS: u64 = 60_000;

/// What the caller should do with the radio peer table after observing
/// a frame source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSlotAction {
    /// Slot empty: register this MAC.
    Register([u8; 6]),
    /// Slot moved after idle expiry: remove the old MAC, register the new
    /// one — the table never holds more than one peer.
    Swap { remove: [u8; 6], add: [u8; 6] },
    /// Frame from the current owner: refresh stickiness, no table change.
    Keep,
    /// Foreign source while the slot is held: drop the frame entirely.
    Ignore,
}

pub struct PeerSlot {
    mac: Option<[u8; 6]>,
    last_seen_ms: u64,
}

impl PeerSlot {
    pub const fn new() -> Self {
        Self {
            mac: None,
            last_seen_ms: 0,
        }
    }

    /// Feed one observed source MAC. `now_ms` is a monotonic millisecond
    /// clock owned by the caller.
    pub fn observe(&mut self, src: [u8; 6], now_ms: u64) -> PeerSlotAction {
        match self.mac {
            Some(current) if current == src => {
                self.last_seen_ms = now_ms;
                PeerSlotAction::Keep
            }
            Some(_) if now_ms.saturating_sub(self.last_seen_ms) <= ACTIVE_HOLD_MS => {
                PeerSlotAction::Ignore
            }
            Some(current) => {
                self.mac = Some(src);
                self.last_seen_ms = now_ms;
                PeerSlotAction::Swap {
                    remove: current,
                    add: src,
                }
            }
            None => {
                self.mac = Some(src);
                self.last_seen_ms = now_ms;
                PeerSlotAction::Register(src)
            }
        }
    }

    /// Current slot owner, if any.
    pub fn current(&self) -> Option<[u8; 6]> {
        self.mac
    }
}

impl Default for PeerSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Publishes the current slot owner to the relay's reverse direction
/// (radio → host learns the MAC; host → radio unicasts to it). Returns
/// the packed value for an `AtomicU64` (`0` = no peer yet).
pub fn publish_current(slot: &PeerSlot, into: &AtomicU64) {
    into.store(
        slot.current()
            .map(crate::espnow_frag::pack_mac)
            .unwrap_or(0),
        portable_atomic::Ordering::Relaxed,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [0xAA; 6];
    const B: [u8; 6] = [0xBB; 6];

    #[test]
    fn first_speaker_registers() {
        let mut slot = PeerSlot::new();
        assert_eq!(slot.observe(A, 1_000), PeerSlotAction::Register(A));
        assert_eq!(slot.current(), Some(A));
    }

    #[test]
    fn owner_frames_keep_slot() {
        let mut slot = PeerSlot::new();
        slot.observe(A, 1_000);
        assert_eq!(slot.observe(A, 5_000), PeerSlotAction::Keep);
        assert_eq!(slot.current(), Some(A));
    }

    #[test]
    fn foreign_ignored_while_active() {
        let mut slot = PeerSlot::new();
        slot.observe(A, 1_000);
        // B speaks well within the hold window
        assert_eq!(slot.observe(B, 2_000), PeerSlotAction::Ignore);
        // and A still owns the slot afterwards
        assert_eq!(slot.observe(A, 3_000), PeerSlotAction::Keep);
        assert_eq!(slot.current(), Some(A));
    }

    #[test]
    fn stickiness_expires_without_owner_frames() {
        let mut slot = PeerSlot::new();
        slot.observe(A, 1_000);
        // last A frame at 1_000; B arrives after the hold window
        assert_eq!(
            slot.observe(B, 1_000 + ACTIVE_HOLD_MS + 1),
            PeerSlotAction::Swap { remove: A, add: B }
        );
        assert_eq!(slot.current(), Some(B));
    }

    #[test]
    fn owner_frames_extend_the_hold() {
        let mut slot = PeerSlot::new();
        slot.observe(A, 1_000);
        // A keeps talking; B tries at a time that would exceed the
        // original hold but not the refreshed one
        slot.observe(A, 30_000);
        assert_eq!(
            slot.observe(B, 30_000 + ACTIVE_HOLD_MS),
            PeerSlotAction::Ignore
        );
        // exactly at the refreshed boundary the owner is still fresh
        // (hold is inclusive)
        assert_eq!(
            slot.observe(B, 30_000 + ACTIVE_HOLD_MS + 1),
            PeerSlotAction::Swap { remove: A, add: B }
        );
    }

    #[test]
    fn idle_owner_returning_keeps_slot_over_newcomer() {
        let mut slot = PeerSlot::new();
        slot.observe(A, 1_000);
        // A went silent past the hold, but its next frame re-claims the
        // slot before any newcomer has spoken
        assert_eq!(
            slot.observe(A, 1_000 + ACTIVE_HOLD_MS + 1),
            PeerSlotAction::Keep
        );
        assert_eq!(slot.current(), Some(A));
    }

    #[test]
    fn publish_current_roundtrips_through_atomic() {
        use crate::espnow_frag::unpack_mac;
        use portable_atomic::Ordering;
        let mut slot = PeerSlot::new();
        let atomic = AtomicU64::new(0);
        publish_current(&slot, &atomic);
        assert_eq!(atomic.load(Ordering::Relaxed), 0);
        slot.observe(A, 1);
        publish_current(&slot, &atomic);
        assert_eq!(unpack_mac(atomic.load(Ordering::Relaxed)), Some(A));
    }
}
