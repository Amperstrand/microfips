//! L2CAP connection exponential backoff.
//!
//! Ported from fips src/transport/ble/backoff.rs — adapted for no_std/ESP32:
//! - No HashMap (single peer, use Option<Entry>)
//! - No std::time::Instant (use embassy_time::Instant)
//! - No BleAddr (ESP32 only talks to one FIPS daemon)
//!
//! Tracks consecutive connection failures and applies exponential backoff
//! to prevent hammering an unreachable BLE peer. After MAX_FAILURES rapid
//! failures, the peer is "denied" (1-hour blacklist).
//!
//! The "healthy threshold" (30s) prevents long-lived connections from
//! incrementing the failure count — only connections that drop within
//! the first 30s count as failures.

#![cfg(feature = "l2cap")]

// Base backoff interval: 5 seconds. Conservative for BLE — HCI-level
// operations (scan, connect) take 1-3s, so a 5s base gives the controller
// time to settle between attempts.
const BASE_SECS: u64 = 5;

// Maximum backoff: 300 seconds (5 minutes). Caps the exponential growth
// to prevent excessive delays on intermittently reachable devices.
const MAX_SECS: u64 = 300;

// Maximum consecutive failures before auto-deny. After 10 rapid failures
// the peer is considered persistently unreachable and is blacklisted.
// 10 gives more room when the peer has a dual-link collision issue.
const MAX_FAILURES: u32 = 10;

// Deny duration: 300 seconds (5 minutes). After MAX_FAILURES consecutive
// failures, the address is blacklisted for 5 minutes to break a failure loop
// without blocking for an hour.
const DENY_SECS: u64 = 300;

/// If a connection lasted longer than this (seconds), it was healthy.
/// Its disconnection was likely due to mobility or session-level issues,
/// not a transport-level failure. 10s is enough for a complete Noise
/// handshake + data exchange; the FIPS cross-connection bug causes
/// 7-15s connections that ARE functional.
const HEALTHY_THRESHOLD_SECS: u64 = 10;

/// Tracks consecutive failures and next-allowed-attempt time for the single FIPS peer.
struct Entry {
    /// Number of consecutive connection failures (reset on success).
    failures: u32,
    /// Earliest time a new connection attempt is allowed.
    next_allowed: embassy_time::Instant,
}

/// Tracks the deny-blacklist expiry time.
struct DenyEntry {
    /// Time at which the deny expires and reconnection is allowed.
    until: embassy_time::Instant,
}

/// Single-peer exponential backoff tracker for L2CAP connections.
///
/// Ported from fips PeerBackoff (src/transport/ble/backoff.rs).
/// Simplified: no HashMap since ESP32 only connects to one FIPS daemon.
///
/// The deny mechanism is similar to TCP's "exponential backoff with timeout"
/// pattern (RFC 6298): repeated failures trigger progressively longer waits,
/// eventually culminating in a hard timeout (the deny period) after which
/// attempts resume.
pub struct L2capBackoff {
    /// Failure count and next-allowed time (single peer).
    entry: Option<Entry>,
    /// Deny-blacklist entry (1-hour blacklist after MAX_FAILURES).
    denied: Option<DenyEntry>,
}

impl L2capBackoff {
    /// Create a new backoff tracker with production defaults.
    pub const fn new() -> Self {
        Self {
            entry: None,
            denied: None,
        }
    }

    /// Whether the peer is currently auto-denied (1-hour blacklist).
    /// Removes expired entries.
    pub fn is_denied(&mut self) -> bool {
        if let Some(ref d) = self.denied {
            if embassy_time::Instant::now() < d.until {
                return true;
            }
        }
        self.denied = None;
        false
    }

    /// Whether the peer is currently in backoff (should not attempt connection).
    pub fn is_in_backoff(&self) -> bool {
        if let Some(ref e) = self.entry {
            return embassy_time::Instant::now() < e.next_allowed;
        }
        false
    }

    /// Remaining seconds until the backoff expires.
    /// Returns 0 if not in backoff.
    pub fn remaining_secs(&self) -> u64 {
        if let Some(ref e) = self.entry {
            let now = embassy_time::Instant::now();
            if now < e.next_allowed {
                return (e.next_allowed - now).as_secs();
            }
        }
        0
    }

    /// Record a connection failure.
    ///
    /// Connections lasting longer than HEALTHY_THRESHOLD_SECS (30s) should NOT
    /// be recorded as failures — only rapid disconnects indicate a transport-
    /// level problem.
    ///
    /// Returns `true` if the peer has been auto-denied as a result.
    // Ported from fips PeerBackoff::record_failure()
    pub fn record_failure(&mut self) -> bool {
        let now = embassy_time::Instant::now();

        let entry = self.entry.get_or_insert(Entry {
            failures: 0,
            next_allowed: now,
        });

        entry.failures += 1;

        if entry.failures >= MAX_FAILURES {
            self.denied = Some(DenyEntry {
                until: now + embassy_time::Duration::from_secs(DENY_SECS),
            });
            self.entry = None;
            return true;
        }

        // Exponential backoff: 2^failures * BASE_SECS, capped at MAX_SECS
        let delay_secs = (1u64 << entry.failures.min(10).try_into().unwrap_or(10)) * BASE_SECS;
        let capped = delay_secs.min(MAX_SECS);
        // Deterministic jitter (simplified — no BleAddr to hash, use failure count)
        let jitter = ((entry.failures as u64).wrapping_mul(0x517cc1b727220a95)) % (capped / 5 + 1);
        entry.next_allowed = now + embassy_time::Duration::from_secs(capped + jitter);

        false
    }

    /// Clear all backoff state (on successful/healthy connection).
    // Ported from fips PeerBackoff::clear()
    pub fn clear(&mut self) {
        self.entry = None;
        self.denied = None;
    }

    /// Get the current failure count.
    pub fn failure_count(&self) -> u32 {
        self.entry.as_ref().map(|e| e.failures).unwrap_or(0)
    }
}
