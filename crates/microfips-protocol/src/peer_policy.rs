use embassy_time::{Duration, Instant};

pub const MIN_RECONNECT_MS: u64 = 5_000;
pub const MAX_RECONNECT_MS: u64 = 300_000;
pub const RECONNECT_BACKOFF_BASE_MS: u64 = 5_000;
pub const FRAME_RATE_WINDOW_MS: u64 = 1_000;
pub const FRAME_RATE_MAX: u16 = 100;
pub const SILENT_PEER_SECS: u64 = 30;
pub const SILENT_PEER_MIN_DATA_RATIO: u32 = 1;
pub const MAX_CONSECUTIVE_BAD: u16 = 20;
pub const MAX_CONSECUTIVE_FAILURES: u16 = 20;

pub struct PeerPolicy {
    last_connect: Option<Instant>,
    consecutive_failures: u16,
    frame_count: u16,
    frame_window_start: Instant,
    data_frames_recv: u32,
    heartbeats_recv: u32,
    session_start: Option<Instant>,
    consecutive_bad_frames: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    Backoff(Duration),
    Reject,
}

impl PeerPolicy {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            last_connect: None,
            consecutive_failures: 0,
            frame_count: 0,
            frame_window_start: now,
            data_frames_recv: 0,
            heartbeats_recv: 0,
            session_start: None,
            consecutive_bad_frames: 0,
        }
    }

    pub fn check_reconnect(&self, now: Instant) -> PolicyVerdict {
        let Some(last_connect) = self.last_connect else {
            return PolicyVerdict::Allow;
        };

        let elapsed_ms = now.as_millis().saturating_sub(last_connect.as_millis()) as u64;

        let failure_backoff_ms = if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            MAX_RECONNECT_MS
        } else if self.consecutive_failures == 0 {
            0
        } else {
            let shift = (self.consecutive_failures - 1).min(15) as u32;
            RECONNECT_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(MAX_RECONNECT_MS)
        };

        let required_ms = MIN_RECONNECT_MS.max(failure_backoff_ms);

        if elapsed_ms < required_ms {
            PolicyVerdict::Backoff(Duration::from_millis(required_ms - elapsed_ms))
        } else {
            PolicyVerdict::Allow
        }
    }

    pub fn check_frame_rate(&mut self, now: Instant) -> PolicyVerdict {
        let elapsed_ms = now
            .as_millis()
            .saturating_sub(self.frame_window_start.as_millis()) as u64;

        if elapsed_ms >= FRAME_RATE_WINDOW_MS {
            self.frame_window_start = now;
            self.frame_count = 0;
        }

        if self.frame_count >= FRAME_RATE_MAX {
            self.frame_window_start = now;
            self.frame_count = 0;
            return PolicyVerdict::Reject;
        }

        self.frame_count = self.frame_count.saturating_add(1);
        PolicyVerdict::Allow
    }

    pub fn record_handshake_ok(&mut self, now: Instant) {
        self.consecutive_failures = 0;
        self.last_connect = None;
        self.reset_session();
        self.session_start = Some(now);
    }

    pub fn record_handshake_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_connect = Some(now);
    }

    pub fn record_connect_attempt(&mut self, now: Instant) {
        self.last_connect = Some(now);
    }

    pub fn record_data_frame(&mut self) {
        self.data_frames_recv = self.data_frames_recv.saturating_add(1);
    }

    pub fn record_heartbeat(&mut self) {
        self.heartbeats_recv = self.heartbeats_recv.saturating_add(1);
    }

    pub fn record_bad_frame(&mut self) {
        self.consecutive_bad_frames = self.consecutive_bad_frames.saturating_add(1);
    }

    pub fn record_good_frame(&mut self) {
        self.consecutive_bad_frames = 0;
    }

    pub fn check_silent_peer(&self, now: Instant) -> PolicyVerdict {
        let Some(session_start) = self.session_start else {
            return PolicyVerdict::Allow;
        };

        let session_secs = now.as_secs().saturating_sub(session_start.as_secs());

        if session_secs > SILENT_PEER_SECS
            && self.data_frames_recv < SILENT_PEER_MIN_DATA_RATIO
            && self.heartbeats_recv > 0
        {
            PolicyVerdict::Reject
        } else {
            PolicyVerdict::Allow
        }
    }

    pub fn check_bad_frame_limit(&self) -> PolicyVerdict {
        if self.consecutive_bad_frames >= MAX_CONSECUTIVE_BAD {
            PolicyVerdict::Reject
        } else {
            PolicyVerdict::Allow
        }
    }

    pub fn reset_session(&mut self) {
        self.data_frames_recv = 0;
        self.heartbeats_recv = 0;
        self.session_start = None;
        self.consecutive_bad_frames = 0;
    }

    pub fn set_session_start(&mut self, instant: Instant) {
        self.session_start = Some(instant);
    }

    #[cfg(test)]
    pub fn force_past_session_start(&mut self) {
        self.session_start = Some(Instant::from_ticks(0));
    }
}

impl Default for PeerPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_backoff(verdict: PolicyVerdict, expected_ms: u64) {
        match verdict {
            PolicyVerdict::Backoff(delay) => {
                assert_eq!(delay, Duration::from_millis(expected_ms));
            }
            other => panic!("expected Backoff({expected_ms}ms), got {other:?}"),
        }
    }

    #[test]
    fn test_new_policy_allows_connect() {
        let policy = PeerPolicy::new();

        assert_eq!(policy.check_reconnect(Instant::now()), PolicyVerdict::Allow);
    }

    #[test]
    fn test_rapid_reconnect_backoff() {
        let mut policy = PeerPolicy::new();
        let now = Instant::now();
        policy.record_connect_attempt(now);

        assert_backoff(policy.check_reconnect(now), MIN_RECONNECT_MS);
    }

    #[test]
    fn test_backoff_increases_with_failures() {
        let mut policy = PeerPolicy::new();
        let now = Instant::now();
        policy.record_handshake_failure(now);

        assert_backoff(
            policy.check_reconnect(now + Duration::from_millis(MIN_RECONNECT_MS - 1)),
            RECONNECT_BACKOFF_BASE_MS - (MIN_RECONNECT_MS - 1),
        );

        assert_eq!(
            policy.check_reconnect(now + Duration::from_millis(RECONNECT_BACKOFF_BASE_MS)),
            PolicyVerdict::Allow
        );

        policy.record_handshake_failure(now + Duration::from_millis(MIN_RECONNECT_MS));
        let after_second = now + Duration::from_millis(MIN_RECONNECT_MS);

        assert_backoff(
            policy.check_reconnect(after_second),
            RECONNECT_BACKOFF_BASE_MS * 2,
        );
    }

    #[test]
    fn test_backoff_caps_at_max() {
        let mut policy = PeerPolicy::new();
        let start = Instant::now();
        let last_failure = start;

        policy.record_handshake_failure(last_failure);
        for _ in 1..MAX_CONSECUTIVE_FAILURES {
            policy.record_handshake_failure(last_failure);
        }

        assert_backoff(policy.check_reconnect(last_failure), MAX_RECONNECT_MS);

        let after_max = last_failure + Duration::from_millis(MAX_RECONNECT_MS + 1);
        assert_eq!(policy.check_reconnect(after_max), PolicyVerdict::Allow);
    }

    #[test]
    fn test_handshake_ok_resets_failures() {
        let mut policy = PeerPolicy::new();
        let now = Instant::now();
        policy.record_handshake_failure(now);
        policy.record_handshake_failure(now + Duration::from_millis(MIN_RECONNECT_MS));

        let ok_at = now + Duration::from_secs(1);
        policy.record_handshake_ok(ok_at);

        assert_eq!(
            policy.check_reconnect(ok_at + Duration::from_millis(MIN_RECONNECT_MS)),
            PolicyVerdict::Allow
        );
    }

    #[test]
    fn test_frame_rate_within_limit() {
        let mut policy = PeerPolicy::new();
        let now = Instant::now();

        for _ in 0..FRAME_RATE_MAX {
            assert_eq!(policy.check_frame_rate(now), PolicyVerdict::Allow);
        }
    }

    #[test]
    fn test_frame_rate_exceeded() {
        let mut policy = PeerPolicy::new();
        let now = Instant::now();

        for _ in 0..FRAME_RATE_MAX {
            assert_eq!(policy.check_frame_rate(now), PolicyVerdict::Allow);
        }

        assert_eq!(policy.check_frame_rate(now), PolicyVerdict::Reject);
    }

    #[test]
    fn test_frame_rate_window_reset() {
        let mut policy = PeerPolicy::new();
        let start = Instant::now();

        for _ in 0..FRAME_RATE_MAX {
            assert_eq!(policy.check_frame_rate(start), PolicyVerdict::Allow);
        }
        assert_eq!(policy.check_frame_rate(start), PolicyVerdict::Reject);

        let next_window = start + Duration::from_millis(FRAME_RATE_WINDOW_MS + 1);
        assert_eq!(policy.check_frame_rate(next_window), PolicyVerdict::Allow);
    }

    #[test]
    fn test_silent_peer_not_detected_early() {
        let mut policy = PeerPolicy::new();
        let start = Instant::now();
        policy.record_handshake_ok(start);
        policy.record_heartbeat();

        let early = start + Duration::from_secs(SILENT_PEER_SECS - 1);
        assert_eq!(policy.check_silent_peer(early), PolicyVerdict::Allow);
    }

    #[test]
    fn test_silent_peer_detected() {
        let mut policy = PeerPolicy::new();
        let start = Instant::now();
        policy.record_handshake_ok(start);
        policy.record_heartbeat();

        let late = start + Duration::from_secs(SILENT_PEER_SECS + 1);
        assert_eq!(policy.check_silent_peer(late), PolicyVerdict::Reject);
    }

    #[test]
    fn test_silent_peer_not_detected_with_data() {
        let mut policy = PeerPolicy::new();
        let start = Instant::now();
        policy.record_handshake_ok(start);
        policy.record_heartbeat();
        policy.record_data_frame();

        let late = start + Duration::from_secs(SILENT_PEER_SECS + 1);
        assert_eq!(policy.check_silent_peer(late), PolicyVerdict::Allow);
    }

    #[test]
    fn test_bad_frame_limit() {
        let mut policy = PeerPolicy::new();

        for _ in 0..MAX_CONSECUTIVE_BAD {
            policy.record_bad_frame();
        }

        assert_eq!(policy.check_bad_frame_limit(), PolicyVerdict::Reject);
    }

    #[test]
    fn test_good_frame_resets_bad_counter() {
        let mut policy = PeerPolicy::new();

        for _ in 0..MAX_CONSECUTIVE_BAD {
            policy.record_bad_frame();
        }
        policy.record_good_frame();

        assert_eq!(policy.check_bad_frame_limit(), PolicyVerdict::Allow);
    }

    #[test]
    fn test_session_reset_clears_counters() {
        let mut policy = PeerPolicy::new();
        let start = Instant::now();
        policy.record_handshake_ok(start);
        policy.record_heartbeat();
        policy.record_data_frame();
        policy.record_bad_frame();
        policy.reset_session();

        let late = start + Duration::from_secs(SILENT_PEER_SECS + 1);
        assert_eq!(policy.check_silent_peer(late), PolicyVerdict::Allow);
        assert_eq!(policy.check_bad_frame_limit(), PolicyVerdict::Allow);
    }
}
